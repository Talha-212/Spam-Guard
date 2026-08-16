import os
from flask import Blueprint, render_template, request, jsonify
import re
import pickle
import nltk
import numpy as np
import socket
import ssl
import requests
from urllib.parse import urlparse

# ---------------- INIT ----------------
user_bp = Blueprint("user_bp", __name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Lazy NLTK Loader
_nltk_downloaded = False

def ensure_nltk_data():
    global _nltk_downloaded
    if not _nltk_downloaded:
        NLTK_DATA_DIR = os.path.join("/tmp", "nltk_data")
        try:
            os.makedirs(NLTK_DATA_DIR, exist_ok=True)
            if NLTK_DATA_DIR not in nltk.data.path:
                nltk.data.path.append(NLTK_DATA_DIR)
            for resource in ["punkt", "punkt_tab", "stopwords", "wordnet"]:
                try:
                    nltk.download(resource, download_dir=NLTK_DATA_DIR, quiet=True)
                except Exception:
                    pass
        except Exception:
            pass
        _nltk_downloaded = True

# ---------------- LOAD MODELS ----------------
MODEL_DIR = os.path.join(BASE_DIR, "model")

# SMS SPAM MODEL
with open(os.path.join(MODEL_DIR, "vectorizer.pkl"), "rb") as f:
    tfidf = pickle.load(f)

with open(os.path.join(MODEL_DIR, "model.pkl"), "rb") as f:
    sms_model = pickle.load(f)

# URL ML MODEL (YOUR GBC MODEL)
with open(os.path.join(MODEL_DIR, "gbc_malicious.pkl"), "rb") as f:
    url_model = pickle.load(f)


# ---------------- UTIL FUNCTIONS ----------------

def transform_text(text):
    text = text.lower()
    ensure_nltk_data()
    try:
        tokens = nltk.word_tokenize(text)
    except Exception:
        tokens = text.split()
    tokens = [t for t in tokens if t.isalnum()]
    try:
        from nltk.corpus import stopwords
        stop_words = set(stopwords.words("english"))
        tokens = [t for t in tokens if t not in stop_words]
    except Exception:
        pass
    try:
        from nltk.stem import WordNetLemmatizer
        lemma = WordNetLemmatizer()
        tokens = [lemma.lemmatize(t) for t in tokens]
    except Exception:
        pass
    return " ".join(tokens)


def extract_urls(text):
    return re.findall(r"http[s]?://\S+", text.lower())

def remove_urls(text):
    return re.sub(r"http[s]?://\S+", "", text).strip()

# --------- FEATURE EXTRACTION (MUST MATCH TRAINING) ---------
def extract_url_features(url):
    return np.array([
        len(url),
        url.count("."),
        1 if "https" in url else 0,
        1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0,
        sum(c.isdigit() for c in url),
        sum(c.isalpha() for c in url),
        1 if any(w in url for w in ["login","verify","secure","update","account"]) else 0
    ]).reshape(1, -1)

# --------- TRUSTED DOMAINS (WHITELIST) ---------
SAFE_DOMAINS = [
    # Global Trusted
    "google.com",
    "github.com",
    "linkedin.com",
    "youtube.com",
    "youtu.be",
    "kaggle.com",
    "gmail.com",
    "facebook.com",
    "instagram.com",
    "udemy.com",

    # Government & Education
    ".gov",
    ".edu",
    ".ac.in",
    ".gov.in",

    # Banking
    "kotak.bank.in",
    "fastag.kotak.bank.in",
    "sbi.co.in",
    "icicibank.com",
    "hdfcbank.com",
    "axisbank.com",
    "paytm.com",
    "phonepe.com",
    "upi",

    # Telecom
    "jio.com",
    "myjio.com",
    "jiocinema.com",
    "jiofiber.com",
    "airtel.in",
    "airtel.com",
    "myairtel.com",
    "airtelfiber.com",
    "vodafoneidea.com",
    "vi.in",
    "bsnl.co.in",

    # Delivery / OTP / SMS Services
    "amazon.in",
    "flipkart.com",
    "swiggy.com",
    "zomato.com",
    "ola.com",
    "uber.com",

    # URL Shorteners (Trusted ones)
    "bit.ly",
    "tinyurl.com",
    "t.co",
]

# --------- FREE LIVE SAFETY CHECKS (NO PAID API) ---------
def domain_exists(url):
    try:
        domain = urlparse(url).netloc
        socket.gethostbyname(domain)
        return True
    except:
        return False

def has_valid_ssl(url):
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True
    except:
        return False

def redirects_to_https(url):
    try:
        r = requests.get(url, allow_redirects=True, timeout=5)
        return r.url.startswith("https://")
    except:
        return False

# --------- HYBRID URL DECISION FUNCTION ---------
def predict_url_ml(url):

    # STEP 1: WHITELIST CHECK
    for domain in SAFE_DOMAINS:
        if domain in url:
            if url.startswith("https://"):
                return "safe", f"Whitelisted trusted domain: {domain}"
            else:
                return "warning", f"Trusted domain but uses HTTP: {domain}"

    # STEP 2: LIVE TECHNICAL CHECKS (FREE ALTERNATIVE TO GOOGLE)
    if not domain_exists(url):
        return "malicious", "Domain does not exist"

    if not has_valid_ssl(url):
        return "warning", "No valid SSL certificate"

    if not redirects_to_https(url):
        return "warning", "Does not properly redirect to HTTPS"

    # STEP 3: FALLBACK TO YOUR GBC MODEL
    features = extract_url_features(url)
    pred = url_model.predict(features)[0]

    # In your mapping: 1 = benign, others = risky
    if pred == 1:
        return "safe", "URL classified as benign by GBC model"
    else:
        return "malicious", "GBC model flagged this URL as risky"

# ---------------- ROUTES ----------------

@user_bp.route("/user")
def user():
    return render_template("user.html")

@user_bp.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()

    if not data or "message" not in data:
        return jsonify({"result": "Please enter a valid message"})

    message = data["message"].strip()

    if not message:
        return jsonify({"result": "Input cannot be empty"})

    # STEP 1: EXTRACT URL
    urls = extract_urls(message)

    # STEP 2: CHECK URL FIRST
    url_warning = None

    for url in urls:
        status, reason = predict_url_ml(url)

        if status == "malicious":
            return jsonify({
                "result": f"🚨 Malicious URL Detected\nReason: {reason}"
            })

        if status == "warning":
            url_warning = f"⚠️ Security Warning\nReason: {reason}"

    # IF ONLY URL WAS PROVIDED
    if urls and message.strip() == urls[0]:
        status, reason = predict_url_ml(urls[0])

        if status == "safe":
            return jsonify({
                "result": f"✅ Legitimate URL\nReason: {reason}"
            })

    # STEP 3: REMOVE URL BEFORE SMS CHECK
    cleaned_message = remove_urls(message)

    if not cleaned_message:
        if url_warning:
            return jsonify({"result": url_warning})
        return jsonify({"result": "✅ Legitimate URL (No text content to analyze)"})

    # STEP 4: SMS SPAM CHECK
    processed_text = transform_text(cleaned_message)
    vector = tfidf.transform([processed_text])
    prediction = sms_model.predict(vector)[0]

    if prediction == 1:
        return jsonify({"result": "⚠️ Spam Message Detected"})

    # STEP 5: SHOW WARNING IF ANY
    if url_warning:
        return jsonify({"result": url_warning})

    # FINAL SAFE OUTPUT
    if urls:
        return jsonify({
            "result": "✅ Legitimate Message (URLs are safe)"
        })

    return jsonify({"result": "✅ Legitimate Message"})


