import os
import re
import pickle
import socket
import ssl

from flask import Blueprint, render_template, request, jsonify

user_bp = Blueprint("user_bp", __name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "model")

# Models are loaded lazily. This keeps the Flask homepage from crashing during
# cold start if a scientific/ML dependency or model has a loading problem.
tfidf = None
sms_model = None
url_model = None
_nltk_downloaded = False


def load_model(filename):
    try:
        with open(os.path.join(MODEL_DIR, filename), "rb") as f:
            return pickle.load(f)
    except Exception:
        return None


def ensure_sms_models():
    global tfidf, sms_model
    if tfidf is None:
        tfidf = load_model("vectorizer.pkl")
    if sms_model is None:
        sms_model = load_model("model.pkl")
    return tfidf is not None and sms_model is not None


def ensure_url_model():
    global url_model
    if url_model is None:
        url_model = load_model("gbc_malicious.pkl")
    return url_model is not None


def ensure_nltk_data():
    global _nltk_downloaded
    if _nltk_downloaded:
        return

    try:
        import nltk
        nltk_data_dir = "/tmp/nltk_data"
        os.makedirs(nltk_data_dir, exist_ok=True)
        if nltk_data_dir not in nltk.data.path:
            nltk.data.path.append(nltk_data_dir)

        for resource in ["punkt", "punkt_tab", "stopwords", "wordnet"]:
            try:
                nltk.download(resource, download_dir=nltk_data_dir, quiet=True)
            except Exception:
                pass
    except Exception:
        pass

    _nltk_downloaded = True


def transform_text(text):
    text = text.lower()
    ensure_nltk_data()

    try:
        import nltk
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


def extract_url_features(url):
    import numpy as np
    return np.array([
        len(url),
        url.count("."),
        1 if "https" in url else 0,
        1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0,
        sum(c.isdigit() for c in url),
        sum(c.isalpha() for c in url),
        1 if any(w in url for w in ["login", "verify", "secure", "update", "account"]) else 0,
    ]).reshape(1, -1)


SAFE_DOMAINS = [
    "google.com", "github.com", "linkedin.com", "youtube.com", "youtu.be",
    "kaggle.com", "gmail.com", "facebook.com", "instagram.com", "udemy.com",
    ".gov", ".edu", ".ac.in", ".gov.in",
    "kotak.bank.in", "fastag.kotak.bank.in", "sbi.co.in", "icicibank.com",
    "hdfcbank.com", "axisbank.com", "paytm.com", "phonepe.com", "upi",
    "jio.com", "myjio.com", "jiocinema.com", "jiofiber.com", "airtel.in",
    "airtel.com", "myairtel.com", "airtelfiber.com", "vodafoneidea.com",
    "vi.in", "bsnl.co.in", "amazon.in", "flipkart.com", "swiggy.com",
    "zomato.com", "ola.com", "uber.com", "bit.ly", "tinyurl.com", "t.co",
]


def domain_exists(url):
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False


def has_valid_ssl(url):
    try:
        from urllib.parse import urlparse
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True
    except Exception:
        return False


def redirects_to_https(url):
    try:
        import requests
        r = requests.get(url, allow_redirects=True, timeout=5)
        return r.url.startswith("https://")
    except Exception:
        return False


def predict_url_ml(url):
    for domain in SAFE_DOMAINS:
        if domain in url:
            if url.startswith("https://"):
                return "safe", f"Whitelisted trusted domain: {domain}"
            return "warning", f"Trusted domain but uses HTTP: {domain}"

    if not domain_exists(url):
        return "malicious", "Domain does not exist"

    if not has_valid_ssl(url):
        return "warning", "No valid SSL certificate"

    if not redirects_to_https(url):
        return "warning", "Does not properly redirect to HTTPS"

    if not ensure_url_model():
        return "warning", "URL model is temporarily unavailable; treat this link with caution"

    try:
        features = extract_url_features(url)
        pred = url_model.predict(features)[0]
        if pred == 1:
            return "safe", "URL classified as benign by GBC model"
        return "malicious", "GBC model flagged this URL as risky"
    except Exception:
        return "warning", "URL model could not analyze this link; treat it with caution"


@user_bp.route("/user")
def user():
    return render_template("user.html")


@user_bp.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(silent=True)

        if not data or "message" not in data:
            return jsonify({"result": "Please enter a valid message"})

        message = str(data["message"]).strip()
        if not message:
            return jsonify({"result": "Input cannot be empty"})

        urls = extract_urls(message)
        url_warning = None

        for url in urls:
            status, reason = predict_url_ml(url)
            if status == "malicious":
                return jsonify({"result": f"🚨 Malicious URL Detected\nReason: {reason}"})
            if status == "warning":
                url_warning = f"⚠️ Security Warning\nReason: {reason}"

        if urls and message.strip() == urls[0]:
            status, reason = predict_url_ml(urls[0])
            if status == "safe":
                return jsonify({"result": f"✅ Legitimate URL\nReason: {reason}"})

        cleaned_message = remove_urls(message)
        if not cleaned_message:
            if url_warning:
                return jsonify({"result": url_warning})
            return jsonify({"result": "✅ Legitimate URL (No text content to analyze)"})

        if not ensure_sms_models():
            return jsonify({"result": "⚠️ Spam model is temporarily unavailable; treat this message with caution"})

        processed_text = transform_text(cleaned_message)
        vector = tfidf.transform([processed_text])
        prediction = sms_model.predict(vector)[0]

        if prediction == 1:
            return jsonify({"result": "⚠️ Spam Message Detected"})

        if url_warning:
            return jsonify({"result": url_warning})

        if urls:
            return jsonify({"result": "✅ Legitimate Message (URLs are safe)"})

        return jsonify({"result": "✅ Legitimate Message"})

    except Exception:
        return jsonify({"result": "⚠️ The analyzer is temporarily unavailable. Please try again."}), 200
