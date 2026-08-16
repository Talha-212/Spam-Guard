# ================== IMPORTS ==================
from flask import Flask, render_template
from views.userbp import user_bp
# ================== APP INIT ==================
app = Flask(__name__)
# ================== REGISTER BLUEPRINT ==================
app.register_blueprint(user_bp)

# ================== ROUTES ==================

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/user")
def user():
    return render_template("user.html")

@app.route("/predict_page")
def predict():
    return render_template("predict.html")

@app.route("/feedback")
def feedback():
    return render_template("feedback.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")
# ================== RUN ==================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
