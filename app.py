from flask import Flask, request, render_template, jsonify
import re
import random

app = Flask(__name__)

def check_strength(pwd):
    score = sum([
        len(pwd) >= 8,
        bool(re.search(r'[A-Z]', pwd)),
        bool(re.search(r'[a-z]', pwd)),
        bool(re.search(r'\d', pwd)),
        bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', pwd))
    ])
    levels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
    return levels[min(score, 4)]

def suggest_password(name, birth, word):
    specials = "!@#$%^&*"
    suggestion = (
        name[:2].capitalize() +
        word[::-1].lower() +
        str(random.randint(10, 99)) +
        birth[-2:] +
        random.choice(specials)
    )
    return suggestion

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/password", methods=["POST"])
def password_tool():
    data = request.get_json()
    if "custom" in data:
        pwd = data["custom"]
        strength = check_strength(pwd)
        return jsonify({"strength": strength})
    else:
        name = data.get("name", "")
        birth = data.get("birth", "")
        word = data.get("word", "")
        suggested = suggest_password(name, birth, word)
        strength = check_strength(suggested)
        return jsonify({"suggested": suggested, "strength": strength})

if __name__ == "__main__":
    app.run(debug=True)
