from flask import Flask, request, render_template, jsonify, session
import re
import random
import requests
import hashlib
from datetime import datetime

app = Flask(__name__)
app.secret_key = "your-secret-key"

# Sample dictionary for demo
DICTIONARY_WORDS = {"password", "admin", "login", "qwerty", "letmein", "welcome"}

# Keyboard patterns (example for demo)
KEYBOARD_PATTERNS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "!@#$%^&*()"
]

# Strength levels and colors
LEVELS = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
COLORS = ["#ff0000", "#ff6600", "#ffcc00", "#33cc33", "#006600"]

# Helper: check if password contains keyboard walks
def contains_keyboard_walk(pwd):
    pwd_lower = pwd.lower()
    for pattern in KEYBOARD_PATTERNS:
        # Check for sequences length >= 3 in pwd inside keyboard rows or reversed
        for i in range(len(pattern) - 2):
            seq = pattern[i:i+3]
            if seq in pwd_lower or seq[::-1] in pwd_lower:
                return True
    return False

# Check if password breached in Have I Been Pwned (HIBP) API
def check_pwned_api(password):
    sha1pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1pwd[:5]
    suffix = sha1pwd[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=3)
        if response.status_code != 200:
            return None  # Could not check
        hashes = response.text.splitlines()
        for line in hashes:
            hsh, count = line.split(':')
            if hsh == suffix:
                return int(count)
        return 0
    except Exception:
        return None  # API error

def analyze_password(pwd):
    score = 0
    suggestions = []
    patterns_found = []

    # Length check
    if len(pwd) >= 8:
        score += 1
    else:
        suggestions.append("Password should be at least 8 characters long.")

    # Character classes
    if re.search(r'[A-Z]', pwd):
        score += 1
    else:
        suggestions.append("Add uppercase letters.")

    if re.search(r'[a-z]', pwd):
        score += 1
    else:
        suggestions.append("Add lowercase letters.")

    if re.search(r'\d', pwd):
        score += 1
    else:
        suggestions.append("Include digits.")

    if re.search(r'[!@#$%^&*(),.?\":{}|<>]', pwd):
        score += 1
    else:
        suggestions.append("Include special characters.")

    # Repeated chars
    if re.search(r'(.)\1{2,}', pwd):
        suggestions.append("Avoid repeated characters (e.g., aaa, 111).")
    else:
        score += 1

    # Dictionary words
    dict_word_found = False
    for word in DICTIONARY_WORDS:
        if word in pwd.lower():
            suggestions.append(f"Avoid dictionary word: '{word}'")
            dict_word_found = True
            patterns_found.append(f"Dictionary word: '{word}'")
            break
    if not dict_word_found:
        score += 1

    # Keyboard walk detection
    if contains_keyboard_walk(pwd):
        suggestions.append("Avoid keyboard patterns (e.g., qwerty, 12345).")
        patterns_found.append("Keyboard pattern detected")
    else:
        score += 1

    # Breach check with Have I Been Pwned
    breach_count = check_pwned_api(pwd)
    if breach_count is None:
        # API unreachable or error - no penalty or bonus
        pass
    elif breach_count > 0:
        suggestions.append(f"This password has appeared in data breaches {breach_count} times! Change it.")
        patterns_found.append("Password breached")
        # Penalize score strongly if breached
        score = max(0, score - 2)
    else:
        score += 1  # Bonus for clean password

    # Cap score to max level index
    level_index = min(score, len(LEVELS) - 1)
    strength_level = LEVELS[level_index]
    color = COLORS[level_index]

    # Store history in session with timestamp, pwd, strength level, color
    history_entry = {
        "password": pwd,
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "strength": strength_level,
        "color": color,
        "patterns": patterns_found
    }

    if "history" not in session:
        session["history"] = []
    session["history"].append(history_entry)
    # Keep only last 10
    session["history"] = session["history"][-10:]

    return {
        "strength": strength_level,
        "color": color,
        "suggestions": suggestions,
        "patterns": patterns_found,
        "breach_count": breach_count or 0,
        "history": session["history"]
    }

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
        result = analyze_password(pwd)
        return jsonify(result)
    else:
        name = data.get("name", "")
        birth = data.get("birth", "")
        word = data.get("word", "")
        suggested = suggest_password(name, birth, word)
        result = analyze_password(suggested)
        result["suggested"] = suggested
        return jsonify(result)

@app.route("/clear-history", methods=["POST"])
def clear_history():
    session.pop("history", None)
    return jsonify({"message": "History cleared"})

if __name__ == "__main__":
    app.run(debug=True)
