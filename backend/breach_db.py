"""
Password Strength Checker + Breach Detail Lookup
Uses:
  1. api.pwnedpasswords.com/range/{prefix}  — checks if password was leaked (free, no key)
  2. haveibeenpwned.com/api/v3/breachedaccount — shows WHICH sites were breached (free key needed)
     If no key available, we show helpful fallback message with manual check link.
"""
import re, hashlib, requests, math, os

COMMON_PASSWORDS = {
    "password", "123456", "qwerty", "111111", "abc123",
    "letmein", "welcome", "monkey", "dragon", "master"
}

HIBP_API_KEY = ""

def calc_entropy(password: str) -> float:
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"\d",    password): charset += 10
    if re.search(r"[^A-Za-z0-9]", password): charset += 32
    if charset == 0: return 0.0
    return len(password) * math.log2(charset)

def hibp_pwned_count(password: str) -> int:
    sha1   = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
            timeout=5
        )
        if resp.status_code != 200:
            return -1
        for line in resp.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return int(count)
        return 0
    except Exception:
        return -1

def hibp_email_breaches(email: str) -> list:
    """
    Returns list of breach site names for an email.
    Requires HIBP_API_KEY. If no key, returns empty list.
    Free key: https://haveibeenpwned.com/API/Key ($3.50/month)
    """
    if not HIBP_API_KEY:
        return []
    try:
        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={
                "hibp-api-key": HIBP_API_KEY,
                "user-agent":   "UPIGuard-Checker"
            },
            timeout=8
        )
        if resp.status_code == 200:
            data = resp.json()
            return [b.get("Name", "") for b in data]
        elif resp.status_code == 404:
            return []
        else:
            return []
    except Exception:
        return []

def analyze_password(pw: str) -> dict:
    feedback = []
    length   = len(pw)

    if length < 12:
        feedback.append("Use at least 12 characters.")
    if not re.search(r"[a-z]", pw):
        feedback.append("Add lowercase letters.")
    if not re.search(r"[A-Z]", pw):
        feedback.append("Add uppercase letters.")
    if not re.search(r"\d", pw):
        feedback.append("Include digits (0-9).")
    if not re.search(r"[^A-Za-z0-9]", pw):
        feedback.append("Include special characters (!@#$%...).")
    if re.search(r"(.)\1{2,}", pw):
        feedback.append("Avoid repeating the same character.")
    if pw.lower() in COMMON_PASSWORDS:
        feedback.append("This is a very common password — change it immediately.")

    entropy = calc_entropy(pw)
    pwned   = hibp_pwned_count(pw)

    breach_detail = ""
    breach_tip    = ""
    if pwned > 0:
        feedback.append(f"⚠️ This password appeared {pwned:,} times in known data breaches!")
        breach_detail = (
            f"Found {pwned:,} times in breach databases. "
            f"This means hackers have this exact password in their lists."
        )
        breach_tip = (
            "Change this password immediately on ALL sites where you use it. "
            "Check https://haveibeenpwned.com to see which sites were affected."
        )
    elif pwned == 0:
        breach_detail = "Password not found in any known breach database."
        breach_tip    = "Stay safe: use a unique password for every site."

    score = 0
    if length >= 12: score += 1
    if length >= 16: score += 1
    if entropy >= 50: score += 1
    if entropy >= 70: score += 1
    if pwned == 0:   score += 1

    if   score <= 1: rating = "Very Weak"
    elif score == 2: rating = "Weak"
    elif score == 3: rating = "Medium"
    elif score == 4: rating = "Strong"
    else:            rating = "Very Strong"

    return {
        "length":        length,
        "entropy":       round(entropy, 2),
        "pwned_count":   pwned,
        "score":         score,
        "rating":        rating,
        "feedback":      feedback,
        "breach_detail": breach_detail,
        "breach_tip":    breach_tip,
    }
