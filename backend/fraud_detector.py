import re, requests, hashlib, time

VIRUSTOTAL_API_KEY = "463e5d77b7989f143bca8b34e1c430344a3cb3ec0f5a2860b39739db95f12b30"

TRUSTED_HANDLES = {
    "okicici", "oksbi", "okaxis", "okhdfcbank", "ybl",
    "paytm", "apl", "ibl", "kotak", "rbl", "federal",
    "pnb", "bob", "okbizaxis", "jupiteraxis", "axisbank",
    "cmsidfc", "naviaxis", "postbank", "barodampay"
}

GENERIC_HANDLES = {"upi", "imobile", "freecharge"}

FRAUD_KEYWORDS = {
    "lottery":40, "win":30, "prize":40, "lucky":35, "reward":30,
    "bonus":25, "cashback":20, "earn":30, "profit":30, "invest":25,
    "daily":25, "income":25, "free":25, "gift":30, "claim":35,
    "refund":35, "helpdesk":40, "support":25, "urgent":35, "verify":30,
    "kyc":35, "otp":40, "update":20, "alert":20, "sarkari":40,
    "yojana":40, "scheme":30, "pm":25, "government":30, "govt":30,
    "official":25, "ration":25, "hack":50, "fake":50, "fraud":50,
    "scam":50, "phish":50, "loan":30, "instant":25, "job":20,
    "hiring":25, "vacancy":25, "parttime":30, "crypto":30, "bitcoin":35,
    "nft":30, "unknown":20, "random":15, "send":20, "transfer":15,
    "pay":15, "fast":20, "quick":20, "money":25, "cash":25, "loot":25
}

BLACKLIST_PATTERNS = [
    r"^(free|win|earn|lottery|prize)\.",
    r"\.(win|earn|free|money|cash)@",
    r"^(pm|govt|sarkari|helpdesk|support)\d*@",
    r"^[a-z]{1,3}\d{6,}@",
    r"^\d{4,}[a-z]{0,3}\d{4,}@",
]


def analyze_upi(upi: str) -> dict:
    upi_clean = upi.strip()
    upi_lower = upi_clean.lower()
    score = 100
    reasons = []
    flags = []

    if "@" not in upi_lower:
        return {
            "upi": upi_clean, "score": 0, "verdict": "FRAUD",
            "reasons": ["Invalid UPI format — missing @ symbol"],
            "risk_level": "CRITICAL"
        }

    parts = upi_lower.split("@")
    local = parts[0]
    handle = parts[1] if len(parts) > 1 else ""

    if handle in TRUSTED_HANDLES:
        reasons.append(f"Trusted bank handle: @{handle}")
    elif handle in GENERIC_HANDLES:
        score -= 10
        flags.append(f"Generic unverified handle: @{handle}")
    elif handle:
        score -= 25
        flags.append(f"Unknown handle @{handle} — not a registered bank UPI")
    else:
        score -= 40
        flags.append("Missing bank handle after @")

    if len(local) < 3:
        score -= 30
        flags.append("Local part too short")
    elif len(local) > 30:
        score -= 15
        flags.append(f"Unusually long UPI ID ({len(local)} chars)")

    for pattern in BLACKLIST_PATTERNS:
        if re.search(pattern, upi_lower):
            score -= 45
            flags.append("Matches known fraud UPI pattern")
            break

    found_kw = []
    for word, penalty in FRAUD_KEYWORDS.items():
        if word in local:
            score -= penalty
            found_kw.append(f"'{word}'(-{penalty})")
    if found_kw:
        flags.append(f"Fraud keywords: {', '.join(found_kw[:5])}")

    digits = sum(c.isdigit() for c in local)
    ratio = digits / max(len(local), 1)
    if re.match(r"^\d{10}$", local):
        reasons.append("Phone-number UPI format — standard")
    elif ratio > 0.6:
        score -= 20
        flags.append(f"High digit ratio ({int(ratio*100)}%) — bot-like ID")
    elif ratio > 0.4:
        score -= 8
        flags.append("Moderate digit ratio — slightly suspicious")

    if local.count(".") >= 3:
        score -= 15
        flags.append(f"Too many dots ({local.count('.')}) — scammer pattern")
    if re.search(r"(.)\1{3,}", local):
        score -= 15
        flags.append("Repeated characters — bot pattern")

    score = max(0, min(100, score))

    if score >= 80:
        verdict = "SAFE"; risk = "LOW"
    elif score >= 55:
        verdict = "SUSPICIOUS"; risk = "MEDIUM"
    else:
        verdict = "FRAUD"; risk = "HIGH"

    all_reasons = reasons + flags
    if not all_reasons:
        all_reasons = ["No suspicious signals detected"]

    return {"upi": upi_clean, "score": score, "verdict": verdict,
            "risk_level": risk, "reasons": all_reasons,
            "local": local, "handle": handle}



def scan_url_virustotal(url: str) -> dict:
    url = url.strip()
    if not url:
        return {"error": "No URL provided"}

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    pre_flags   = []
    pre_risk    = "LOW"
    import re as _re
    from urllib.parse import urlparse as _urlparse

    parsed = _urlparse(url)
    host   = parsed.hostname or ""

    ip_pattern = _re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    if ip_pattern.match(host):
        pre_flags.append("🚨 Direct IP address — legitimate banks NEVER use raw IPs")
        pre_risk = "HIGH"

    sus_words = ["login","verify","kyc","otp","update","secure","bank",
                 "upi","paytm","phonepe","gpay","account","pin","reward",
                 "lucky","win","prize","free","claim","refund","helpdesk"]
    found_words = [w for w in sus_words if w in url.lower()]
    if found_words:
        pre_flags.append(f"⚠️ Suspicious keywords in URL: {', '.join(found_words)}")
        if pre_risk != "HIGH":
            pre_risk = "MEDIUM"

    if url.startswith("http://"):
        pre_flags.append("⚠️ No HTTPS — connection is not encrypted")
        if pre_risk == "LOW":
            pre_risk = "MEDIUM"

    if parsed.port and parsed.port not in (80, 443):
        pre_flags.append(f"⚠️ Unusual port {parsed.port} — not standard web traffic")
        if pre_risk != "HIGH":
            pre_risk = "MEDIUM"

    if "index-of" in url.lower() or "index of" in url.lower():
        pre_flags.append("🚨 'Index-of' pattern — this is an open directory, often used for piracy or malware hosting")
        pre_risk = "HIGH"

    headers = {"x-apikey": VIRUSTOTAL_API_KEY, "accept": "application/json"}

    try:
        submit_res = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )

        if submit_res.status_code == 429:
            return {
                "url": url, "safe": None,
                "message": "Rate limited — wait 1 minute (free plan: 4 scans/min)",
                "malicious": 0, "suspicious": 0, "total": 0,
                "pre_flags": pre_flags, "pre_risk": pre_risk,
                "tip": "Free plan: 4 requests/minute, 1000/day."
            }

        if submit_res.status_code not in (200, 201):
            return _vt_error(url, f"HTTP {submit_res.status_code}", pre_flags, pre_risk)

        analysis_id = submit_res.json().get("data", {}).get("id", "")
        if not analysis_id:
            return _vt_error(url, "No analysis ID returned", pre_flags, pre_risk)

        import time as _time
        for _ in range(6):
            _time.sleep(3)
            report_res = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers, timeout=10
            )
            if report_res.status_code != 200:
                continue

            report = report_res.json()
            status = report.get("data", {}).get("attributes", {}).get("status", "")

            if status == "completed":
                stats      = report["data"]["attributes"]["stats"]
                malicious  = stats.get("malicious",  0)
                suspicious = stats.get("suspicious", 0)
                harmless   = stats.get("harmless",   0)
                undetected = stats.get("undetected", 0)
                total      = malicious + suspicious + harmless + undetected

                if malicious >= 3:
                    safe    = False
                    verdict = f"DANGEROUS — {malicious}/{total} engines flagged this URL!"
                    tip     = "Do NOT open. May steal your UPI PIN or banking credentials."
                elif malicious >= 1 or suspicious >= 3:
                    safe    = False
                    verdict = f"SUSPICIOUS — {malicious} engine(s) detected threats."
                    tip     = "Avoid this link. May be a phishing page targeting UPI/bank users."
                elif pre_risk == "HIGH":
                    safe    = False
                    verdict = f"SUSPICIOUS — VirusTotal shows clean but our analysis found serious signals."
                    tip     = "Do not trust this URL. " + (pre_flags[0] if pre_flags else "")
                elif pre_risk == "MEDIUM":
                    safe    = None
                    verdict = f"CAUTION — VirusTotal clean but suspicious signals detected."
                    tip     = "Verify this URL carefully before clicking."
                else:
                    safe    = True
                    verdict = f"CLEAN — 0/{total} engines detected any threat."
                    tip     = "URL appears safe. Still verify sender identity before clicking."

                return {
                    "url": url, "safe": safe, "message": verdict,
                    "malicious": malicious, "suspicious": suspicious,
                    "harmless": harmless, "total": total, "tip": tip,
                    "pre_flags": pre_flags, "pre_risk": pre_risk,
                    "powered_by": "VirusTotal free API"
                }

        return {
            "url": url, "safe": None,
            "message": "Scan queued — VirusTotal is processing. Try again in 30s.",
            "malicious": 0, "suspicious": 0, "total": 0,
            "pre_flags": pre_flags, "pre_risk": pre_risk,
            "tip": "Free API has a small delay for new URLs."
        }

    except requests.exceptions.Timeout:
        return _vt_error(url, "Request timed out", pre_flags, pre_risk)
    except Exception as e:
        return _vt_error(url, str(e), pre_flags, pre_risk)


def _vt_error(url, reason, pre_flags=None, pre_risk="LOW"):
    return {
        "url": url, "safe": None,
        "message": f"Scan error: {reason}",
        "malicious": 0, "suspicious": 0, "total": 0,
        "pre_flags": pre_flags or [], "pre_risk": pre_risk,
        "tip": "Check URL manually at virustotal.com"
    }


def check_email_breach(target: str) -> dict:
    from backend.breach_db import check_email_breach as _check
    return _check(target)
