import re
from urllib.parse import urlparse, parse_qs

# High-risk TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".loan", ".work", ".date", ".racing",
    ".win", ".download", ".stream", ".gq", ".ml", ".cf", ".tk", ".ga",
    ".men", ".ru", ".cn", ".pw", ".cc", ".su"
}

# Keywords often found in phishing URLs
PHISHING_KEYWORDS = [
    "login", "verify", "secure", "update", "bank", "account",
    "confirm", "signin", "password", "credential", "paypal",
    "amazon", "apple", "microsoft", "support", "alert", "unlock"
]


def analyze_url(url):
    """
    Performs lexical/heuristic analysis on a URL to detect phishing traits.

    Args:
        url (str): The final (resolved) URL to analyze.

    Returns:
        dict: Contains 'verdict', 'risk_score', and 'flags' list.
    """
    result = {
        "verdict": "SAFE",
        "risk_score": 0,
        "flags": []
    }

    if not url:
        result["flags"].append("Empty URL provided.")
        result["risk_score"] = 10
        result["verdict"] = "SUSPICIOUS"
        return result

    url_lower = url.lower()

    # ── PROTOCOL AWARENESS: Handle Non-Web Payloads safely ──────────────────
    
    if url_lower.startswith("upi://pay"):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        payee = qs.get('pn', ['Unknown Payee'])[0]
        vpa = qs.get('pa', ['Unknown VPA'])[0]
        
        result["verdict"] = "SAFE"
        result["risk_score"] = 0
        result["flags"].append(f"Valid UPI Payment Link for: {payee}")
        result["flags"].append(f"Target VPA: {vpa}")
        return result

    if url_lower.startswith("wifi:"):
        result["verdict"] = "SAFE"
        result["risk_score"] = 0
        result["flags"].append("Standard WiFi Configuration payload.")
        return result

    if url_lower.startswith("mailto:"):
        result["verdict"] = "SAFE"
        result["risk_score"] = 0
        result["flags"].append("Standard Email Draft payload.")
        return result

    # ── Verify it's a web URL before proceeding ─────────────────────────────
    if not url_lower.startswith(("http://", "https://")):
        result["flags"].append("Not a valid HTTP/HTTPS URL.")
        result["risk_score"] = 10
        result["verdict"] = "SUSPICIOUS"
        return result

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()
        full   = url.lower()
    except Exception:
        result["flags"].append("URL parsing failed.")
        result["risk_score"] = 20
        result["verdict"] = "SUSPICIOUS"
        return result

    score = 0

    # ── Check 1: IP address used instead of domain ──────────────────────────
    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$")
    if ip_pattern.match(domain):
        score += 30
        result["flags"].append("IP address used instead of domain name.")

    # ── Check 2: Suspicious TLD ─────────────────────────────────────────────
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 20
            result["flags"].append(f"High-risk TLD detected: '{tld}'")
            break

    # ── Check 3: Phishing keywords in domain or path ────────────────────────
    matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in domain or kw in path]
    if matched_keywords:
        score += min(len(matched_keywords) * 10, 25)
        result["flags"].append(f"Phishing keywords found: {', '.join(matched_keywords)}")

    # ── Check 4: '@' symbol in URL (browser trick) ──────────────────────────
    if "@" in full:
        score += 25
        result["flags"].append("'@' symbol detected in URL — possible browser redirect trick.")

    # ── Check 5: Excessive subdomains ───────────────────────────────────────
    subdomain_count = len(domain.split(".")) - 2
    if subdomain_count >= 3:
        score += 15
        result["flags"].append(f"Excessive subdomains ({subdomain_count}) detected.")

    # ── Check 6: Very long URL ───────────────────────────────────────────────
    if len(url) > 100:
        score += 10
        result["flags"].append(f"URL is unusually long ({len(url)} chars).")

    # ── Check 7: Double slashes in path (obfuscation) ───────────────────────
    if "//" in parsed.path:
        score += 10
        result["flags"].append("Double slashes in URL path (possible obfuscation).")

    # ── Check 8: HTTP (not HTTPS) ────────────────────────────────────────────
    if url.startswith("http://"):
        score += 10
        result["flags"].append("Non-secure HTTP connection (no SSL).")

    # ── Assign verdict based on final score ─────────────────────────────────
    result["risk_score"] = min(score, 100)

    if score >= 50:
        result["verdict"] = "MALICIOUS"
    elif score >= 20:
        result["verdict"] = "SUSPICIOUS"
    else:
        result["verdict"] = "SAFE"

    return result


# ── Alias for backwards compatibility ───────────────────────────────────────
def analyze_lexical_features(url):
    return analyze_url(url)