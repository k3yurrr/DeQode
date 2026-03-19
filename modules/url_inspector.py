import re
from urllib.parse import urlparse, parse_qs
from .ssl_checker import check_ssl_certificate

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

# Whitelist of trusted domains that are immune from keyword-based scoring
# These are major legitimate companies where security keywords are normal
TRUSTED_DOMAINS = {
    # Major e-commerce
    "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.in",
    "ebay.com", "ebay.co.uk", "walmart.com", "target.com", "shop.app",
    
    # Payment processors & fintech
    "paypal.com", "stripe.com", "square.cash", "venmo.com", "wise.com",
    "revolut.com", "n26.com", "chime.com", "robinhood.com", "coinbase.com",
    
    # Banks (major international)
    "chase.com", "bofa.com", "wellsfargo.com", "bankofamerica.com",
    "citi.com", "hsbc.com", "barclays.com", "lloyds.com", "ing.com",
    "deutsche-bank.com", "societe-generale.com", "bnp-paribas.com",
    
    # Tech giants
    "google.com", "apple.com", "microsoft.com", "amazon.com", "meta.com",
    "facebook.com", "instagram.com", "whatsapp.com", "twitter.com", "x.com",
    "github.com", "reddit.com", "slack.com", "atlassian.com", "dropbox.com",
    
    # Email & messaging
    "gmail.com", "outlook.com", "mail.yahoo.com", "protonmail.com",
    "tutanota.com", "fastmail.com", "zoho.com", "icloud.com",
    
    # Cloud & productivity
    "office365.com", "sharepoint.com", "onedrive.com", "google-drive.com",
    "dropbox.com", "box.com", "onedrive.live.com", "drive.google.com",
    
    # Utilities & services
    "github.com", "bitbucket.org", "gitlab.com", "jira.atlassian.net",
    "twilio.com", "cloudflare.com", "digitalocean.com", "heroku.com",
}

def is_trusted_domain(domain):
    """
    Check if a domain is in the trusted list (handles subdomains).
    E.g., 'secure.amazon.com' matches 'amazon.com'
    """
    domain_lower = domain.lower()
    
    # Exact match
    if domain_lower in TRUSTED_DOMAINS:
        return True
    
    # Subdomain match (e.g., secure.amazon.com matches amazon.com)
    for trusted in TRUSTED_DOMAINS:
        if domain_lower.endswith("." + trusted) or domain_lower == trusted:
            return True
    
    return False


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

    # ── TRUSTED DOMAIN FAST-PATH ────────────────────────────────────────────
    # If it's a known legitimate domain, skip most checks and return early
    if is_trusted_domain(domain):
        result["verdict"] = "SAFE"
        result["risk_score"] = 0
        result["flags"].append(f"✓ Verified trusted domain ({domain.split('.')[-2]}.{domain.split('.')[-1]})")
        return result

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
        # REDUCED SCORING: Keywords alone are weak indicators (many legit sites use them)
        # Instead of min(len * 10, 25), now cap at 15 to require other red flags
        keyword_score = min(len(matched_keywords) * 5, 15)
        score += keyword_score
        result["flags"].append(f"Keywords detected: {', '.join(matched_keywords)} ({keyword_score} pts)")

    # ── Check 3b: SSL/TLS Certificate Validation ────────────────────────────
    # Only check non-trusted domains (trusted domains are fast-pathed earlier)
    try:
        ssl_check = check_ssl_certificate(url)
        
        if ssl_check["verdict"] == "UNENCRYPTED":
            score += 15
            result["flags"].append("⚠️  Unencrypted HTTP connection (no SSL/TLS).")
        
        elif ssl_check["verdict"] in ["SELF_SIGNED", "UNTRUSTED_CA", "HOSTNAME_MISMATCH"]:
            score += 25
            result["flags"].extend(ssl_check["flags"])
        
        elif ssl_check["verdict"] == "EXPIRED":
            score += 20
            result["flags"].extend(ssl_check["flags"])
        
        elif ssl_check["verdict"] == "SECURE":
            result["flags"].append("✓ Valid SSL certificate from trusted CA.")
        
        elif ssl_check["verdict"] in ["SAFE_PROTOCOL", "ERROR", "TIMEOUT", "UNREACHABLE"]:
            # These don't add points - they're either non-web protocols or unavailable
            pass
    
    except Exception:
        # SSL check failed (likely network unreachable) - don't penalize
        pass

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

    # ── Assign verdict based on final score ─────────────────────────────────
    result["risk_score"] = min(score, 100)

    if score >= 60:
        result["verdict"] = "MALICIOUS"
    elif score >= 30:
        result["verdict"] = "SUSPICIOUS"
    else:
        result["verdict"] = "SAFE"

    return result


# ── Alias for backwards compatibility ───────────────────────────────────────
def analyze_lexical_features(url):
    return analyze_url(url)