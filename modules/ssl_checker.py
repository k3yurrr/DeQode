"""
SSL Certificate & Authentication Validator
Checks if a URL is served over HTTPS with a valid, trusted SSL certificate.
"""

import ssl
import socket
import requests
from urllib.parse import urlparse
from datetime import datetime
import urllib3

# Suppress SSL warnings for our own verification
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def check_ssl_certificate(url):
    """
    Validates SSL certificate for a given URL.
    
    Args:
        url (str): The URL to check (must be HTTPS)
    
    Returns:
        dict: Contains 'is_secure', 'certificate_info', 'flags', and 'verdict'
    """
    result = {
        "is_secure": False,
        "certificate_valid": False,
        "certificate_trusted": False,
        "certificate_info": {},
        "flags": [],
        "verdict": "UNKNOWN"
    }

    parsed = urlparse(url)
    
    # ── Protocol Check ─────────────────────────────────────────────────────
    if url.lower().startswith("http://"):
        result["verdict"] = "UNENCRYPTED"
        result["flags"].append("No SSL/TLS encryption (HTTP only).")
        return result
    
    if not url.lower().startswith("https://"):
        # Non-web protocol (upi://, mailto:, wifi:)
        result["is_secure"] = True  # These are safe by nature
        result["verdict"] = "SAFE_PROTOCOL"
        result["flags"].append("Non-web protocol (no SSL needed).")
        return result

    # ── Extract hostname ───────────────────────────────────────────────────
    hostname = parsed.hostname
    if not hostname:
        result["verdict"] = "INVALID_URL"
        result["flags"].append("Could not extract hostname from URL.")
        return result

    # ── Try to fetch certificate ───────────────────────────────────────────
    try:
        # Method 1: Use requests to get certificate info
        response = requests.get(
            url,
            verify=True,
            timeout=10,
            allow_redirects=False
        )
        
        # If we got here, SSL cert is valid
        result["is_secure"] = True
        result["certificate_valid"] = True
        result["certificate_trusted"] = True
        result["verdict"] = "SECURE"
        result["flags"].append(f"✓ Valid SSL certificate from trusted CA.")
        
        return result

    except requests.exceptions.SSLError as e:
        error_str = str(e).lower()
        
        # Distinguish between different SSL errors
        if "self signed" in error_str or "self-signed" in error_str:
            result["verdict"] = "SELF_SIGNED"
            result["flags"].append("⚠️  Certificate is self-signed (not from trusted CA).")
        elif "certificate verify failed" in error_str or "certificate_verify_failed" in error_str:
            result["verdict"] = "UNTRUSTED_CA"
            result["flags"].append("⚠️  Certificate from untrusted or unknown CA.")
        elif "expired" in error_str:
            result["verdict"] = "EXPIRED"
            result["flags"].append("⚠️  SSL certificate has expired.")
        elif "hostname mismatch" in error_str or "doesn't match" in error_str:
            result["verdict"] = "HOSTNAME_MISMATCH"
            result["flags"].append("⚠️  Certificate hostname mismatch (domain spoofing attempt?).")
        else:
            result["verdict"] = "INVALID_CERTIFICATE"
            result["flags"].append(f"⚠️  Invalid SSL certificate: {error_str[:60]}")
        
        return result

    except requests.exceptions.Timeout:
        result["verdict"] = "TIMEOUT"
        result["flags"].append("Connection timeout (could not verify certificate).")
        return result

    except requests.exceptions.ConnectionError:
        result["verdict"] = "UNREACHABLE"
        result["flags"].append("Site unreachable (could not verify certificate).")
        return result

    except Exception as e:
        result["verdict"] = "ERROR"
        result["flags"].append(f"Certificate check failed: {str(e)[:60]}")
        return result


def get_certificate_chain(hostname, port=443):
    """
    Retrieves the SSL certificate chain for a hostname.
    Returns certificate details including issuer and expiry.
    """
    try:
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cert_der = ssock.getpeercert(binary_form=True)
                
                return {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "version": cert.get("version"),
                    "serial_number": cert.get("serialNumber"),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                    "subjectAltName": cert.get("subjectAltName", []),
                    "success": True
                }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def is_authentic_source(url):
    """
    Determines if a URL is from an authenticated/secure source.
    
    Returns:
        dict with 'is_authentic', 'verdict', and 'details'
    """
    result = {
        "is_authentic": False,
        "verdict": "UNKNOWN",
        "details": []
    }
    
    # Check SSL
    ssl_check = check_ssl_certificate(url)
    result["ssl_status"] = ssl_check["verdict"]
    
    if ssl_check["verdict"] == "SECURE":
        result["is_authentic"] = True
        result["verdict"] = "AUTHENTICATED"
        result["details"].append("✓ Valid SSL certificate from trusted CA")
    
    elif ssl_check["verdict"] == "SAFE_PROTOCOL":
        result["is_authentic"] = True
        result["verdict"] = "SAFE_PROTOCOL"
        result["details"].append("✓ Required protocol type (non-web)")
    
    elif ssl_check["verdict"] == "UNENCRYPTED":
        result["is_authentic"] = False
        result["verdict"] = "UNENCRYPTED"
        result["details"].append("✗ No encryption (HTTP only)")
    
    else:
        result["is_authentic"] = False
        result["verdict"] = "UNAUTHENTICATED"
        result["details"] = ssl_check["flags"]
    
    return result
