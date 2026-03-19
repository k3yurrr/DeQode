"""
WHOIS Domain Lookup Module
Fetches domain registration details (registrar, creation date, expiration, etc.)
"""

import whois
import socket
from urllib.parse import urlparse
from datetime import datetime
import logging
import signal

logger = logging.getLogger(__name__)

# Domains that shouldn't have WHOIS lookups (redirectors, shorteners, etc.)
SKIP_WHOIS_DOMAINS = {
    'tinyurl.com', 'bit.ly', 'short.link', 'ow.ly', 'tco.me',
    'goo.gl', 'adf.ly', 'rev.link', 'cutt.ly', 'rebrand.ly',
    'buff.ly', 'soo.gd', 'j.mp', 'clck.ru', 'is.gd'
}

def timeout_handler(signum, frame):
    """Handle timeout"""
    raise TimeoutError("WHOIS lookup timed out")



def extract_domain(url):
    """
    Extracts the root domain from a URL or payload.
    
    Examples:
        https://github.com/k3yur → github.com
        http://subdomain.example.co.uk → example.co.uk
        upi://pay?pa=merchant → None (non-web protocol)
        https://tinyurl.com/4c7fksje → None (shortener domain)
    
    Args:
        url (str): The URL or payload to extract domain from
    
    Returns:
        str: The root domain, or None if extraction fails or non-web protocol
    """
    if not url or not isinstance(url, str):
        return None
    
    # ── Non-web protocols: return None (no WHOIS needed) ─────────────────────
    if url.lower().startswith(('upi://', 'wifi:', 'mailto:')):
        return None
    
    # ── Extract domain from URL ────────────────────────────────────────────────
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        
        if not netloc:
            return None
        
        # Remove port numbers if present (example.com:8080 → example.com)
        if ':' in netloc:
            netloc = netloc.split(':')[0]
        
        # Remove 'www.' prefix (www.example.com → example.com)
        if netloc.startswith('www.'):
            netloc = netloc[4:]
        
        # Check if it's an IP address (no WHOIS for IPs)
        if _is_ip_address(netloc):
            return None
        
        # Skip URL shortener domains (they're not useful for WHOIS)
        if netloc in SKIP_WHOIS_DOMAINS:
            return None
        
        return netloc
    
    except Exception:
        return None


def _is_ip_address(domain):
    """
    Checks if a string is an IPv4 address.
    """
    try:
        parts = domain.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True
    except ValueError:
        return False


def lookup_whois(url, timeout=5):
    """
    Performs a WHOIS lookup on a domain extracted from a URL.
    
    Args:
        url (str): The URL to extract domain from and lookup
        timeout (int): Timeout in seconds (default: 5, reduced for performance)
    
    Returns:
        dict: WHOIS information or error details
              Keys: registrar, created_date, expiration_date, organization, country, status
              Returns None if domain is not web-based or lookup fails
    """
    domain = extract_domain(url)
    
    if not domain:
        # Non-web protocol or IP address or shortener — return None for clean frontend skip
        return None
    
    result = {
        "domain": domain,
        "registrar": "Unknown",
        "created_date": "Unknown",
        "expiration_date": "Unknown",
        "organization": "Unknown",
        "country": "Unknown",
        "status": "unknown",
        "error": None
    }
    
    try:
        # ── Perform WHOIS lookup ───────────────────────────────────────────
        # Note: Using a shorter timeout to prevent blocking
        try:
            whois_data = whois.whois(domain, timeout=timeout)
        except (socket.timeout, TimeoutError):
            # Timeout - return None to show "No WHOIS Data Available" message
            logger.debug(f"WHOIS timeout for {domain}")
            return None
        
        if not whois_data:
            return None
        
        # ── Extract registrar ──────────────────────────────────────────────
        registrar = whois_data.get("registrar")
        if registrar:
            if isinstance(registrar, list):
                result["registrar"] = registrar[0] if registrar else "Unknown"
            else:
                result["registrar"] = registrar.strip() if isinstance(registrar, str) else str(registrar)
        
        # ── Extract creation date ──────────────────────────────────────────
        created = whois_data.get("creation_date") or whois_data.get("created_date")
        if created:
            if isinstance(created, list):
                created = created[0]
            if isinstance(created, datetime):
                result["created_date"] = created.strftime("%Y-%m-%d")
            else:
                result["created_date"] = str(created)[:10]
        
        # ── Extract expiration date ────────────────────────────────────────
        expiry = whois_data.get("expiration_date") or whois_data.get("updated_date") or whois_data.get("expires")
        if expiry:
            if isinstance(expiry, list):
                expiry = expiry[0]
            if isinstance(expiry, datetime):
                result["expiration_date"] = expiry.strftime("%Y-%m-%d")
            else:
                result["expiration_date"] = str(expiry)[:10]
        
        # ── Extract organization ───────────────────────────────────────────
        org = whois_data.get("org") or whois_data.get("organization")
        if org:
            if isinstance(org, list):
                org = org[0]
            result["organization"] = org.strip() if isinstance(org, str) else str(org)
        
        # ── Extract country ────────────────────────────────────────────────
        country = whois_data.get("country")
        if country:
            if isinstance(country, list):
                country = country[0]
            result["country"] = country.strip() if isinstance(country, str) else str(country)
        
        # ── Status ────────────────────────────────────────────────────────
        result["status"] = "found"
        return result
    
    except Exception as e:
        # Catch ALL exceptions including socket errors, timeouts, parsing errors
        # and gracefully return None to show "No WHOIS Data Available"
        logger.debug(f"WHOIS lookup failed for {domain}: {type(e).__name__}: {str(e)[:80]}")
        return None


def format_whois_for_display(whois_result):
    """
    Formats WHOIS result for frontend display.
    Hides error details, keeps only user-friendly information.
    
    Args:
        whois_result (dict): Result from lookup_whois()
    
    Returns:
        dict: Cleaned data ready for frontend, or None if should be hidden
    """
    if whois_result is None:
        return None
    
    # Return clean, user-friendly data
    return {
        "domain": whois_result.get("domain"),
        "registrar": whois_result.get("registrar"),
        "created_date": whois_result.get("created_date"),
        "expiration_date": whois_result.get("expiration_date"),
        "organization": whois_result.get("organization"),
        "country": whois_result.get("country"),
        "status": "found"
    }
