import re
import requests
from urllib.parse import urlparse


def resolve_url(url):
    """
    Follows HTTP redirects to find the final destination of a URL.
    Even if the final site is unreachable, returns the last known
    resolved URL from the redirect chain.
    """
    # --- PROTOCOL AWARENESS: Skip non-web URLs (upi://, wifi:, mailto:) ---
    if not url.lower().startswith(('http://', 'https://')):
        return {
            "original_url": url,
            "final_url": url,
            "status_code": None,
            "error": None  # Clean exit for safe protocols
        }

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    }

    result = {
        "original_url": url,
        "final_url":    None,
        "status_code":  None,
        "error":        None
    }

    last_known_url = url

    try:
        session = requests.Session()
        session.max_redirects = 10

        response = session.get(
            url,
            headers=headers,
            allow_redirects=True,
            timeout=10,
            stream=True
        )
        response.close()

        result["final_url"]   = response.url
        result["status_code"] = response.status_code

    except requests.exceptions.TooManyRedirects:
        result["error"]     = "Too many redirects (possible redirect loop)."
        result["final_url"] = last_known_url

    except requests.exceptions.ConnectionError as e:
        error_str = str(e)
        resolved = _extract_url_from_error(error_str, url)
        result["final_url"] = resolved
        
        # --- UX FIX: Provide clean, human-readable error messages ---
        if "NameResolutionError" in error_str or "Failed to resolve" in error_str:
            result["error"] = "Site unreachable: The domain does not exist or is offline."
        elif "Connection refused" in error_str:
            result["error"] = "Site unreachable: Connection refused by the server."
        else:
            result["error"] = "Site unreachable: Could not establish a connection."

    except requests.exceptions.Timeout:
        result["error"]     = "Connection timed out: The server took too long to respond."
        result["final_url"] = last_known_url

    except requests.exceptions.RequestException as e:
        result["error"]     = "Network request failed."
        result["final_url"] = last_known_url

    if not result["final_url"]:
        result["final_url"] = url

    return result


def _extract_url_from_error(error_str, fallback_url):
    """
    Parses the hostname out of a requests ConnectionError string.
    """
    try:
        host_match = re.search(r"host='([^']+)'", error_str)
        port_match = re.search(r"port=(\d+)", error_str)
        path_match = re.search(r"with url: (\S+)", error_str)

        if host_match:
            host   = host_match.group(1)
            port   = port_match.group(1) if port_match else "80"
            path   = path_match.group(1) if path_match else "/"
            scheme = "https" if port == "443" else "http"

            if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
                return f"{scheme}://{host}{path}"
            else:
                return f"{scheme}://{host}:{port}{path}"
    except Exception:
        pass

    return fallback_url


def extract_domain(url):
    """Extracts just the domain name from a full URL."""
    try:
        return urlparse(url).netloc
    except Exception:
        return None