import requests
from urllib.parse import urlparse


def resolve_url(url):
    """
    Follows HTTP redirects to find the final destination of a URL.
    Even if the final site is unreachable, returns the last known
    resolved URL from the redirect chain.

    Args:
        url (str): The URL to resolve (may be shortened).

    Returns:
        dict: {
            original_url  : the input URL,
            final_url     : last successfully resolved URL,
            status_code   : HTTP status of final response (or None),
            error         : error message if something went wrong (or None)
        }
    """
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

    # ── Step 1: Follow redirects manually to capture each hop ───────────────
    # We do this so we can record the last URL reached before any failure.
    last_known_url = url

    try:
        # Use a session so cookies are preserved across redirects
        session = requests.Session()
        session.max_redirects = 10

        response = session.get(
            url,
            headers=headers,
            allow_redirects=True,
            timeout=10,
            stream=True        # Don't download the body — just headers
        )
        response.close()

        result["final_url"]   = response.url   # Final URL after all redirects
        result["status_code"] = response.status_code

    except requests.exceptions.TooManyRedirects as e:
        result["error"]     = "Too many redirects (possible redirect loop)."
        result["final_url"] = last_known_url

    except requests.exceptions.ConnectionError as e:
        # ── Key fix: extract the attempted hostname from the error ──────────
        # When requests fails on the FINAL hop, response.url is unavailable,
        # but the exception contains the host it was trying to reach.
        # We reconstruct the URL from the original to capture the resolved host.
        resolved = _extract_url_from_error(str(e), url)
        result["final_url"] = resolved
        result["error"]     = f"Network Error: {e}"

    except requests.exceptions.Timeout:
        result["error"]     = "Connection timed out."
        result["final_url"] = last_known_url

    except requests.exceptions.RequestException as e:
        result["error"]     = f"Network Error: {e}"
        result["final_url"] = last_known_url

    # Fallback: never return None for final_url
    if not result["final_url"]:
        result["final_url"] = url

    return result


def _extract_url_from_error(error_str, fallback_url):
    """
    Parses the hostname out of a requests ConnectionError string.
    Example error: "HTTPConnectionPool(host='secure-update-login.xyz', port=80):
                    Max retries exceeded with url: /auth?token=abc"
    Returns a reconstructed URL like: http://secure-update-login.xyz/auth?token=abc
    """
    import re

    try:
        # Extract host
        host_match = re.search(r"host='([^']+)'", error_str)
        # Extract port
        port_match = re.search(r"port=(\d+)", error_str)
        # Extract path+query
        path_match = re.search(r"with url: (\S+)", error_str)

        if host_match:
            host   = host_match.group(1)
            port   = port_match.group(1) if port_match else "80"
            path   = path_match.group(1) if path_match else "/"
            scheme = "https" if port == "443" else "http"

            # Don't add default ports to the URL
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