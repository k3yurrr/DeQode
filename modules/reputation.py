import requests
import time


def check_virustotal(url, api_key):
    """
    Submits a URL to VirusTotal and polls until the scan is complete.

    Args:
        url (str): The URL to check.
        api_key (str): Your VirusTotal API key.

    Returns:
        dict: Result with verdict, engine counts, and any error.
    """
    result = {
        "checked":       False,
        "malicious":     0,
        "suspicious":    0,
        "harmless":      0,
        "undetected":    0,
        "total_engines": 0,
        "verdict":       "Unknown",
        "error":         None
    }

    if not api_key or len(api_key.strip()) < 32:
        result["error"] = "API Key missing or invalid."
        return result

    api_key = api_key.strip()
    headers = {"x-apikey": api_key}

    # ── Step 1: Submit URL for scanning ─────────────────────────────────────
    try:
        submit_resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=15
        )
    except requests.exceptions.RequestException as e:
        result["error"] = f"Submission network error: {e}"
        return result

    if submit_resp.status_code == 401:
        result["error"] = "Invalid API Key (401 Unauthorized)."
        return result

    if submit_resp.status_code not in (200, 201):
        result["error"] = f"Submission failed. HTTP {submit_resp.status_code}"
        return result

    analysis_id = submit_resp.json().get("data", {}).get("id")
    if not analysis_id:
        result["error"] = "No analysis ID returned by VirusTotal."
        return result

    # ── Step 2: Poll until scan status is "completed" ───────────────────────
    report_url   = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    max_attempts = 8      # max ~24 seconds total wait
    wait_seconds = 3

    for attempt in range(1, max_attempts + 1):
        print(f"  > Waiting for scan... (attempt {attempt}/{max_attempts})", end="\r")
        time.sleep(wait_seconds)

        try:
            report_resp = requests.get(report_url, headers=headers, timeout=15)
        except requests.exceptions.RequestException as e:
            result["error"] = f"Report fetch error: {e}"
            return result

        if report_resp.status_code != 200:
            result["error"] = f"Report fetch failed. HTTP {report_resp.status_code}"
            return result

        data       = report_resp.json().get("data", {})
        attributes = data.get("attributes", {})
        status     = attributes.get("status", "")
        stats      = attributes.get("stats", {})
        total      = sum(stats.values())

        # Once engines have responded, we're done
        if status == "completed" or total > 0:
            print()  # clear the \r progress line
            result["checked"]       = True
            result["malicious"]     = stats.get("malicious",  0)
            result["suspicious"]    = stats.get("suspicious", 0)
            result["harmless"]      = stats.get("harmless",   0)
            result["undetected"]    = stats.get("undetected", 0)
            result["total_engines"] = total

            if result["malicious"] > 0:
                result["verdict"] = "MALICIOUS"
            elif result["suspicious"] > 0:
                result["verdict"] = "SUSPICIOUS"
            else:
                result["verdict"] = "CLEAN"

            return result

    # All attempts exhausted
    print()
    result["error"] = "Scan timed out — VirusTotal did not finish. Try again shortly."
    return result