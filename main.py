import os
from pathlib import Path

# ── Load .env manually ──────────────────────────────────────────────────────
env_path  = Path(__file__).parent / ".env"
VT_API_KEY = ""

if env_path.exists():
    with open(env_path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("VT_API_KEY="):
                VT_API_KEY = line.split("=", 1)[1].strip().strip('"').strip("'")
                break

if not VT_API_KEY:
    VT_API_KEY = os.environ.get("VT_API_KEY", "").strip()

# ── Import modules ──────────────────────────────────────────────────────────
from modules.decoder       import decode_qr_from_image
from modules.network       import resolve_url
from modules.url_inspector import analyze_url
from modules.reputation    import check_virustotal


def get_final_verdict(heuristic_verdict, vt_verdict):
    """Combine heuristic + VT results into one overall verdict."""
    danger = {"MALICIOUS", "SUSPICIOUS"}
    if heuristic_verdict in danger or vt_verdict in danger:
        if heuristic_verdict == "MALICIOUS" or vt_verdict == "MALICIOUS":
            return "MALICIOUS"
        return "SUSPICIOUS"
    return "SAFE"


def main():
    print("=" * 54)
    print("        DeQode: QR Phishing Detector v1.1")
    print("=" * 54)

    if VT_API_KEY and len(VT_API_KEY) >= 32:
        print(f"[SYSTEM] Threat Intel Key loaded ✓  ({VT_API_KEY[:6]}...{VT_API_KEY[-4:]})")
    else:
        print("[SYSTEM] WARNING: VT_API_KEY not found — VirusTotal will be skipped.")

    print()
    image_path = input("Enter path to QR image (e.g., test_qr.png): ").strip().strip('"').strip("'")

    if not image_path:
        print("[ERROR] No path entered. Exiting.")
        return

    print(f"\n[*] Scanning: {image_path} ...")
    urls = decode_qr_from_image(image_path)

    if not urls:
        print("[!] No QR code found or image failed to load.")
        return

    print(f"[SUCCESS] Found {len(urls)} QR Code(s):\n")

    for i, raw_url in enumerate(urls, 1):
        print("=" * 54)
        print(f"  PAYLOAD {i} ANALYSIS")
        print("=" * 54)
        print(f"  Original Data : {raw_url}")

        # ── Step 1: Resolve redirects ───────────────────────────────────────
        print("\n[*] Tracing URL redirects...")
        net_result  = resolve_url(raw_url)
        net_error   = net_result.get("error")
        final_url   = net_result.get("final_url") or raw_url
        status_code = net_result.get("status_code")

        if net_error:
            # The site may be offline/dead — but we still have the resolved
            # URL from the redirect chain (if any), otherwise use raw_url.
            # Either way we pass it to the heuristic scanner below.
            print(f"  [!] Site unreachable: {net_error}")
            if final_url and final_url != raw_url:
                print(f"  Resolved URL  : {final_url}  (site offline)")
            else:
                print(f"  Resolved URL  : {raw_url}  (could not resolve — using original)")
                final_url = raw_url
        else:
            print(f"  Final Destination : {final_url}")
            print(f"  Status Code       : {status_code}")
            if final_url != raw_url:
                print("  [!] Redirection detected — shortened URL unmasked.")

        # ── Step 2: Heuristic analysis on RESOLVED URL ─────────────────────
        print("\n[*] Running Local Heuristic Scan...")
        print(f"  Analysing: {final_url}")
        heuristic = analyze_url(final_url)
        h_verdict = heuristic.get("verdict", "UNKNOWN")
        h_score   = heuristic.get("risk_score", 0)
        flags     = heuristic.get("flags", [])

        print(f"  > Verdict    : [{h_verdict}]")
        print(f"  > Risk Score : {h_score}/100")
        if flags:
            for flag in flags:
                print(f"  > [FLAG] {flag}")
        else:
            print("  > Red Flags  : None. Looks clean structurally.")

        # ── Step 3: VirusTotal ──────────────────────────────────────────────
        print("\n[*] Querying VirusTotal Threat Intelligence...")
        vt_verdict = "UNKNOWN"

        if not VT_API_KEY or len(VT_API_KEY) < 32:
            print("  > [SKIP] No valid API key found.")
        else:
            vt = check_virustotal(final_url, VT_API_KEY)
            if vt.get("error"):
                print(f"  > [ERROR] {vt['error']}")
            else:
                vt_verdict = vt["verdict"]
                print(f"  > VT Verdict    : {vt_verdict}")
                print(f"  > Malicious     : {vt['malicious']} / {vt['total_engines']} engines")
                print(f"  > Suspicious    : {vt['suspicious']}")
                print(f"  > Harmless      : {vt['harmless']}")

        # ── Final combined verdict ──────────────────────────────────────────
        overall = get_final_verdict(h_verdict, vt_verdict)
        print()
        print("=" * 54)
        if overall == "MALICIOUS":
            print("  ⚠️  FINAL VERDICT : *** MALICIOUS — DO NOT OPEN ***")
        elif overall == "SUSPICIOUS":
            print("  ⚠️  FINAL VERDICT : SUSPICIOUS — Proceed with caution")
        else:
            print("  ✅  FINAL VERDICT : SAFE")
        print("=" * 54 + "\n")


if __name__ == "__main__":
    main()