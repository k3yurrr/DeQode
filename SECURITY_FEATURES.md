# 🛡️ DeQode Security Analysis Features

## Component Overview

### 1. **URL Decoder** (`modules/decoder.py`)
Extracts URLs from QR code images using OpenCV and pyzbar with 7 detection strategies:
- Direct QR decoding
- Image rotations (90°, 180°, 270°)
- Contrast enhancement
- Noise reduction
- Resolution upscaling
- Grayscale conversion
- Adaptive thresholding

---

### 2. **Network Layer** (`modules/network.py`)
**Redirect Tracking & URL Resolution**
- Follows HTTP/HTTPS redirects (max 10 hops)
- Detects redirect loops
- Un-masks shortened URLs
- Handles connection errors gracefully
- Returns complete redirect chain

**Key Features:**
```
Original URL: https://short.url/abc123
   ↓ (traceback)
Final URL: https://actual-destination.com/page
```

---

### 3. **SSL/TLS Authentication** (`modules/ssl_checker.py`) ⭐ **NEW**
**Validates Authenticated Sources**
- Checks SSL certificate validity
- Verifies certificate is from trusted CA
- Detects self-signed certificates
- Detects expired certificates
- Detects hostname mismatches
- Differentiates HTTPS from HTTP

**Verdicts:**
| Verdict | Meaning |
|---------|---------|
| `SECURE` | Valid SSL from trusted CA ✓ |
| `UNENCRYPTED` | HTTP (no TLS) ⚠️ |
| `SELF_SIGNED` | Not from trusted CA ⚠️ |
| `EXPIRED` | Certificate expired ⚠️ |
| `HOSTNAME_MISMATCH` | Domain fraud attempt ⚠️ |
| `SAFE_PROTOCOL` | Non-web (wifi://, mailto:) |

---

### 4. **Heuristic Analysis** (`modules/url_inspector.py`)
**Local Structural Inspection (No Network Calls)**

#### Trusted Domain Fast-Path ✓
50+ major legitimate companies auto-pass:
- E-commerce: Amazon, eBay, Walmart, Target
- Payment: PayPal, Stripe, Wise, Revolut
- Banks: Chase, BoA, Wells Fargo, HSBC, ING
- Tech: Google, Apple, Microsoft, Meta, GitHub
- Email: Gmail, Outlook, ProtonMail
- Cloud: OneDrive, Dropbox, Box

#### Risk Scoring System
| Score | Verdict |
|-------|---------|
| 0-29 | SAFE ✅ |
| 30-59 | SUSPICIOUS ⚠️ |
| 60+ | MALICIOUS 🚨 |

#### Checks Performed (Cumulative Scoring)
1. **Trusted Domain** (0 pts) → Fast exit if known legitimate
2. **IP Address** (+30 pts) → 192.168.1.1 instead of domain name
3. **Suspicious TLD** (+20 pts) → .xyz, .top, .loan, .ru, .cn, etc.
4. **Phishing Keywords** (+15 pts max) → "login", "verify", "secure", "password", etc.
5. **SSL/TLS Certificate Validation** (+15-25 pts) → HTTP, self-signed, expired, untrusted
6. **@ Symbol** (+25 pts) → Browser redirect trick
7. **Excessive Subdomains** (+15 pts) → 3+ subdomains
8. **URL Length** (+10 pts) → >100 characters
9. **Path Obfuscation** (+10 pts) → Double slashes "//"

---

### 5. **VirusTotal Integration** (`modules/reputation.py`)
**Global Threat Intelligence (94 Security Engines)**
- Submits URL to VirusTotal API v3
- Polls until scan completes
- Returns verdict from consensus:
  - **MALICIOUS**: 1+ engines flag it
  - **SUSPICIOUS**: 0 malicious, 1+ suspicious
  - **CLEAN**: No flags detected

---

## Test Scenario Coverage

### ✅ Test 1: Safe URL
```
Input: https://github.com/k3yur
Result: SAFE (0/100)
  ✓ Verified trusted domain (github.com)
  ✓ Valid SSL from trusted CA
  ✓ VirusTotal: Clean
```

### ✅ Test 2: Shortened URL Unmasker
```
Input: https://tinyurl.com/google-safe-test-123
  ↓ Redirect following
Result: https://www.google.com/search?q=...
Verdict: SAFE
```

### ⚠️ Test 3: Heuristic Malicious Detection
```
Input: http://secure-update-login.xyz@192.168.1.100//auth
Result: MALICIOUS (80/100)
  ⚠️  Unencrypted HTTP connection (+15 pts)
  ⚠️  Keywords: login, secure, update (+15 pts)
  ⚠️  '@' symbol trick (+25 pts)
  ⚠️  Excessive subdomains (+15 pts)
  ⚠️  Double slashes in path (+10 pts)
```

### 🌍 Test 4: VirusTotal Global Detection
```
Input: https://secure.eicar.org/eicar.com
Local Heuristics: SAFE (might miss it)
VirusTotal: MALICIOUS (65/90 engines flagged)
Final Verdict: MALICIOUS (VT overrides local)
```

### 🛡️ Test 5a: WiFi Configuration
```
Input: WIFI:T:WPA;S:Starbucks_Guest;P:Coffee1234;;
Result: SAFE
  ✓ Standard WiFi Configuration
  ✓ No SSL check needed (non-web protocol)
```

### 📧 Test 5b: Email Draft
```
Input: mailto:support@bank.com?subject=Account%20Help
Result: SAFE
  ✓ Standard Email Draft
  ✓ No network check performed
```

### 💳 Test 5c: UPI Payment Link
```
Input: upi://pay?pa=merchant@upi&pn=Local%20Coffee%20Shop&am=150.00
Result: SAFE
  ✓ Valid UPI Payment Link for: Local Coffee Shop
  ✓ Target VPA: merchant@upi
```

---

## False Positive Fixes

### Before Integration
```
❌ amazon.com/ap/signin → SUSPICIOUS (20/100)
❌ paypal.com/secure/login → SUSPICIOUS (25/100)
❌ microsoft.com/security-info → SUSPICIOUS (20/100)
```

### After Integration
```
✅ amazon.com/ap/signin → SAFE (0/100) [Trusted Domain]
✅ paypal.com/secure/login → SAFE (0/100) [Trusted Domain]
✅ microsoft.com/security-info → SAFE (0/100) [Trusted Domain]
```

### Changes Made
1. ✅ Added 50+ trusted domain whitelist
2. ✅ Reduced keyword scoring (10 → 5 points per keyword, max 15)
3. ✅ Raised verdict thresholds (SUSPICIOUS: 20→30, MALICIOUS: 50→60)
4. ✅ Added SSL/TLS certificate validation
5. ✅ Protocol awareness for non-web URLs

---

## File Structure

```
DeQode/
├── modules/
│   ├── decoder.py           # QR decoding (7 strategies)
│   ├── network.py           # URL resolution & redirect following
│   ├── ssl_checker.py       # SSL/TLS certificate validation ⭐ NEW
│   ├── url_inspector.py     # Heuristic phishing analysis
│   └── reputation.py        # VirusTotal API integration
├── main.py                  # CLI interface
├── gui.py                   # Tkinter GUI
├── test_cases.py            # Comprehensive test suite
└── requirements.txt         # Dependencies
```

---

## Key Improvements

| Feature | Status | Impact |
|---------|--------|--------|
| Trusted Domain Whitelist | ✅ Added | Eliminates false positives for major retailers |
| SSL/TLS Validation | ✅ Added | Detects unauthenticated sources |
| Protocol Awareness | ✅ Implemented | Safely handles QR codes for WiFi, email, payments |
| Reduced Keyword Scoring | ✅ Tuned | Legitimate sites with "secure", "login" now safe |
| Redirect Tracking | ✅ Working | Un-masks shortened URLs |
| VirusTotal Integration | ✅ Integrated | Uses 94 antivirus engines for consensus verdict |

---

## Running Tests

```bash
# Run comprehensive test suite
python3 test_cases.py

# Run CLI version
python3 main.py

# Run GUI version
python3 gui.py
```

Expected output shows:
- ✅ All 5 test scenarios passing
- ✅ No false positives on trusted domains
- ✅ Correct SSL authentication checks
- ✅ Proper protocol handling (WiFi, email, UPI)
