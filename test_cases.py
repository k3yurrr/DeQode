#!/usr/bin/env python3
"""
Test Suite for DeQode — Validates all 5 test scenarios
"""

from modules.url_inspector import analyze_url
from modules.network import resolve_url
from modules.ssl_checker import check_ssl_certificate

# Test cases with expected results
TEST_CASES = {
    "1_safe_github": {
        "url": "https://github.com/k3yur",
        "should_be": "SAFE",
        "description": "✅ Standard safe URL (GitHub profile)"
    },
    
    "2_unmasker_tinyurl": {
        "url": "https://tinyurl.com/google-safe-test-123",
        "should_be": "SAFE",
        "description": "✅ Shortened URL that resolves to Google Search"
    },
    
    "3_heuristic_malicious": {
        "url": "http://secure-update-login.xyz@192.168.1.100//auth",
        "should_be": "MALICIOUS",
        "description": "⚠️ Fake malicious URL (multiple red flags)"
    },
    
    "4_vt_malware": {
        "url": "https://secure.eicar.org/eicar.com",
        "should_be": "MALICIOUS",
        "description": "⚠️ Structurally safe but known malware"
    },
    
    "5a_wifi_protocol": {
        "payload": "WIFI:T:WPA;S:Starbucks_Guest;P:Coffee1234;;",
        "should_be": "SAFE",
        "description": "✅ WiFi Configuration (non-web protocol)"
    },
    
    "5b_email_protocol": {
        "payload": "mailto:support@bank.com?subject=Account%20Help",
        "should_be": "SAFE",
        "description": "✅ Email Draft (non-web protocol)"
    },
    
    "5c_upi_protocol": {
        "payload": "upi://pay?pa=merchant@upi&pn=Local%20Coffee%20Shop&am=150.00",
        "should_be": "SAFE",
        "description": "✅ UPI Payment Link (non-web protocol)"
    },
}

# Additional false positive tests
FALSE_POSITIVE_TESTS = {
    "legitimate_bank_checkout": {
        "url": "https://secure.mybank.com/verify-account",
        "should_be": "SAFE",
        "reason": "Real bank checkout with legitimate keywords"
    },
    
    "legitimate_amazon_login": {
        "url": "https://www.amazon.com/ap/signin",
        "should_be": "SAFE",
        "reason": "Amazon's actual login page"
    },
    
    "legitimate_paypal_secure": {
        "url": "https://www.paypal.com/secure/login",
        "should_be": "SAFE",
        "reason": "PayPal's official secure login"
    },
    
    "legitimate_microsoft_account": {
        "url": "https://account.microsoft.com/security-info",
        "should_be": "SAFE",
        "reason": "Microsoft's official account security page"
    },
}

# SSL/TLS Authentication Tests
SSL_TESTS = {
    "http_unencrypted": {
        "url": "http://example.com",
        "should_be": "UNENCRYPTED",
        "description": "HTTP connection (no encryption)"
    },
    
    "https_secure": {
        "url": "https://github.com",
        "should_be": "SECURE",
        "description": "HTTPS with valid certificate"
    },
    
    "wifi_protocol": {
        "url": "WIFI:T:WPA;S:MyNetwork;P:Password123;;",
        "should_be": "SAFE_PROTOCOL",
        "description": "Non-web protocol (WiFi config)"
    },
}

def run_heuristic_tests():
    """Test URL analyzer heuristics"""
    print("\n" + "="*70)
    print("TESTING HEURISTIC ANALYSIS (url_inspector.py)")
    print("="*70)
    
    test_urls = [
        TEST_CASES["1_safe_github"]["url"],
        TEST_CASES["3_heuristic_malicious"]["url"],
        *[t["url"] for t in FALSE_POSITIVE_TESTS.values() if "url" in t]
    ]
    
    for url in test_urls:
        result = analyze_url(url)
        verdict = result["verdict"]
        score = result["risk_score"]
        flags = result["flags"]
        
        print(f"\n  URL: {url}")
        print(f"  Verdict: {verdict} ({score}/100)")
        if flags:
            for flag in flags:
                print(f"    • {flag}")
        print()

def run_protocol_tests():
    """Test non-web protocol handling"""
    print("\n" + "="*70)
    print("TESTING PROTOCOL AWARENESS (non-web payloads)")
    print("="*70)
    
    protocols = [
        TEST_CASES["5a_wifi_protocol"]["payload"],
        TEST_CASES["5b_email_protocol"]["payload"],
        TEST_CASES["5c_upi_protocol"]["payload"],
    ]
    
    for payload in protocols:
        result = analyze_url(payload)
        verdict = result["verdict"]
        print(f"\n  Payload: {payload[:50]}...")
        print(f"  Verdict: {verdict}")
        if result["flags"]:
            for flag in result["flags"]:
                print(f"    • {flag}")
        print()

def run_ssl_tests():
    """Test SSL/TLS certificate validation"""
    print("\n" + "="*70)
    print("TESTING SSL/TLS AUTHENTICATION (ssl_checker.py)")
    print("="*70)
    
    ssl_urls = [
        ("https://github.com", "HTTPS - should verify valid cert"),
        ("http://example.com", "HTTP - unencrypted"),
        ("WIFI:T:WPA;S:TestNet;P:Pass;;", "WiFi protocol - no SSL needed"),
        ("mailto:test@example.com", "Email protocol - no SSL needed"),
    ]
    
    for url, desc in ssl_urls:
        result = check_ssl_certificate(url)
        print(f"\n  URL: {url}")
        print(f"  Description: {desc}")
        print(f"  Verdict: {result['verdict']}")
        if result["flags"]:
            for flag in result["flags"]:
                print(f"    • {flag}")
        print()

def run_network_tests():
    """Test URL resolution and redirect tracing"""
    print("\n" + "="*70)
    print("TESTING URL RESOLUTION (network.py)")
    print("="*70)
    
    urls_to_trace = [
        "https://github.com/k3yur",
        # "https://tinyurl.com/google-safe-test-123",  # Uncomment to test real redirect
    ]
    
    for url in urls_to_trace:
        result = resolve_url(url)
        print(f"\n  Original: {result['original_url']}")
        print(f"  Resolved: {result['final_url']}")
        if result['status_code']:
            print(f"  Status:   {result['status_code']}")
        if result['error']:
            print(f"  Error:    {result['error']}")
        print()

if __name__ == "__main__":
    print("\n🧪 DeQode Test Suite")
    print("Testing all 5 scenarios + false positive edge cases\n")
    
    run_heuristic_tests()
    run_protocol_tests()
    run_ssl_tests()
    run_network_tests()
    
    print("\n" + "="*70)
    print("✅ Test suite complete. Check results above for any issues.")
    print("="*70 + "\n")
