#!/usr/bin/env python3
"""
Quick test for WHOIS Lookup Feature
"""

from modules.whois_lookup import lookup_whois, format_whois_for_display, extract_domain

# Test domain extraction
print("=" * 70)
print("TESTING DOMAIN EXTRACTION")
print("=" * 70)

test_urls = [
    "https://github.com/k3yur",
    "http://www.amazon.com/ap/signin",
    "https://secure.paypal.com/login",
    "upi://pay?pa=merchant@upi",  # Non-web
    "mailto:test@example.com",      # Non-web
    "192.168.1.100",                # IP address
]

for url in test_urls:
    domain = extract_domain(url)
    print(f"\nURL: {url}")
    print(f"Extracted Domain: {domain}")

# Test WHOIS lookup
print("\n" + "=" * 70)
print("TESTING WHOIS LOOKUP")
print("=" * 70)

test_domains = [
    "https://github.com",
    "https://google.com",
    "https://invalid-domain-xyz-12345.com",  # Should failgracefully
    "upi://pay?pa=merchant@upi",  # Non-web protocol
]

for url in test_domains:
    print(f"\n📍 Looking up: {url}")
    print("-" * 50)
    
    whois_result = lookup_whois(url)
    
    if whois_result is None:
        print("   ℹ️  Non-web protocol or IP address (WHOIS skipped)")
        continue
    
    formatted = format_whois_for_display(whois_result)
    
    if formatted is None:
        print(f"   ℹ️  Status: {whois_result.get('status', 'unknown')}")
        print(f"   ℹ️  Message: {whois_result.get('error', 'Lookup failed')}")
        continue
    
    print(f"   ✓ Domain: {formatted.get('domain')}")
    print(f"   ✓ Registrar: {formatted.get('registrar')}")
    print(f"   ✓ Created: {formatted.get('created_date')}")
    print(f"   ✓ Expires: {formatted.get('expiration_date')}")
    if formatted.get('organization') and formatted.get('organization') != 'Unknown':
        print(f"   ✓ Organization: {formatted.get('organization')}")
    if formatted.get('country') and formatted.get('country') != 'Unknown':
        print(f"   ✓ Country: {formatted.get('country')}")

print("\n" + "=" * 70)
print("✅ WHOIS test complete!")
print("=" * 70)
