#!/usr/bin/env python3
"""
Attack Pattern Tester
Tests specific attack patterns against the API to verify detection
"""

import requests
import sys
import time

BASE_URL = "https://nexusmxp.com"

def test_sql_injection():
    print("\n🔴 Testing SQL Injection Attacks...")
    payloads = [
        "' OR '1'='1",
        "admin' --",
        "1' UNION SELECT NULL--",
    ]
    
    for payload in payloads:
        print(f"  Testing: {payload[:30]}...")
        try:
            r = requests.get(f"{BASE_URL}/api/gcp?page={payload}", timeout=5)
            print(f"    Status: {r.status_code}")
        except Exception as e:
            print(f"    Error: {e}")
        time.sleep(0.5)

def test_xss():
    print("\n🔴 Testing XSS Attacks...")
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
    ]
    
    for payload in payloads:
        print(f"  Testing: {payload[:30]}...")
        try:
            r = requests.post(
                f"{BASE_URL}/api/gcp",
                json={"title": payload, "name": payload},
                timeout=5
            )
            print(f"    Status: {r.status_code}")
        except Exception as e:
            print(f"    Error: {e}")
        time.sleep(0.5)

def test_path_traversal():
    print("\n🔴 Testing Path Traversal Attacks...")
    payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
    ]
    
    for payload in payloads:
        print(f"  Testing: {payload[:30]}...")
        try:
            r = requests.get(f"{BASE_URL}/api/documents/{payload}", timeout=5)
            print(f"    Status: {r.status_code}")
        except Exception as e:
            print(f"    Error: {e}")
        time.sleep(0.5)

def test_brute_force():
    print("\n🔴 Testing Brute Force Pattern...")
    print("  Sending rapid requests...")
    for i in range(10):
        try:
            fake_id = f"{'0' * 24}"
            r = requests.get(f"{BASE_URL}/api/gcp/{fake_id}", timeout=5)
            print(f"    Request {i+1}: {r.status_code}", end='\r')
        except Exception as e:
            print(f"    Error: {e}")
        time.sleep(0.05)
    print("\n  Brute force test complete")

def test_legitimate_traffic():
    print("\n✅ Testing Legitimate Traffic...")
    
    print("  Browsing GCPs...")
    try:
        r = requests.get(f"{BASE_URL}/api/gcp?page=1&limit=10", timeout=5)
        print(f"    Status: {r.status_code}")
    except Exception as e:
        print(f"    Error: {e}")
    time.sleep(1)
    
    print("  Browsing documents...")
    try:
        r = requests.get(f"{BASE_URL}/api/documents?page=1&limit=6", timeout=5)
        print(f"    Status: {r.status_code}")
    except Exception as e:
        print(f"    Error: {e}")
    time.sleep(1)

def main():
    print("="*60)
    print("  Attack Pattern Tester")
    print("="*60)
    print(f"\nTarget: {BASE_URL}")
    print("\nThis script tests various attack patterns to verify")
    print("that they are being logged and detected properly.")
    print("\nMake sure to monitor:")
    print("  • Nginx access logs: sudo tail -f /var/log/nginx/access.log")
    print("  • Fluent-bit logs: sudo journalctl -u fluent-bit -f")
    print("  • LogGuard dashboard for anomaly alerts")
    
    input("\nPress Enter to start testing...")
    
    test_legitimate_traffic()
    test_sql_injection()
    test_xss()
    test_path_traversal()
    test_brute_force()
    
    print("\n" + "="*60)
    print("  Testing Complete!")
    print("="*60)
    print("\nCheck your LogGuard dashboard to verify these attacks")
    print("were detected and flagged as anomalies.")
    print("")

if __name__ == "__main__":
    main()
