#!/usr/bin/env python3
"""
Transformer Anomaly Detection Examples
=======================================

This script demonstrates specific log sequences that the transformer
would flag as anomalous after training on 50k+ normal logs.

Run this AFTER the system has trained (50,000+ logs processed).
"""

import requests
import time
from datetime import datetime, timedelta
from typing import List

API_URL = "http://localhost/anomaly"
BATCH_ENDPOINT = f"{API_URL}/detect/batch"
STATUS_ENDPOINT = f"{API_URL}/status"


def format_nginx_log(ip: str, timestamp: datetime, method: str, path: str, status: int, size: int = 450) -> str:
    """Format a nginx log line."""
    time_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{time_str}] "{method} {path} HTTP/1.1" {status} {size} "-" "Mozilla/5.0"'


def send_and_analyze(title: str, logs: List[str], expected: str):
    """Send logs and display results."""
    print("\n" + "="*80)
    print(f"📊 {title}")
    print("="*80)
    print(f"Expected: {expected}\n")
    
    # Show the logs
    print("Log Sequence:")
    for i, log in enumerate(logs, 1):
        # Extract key parts for display
        parts = log.split('"')
        if len(parts) >= 2:
            request = parts[1]
            status = log.split('"')[2].strip().split()[0]
            print(f"  {i}. {request} → {status}")
    
    # Send to API
    payload = {"log_lines": logs, "session_id": f"demo_{title.replace(' ', '_')}"}
    response = requests.post(BATCH_ENDPOINT, json=payload)
    
    if response.status_code != 200:
        print(f"\n❌ Error: {response.status_code}")
        return
    
    results = response.json()['results']
    
    # Analyze results
    print("\n" + "-"*80)
    print("Detection Results:")
    print("-"*80)
    print(f"{'#':<4} {'Anomaly':<10} {'Score':<12} {'Trans Score':<12} {'Status':<10}")
    print("-"*80)
    
    for i, result in enumerate(results, 1):
        is_anom = "YES" if result['is_anomaly'] else "NO"
        score = result['anomaly_score']
        
        details = result.get('details', {})
        trans = details.get('transformer', {})
        # Transformer always returns score if ready, no need to check 'enabled'
        trans_score = trans.get('score', 0.0)
        transformer_ready = details.get('transformer_ready', False)
        
        status_indicator = "🚨" if result['is_anomaly'] else "✅"
        
        print(f"{i:<4} {is_anom:<10} {score:<12.4f} {trans_score:<12.4f} {status_indicator:<10}")
    
    # Show transformer context if available
    if results and results[0].get('details', {}).get('transformer_ready'):
        print("\n📈 Transformer Analysis:")
        for i, result in enumerate(results, 1):
            trans = result.get('details', {}).get('transformer', {})
            seq_len = trans.get('sequence_length', 0)
            threshold = trans.get('threshold', 0.0)
            context = trans.get('context', 'unknown')
            score = trans.get('score', 0.0)
            
            if seq_len > 0:
                print(f"  Log {i}: Score={score:.4f}, Seq Length={seq_len}, Threshold={threshold:.2f}, Context={context}")
    else:
        print("\n⚠️  Transformer not trained yet - need 50k+ logs")


def main():
    """Run all transformer detection examples."""
    
    print("\n" + "🔬"*40)
    print("TRANSFORMER ANOMALY DETECTION EXAMPLES")
    print("🔬"*40)
    
    # Check status
    try:
        status = requests.get(STATUS_ENDPOINT).json()
        print(f"\nSystem Status:")
        print(f"  Logs processed: {status.get('logs_processed', 0):,}")
        print(f"  Transformer ready: {status.get('transformer_ready', False)}")
        print(f"  Phase: {status.get('phase', 'unknown')}")
        
        if not status.get('transformer_ready'):
            print("\n⚠️  WARNING: Transformer not trained yet!")
            print("   These examples will show limited detection.")
            print("   Process 50,000+ logs first for full functionality.\n")
    except Exception as e:
        print(f"\n⚠️  Could not check status: {e}\n")
    
    base_time = datetime.now()
    
    # ===================================================================
    # Example 1: Normal User Workflow (Should be LOW score)
    # ===================================================================
    logs = []
    ip = "192.168.1.100"
    for i in range(5):
        path = "/api/users" if i < 3 else "/api/profile"
        logs.append(format_nginx_log(ip, base_time + timedelta(seconds=i), "GET", path, 200))
    
    send_and_analyze(
        "Example 1: Normal User Workflow",
        logs,
        "LOW score - typical browsing pattern"
    )
    time.sleep(1)
    
    # ===================================================================
    # Example 2: SQL Injection Attack (Should be HIGH score)
    # ===================================================================
    logs = []
    ip = "192.168.1.200"
    logs.append(format_nginx_log(ip, base_time, "GET", "/api/login", 200))
    logs.append(format_nginx_log(ip, base_time + timedelta(seconds=1), "GET", "/api/search?q=' OR 1=1--", 403, 120))
    logs.append(format_nginx_log(ip, base_time + timedelta(seconds=2), "GET", "/api/search?q='; DROP TABLE--", 403, 120))
    logs.append(format_nginx_log(ip, base_time + timedelta(seconds=3), "GET", "/api/search?q=admin'--", 403, 120))
    
    send_and_analyze(
        "Example 2: SQL Injection Attack",
        logs,
        "HIGH score - unusual template after login, repeated 403s"
    )
    time.sleep(1)
    
    # ===================================================================
    # Example 3: Directory Traversal (Should be HIGH score)
    # ===================================================================
    logs = []
    ip = "192.168.1.201"
    logs.append(format_nginx_log(ip, base_time, "GET", "/api/data", 200, 1200))
    logs.append(format_nginx_log(ip, base_time + timedelta(seconds=1), "GET", "/api/../etc/passwd", 403, 50))
    logs.append(format_nginx_log(ip, base_time + timedelta(seconds=2), "GET", "/api/../../etc/shadow", 403, 50))
    logs.append(format_nginx_log(ip, base_time + timedelta(seconds=3), "GET", "/api/../../../root/.ssh", 403, 50))
    
    send_and_analyze(
        "Example 3: Directory Traversal Attack",
        logs,
        "HIGH score - path traversal templates never seen in training"
    )
    time.sleep(1)
    
    # ===================================================================
    # Example 4: Enumeration/Scanning (Should be HIGH score)
    # ===================================================================
    logs = []
    ip = "192.168.1.202"
    paths = ["/api/admin", "/api/config", "/api/backup", "/api/debug", "/api/test", "/api/dev"]
    for i, path in enumerate(paths):
        logs.append(format_nginx_log(ip, base_time + timedelta(seconds=i), "GET", path, 403, 120))
    
    send_and_analyze(
        "Example 4: Endpoint Enumeration",
        logs,
        "HIGH score - rapid switching between many different endpoints, all 403s"
    )
    time.sleep(1)
    
    # ===================================================================
    # Example 5: Credential Stuffing (Should be HIGH score)
    # ===================================================================
    logs = []
    ip = "192.168.1.203"
    for i in range(5):
        logs.append(format_nginx_log(ip, base_time + timedelta(seconds=i), "POST", "/api/login", 401, 80))
    logs.append(format_nginx_log(ip, base_time + timedelta(seconds=5), "POST", "/api/login", 200, 450))
    
    send_and_analyze(
        "Example 5: Credential Stuffing/Brute Force",
        logs,
        "HIGH score - repeated failures unusual, normal users don't fail 5 times"
    )
    time.sleep(1)
    
    # ===================================================================
    # Example 6: Unusual Sequence Order (Should be MEDIUM-HIGH score)
    # ===================================================================
    logs = []
    ip = "192.168.1.204"
    logs.append(format_nginx_log(ip, base_time, "POST", "/api/update", 200, 150))  # Unusual start
    logs.append(format_nginx_log(ip, base_time + timedelta(seconds=1), "GET", "/api/data", 200, 1200))
    logs.append(format_nginx_log(ip, base_time + timedelta(seconds=2), "POST", "/api/update", 200, 150))
    logs.append(format_nginx_log(ip, base_time + timedelta(seconds=3), "POST", "/api/update", 200, 150))
    
    send_and_analyze(
        "Example 6: Unusual Sequence Order",
        logs,
        "MEDIUM-HIGH score - starting with POST unusual, repeated POSTs suspicious"
    )
    time.sleep(1)
    
    # ===================================================================
    # Example 7: Context Matters - Same Template Different Context
    # ===================================================================
    print("\n" + "="*80)
    print("📊 Example 7: Context Matters")
    print("="*80)
    print("Demonstrating how the SAME template can be normal or anomalous\n")
    
    # Part A: Admin access after normal workflow (MORE normal)
    logs_a = []
    ip = "192.168.1.205"
    logs_a.append(format_nginx_log(ip, base_time, "GET", "/api/users", 200))
    logs_a.append(format_nginx_log(ip, base_time + timedelta(seconds=1), "GET", "/api/profile", 200))
    logs_a.append(format_nginx_log(ip, base_time + timedelta(seconds=2), "GET", "/api/settings", 200))
    logs_a.append(format_nginx_log(ip, base_time + timedelta(seconds=3), "GET", "/api/admin", 200))
    
    send_and_analyze(
        "Example 7A: Admin Access After Normal Navigation",
        logs_a,
        "LOWER score - admin access in context of normal user workflow"
    )
    time.sleep(1)
    
    # Part B: Admin access immediately (MORE suspicious)
    logs_b = []
    ip = "192.168.1.206"
    logs_b.append(format_nginx_log(ip, base_time, "GET", "/api/admin", 403))
    logs_b.append(format_nginx_log(ip, base_time + timedelta(seconds=1), "GET", "/api/admin", 403))
    logs_b.append(format_nginx_log(ip, base_time + timedelta(seconds=2), "GET", "/api/config", 403))
    
    send_and_analyze(
        "Example 7B: Immediate Admin Access Attempts",
        logs_b,
        "HIGHER score - no normal workflow, direct admin attempts, failures"
    )
    
    # ===================================================================
    # Summary
    # ===================================================================
    print("\n" + "="*80)
    print("SUMMARY: Key Takeaways")
    print("="*80)
    print("""
1. NORMAL SEQUENCES (Low Scores):
   - Typical user workflows (browse → view → update)
   - Consistent patterns seen during training
   - Occasional errors are OK in context

2. ANOMALOUS SEQUENCES (High Scores):
   - SQL injection patterns (never seen in training)
   - Path traversal attempts (rare templates)
   - Rapid endpoint enumeration (no coherent workflow)
   - Repeated failures (credential stuffing)
   - Unusual request orders (POST before GET)

3. CONTEXT MATTERS:
   - Same template can be normal or anomalous
   - Depends on what came before in the sequence
   - Transformer learns typical patterns and flags deviations

4. HOW TO IMPROVE DETECTION:
   - More normal traffic → Better pattern learning
   - Diverse workflows → Better coverage
   - After 50k logs → Full transformer capability
    """)
    
    print("\n✅ Examples completed!")
    print("\nTo see real transformer scores, ensure system has processed 50k+ logs.")


if __name__ == "__main__":
    main()
