#!/usr/bin/env python3
"""
=============================================================================
CONTEXTUAL ANOMALY DETECTION: Score Evolution Test
=============================================================================

This test demonstrates how anomaly detection scores evolve across a batch of
logs, showing the transformer model's contextual awareness and how it learns
patterns over sequences of requests.

WHAT THIS TEST SHOWS:
---------------------
1. **Sequence Length Progression**: 
   - Each log in a session builds on the previous context
   - Transformer maintains a sliding window (default: 20 logs)
   - Sequence length increases: 1 → 2 → 3 → 4 → ... → 20

2. **Normal Pattern Recognition**:
   - Repeated similar logs create LOW anomaly scores
   - Context reinforces "this is expected behavior"
   - Scores should stabilize as the pattern becomes clear

3. **Anomaly Detection in Context**:
   - Deviations from established patterns score HIGHER
   - Rule-based catches known attack patterns (SQL injection, XSS, etc.)
   - Transformer catches unusual sequences and contextual deviations
   - Isolation Forest catches statistical outliers in request features

4. **Session Independence**:
   - Each session_id maintains separate context
   - No cross-contamination between different users/IPs
   - Fresh context for each new session

5. **Contextual vs Isolated Detection**:
   - Single log (seq=1): Limited context, relies on rule-based patterns
   - Multiple logs (seq>=5): Rich context, transformer can identify deviations
   - Anomalies become more obvious with more context

TEST SCENARIOS:
---------------
- **Test 1**: Normal access pattern - scores should stay low throughout
- **Test 2**: Anomaly appears mid-sequence - should spike at anomaly
- **Test 3**: Gradual escalation - scores should increase progressively  
- **Test 4**: Session independence - verify separate contexts

IMPORTANT NOTES:
----------------
- The transformer needs 50,000+ logs to train
- Before training, you'll see sequence tracking but scores will be 0.0
- After training, scores will reflect contextual deviations
- Rule-based detection works immediately (no training needed)
- Isolation Forest trains alongside transformer at 50k logs

HOW TO USE:
-----------
1. Run before training to see baseline behavior
2. Accumulate 50k logs through normal traffic
3. Run again after training to see contextual scoring
4. Compare results to understand the improvement

EXPECTED BEHAVIOR (After Training):
------------------------------------
- Normal sequences: Low scores (0.0 - 0.3)
- Slight deviations: Medium scores (0.3 - 0.7)
- Clear anomalies: High scores (0.7 - 1.0)
- Sequence length visible in transformer results
- Context field shows "single-log" vs "sequential" vs "batch"

LOG FORMAT:
-----------
Uses nginx Combined Log Format (default nginx access log format):
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"

Example:
192.168.1.1 - - [27/Oct/2025:10:00:00 +0000] "GET /api/users HTTP/1.1" 200 450 "-" "Mozilla/5.0"

=============================================================================
"""

import json
import requests
import time
from typing import List, Dict, Any
from datetime import datetime, timedelta

# API endpoint (via nginx proxy)
API_URL = "http://localhost/anomaly"
BATCH_ENDPOINT = f"{API_URL}/detect/batch"
STATUS_ENDPOINT = f"{API_URL}/status"


def create_log_entry(template: str, timestamp: datetime, **kwargs) -> Dict[str, Any]:
    """Create a log entry with the given template and parameters."""
    return {
        "timestamp": timestamp.isoformat(),
        "level": kwargs.get("level", "INFO"),
        "message": template.format(**kwargs),
        "source": kwargs.get("source", "web_server"),
        "user_id": kwargs.get("user_id", "user123"),
        "ip_address": kwargs.get("ip_address", "192.168.1.100"),
        "request_method": kwargs.get("method", "GET"),
        "request_path": kwargs.get("path", "/api/data"),
        "response_status": kwargs.get("status", 200),
        "response_time_ms": kwargs.get("response_time", 50),
        "user_agent": kwargs.get("user_agent", "Mozilla/5.0"),
    }


def check_system_status() -> Dict[str, Any]:
    """Check if the system is ready and trained."""
    response = requests.get(STATUS_ENDPOINT)
    response.raise_for_status()
    return response.json()


def format_log_line(log: Dict[str, Any]) -> str:
    """Convert log dict to nginx Combined Log Format.
    
    nginx default combined format:
    $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
    
    Example:
    192.168.1.1 - - [27/Oct/2025:10:00:00 +0000] "GET /api/data HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
    """
    # Convert ISO timestamp to nginx format [27/Oct/2025:10:00:00 +0000]
    dt = datetime.fromisoformat(log['timestamp'])
    nginx_time = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
    
    # Estimate size based on response time (just for realism)
    size = log['response_time_ms'] * 10
    
    return (f"{log['ip_address']} - - [{nginx_time}] "
            f"\"{log['request_method']} {log['request_path']} HTTP/1.1\" "
            f"{log['response_status']} {size} "
            f"\"-\" \"{log['user_agent']}\"")


def send_batch(logs: List[Dict[str, Any]], session_id: str = "test_session") -> Dict[str, Any]:
    """Send a batch of logs and get detection results."""
    # Convert log dicts to formatted strings
    log_lines = [format_log_line(log) for log in logs]
    
    payload = {
        "log_lines": log_lines,
        "session_id": session_id
    }
    response = requests.post(BATCH_ENDPOINT, json=payload)
    response.raise_for_status()
    return response.json()


def print_section_header(title: str):
    """Print a formatted section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def print_detection_result(idx: int, log: Dict[str, Any], result: Dict[str, Any]):
    """Print a formatted detection result."""
    print(f"\nLog #{idx + 1}: {log['message'][:60]}...")
    print(f"  Timestamp: {log['timestamp']}")
    print(f"  IP: {log['ip_address']}, Status: {log['response_status']}, Response: {log['response_time_ms']}ms")
    print(f"\n  Overall Detection:")
    print(f"    Is Anomaly: {result['is_anomaly']}")
    print(f"    Anomaly Score: {result['anomaly_score']:.4f}")
    print(f"    Phase: {result['phase']}")
    
    details = result.get('details', {})
    print(f"\n  Model Scores:")
    
    # Rule-based
    rule = details.get('rule_based', {})
    print(f"    Rule-based: {rule.get('score', 0.0):.4f} | Patterns: {rule.get('matched_patterns', [])}")
    
    # Isolation Forest
    iso = details.get('isolation_forest', {})
    if iso.get('enabled'):
        print(f"    Isolation Forest: {iso.get('score', 0.0):.4f} | Features: {iso.get('num_features', 0)}")
    else:
        print(f"    Isolation Forest: Not ready")
    
    # Transformer
    trans = details.get('transformer', {})
    if trans.get('enabled'):
        seq_len = trans.get('sequence_length', 0)
        threshold = trans.get('threshold', 0.0)
        context = trans.get('context', 'unknown')
        print(f"    Transformer: {trans.get('score', 0.0):.4f} | Seq Length: {seq_len} | Threshold: {threshold:.4f}")
        print(f"      Context: {context}")
    else:
        print(f"    Transformer: Not ready")


def print_evolution_summary(results: List[Dict[str, Any]]):
    """Print a summary table showing score evolution."""
    print("\n" + "-" * 80)
    print("CONTEXTUAL SCORE EVOLUTION SUMMARY")
    print("-" * 80)
    print(f"{'Log#':<6} {'Seq Len':<10} {'Trans Score':<15} {'Anomaly Score':<15} {'Anomaly':<10}")
    print("-" * 80)
    
    for idx, result in enumerate(results):
        details = result.get('details', {})
        trans = details.get('transformer', {})
        seq_len = trans.get('sequence_length', 0) if trans.get('enabled') else 0
        trans_score = trans.get('score', 0.0) if trans.get('enabled') else 0.0
        anomaly_score = result.get('anomaly_score', 0.0)
        is_anomaly = "YES" if result['is_anomaly'] else "NO"
        
        print(f"{idx + 1:<6} {seq_len:<10} {trans_score:<15.4f} {anomaly_score:<15.4f} {is_anomaly:<10}")


def test_normal_sequence():
    """Test 1: Normal access pattern - scores should remain low."""
    print_section_header("TEST 1: Normal Access Pattern (Expected: Low scores throughout)")
    
    base_time = datetime.now()
    logs = []
    
    # Create 5 normal access logs
    for i in range(5):
        logs.append(create_log_entry(
            "User {user} accessed {path} from {ip}",
            base_time + timedelta(seconds=i),
            user="alice",
            path="/api/users",
            ip="192.168.1.100",
            status=200,
            response_time=45 + i * 5,
            method="GET"
        ))
    
    print(f"\nSending {len(logs)} normal access logs...")
    result = send_batch(logs, session_id="test_normal")
    
    for idx, (log, detection) in enumerate(zip(logs, result['results'])):
        print_detection_result(idx, log, detection)
    
    print_evolution_summary(result['results'])
    
    print("\n📊 Analysis:")
    print("  - Transformer scores should stay low as context builds")
    print("  - Each log reinforces the normal pattern")
    print("  - Sequence length increases: 1 → 2 → 3 → 4 → 5")


def test_anomaly_in_sequence():
    """Test 2: Anomaly appears in middle of normal sequence."""
    print_section_header("TEST 2: Anomaly in Context (Expected: Score spike at anomaly)")
    
    base_time = datetime.now()
    logs = []
    
    # 2 normal logs
    for i in range(2):
        logs.append(create_log_entry(
            "User {user} accessed {path} from {ip}",
            base_time + timedelta(seconds=i),
            user="bob",
            path="/api/profile",
            ip="192.168.1.101",
            status=200,
            response_time=50,
            method="GET"
        ))
    
    # 1 SQL injection attempt (anomaly)
    logs.append(create_log_entry(
        "User {user} accessed {path} from {ip}",
        base_time + timedelta(seconds=2),
        user="bob",
        path="/api/search?q=' OR 1=1--",
        ip="192.168.1.101",
        status=403,
        response_time=5,
        method="GET"
    ))
    
    # 2 more normal logs
    for i in range(3, 5):
        logs.append(create_log_entry(
            "User {user} accessed {path} from {ip}",
            base_time + timedelta(seconds=i),
            user="bob",
            path="/api/profile",
            ip="192.168.1.101",
            status=200,
            response_time=50,
            method="GET"
        ))
    
    print(f"\nSending batch with anomaly at position 3...")
    result = send_batch(logs, session_id="test_anomaly")
    
    for idx, (log, detection) in enumerate(zip(logs, result['results'])):
        print_detection_result(idx, log, detection)
    
    print_evolution_summary(result['results'])
    
    print("\n📊 Analysis:")
    print("  - Logs 1-2: Build normal context")
    print("  - Log 3: SQL injection breaks pattern → HIGH score")
    print("  - Logs 4-5: Return to normal, may still be elevated due to recent anomaly")
    print("  - Rule-based catches SQL pattern immediately")
    print("  - Transformer sees contextual deviation")


def test_gradual_escalation():
    """Test 3: Gradual behavior change."""
    print_section_header("TEST 3: Gradual Escalation (Expected: Progressive score increase)")
    
    base_time = datetime.now()
    logs = []
    
    # Start with normal access
    logs.append(create_log_entry(
        "User {user} accessed {path} from {ip}",
        base_time,
        user="charlie",
        path="/api/data",
        ip="192.168.1.102",
        status=200,
        response_time=50,
        method="GET"
    ))
    
    # Gradually increase request frequency and add different paths
    logs.append(create_log_entry(
        "User {user} accessed {path} from {ip}",
        base_time + timedelta(seconds=1),
        user="charlie",
        path="/api/admin",
        ip="192.168.1.102",
        status=403,
        response_time=10,
        method="GET"
    ))
    
    logs.append(create_log_entry(
        "User {user} accessed {path} from {ip}",
        base_time + timedelta(seconds=2),
        user="charlie",
        path="/api/users/list",
        ip="192.168.1.102",
        status=403,
        response_time=8,
        method="GET"
    ))
    
    logs.append(create_log_entry(
        "User {user} accessed {path} from {ip}",
        base_time + timedelta(seconds=3),
        user="charlie",
        path="/api/config",
        ip="192.168.1.102",
        status=403,
        response_time=7,
        method="GET"
    ))
    
    logs.append(create_log_entry(
        "User {user} accessed {path} from {ip}",
        base_time + timedelta(seconds=4),
        user="charlie",
        path="/api/../../../etc/passwd",
        ip="192.168.1.102",
        status=403,
        response_time=5,
        method="GET"
    ))
    
    print(f"\nSending batch showing escalating suspicious behavior...")
    result = send_batch(logs, session_id="test_escalation")
    
    for idx, (log, detection) in enumerate(zip(logs, result['results'])):
        print_detection_result(idx, log, detection)
    
    print_evolution_summary(result['results'])
    
    print("\n📊 Analysis:")
    print("  - Log 1: Normal access")
    print("  - Log 2: First 403 - slight deviation")
    print("  - Logs 3-4: Multiple 403s - pattern becomes suspicious")
    print("  - Log 5: Path traversal attempt - clear attack")
    print("  - Transformer scores should increase progressively")
    print("  - Context helps identify escalation pattern")


def test_different_sessions():
    """Test 4: Same pattern in different sessions."""
    print_section_header("TEST 4: Session Independence (Expected: Reset context per session)")
    
    base_time = datetime.now()
    
    # Session 1: Normal pattern
    logs1 = []
    for i in range(3):
        logs1.append(create_log_entry(
            "User {user} accessed {path} from {ip}",
            base_time + timedelta(seconds=i),
            user="dave",
            path="/api/data",
            ip="192.168.1.103",
            status=200,
            response_time=50,
            method="GET"
        ))
    
    print("\n--- Session 1: Normal Access ---")
    result1 = send_batch(logs1, session_id="session_1")
    for idx, detection in enumerate(result1['results']):
        details = detection.get('details', {})
        trans = details.get('transformer', {})
        seq_len = trans.get('sequence_length', 0) if trans.get('enabled') else 0
        print(f"  Log {idx + 1}: Seq Length = {seq_len}, Score = {trans.get('score', 0.0):.4f}")
    
    # Session 2: Same pattern (should start fresh)
    logs2 = []
    for i in range(3):
        logs2.append(create_log_entry(
            "User {user} accessed {path} from {ip}",
            base_time + timedelta(seconds=i + 10),
            user="eve",
            path="/api/data",
            ip="192.168.1.104",
            status=200,
            response_time=50,
            method="GET"
        ))
    
    print("\n--- Session 2: Same Pattern (New Session) ---")
    result2 = send_batch(logs2, session_id="session_2")
    for idx, detection in enumerate(result2['results']):
        details = detection.get('details', {})
        trans = details.get('transformer', {})
        seq_len = trans.get('sequence_length', 0) if trans.get('enabled') else 0
        print(f"  Log {idx + 1}: Seq Length = {seq_len}, Score = {trans.get('score', 0.0):.4f}")
    
    print("\n📊 Analysis:")
    print("  - Each session maintains independent context")
    print("  - Session 2 starts with sequence length 1 (not 4)")
    print("  - Context doesn't bleed between different users/sessions")


def main():
    """Run all contextual evolution tests."""
    print("\n" + "🔬" * 40)
    print("CONTEXTUAL ANOMALY DETECTION: SCORE EVOLUTION TEST")
    print("🔬" * 40)
    
    # Check system status
    print("\nChecking system status...")
    try:
        status = check_system_status()
        print(f"  Logs processed: {status.get('logs_processed', 0)}")
        print(f"  Isolation Forest ready: {status.get('isolation_forest_ready', False)}")
        print(f"  Transformer ready: {status.get('transformer_ready', False)}")
        
        if not status.get('transformer_ready'):
            print("\n⚠️  WARNING: Transformer not yet trained!")
            print("   This test will show limited contextual behavior.")
            print("   The system needs 50,000+ logs to train the transformer.")
            print("   However, you'll still see sequence length progression.\n")
    except Exception as e:
        print(f"  Error checking status: {e}")
        print("  Continuing with tests anyway...\n")
    
    try:
        # Run all tests
        test_normal_sequence()
        time.sleep(1)
        
        test_anomaly_in_sequence()
        time.sleep(1)
        
        test_gradual_escalation()
        time.sleep(1)
        
        test_different_sessions()
        
        # Final summary
        print_section_header("SUMMARY: KEY CONTEXTUAL INSIGHTS")
        print("""
1. SEQUENCE LENGTH PROGRESSION:
   - Each log in a session adds to the context window
   - Transformer sees 1, 2, 3... logs progressively
   - Maximum window size is typically 20 logs

2. NORMAL PATTERNS:
   - Repeated similar logs create low anomaly scores
   - Context reinforces "this is normal behavior"
   - Scores stabilize as pattern becomes clear

3. ANOMALY DETECTION:
   - Deviations from established context score higher
   - Rule-based catches known patterns instantly
   - Transformer catches contextual deviations
   - Isolation Forest catches statistical outliers

4. SESSION INDEPENDENCE:
   - Each session_id gets its own context
   - No cross-contamination between users
   - Fresh start for each new interaction

5. CONTEXTUAL vs ISOLATED:
   - Single log (seq=1): Limited context, higher variance
   - Multiple logs (seq>5): Rich context, more reliable
   - Anomalies stand out more clearly with context
        """)
        
        print("\n✅ All tests completed successfully!")
        print("\nNext steps:")
        print("  - Send real traffic to accumulate 50k logs")
        print("  - Re-run this test after transformer training")
        print("  - Compare scores before/after training")
        
    except Exception as e:
        print(f"\n❌ Error running tests: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
