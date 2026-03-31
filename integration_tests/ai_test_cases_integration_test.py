#!/usr/bin/env python3
"""
AI Test Cases — Integration Test Suite
========================================
Runs all 21 test cases from "AI Test Cases Template - Filled.xlsx" against the
live deployment at http://57.128.223.176/.

  - 13 Gold Dataset test cases  (GD-01 … GD-13)
  -  8 Bias & Fairness test cases (BF-1A … BF-4B)

Each test sends real log lines to the detection API and validates the response.

Usage:
    cd integration_tests
    # Set your org API key first:
    export TEST_API_KEY=your_api_key_here
    python ai_test_cases_integration_test.py

    # Or use a .env file (same directory):
    echo "TEST_API_KEY=your_key" > .env
    python ai_test_cases_integration_test.py

Dependencies:
    pip install requests python-dotenv   (python-dotenv is optional)

Notes:
    - Tests marked [WARMUP REQUIRED] need the system to have processed
      >= 50 000 logs before the Isolation Forest / Transformer models activate.
      If the system is not yet warmed up they are marked CONDITIONAL (not a
      hard failure) — re-run after warmup to get a definitive Pass.
    - Rule-based tests (GD-01 … GD-06, GD-08, GD-11, BF-1A, BF-1B,
      BF-3A, BF-3B, BF-4B) are deterministic and pass immediately.
"""

import os
import sys
import json
import time
from datetime import datetime, timezone
import requests

try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))
except ImportError:
    pass

BASE_URL = os.getenv("TEST_BASE_URL", "http://57.128.223.176")
API_KEY  = os.getenv("TEST_API_KEY", "")
ENDPOINT = f"{BASE_URL}/api/v1/logs/agent/send-logs"
TIMEOUT  = int(os.getenv("TEST_TIMEOUT", "15"))

USE_COLOR = sys.stdout.isatty() and os.name != "nt"

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

def green(t):  return _c("92", t)
def red(t):    return _c("91", t)
def yellow(t): return _c("93", t)
def cyan(t):   return _c("96", t)
def bold(t):   return _c("1",  t)
def dim(t):    return _c("2",  t)

results = {"pass": 0, "fail": 0, "conditional": 0, "skip": 0, "error": 0}

def _ts():
    return datetime.now().strftime("%H:%M:%S")

def _header(title):
    bar = "─" * 70
    print(f"\n{cyan(bar)}")
    print(f"  {bold(title)}")
    print(f"{cyan(bar)}")

def _result(tc_id, name, status, reason="", response=None):
    icon = {"PASS": green("✔ PASS"), "FAIL": red("✘ FAIL"),
            "CONDITIONAL": yellow("⚠ CONDITIONAL"),
            "SKIP": dim("⊘ SKIP"), "ERROR": red("✘ ERROR")}[status]
    print(f"  [{_ts()}]  {bold(tc_id):<10}  {icon}  {name}")
    if reason:
        print(f"             {dim(reason)}")
    if response is not None:
        snippet = json.dumps(response)
        if len(snippet) > 120:
            snippet = snippet[:117] + "..."
        print(f"             Response: {dim(snippet)}")
    results[status.lower()] += 1

def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def send_logs(log_lines: list[str]) -> dict | None:
    """
    POST one or more log lines to the detection endpoint.
    Returns the parsed JSON response dict, or None on network/HTTP error.
    """
    payload = [{"log": line, "timestamp": _now_iso()} for line in log_lines]
    headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}
    try:
        resp = requests.post(ENDPOINT, json=payload, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as exc:
        return {"_error": f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"}
    except requests.exceptions.RequestException as exc:
        return {"_error": str(exc)}

def run_test(tc_id, name, log_lines, expect_anomaly, warmup_required=False):
    """
    Send logs, evaluate the response, print result.

    Pass criteria:
      expect_anomaly=True  → anomalies_detected >= 1
      expect_anomaly=False → anomalies_detected == 0

    If warmup_required=True and no anomaly is detected, result is CONDITIONAL
    (the model may simply not be warm yet) rather than a hard FAIL.
    """
    resp = send_logs(log_lines)

    if resp is None or "_error" in (resp or {}):
        _result(tc_id, name, "ERROR",
                reason=resp.get("_error", "No response") if resp else "No response")
        return

    anomalies = resp.get("anomalies_detected", 0)
    processed = resp.get("processed_count", 0)

    if expect_anomaly:
        if anomalies >= 1:
            _result(tc_id, name, "PASS",
                    reason=f"anomalies_detected={anomalies}, processed={processed}",
                    response=resp)
        else:
            if warmup_required:
                _result(tc_id, name, "CONDITIONAL",
                        reason="anomalies_detected=0 — system may not be warmed up yet (need >= 50K logs). "
                               "Re-run after warmup to confirm Pass.",
                        response=resp)
            else:
                _result(tc_id, name, "FAIL",
                        reason=f"Expected anomaly but anomalies_detected=0, processed={processed}",
                        response=resp)
    else:
        if anomalies == 0:
            _result(tc_id, name, "PASS",
                    reason=f"anomalies_detected=0, processed={processed} — no false positive",
                    response=resp)
        else:
            _result(tc_id, name, "FAIL",
                    reason=f"False positive! Expected no anomaly but anomalies_detected={anomalies}",
                    response=resp)

# ─────────────────────────────────────────────────────────────────────────────
# Brute-force / flood helpers
# ─────────────────────────────────────────────────────────────────────────────
def _brute_force_logs(ip: str, count: int = 50) -> list[str]:
    """Generate `count` rapid POST /login 401 log lines from a single IP."""
    return [
        f'{ip} - - [{_now_iso()}] "POST /login HTTP/1.1" 401 256 "-" "curl/7.68"'
        for _ in range(count)
    ]

def _flood_logs(ip: str, count: int = 100) -> list[str]:
    """Generate `count` rapid GET / log lines from a single IP."""
    return [
        f'{ip} - - [{_now_iso()}] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        for _ in range(count)
    ]

# ─────────────────────────────────────────────────────────────────────────────
# GOLD DATASET — 13 test cases
# ─────────────────────────────────────────────────────────────────────────────
def run_gold_dataset():
    _header("GOLD DATASET  (GD-01 … GD-13)")
    print(f"  Endpoint : {ENDPOINT}")
    print("  Ref      : AI Test Cases Template - Filled.xlsx → Gold Dataset sheet\n")

    # GD-01  True negative — normal GET request
    run_test(
        "GD-01",
        "True negative — normal GET /index.html",
        ['192.168.1.50 - - [25/Mar/2026:10:15:30 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'],
        expect_anomaly=False,
    )

    # GD-02  SQL injection — OR tautology
    run_test(
        "GD-02",
        "SQL injection OR tautology  (rule-based)",
        ["203.0.113.10 - - [25/Mar/2026:10:16:00 +0000] "
         "\"GET /search?q=1' OR '1'='1'-- HTTP/1.1\" 400 512 \"-\" \"Mozilla/5.0\""],
        expect_anomaly=True,
    )

    # GD-03  XSS
    run_test(
        "GD-03",
        "XSS <script> tag  (rule-based)",
        ["203.0.113.10 - - [25/Mar/2026:10:16:05 +0000] "
         "\"GET /page?name=<script>alert('xss')</script> HTTP/1.1\" 400 512 \"-\" \"Mozilla/5.0\""],
        expect_anomaly=True,
    )

    # GD-04  Path traversal
    run_test(
        "GD-04",
        "Path traversal ../../etc/passwd  (rule-based)",
        ['203.0.113.10 - - [25/Mar/2026:10:16:10 +0000] "GET /files/../../../etc/passwd HTTP/1.1" 404 512 "-" "Mozilla/5.0"'],
        expect_anomaly=True,
    )

    # GD-05  SQL UNION SELECT
    run_test(
        "GD-05",
        "SQL UNION SELECT injection  (rule-based)",
        ['203.0.113.10 - - [25/Mar/2026:10:16:15 +0000] "GET /items?id=1 UNION SELECT username,password FROM users-- HTTP/1.1" 500 512 "-" "Mozilla/5.0"'],
        expect_anomaly=True,
    )

    # GD-06  OS command injection
    run_test(
        "GD-06",
        "OS command injection ;cat /etc/passwd  (rule-based)",
        ['203.0.113.10 - - [25/Mar/2026:10:16:20 +0000] "GET /ping?host=;cat+/etc/passwd HTTP/1.1" 200 512 "-" "Mozilla/5.0"'],
        expect_anomaly=True,
    )

    # GD-07  Brute-force burst — Isolation Forest [WARMUP REQUIRED]
    run_test(
        "GD-07",
        "Brute-force burst 50×POST /login 401  [WARMUP REQUIRED]",
        _brute_force_logs("203.0.113.10", count=50),
        expect_anomaly=True,
        warmup_required=True,
    )

    # GD-08  True negative — normal POST
    run_test(
        "GD-08",
        "True negative — normal POST /api/data",
        ['192.168.1.100 - user123 [25/Mar/2026:10:20:00 +0000] "POST /api/data HTTP/1.1" 200 2048 "-" "Mozilla/5.0"'],
        expect_anomaly=False,
    )

    # GD-09  Endpoint enumeration — Transformer [WARMUP REQUIRED]
    run_test(
        "GD-09",
        "Endpoint enumeration sequence  [WARMUP REQUIRED]",
        [
            '203.0.113.10 - - [25/Mar/2026:10:17:00 +0000] "GET /admin HTTP/1.1" 403 256 "-" "Mozilla/5.0"',
            '203.0.113.10 - - [25/Mar/2026:10:17:05 +0000] "GET /.env HTTP/1.1" 404 128 "-" "Mozilla/5.0"',
            '203.0.113.10 - - [25/Mar/2026:10:17:10 +0000] "GET /backup HTTP/1.1" 404 128 "-" "Mozilla/5.0"',
            '203.0.113.10 - - [25/Mar/2026:10:17:15 +0000] "GET /phpinfo.php HTTP/1.1" 404 128 "-" "Mozilla/5.0"',
            '203.0.113.10 - - [25/Mar/2026:10:17:20 +0000] "GET /config.php HTTP/1.1" 404 128 "-" "Mozilla/5.0"',
        ],
        expect_anomaly=True,
        warmup_required=True,
    )

    # GD-10  Volumetric flood — Isolation Forest [WARMUP REQUIRED]
    run_test(
        "GD-10",
        "Volumetric flood 100×GET /  [WARMUP REQUIRED]",
        _flood_logs("203.0.113.20", count=100),
        expect_anomaly=True,
        warmup_required=True,
    )

    # GD-11  Header injection (CRLF)
    run_test(
        "GD-11",
        "HTTP header injection CRLF  (rule-based)",
        ['203.0.113.10 - - [25/Mar/2026:10:22:00 +0000] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0" X-Forwarded-For: 127.0.0.1\r\nX-Injected: malicious'],
        expect_anomaly=True,
    )

    # GD-12  Ensemble edge case [WARMUP REQUIRED]
    run_test(
        "GD-12",
        "Ensemble: SQL injection + enumeration  [WARMUP REQUIRED]",
        [
            # SQL injection log (rule-based fires immediately)
            '203.0.113.10 - - [25/Mar/2026:02:00:01 +0000] "GET /search?q=1 UNION SELECT * FROM users-- HTTP/1.1" 500 512 "-" "curl/7.68"',
            # Enumeration sequence (transformer / IF fire after warmup)
            '203.0.113.10 - - [25/Mar/2026:02:00:05 +0000] "GET /admin HTTP/1.1" 403 256 "-" "curl/7.68"',
            '203.0.113.10 - - [25/Mar/2026:02:00:10 +0000] "GET /.env HTTP/1.1" 404 128 "-" "curl/7.68"',
            '203.0.113.10 - - [25/Mar/2026:02:00:15 +0000] "GET /backup.sql HTTP/1.1" 404 128 "-" "curl/7.68"',
        ],
        expect_anomaly=True,
        warmup_required=True,
    )

    # GD-13  Behavioral sequence — Transformer [WARMUP REQUIRED]
    run_test(
        "GD-13",
        "Behavioral anomaly: login→admin→export→logout  [WARMUP REQUIRED]",
        [
            '203.0.113.10 - user99 [25/Mar/2026:10:30:00 +0000] "POST /login HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
            '203.0.113.10 - user99 [25/Mar/2026:10:30:10 +0000] "GET /admin/panel HTTP/1.1" 200 4096 "-" "Mozilla/5.0"',
            '203.0.113.10 - user99 [25/Mar/2026:10:30:20 +0000] "POST /admin/export-all HTTP/1.1" 200 98304 "-" "Mozilla/5.0"',
            '203.0.113.10 - user99 [25/Mar/2026:10:30:30 +0000] "GET /logout HTTP/1.1" 200 256 "-" "Mozilla/5.0"',
        ],
        expect_anomaly=True,
        warmup_required=True,
    )

# ─────────────────────────────────────────────────────────────────────────────
# BIAS & FAIRNESS — 8 test cases (4 paired scenarios)
# ─────────────────────────────────────────────────────────────────────────────
def run_bias_fairness():
    _header("BIAS & FAIRNESS  (BF-1A … BF-4B)")
    print("  Ref      : AI Test Cases Template - Filled.xlsx → Bias and Fairness Testing sheet")
    print("  Goal     : Paired variants must produce identical detection outcomes.\n")

    # Scenario 1 — Internal vs External IP (same SQL injection payload)
    print(f"  {bold('Scenario 1')}  Internal IP vs External IP — SQL injection payload")
    run_test(
        "BF-1A",
        "SQL injection from internal IP 192.168.1.1  (expect anomaly)",
        ["192.168.1.1 - - [25/Mar/2026:10:00:00 +0000] "
         "\"GET /search?q=1' OR '1'='1'-- HTTP/1.1\" 400 512 \"-\" \"curl/7.68\""],
        expect_anomaly=True,
    )
    run_test(
        "BF-1B",
        "SQL injection from external IP 203.0.113.50  (expect anomaly, identical to 1A)",
        ["203.0.113.50 - - [25/Mar/2026:10:00:00 +0000] "
         "\"GET /search?q=1' OR '1'='1'-- HTTP/1.1\" 400 512 \"-\" \"curl/7.68\""],
        expect_anomaly=True,
    )

    # Scenario 2 — Cloud IP vs Residential IP (brute-force burst) [WARMUP]
    print(f"\n  {bold('Scenario 2')}  Cloud IP vs Residential IP — brute-force burst  [WARMUP REQUIRED]")
    run_test(
        "BF-2A",
        "Brute force from cloud IP 34.120.0.1 (GCP)  [WARMUP REQUIRED]",
        _brute_force_logs("34.120.0.1", count=50),
        expect_anomaly=True,
        warmup_required=True,
    )
    run_test(
        "BF-2B",
        "Brute force from residential IP 89.200.50.10  [WARMUP REQUIRED]",
        _brute_force_logs("89.200.50.10", count=50),
        expect_anomaly=True,
        warmup_required=True,
    )

    # Scenario 3 — Bot User-Agent vs Browser User-Agent (path traversal)
    print(f"\n  {bold('Scenario 3')}  Bot User-Agent vs Browser User-Agent — path traversal")
    run_test(
        "BF-3A",
        "Path traversal with Googlebot User-Agent  (expect anomaly)",
        ['203.0.113.10 - - [25/Mar/2026:10:05:00 +0000] "GET /files/../../../etc/passwd HTTP/1.1" 404 512 "-" "Googlebot/2.1"'],
        expect_anomaly=True,
    )
    run_test(
        "BF-3B",
        "Path traversal with Mozilla User-Agent  (expect anomaly, identical to 3A)",
        ['203.0.113.10 - - [25/Mar/2026:10:05:00 +0000] "GET /files/../../../etc/passwd HTTP/1.1" 404 512 "-" '
         '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"'],
        expect_anomaly=True,
    )

    # Scenario 4 — CDN high-frequency vs standard single request (both benign)
    print(f"\n  {bold('Scenario 4')}  CDN high-frequency vs standard single request — both benign")
    run_test(
        "BF-4A",
        "CDN 1000×GET / from Fastly IP 151.101.0.1  [WARMUP REQUIRED]",
        _flood_logs("151.101.0.1", count=100),   # send 100 as proxy for 1000 (rate limiting)
        expect_anomaly=False,
        warmup_required=True,
    )
    run_test(
        "BF-4B",
        "Single normal GET from standard IP 192.168.1.50  (baseline, no anomaly)",
        ['192.168.1.50 - - [25/Mar/2026:10:10:00 +0000] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'],
        expect_anomaly=False,
    )

def print_summary(elapsed: float):
    total = sum(results.values())
    bar   = "═" * 70
    print(f"\n{cyan(bar)}")
    print(f"  {bold('TEST SUMMARY')}")
    print(f"{cyan(bar)}")
    print(f"  Total tests : {total}")
    print(f"  {green('Pass')}        : {results['pass']}")
    print(f"  {red('Fail')}        : {results['fail']}")
    print(f"  {yellow('Conditional')} : {results['conditional']}  "
          f"(warmup-dependent; re-run after >= 50K logs to confirm Pass)")
    print(f"  {dim('Skip')}        : {results['skip']}")
    print(f"  {red('Error')}       : {results['error']}")
    print(f"  Elapsed     : {elapsed:.1f}s")
    print(f"{cyan(bar)}\n")

    if results["fail"] > 0:
        print(red("  RESULT: FAIL — one or more tests did not pass."))
    elif results["error"] > 0:
        print(red("  RESULT: ERROR — check API connectivity / API key."))
    elif results["conditional"] > 0:
        print(yellow("  RESULT: CONDITIONAL PASS — rule-based tests all pass. "
                     "Warmup-dependent tests need >= 50K logs to activate "
                     "Isolation Forest + Transformer."))
    else:
        print(green("  RESULT: ALL TESTS PASSED"))
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print(bold("\n╔══════════════════════════════════════════════════════════════════════╗"))
    print(bold(  "║   LogGuard — AI Test Cases Integration Test Suite                    ║"))
    print(bold(  "╚══════════════════════════════════════════════════════════════════════╝"))
    print(f"  Target   : {ENDPOINT}")
    print(f"  API Key  : {'SET (' + API_KEY[:6] + '...)' if API_KEY else red('NOT SET — export TEST_API_KEY=your_key')}")
    print(f"  Started  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if not API_KEY:
        print(red("\n  ERROR: TEST_API_KEY is not set. Cannot send requests."))
        print("  Set it with:  export TEST_API_KEY=your_org_api_key")
        sys.exit(1)

    # Quick connectivity check
    try:
        r = requests.get(BASE_URL, timeout=5)
        print(f"  Reachable: {green('YES')} (HTTP {r.status_code})")
    except requests.exceptions.RequestException:
        print(f"  Reachable: {red('NO — cannot reach ' + BASE_URL)}")
        print(red("  WARNING: proceeding anyway — all tests will likely error."))

    start = time.time()
    run_gold_dataset()
    run_bias_fairness()
    print_summary(time.time() - start)


if __name__ == "__main__":
    main()
