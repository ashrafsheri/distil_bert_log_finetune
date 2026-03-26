#!/usr/bin/env python3
"""
LogGuard Server Stress Test
============================
Directly POSTs fake nginx log lines to the LogGuard API, simulating
Fluent Bit traffic from both connected organisations simultaneously.
Ramps up rate until the server degrades or crashes, then records results.

Pipeline under test:
  This script → POST /api/v1/logs/agent/send-logs (SaaS Starter API key)  ─┐
  This script → POST /api/v1/logs/agent/send-logs (Playground API key)    ─┤
                                                                             ↓
                                               LogGuard (57.128.223.176)
                                                 → AnomalyDetectionService
                                                 → Elasticsearch storage
                                                 → WebSocket dashboard

The two websites (152.70.28.154:80 and :81) are NOT touched.
We generate fake nginx log strings locally and POST them directly.

Usage:
    cd integration_tests
    python3 stress_test.py

    # Stop after phase 3 (0-indexed):
    STRESS_MAX_PHASE=3 python3 stress_test.py

    # Verify config without sending traffic:
    STRESS_DRY_RUN=1 python3 stress_test.py

Output:
    - Live terminal status line updated every second
    - stress_test_results_<timestamp>.json saved on exit
      (feed this file into generate_stress_report.py for the Word doc)
"""

import os
import sys
import time
import json
import random
import signal
import threading
import datetime
from concurrent.futures import ThreadPoolExecutor

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))
except ImportError:
    pass

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────
LOGGUARD_ENDPOINT = "http://57.128.223.176/api/v1/logs/agent/send-logs"

ORGS = [
    {
        "name":    "SaaS Starter",
        "api_key": os.getenv("SAAS_API_KEY", ""),
        "site":    "http://152.70.28.154",       # just used in fake log Host header
    },
    {
        "name":    "Playground",
        "api_key": os.getenv("PLAYGROUND_API_KEY", ""),
        "site":    "http://152.70.28.154:81",
    },
]

# Batch size: how many log lines per POST request
BATCH_SIZE = 10

# Ramp-up phases: (label, logs_per_sec_per_org, duration_seconds)
# Total logs/sec = logs_per_sec_per_org × number of orgs (2)
PHASES = [
    ("Warmup",  5,    30),    #   10 logs/s total
    ("Low",     25,   60),    #   50 logs/s total
    ("Medium",  50,   60),    #  100 logs/s total
    ("High",    150,  60),    #  300 logs/s total
    ("Stress",  300,  60),    #  600 logs/s total
    ("Max",     500,  300),   # 1000 logs/s total — run until crash or 5 min
]

MAX_PHASE   = int(os.getenv("STRESS_MAX_PHASE", str(len(PHASES) - 1)))
DRY_RUN     = os.getenv("STRESS_DRY_RUN", "0") == "1"

# Health probe: separate from stress traffic
PROBE_INTERVAL_SEC   = 3
PROBE_FAIL_THRESHOLD = 3      # consecutive failures → crash
LATENCY_MULTIPLIER   = 8      # avg_ms > N × baseline → degraded
POST_TIMEOUT         = 20     # seconds per POST

# ─────────────────────────────────────────────────────────────────────────────
# Realistic fake nginx log data
# ─────────────────────────────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
]

PATHS_SAAS = [
    "/", "/login", "/signup", "/dashboard", "/settings", "/profile",
    "/api/v1/users", "/api/v1/projects", "/api/v1/billing", "/api/v1/stats",
    "/pricing", "/features", "/docs", "/blog", "/about", "/contact",
    "/static/main.js", "/static/style.css", "/favicon.ico", "/health",
]

PATHS_PLAYGROUND = [
    "/", "/playground", "/examples", "/sandbox", "/editor",
    "/api/run", "/api/reset", "/api/status", "/api/logs", "/api/save",
    "/templates", "/share", "/embed", "/docs",
    "/static/app.js", "/static/theme.css", "/favicon.ico",
]

STATUS_CODES = [200, 200, 200, 200, 200, 200, 301, 304, 400, 404, 500]

def _now_iso():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def _nginx_ts():
    return datetime.datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")

def random_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def make_log_line(org: dict) -> str:
    ip      = random_ip()
    ts      = _nginx_ts()
    paths   = PATHS_SAAS if "SaaS" in org["name"] else PATHS_PLAYGROUND
    path    = random.choice(paths)
    status  = random.choice(STATUS_CODES)
    size    = random.randint(256, 51200)
    ua      = random.choice(USER_AGENTS)
    return f'{ip} - - [{ts}] "GET {path} HTTP/1.1" {status} {size} "-" "{ua}"'

def make_batch(org: dict, n: int = BATCH_SIZE) -> list:
    return [{"log": make_log_line(org), "timestamp": _now_iso()} for _ in range(n)]

# ─────────────────────────────────────────────────────────────────────────────
# Shared state (guarded by lock)
# ─────────────────────────────────────────────────────────────────────────────
_lock = threading.Lock()
_state = {
    "running":           True,
    "crash_detected":    False,
    "crash_reason":      "",
    "crash_time":        None,
    "current_phase":     "init",
    "current_rate":      0,          # logs/sec per org
    "total_logs_sent":   0,          # successful log entries accepted by LogGuard
    "total_posts":       0,          # total POST requests made
    "total_post_errors": 0,          # POSTs that got non-2xx or timed out
    "probe_latencies":   [],         # rolling window (last 20 probe ms values)
    "baseline_ms":       None,
    "consecutive_fails": 0,
    "phase_log":         [],
    "start_time":        None,
}

def _inc(key, n=1):
    with _lock:
        _state[key] += n

def _get(key):
    with _lock:
        return _state[key]

def _set(key, val):
    with _lock:
        _state[key] = val

# ─────────────────────────────────────────────────────────────────────────────
# Session factory
# ─────────────────────────────────────────────────────────────────────────────
def make_session():
    s = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=20,
        pool_maxsize=100,
        max_retries=Retry(total=0),
    )
    s.mount("http://", adapter)
    return s

# ─────────────────────────────────────────────────────────────────────────────
# Stress worker — one thread per org
# ─────────────────────────────────────────────────────────────────────────────
def stress_worker(org: dict, stop_event: threading.Event):
    """
    Continuously POSTs batches of fake logs to LogGuard as this org.
    Throttles to the current target rate set by the ramp-up controller.
    """
    session = make_session()
    headers = {
        "X-API-Key":    org["api_key"],
        "Content-Type": "application/json",
    }

    while not stop_event.is_set():
        rate = _get("current_rate")   # logs/sec for this org
        if rate == 0:
            time.sleep(0.1)
            continue

        # How long to wait between batches to hit the target rate
        interval = BATCH_SIZE / rate  # seconds per batch

        payload = make_batch(org, BATCH_SIZE)
        t0 = time.time()

        try:
            resp = session.post(
                LOGGUARD_ENDPOINT,
                json=payload,
                headers=headers,
                timeout=POST_TIMEOUT,
            )
            _inc("total_posts")

            if resp.status_code == 200:
                data = resp.json()
                _inc("total_logs_sent", data.get("processed_count", BATCH_SIZE))
            else:
                _inc("total_post_errors")

        except requests.exceptions.RequestException:
            _inc("total_posts")
            _inc("total_post_errors")

        # Throttle: sleep for remainder of interval
        elapsed = time.time() - t0
        sleep_for = max(0, interval - elapsed)
        if sleep_for > 0:
            time.sleep(sleep_for)

# ─────────────────────────────────────────────────────────────────────────────
# Health monitor — separate probe thread
# ─────────────────────────────────────────────────────────────────────────────
def health_monitor(stop_event: threading.Event):
    """
    Every PROBE_INTERVAL_SEC seconds, sends one small probe POST per org
    and measures LogGuard's response time. Declares crash on repeated failures
    or severe latency degradation.
    """
    session  = make_session()
    failures = 0

    while not stop_event.is_set():
        time.sleep(PROBE_INTERVAL_SEC)
        if stop_event.is_set():
            break

        round_ms = []
        round_ok = True

        for org in ORGS:
            probe = [{"log": make_log_line(org), "timestamp": _now_iso()}]
            headers = {"X-API-Key": org["api_key"], "Content-Type": "application/json"}
            try:
                t0   = time.time()
                resp = session.post(LOGGUARD_ENDPOINT, json=probe, headers=headers, timeout=POST_TIMEOUT)
                ms   = (time.time() - t0) * 1000
                round_ms.append(ms)
                if resp.status_code >= 500:
                    round_ok = False
            except requests.exceptions.RequestException as e:
                round_ok = False
                round_ms.append(POST_TIMEOUT * 1000)

        avg_ms = sum(round_ms) / len(round_ms) if round_ms else 0

        with _lock:
            _state["probe_latencies"].append(round(avg_ms, 1))
            if len(_state["probe_latencies"]) > 30:
                _state["probe_latencies"] = _state["probe_latencies"][-30:]

            # Set baseline from first 3 clean probes
            if _state["baseline_ms"] is None and len(_state["probe_latencies"]) >= 3:
                _state["baseline_ms"] = round(sum(_state["probe_latencies"][:3]) / 3, 1)

        if not round_ok:
            failures += 1
            if failures >= PROBE_FAIL_THRESHOLD:
                with _lock:
                    if not _state["crash_detected"]:
                        _state["crash_detected"] = True
                        _state["crash_reason"]   = (
                            f"{PROBE_FAIL_THRESHOLD} consecutive health probe failures "
                            f"(last avg response: {avg_ms:.0f}ms)"
                        )
                        _state["crash_time"] = _now_iso()
                stop_event.set()
                return
        else:
            failures = 0
            _set("consecutive_fails", 0)

        # Latency degradation check
        baseline = _get("baseline_ms")
        if baseline and avg_ms > baseline * LATENCY_MULTIPLIER:
            with _lock:
                if not _state["crash_detected"]:
                    _state["crash_detected"] = True
                    _state["crash_reason"]   = (
                        f"Severe latency degradation: {avg_ms:.0f}ms "
                        f"({LATENCY_MULTIPLIER}× baseline of {baseline:.0f}ms)"
                    )
                    _state["crash_time"] = _now_iso()
            stop_event.set()
            return

# ─────────────────────────────────────────────────────────────────────────────
# ANSI helpers
# ─────────────────────────────────────────────────────────────────────────────
USE_COLOR = sys.stdout.isatty()
def _c(code, t): return f"\033[{code}m{t}\033[0m" if USE_COLOR else t
def green(t):  return _c("92", t)
def red(t):    return _c("91", t)
def yellow(t): return _c("93", t)
def cyan(t):   return _c("96", t)
def bold(t):   return _c("1",  t)
def dim(t):    return _c("2",  t)

# ─────────────────────────────────────────────────────────────────────────────
# Live display
# ─────────────────────────────────────────────────────────────────────────────
def display_loop(stop_event: threading.Event):
    start = _state["start_time"]
    while not stop_event.is_set():
        time.sleep(1)
        elapsed = int(time.time() - start)
        m, s    = divmod(elapsed, 60)

        with _lock:
            phase   = _state["current_phase"]
            rate    = _state["current_rate"]
            logs    = _state["total_logs_sent"]
            posts   = _state["total_posts"]
            errors  = _state["total_post_errors"]
            probes  = _state["probe_latencies"]
            crash   = _state["crash_detected"]

        avg_ms  = f"{sum(probes[-5:]) / len(probes[-5:]):.0f}ms" if probes else "—"
        err_pct = f"{100 * errors / max(posts, 1):.1f}%"
        status  = red("CRASH DETECTED") if crash else green("OK")

        print(
            f"\r  [{m:02d}:{s:02d}]  "
            f"Phase: {bold(phase):<10}  "
            f"Rate: {bold(str(rate*2)+'/s'):<10}  "
            f"Logs sent: {bold(str(logs)):<10}  "
            f"LogGuard: {cyan(avg_ms):<9}  "
            f"Err: {err_pct:<7}  "
            f"{status}      ",
            end="", flush=True,
        )
    print()

# ─────────────────────────────────────────────────────────────────────────────
# Report writer
# ─────────────────────────────────────────────────────────────────────────────
def write_report() -> str:
    ts       = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_dir  = os.path.dirname(os.path.abspath(__file__))
    filename = os.path.join(out_dir, f"stress_test_results_{ts}.json")

    with _lock:
        probes   = _state["probe_latencies"]
        elapsed  = int(time.time() - _state["start_time"])
        report   = {
            "test_run_at":               _now_iso(),
            "logguard_endpoint":         LOGGUARD_ENDPOINT,
            "organisations_tested":      [o["name"] for o in ORGS],
            "batch_size":                BATCH_SIZE,
            "phases_run":                _state["phase_log"],
            "peak_rate_per_org":         _state["current_rate"],
            "peak_rate_total_logs_per_s":_state["current_rate"] * len(ORGS),
            "total_logs_accepted":       _state["total_logs_sent"],
            "total_post_requests":       _state["total_posts"],
            "total_post_errors":         _state["total_post_errors"],
            "post_error_rate_pct":       round(100 * _state["total_post_errors"] / max(_state["total_posts"], 1), 2),
            "logguard_baseline_ms":      _state["baseline_ms"],
            "logguard_avg_ms_at_end":    round(sum(probes[-5:]) / len(probes[-5:]), 1) if probes else None,
            "logguard_all_probe_ms":     probes,
            "crash_detected":            _state["crash_detected"],
            "crash_reason":              _state["crash_reason"] or "None — all phases completed without crash",
            "crash_time":                _state["crash_time"],
            "crash_at_total_logs":       _state["total_logs_sent"] if _state["crash_detected"] else None,
            "total_elapsed_seconds":     elapsed,
        }

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    # Print summary
    bar = "═" * 72
    print(f"\n{cyan(bar)}")
    print(f"  {bold('STRESS TEST COMPLETE')}")
    print(f"{cyan(bar)}")
    print(f"  LogGuard endpoint     : {LOGGUARD_ENDPOINT}")
    print(f"  Orgs tested           : {', '.join(o['name'] for o in ORGS)}")
    print(f"  Total logs accepted   : {bold(str(report['total_logs_accepted']))}")
    print(f"  Total POST requests   : {report['total_post_requests']}")
    print(f"  POST error rate       : {report['post_error_rate_pct']}%")
    print(f"  Peak rate             : {bold(str(report['peak_rate_total_logs_per_s']) + ' logs/s total')}")
    print(f"  LogGuard baseline     : {report['logguard_baseline_ms'] or '—'} ms")
    print(f"  LogGuard final avg    : {report['logguard_avg_ms_at_end'] or '—'} ms")
    print(f"  Elapsed               : {elapsed}s")
    print()
    if report["crash_detected"]:
        print(f"  {red('CRASH DETECTED')}")
        print(f"  Reason     : {report['crash_reason']}")
        print(f"  Time       : {report['crash_time']}")
        print(f"  Logs at crash: {report['crash_at_total_logs']}")
    else:
        print(f"  {green('No crash detected — server survived all phases.')}")
    print()
    print(f"  Results JSON : {filename}")
    print(f"  {dim('Run generate_stress_report.py to create the Word document.')}")
    print(f"{cyan(bar)}\n")

    return filename

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print(bold("\n╔══════════════════════════════════════════════════════════════════════╗"))
    print(bold(  "║   LogGuard Direct-POST Stress Test                                   ║"))
    print(bold(  "╚══════════════════════════════════════════════════════════════════════╝"))
    print(f"  Target    : {LOGGUARD_ENDPOINT}")
    print(f"  Orgs      : {', '.join(o['name'] for o in ORGS)}")
    print(f"  Batch     : {BATCH_SIZE} logs per POST")
    print(f"  Phases    : {', '.join(p[0]+f'({p[1]*2}/s)' for p in PHASES[:MAX_PHASE+1])}")
    print(f"  Peak rate : {PHASES[MAX_PHASE][1] * len(ORGS)} logs/s total\n")

    if DRY_RUN:
        print(yellow("  DRY RUN mode — config looks good. Exiting without sending traffic."))
        return

    # Connectivity check
    print("  Checking LogGuard is reachable...", end=" ", flush=True)
    try:
        r = requests.get("http://57.128.223.176", timeout=8)
        print(green(f"OK (HTTP {r.status_code})"))
    except requests.exceptions.RequestException as e:
        print(red(f"FAILED ({e})"))
        sys.exit(1)

    # Quick API key validation — probe both orgs once
    print("  Validating API keys...", end=" ", flush=True)
    session = make_session()
    for org in ORGS:
        probe = [{"log": make_log_line(org), "timestamp": _now_iso()}]
        try:
            r = session.post(
                LOGGUARD_ENDPOINT,
                json=probe,
                headers={"X-API-Key": org["api_key"], "Content-Type": "application/json"},
                timeout=15,
            )
            if r.status_code == 401:
                print(red(f"\n  INVALID API KEY for {org['name']} — check your keys."))
                sys.exit(1)
            elif r.status_code >= 500:
                print(yellow(f"\n  WARNING: {org['name']} probe returned HTTP {r.status_code}. Continuing."))
        except requests.exceptions.RequestException as e:
            print(red(f"\n  Could not reach LogGuard: {e}"))
            sys.exit(1)
    print(green("OK"))

    print(f"\n  {'Phase':<12} {'Rate/org':<14} {'Total':<14} {'Duration'}")
    print(f"  {'─'*52}")
    print()

    stop_event = threading.Event()
    _set("start_time", time.time())

    def handle_sigint(sig, frame):
        print(f"\n\n  {yellow('Stopped by user (Ctrl+C)')}")
        stop_event.set()
    signal.signal(signal.SIGINT, handle_sigint)

    # Start health monitor thread
    threading.Thread(target=health_monitor, args=(stop_event,), daemon=True).start()

    # Start display thread
    threading.Thread(target=display_loop, args=(stop_event,), daemon=True).start()

    # Start one stress worker thread per org
    for org in ORGS:
        threading.Thread(target=stress_worker, args=(org, stop_event), daemon=True).start()

    # Ramp-up controller (main thread)
    for phase_idx, (label, rate_per_org, duration) in enumerate(PHASES[:MAX_PHASE + 1]):
        if stop_event.is_set():
            break

        _set("current_phase", label)
        _set("current_rate",  rate_per_org)

        print(f"  {bold(label):<12} {str(rate_per_org)+' logs/s':<14} {str(rate_per_org*len(ORGS))+' logs/s':<14} {duration}s")

        phase_start     = time.time()
        logs_at_start   = _get("total_logs_sent")

        deadline = time.time() + duration
        while time.time() < deadline and not stop_event.is_set():
            time.sleep(0.5)

        phase_dur  = round(time.time() - phase_start, 1)
        phase_logs = _get("total_logs_sent") - logs_at_start

        with _lock:
            _state["phase_log"].append({
                "phase":              label,
                "rate_per_org":       rate_per_org,
                "total_rate":         rate_per_org * len(ORGS),
                "duration_s":         phase_dur,
                "logs_sent":          phase_logs,
                "throughput_logs_s":  round(phase_logs / max(phase_dur, 1), 1),
            })

    stop_event.set()
    time.sleep(1.5)
    write_report()


if __name__ == "__main__":
    main()
