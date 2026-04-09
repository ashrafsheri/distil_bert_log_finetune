#!/usr/bin/env python3
"""
LogGuard Model Health & Performance Dashboard

CLI tool to check the health and performance of the anomaly detection service.
Queries the running service and displays per-project model stats, online update
status, escalation rates, reservoir health, and detector metrics.

Usage:
    python scripts/check_model_health.py                  # full dashboard
    python scripts/check_model_health.py --project <id>   # single project detail
    python scripts/check_model_health.py --metrics         # runtime metrics only
    python scripts/check_model_health.py --json            # machine-readable output

Requires the anomaly detection service to be running on ANOMALY_SERVICE_URL
(default: http://localhost:8001).
"""

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError:
    print("ERROR: 'requests' package required. Install with: pip install requests")
    sys.exit(1)


BASE_URL = os.getenv("ANOMALY_SERVICE_URL", "http://localhost:8001")
ADMIN_KEY = os.getenv("ANOMALY_ADMIN_KEY", "")


def _get(path: str, params: Optional[Dict] = None) -> Any:
    url = f"{BASE_URL}{path}"
    if ADMIN_KEY:
        params = params or {}
        params["admin_key"] = ADMIN_KEY
    try:
        resp = requests.get(url, params=params, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.ConnectionError:
        print(f"ERROR: Cannot connect to anomaly service at {BASE_URL}")
        print("       Is the service running? Set ANOMALY_SERVICE_URL if using a different host.")
        sys.exit(1)
    except requests.HTTPError as e:
        print(f"ERROR: {e}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

def _phase_indicator(phase: str) -> str:
    indicators = {
        "warmup": "[WARMUP]",
        "training": "[TRAINING]",
        "active": "[ACTIVE]",
        "suspended": "[SUSPENDED]",
        "error": "[ERROR]",
    }
    return indicators.get(phase, f"[{phase.upper()}]")


def _pct(value: float) -> str:
    return f"{value:.1f}%"


def _num(value: int) -> str:
    return f"{value:,}"


def _ago(iso_timestamp: Optional[str]) -> str:
    if not iso_timestamp:
        return "never"
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
        now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
        delta = now - dt
        if delta.days > 0:
            return f"{delta.days}d ago"
        hours = delta.seconds // 3600
        if hours > 0:
            return f"{hours}h ago"
        minutes = delta.seconds // 60
        return f"{minutes}m ago"
    except Exception:
        return iso_timestamp[:19]


# ---------------------------------------------------------------------------
# Display functions
# ---------------------------------------------------------------------------

def print_header(title: str):
    width = 72
    print(f"\n{'=' * width}")
    print(f"  {title}")
    print(f"{'=' * width}")


def print_section(title: str):
    print(f"\n--- {title} ---")


def display_service_health(health: Dict):
    print_header("SERVICE HEALTH")
    print(f"  Status:      {health.get('status', 'unknown')}")
    print(f"  Teacher:     {'loaded' if health.get('teacher_loaded') else 'NOT LOADED'}")
    print(f"  Projects:    {health.get('active_projects', '?')}")
    print(f"  Students:    {health.get('loaded_students', '?')}")
    uptime = health.get('uptime_seconds')
    if uptime:
        hours = int(uptime) // 3600
        mins = (int(uptime) % 3600) // 60
        print(f"  Uptime:      {hours}h {mins}m")


def display_runtime_metrics(metrics: Dict):
    print_header("RUNTIME METRICS")

    counters = metrics.get("counters", {})
    if counters:
        print_section("Counters")
        for name in sorted(counters):
            print(f"  {name:<45} {_num(counters[name])}")

    observations = metrics.get("observations", {})
    if observations:
        print_section("Observations (latency, sizes)")
        print(f"  {'metric':<35} {'count':>7} {'p50':>8} {'p95':>8} {'p99':>8} {'avg':>8}")
        print(f"  {'-'*35} {'-'*7} {'-'*8} {'-'*8} {'-'*8} {'-'*8}")
        for name in sorted(observations):
            o = observations[name]
            print(
                f"  {name:<35} {o['count']:>7} {o['p50']:>8.4f} "
                f"{o['p95']:>8.4f} {o['p99']:>8.4f} {o['avg']:>8.4f}"
            )

    # Highlight escalation stats
    esc_total = counters.get("teacher_escalations_total", 0)
    det_total = counters.get("detections_total", 0) + counters.get("structured_detections_total", 0)
    updates_triggered = counters.get("online_updates_triggered", 0)
    if det_total > 0:
        print_section("Key Rates")
        print(f"  Teacher escalation rate:   {esc_total}/{det_total} = {_pct(100 * esc_total / det_total)}")
        print(f"  Online updates triggered:  {updates_triggered}")


def display_projects_summary(projects: List[Dict]):
    print_header("PROJECT SUMMARY")

    if not projects:
        print("  No projects found.")
        return

    print(
        f"  {'Project':<20} {'Phase':<12} {'Logs':>10} {'Warmup':>8} "
        f"{'Student':>8} {'Profile':<12} {'Last Activity'}"
    )
    print(f"  {'-'*20} {'-'*12} {'-'*10} {'-'*8} {'-'*8} {'-'*12} {'-'*15}")

    for p in projects:
        name = (p.get("project_name") or p.get("project_id", "?"))[:20]
        phase = _phase_indicator(p.get("phase", "?"))
        logs = _num(p.get("log_count", 0))
        warmup = _pct(p.get("warmup_progress", 0))
        student = "yes" if p.get("has_student_model") else "no"
        profile = p.get("traffic_profile", "standard")
        last = _ago(p.get("last_activity"))
        print(f"  {name:<20} {phase:<12} {logs:>10} {warmup:>8} {student:>8} {profile:<12} {last}")


def display_project_detail(status: Dict):
    pid = status.get("project_id", "?")
    print_header(f"PROJECT: {status.get('project_name', pid)}")

    # Basic info
    print_section("Overview")
    print(f"  ID:              {pid}")
    print(f"  Phase:           {_phase_indicator(status.get('phase', '?'))}")
    print(f"  Traffic Profile: {status.get('traffic_profile', 'standard')}")
    print(f"  Total Logs:      {_num(status.get('log_count', 0))}")
    print(f"  Warmup Progress: {_pct(status.get('warmup_progress', 0))}")
    print(f"  Warmup Target:   {_num(status.get('warmup_threshold', 0))}")
    print(f"  Created:         {_ago(status.get('created_at'))}")
    print(f"  Last Activity:   {_ago(status.get('last_activity'))}")

    # Baseline stats
    print_section("Baseline & Data Quality")
    print(f"  Baseline eligible:     {_num(status.get('baseline_eligible_count', 0))}")
    print(f"  Clean baseline:        {_num(status.get('clean_baseline_count', 0))}")
    print(f"  Dirty excluded:        {_num(status.get('dirty_excluded_count', 0))}")
    print(f"  Probes skipped:        {_num(status.get('probe_skipped_count', 0))}")
    print(f"  Parse failure rate:    {_pct(100 * status.get('parse_failure_rate', 0))}")
    print(f"  Distinct templates:    {_num(status.get('distinct_template_count', 0))}")
    print(f"  Observed hours:        {status.get('observed_hours', 0):.1f}")

    # Calibration
    print_section("Threshold & Calibration")
    print(f"  Threshold:             {status.get('calibration_threshold', '?')}")
    print(f"  Source:                {status.get('threshold_source', '?')}")
    print(f"  Fitted at:             {_ago(status.get('threshold_fitted_at'))}")
    print(f"  Calibration samples:   {_num(status.get('calibration_sample_count', 0))}")
    if status.get("low_sample_calibration"):
        print(f"  WARNING: Low-sample calibration active — threshold may be unstable")

    # Reservoirs
    res = status.get("reservoir_counts", {})
    print_section("Reservoirs")
    print(f"  Clean normal:          {_num(res.get('clean_normal', 0))}")
    print(f"  Suspicious:            {_num(res.get('suspicious', 0))}")
    print(f"  Confirmed malicious:   {_num(res.get('confirmed_malicious', 0))}")

    # Student model detail
    si = status.get("student_info")
    if si:
        print_section("Student Model")
        print(f"  Trained:               {'yes' if si.get('is_trained') else 'no'}")
        print(f"  Vocab size:            {_num(si.get('vocab_size') or 0)}")
        print(f"  Templates:             {_num(si.get('num_templates', 0))}")
        print(f"  Transformer threshold: {si.get('transformer_threshold', '?')}")
        print(f"  Logs processed:        {_num(si.get('logs_processed', 0))}")
        print(f"  Last trained:          {_ago(si.get('last_trained_at'))}")

        # Online update stats
        print_section("Online Learning")
        print(f"  Update count:          {si.get('online_update_count', 0)}")
        print(f"  Logs since update:     {_num(si.get('logs_since_last_update', 0))}")
        print(f"  Last update:           {_ago(si.get('last_online_update_at'))}")
        training_pending = si.get('training_sequences_pending', 0)
        if training_pending > 0:
            print(f"  Training sequences pending: {_num(training_pending)}")
    else:
        print_section("Student Model")
        print(f"  No student model loaded")

    # Training blockers
    blockers = status.get("student_training_blockers")
    if blockers:
        print_section("Training Blockers")
        for blocker in blockers:
            print(f"  - {blocker}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="LogGuard Model Health & Performance Dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--project", "-p",
        help="Show detailed status for a specific project ID",
    )
    parser.add_argument(
        "--metrics", "-m",
        action="store_true",
        help="Show runtime metrics only",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of formatted text",
    )
    parser.add_argument(
        "--url",
        default=None,
        help="Override anomaly service URL (default: ANOMALY_SERVICE_URL or localhost:8001)",
    )
    args = parser.parse_args()

    global BASE_URL
    if args.url:
        BASE_URL = args.url

    # JSON mode: dump everything and exit
    if args.json:
        output = {}
        output["health"] = _get("/health")
        output["metrics"] = _get("/metrics")
        if args.project:
            output["project"] = _get(f"/internal/projects/{args.project}/status")
        else:
            output["projects"] = _get("/projects")
        print(json.dumps(output, indent=2, default=str))
        return

    # Single project detail
    if args.project:
        status = _get(f"/internal/projects/{args.project}/status")
        display_project_detail(status)
        return

    # Metrics only
    if args.metrics:
        metrics = _get("/metrics")
        display_runtime_metrics(metrics)
        return

    # Full dashboard
    health = _get("/health")
    display_service_health(health)

    projects = _get("/projects")
    display_projects_summary(projects)

    metrics = _get("/metrics")
    display_runtime_metrics(metrics)

    # Show detailed view for active projects with students
    active_projects = [p for p in projects if p.get("has_student_model")]
    if active_projects:
        print_header("ACTIVE STUDENT MODELS — ONLINE LEARNING STATUS")
        print(
            f"  {'Project':<20} {'Updates':>8} {'Since Last':>11} "
            f"{'Reservoir':>10} {'Last Update':<15}"
        )
        print(f"  {'-'*20} {'-'*8} {'-'*11} {'-'*10} {'-'*15}")
        for p in active_projects:
            pid = p.get("project_id", "?")
            status = _get(f"/internal/projects/{pid}/status")
            si = status.get("student_info", {})
            name = (p.get("project_name") or pid)[:20]
            updates = si.get("online_update_count", 0)
            since = _num(si.get("logs_since_last_update", 0))
            reservoir = _num(si.get("clean_normal_reservoir_count", 0))
            last = _ago(si.get("last_online_update_at"))
            print(f"  {name:<20} {updates:>8} {since:>11} {reservoir:>10} {last:<15}")

    print()


if __name__ == "__main__":
    main()
