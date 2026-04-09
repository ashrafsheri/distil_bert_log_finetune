#!/usr/bin/env python3
"""
LogGuard Offline Model Performance Evaluator

Loads saved student/teacher model state from disk and reports performance
metrics without requiring the service to be running. Useful for:
  - Checking model state after a deploy
  - Auditing threshold calibration
  - Verifying online updates have been applied
  - Comparing student vs teacher scoring on sample data

Usage:
    python scripts/evaluate_model_performance.py --storage-dir ./data/detector
    python scripts/evaluate_model_performance.py --storage-dir ./data/detector --project <id>
    python scripts/evaluate_model_performance.py --storage-dir ./data/detector --compare-models
"""

import argparse
import json
import os
import pickle
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np


def load_student_state(state_path: Path) -> Optional[Dict]:
    if not state_path.exists():
        return None
    with open(state_path, "rb") as f:
        return pickle.load(f)


def load_teacher_state(state_path: Path) -> Optional[Dict]:
    if not state_path.exists():
        return None
    with open(state_path, "rb") as f:
        return pickle.load(f)


def _ago(iso_timestamp: Optional[str]) -> str:
    if not iso_timestamp:
        return "never"
    try:
        dt = datetime.fromisoformat(iso_timestamp)
        delta = datetime.now() - dt
        if delta.days > 0:
            return f"{delta.days}d ago"
        hours = delta.seconds // 3600
        if hours > 0:
            return f"{hours}h ago"
        return f"{delta.seconds // 60}m ago"
    except Exception:
        return str(iso_timestamp)[:19]


def print_header(title: str):
    print(f"\n{'=' * 68}")
    print(f"  {title}")
    print(f"{'=' * 68}")


def print_section(title: str):
    print(f"\n--- {title} ---")


def analyze_teacher(storage_dir: Path):
    """Analyze teacher model state from disk."""
    teacher_dir = storage_dir / "teacher"
    state_path = teacher_dir / "teacher_state.pkl"
    model_path = teacher_dir / "teacher_transformer.pt"
    iso_path = teacher_dir / "teacher_iso_forest.pkl"

    print_header("TEACHER MODEL")

    state = load_teacher_state(state_path)
    if state is None:
        print("  No teacher state found at", state_path)
        return

    print_section("State")
    print(f"  Vocab size:              {state.get('vocab_size', '?')}")
    print(f"  Templates:               {len(state.get('id_to_template', []))}")
    print(f"  Transformer threshold:   {state.get('transformer_threshold', '?')}")
    print(f"  ISO threshold:           {state.get('iso_threshold', '?')}")
    print(f"  Total logs processed:    {state.get('total_logs_processed', 0):,}")
    print(f"  Saved at:                {_ago(state.get('saved_at'))}")

    print_section("Artifacts on Disk")
    print(f"  Transformer weights:     {'present' if model_path.exists() else 'MISSING'}")
    print(f"  Isolation forest:        {'present' if iso_path.exists() else 'MISSING'}")
    print(f"  State file:              {'present' if state_path.exists() else 'MISSING'}")
    calibrator_path = teacher_dir / "calibrator.pkl"
    print(f"  Calibrator:              {'present' if calibrator_path.exists() else 'not fitted'}")

    # Template distribution
    template_to_id = state.get("template_to_id", {})
    if template_to_id:
        print_section("Template Vocabulary Sample (top 10)")
        sorted_templates = sorted(template_to_id.items(), key=lambda x: x[1])[:10]
        for t, tid in sorted_templates:
            display = t[:60] + "..." if len(t) > 60 else t
            print(f"  [{tid:>4}] {display}")
        print(f"  ... ({len(template_to_id)} total templates)")


def analyze_student(project_dir: Path, project_id: str):
    """Analyze a single student model from disk."""
    state_path = project_dir / "student_state.pkl"
    model_path = project_dir / "student_transformer.pt"
    iso_path = project_dir / "student_iso_forest.pkl"

    state = load_student_state(state_path)
    if state is None:
        print(f"  No student state found for project {project_id}")
        return

    print_header(f"STUDENT: {project_id[:16]}")

    print_section("Model State")
    print(f"  Vocab size:              {state.get('vocab_size', '?')}")
    print(f"  Templates:               {len(state.get('id_to_template', []))}")
    print(f"  Vocab frozen:            {state.get('vocab_frozen', '?')}")
    print(f"  Transformer threshold:   {state.get('transformer_threshold', '?')}")
    print(f"  ISO threshold:           {state.get('iso_threshold', '?')}")
    print(f"  Logs processed:          {state.get('logs_processed', 0):,}")
    print(f"  Last trained:            {_ago(state.get('last_trained_at'))}")
    print(f"  Saved at:                {_ago(state.get('saved_at'))}")

    print_section("Online Learning")
    print(f"  Online updates:          {state.get('online_update_count', 0)}")
    print(f"  Logs since last update:  {state.get('logs_since_last_update', 0):,}")
    print(f"  Last online update:      {_ago(state.get('last_online_update_at'))}")

    print_section("Reservoirs (saved snapshot)")
    clean = state.get("clean_normal_reservoir", [])
    suspicious = state.get("suspicious_reservoir", [])
    malicious = state.get("confirmed_malicious_reservoir", [])
    print(f"  Clean normal:            {len(clean)}")
    print(f"  Suspicious:              {len(suspicious)}")
    print(f"  Confirmed malicious:     {len(malicious)}")

    # Reservoir sequence length distribution
    if clean:
        lengths = [len(s) for s in clean]
        print(f"  Clean seq len:           min={min(lengths)}, max={max(lengths)}, avg={np.mean(lengths):.1f}")

    print_section("Artifacts on Disk")
    print(f"  Transformer weights:     {'present' if model_path.exists() else 'MISSING'}")
    print(f"  Isolation forest:        {'present' if iso_path.exists() else 'MISSING'}")
    print(f"  State file:              {'present' if state_path.exists() else 'MISSING'}")
    calibrator_path = project_dir / "calibrator.pkl"
    print(f"  Calibrator:              {'present' if calibrator_path.exists() else 'not fitted'}")

    # Template distribution
    template_counts = state.get("template_counts", {})
    if template_counts:
        print_section("Top Templates by Frequency")
        sorted_templates = sorted(template_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        total = sum(template_counts.values())
        for t, count in sorted_templates:
            pct = 100 * count / total if total else 0
            display = t[:50] + "..." if len(t) > 50 else t
            print(f"  {count:>8,} ({pct:>5.1f}%)  {display}")


def list_all_students(storage_dir: Path):
    """Discover and summarize all student models."""
    projects_dir = storage_dir / "projects"
    if not projects_dir.exists():
        print("  No projects directory found")
        return

    print_header("ALL STUDENT MODELS")

    students = []
    for entry in sorted(projects_dir.iterdir()):
        if not entry.is_dir():
            continue
        state_path = entry / "student_state.pkl"
        if state_path.exists():
            state = load_student_state(state_path)
            if state:
                students.append((entry.name, state, entry))

    if not students:
        print("  No trained student models found")
        return

    print(
        f"  {'Project ID':<18} {'Logs':>10} {'Templates':>10} "
        f"{'Updates':>8} {'Since':>8} {'Threshold':>10} {'Last Update':<15}"
    )
    print(
        f"  {'-'*18} {'-'*10} {'-'*10} "
        f"{'-'*8} {'-'*8} {'-'*10} {'-'*15}"
    )

    for pid, state, _ in students:
        logs = state.get("logs_processed", 0)
        templates = len(state.get("id_to_template", []))
        updates = state.get("online_update_count", 0)
        since = state.get("logs_since_last_update", 0)
        threshold = state.get("transformer_threshold", 0)
        last_update = _ago(state.get("last_online_update_at"))
        print(
            f"  {pid[:18]:<18} {logs:>10,} {templates:>10} "
            f"{updates:>8} {since:>8,} {threshold:>10.4f} {last_update:<15}"
        )

    print(f"\n  Total students: {len(students)}")

    # Flag students that may need attention
    stale = [
        (pid, s) for pid, s, _ in students
        if s.get("logs_since_last_update", 0) > 5000
        and s.get("online_update_count", 0) == 0
    ]
    if stale:
        print_section("ATTENTION: Students with no online updates and high log counts")
        for pid, s in stale:
            print(f"  {pid[:18]}: {s.get('logs_processed', 0):,} logs, 0 online updates")


def compare_models(storage_dir: Path):
    """Compare teacher vs student thresholds and vocab coverage."""
    print_header("TEACHER vs STUDENT COMPARISON")

    teacher_state_path = storage_dir / "teacher" / "teacher_state.pkl"
    teacher_state = load_teacher_state(teacher_state_path)
    if not teacher_state:
        print("  Teacher state not found")
        return

    teacher_templates = set(teacher_state.get("template_to_id", {}).keys())
    teacher_threshold = teacher_state.get("transformer_threshold", 0)

    print(f"  Teacher: {len(teacher_templates)} templates, threshold={teacher_threshold:.4f}")
    print()

    projects_dir = storage_dir / "projects"
    if not projects_dir.exists():
        return

    print(
        f"  {'Student':<18} {'Templates':>10} {'Shared':>8} {'Student-Only':>13} "
        f"{'Threshold':>10} {'Delta':>8}"
    )
    print(
        f"  {'-'*18} {'-'*10} {'-'*8} {'-'*13} "
        f"{'-'*10} {'-'*8}"
    )

    for entry in sorted(projects_dir.iterdir()):
        state_path = entry / "student_state.pkl"
        if not state_path.exists():
            continue
        state = load_student_state(state_path)
        if not state:
            continue

        student_templates = set(state.get("template_to_id", {}).keys())
        shared = len(teacher_templates & student_templates)
        student_only = len(student_templates - teacher_templates)
        s_threshold = state.get("transformer_threshold", 0)
        delta = s_threshold - teacher_threshold

        print(
            f"  {entry.name[:18]:<18} {len(student_templates):>10} {shared:>8} "
            f"{student_only:>13} {s_threshold:>10.4f} {delta:>+8.4f}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="LogGuard Offline Model Performance Evaluator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--storage-dir", "-s",
        default=os.getenv("DETECTOR_STORAGE_DIR", "./data/detector"),
        help="Path to detector storage directory (default: ./data/detector or DETECTOR_STORAGE_DIR)",
    )
    parser.add_argument(
        "--project", "-p",
        help="Show detailed analysis for a specific project ID",
    )
    parser.add_argument(
        "--compare-models", "-c",
        action="store_true",
        help="Compare teacher vs student template coverage and thresholds",
    )
    args = parser.parse_args()

    storage_dir = Path(args.storage_dir)
    if not storage_dir.exists():
        print(f"ERROR: Storage directory not found: {storage_dir}")
        print("       Use --storage-dir to specify the correct path.")
        sys.exit(1)

    if args.project:
        project_dir = storage_dir / "projects" / args.project
        if not project_dir.exists():
            print(f"ERROR: Project directory not found: {project_dir}")
            sys.exit(1)
        analyze_student(project_dir, args.project)
        return

    if args.compare_models:
        compare_models(storage_dir)
        return

    # Full analysis
    analyze_teacher(storage_dir)
    list_all_students(storage_dir)
    compare_models(storage_dir)
    print()


if __name__ == "__main__":
    main()
