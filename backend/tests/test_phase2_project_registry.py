"""Regression tests for Phase 2 detector project registry state."""

from __future__ import annotations

import os
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "realtime_anomaly_detection" / "models"))

from project_manager import ProjectManager


def test_project_manager_ensure_project_and_ingest_stats(tmp_path: Path) -> None:
    manager = ProjectManager(storage_dir=tmp_path / "projects")

    project = manager.ensure_project(
        project_id="proj-123",
        project_name="Payments",
        warmup_threshold=250,
        metadata={"log_type": "nginx"},
    )
    assert project.project_id == "proj-123"
    assert project.project_name == "Payments"
    assert project.warmup_threshold == 250

    updated = manager.record_ingest_stats(
        "proj-123",
        total_records=100,
        parse_failures=4,
        baseline_eligible=96,
        observed_hours=[1, 2, 5, 9],
        data_quality_incident_open=False,
    )

    assert updated is not None
    assert updated.total_received_count == 100
    assert updated.parse_failure_count == 4
    assert updated.baseline_eligible_count == 96
    assert updated.observed_hours == [1, 2, 5, 9]
