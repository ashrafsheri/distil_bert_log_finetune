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
        clean_baseline_count=96,
        dirty_excluded_count=2,
        probe_skipped_count=3,
        distinct_template_count=12,
        observed_hours=[1, 2, 5, 9],
        data_quality_incident_open=False,
        traffic_profile="low_traffic",
    )

    assert updated is not None
    assert updated.total_received_count == 100
    assert updated.parse_failure_count == 4
    assert updated.baseline_eligible_count == 96
    assert updated.clean_baseline_count == 96
    assert updated.dirty_excluded_count == 2
    assert updated.probe_skipped_count == 3
    assert updated.distinct_template_count == 12
    assert updated.traffic_profile == "low_traffic"
    assert updated.observed_hours == [1, 2, 5, 9]

def test_project_manager_persists_low_traffic_threshold_metadata(tmp_path: Path) -> None:
    manager = ProjectManager(storage_dir=tmp_path / "projects")

    project = manager.ensure_project(
        project_id="proj-low",
        project_name="Quiet Service",
        warmup_threshold=1000,
        metadata={"traffic_profile": "low_traffic"},
    )
    assert project.traffic_profile == "low_traffic"
    assert project.warmup_threshold == 1000

    updated = manager.update_threshold_metadata(
        "proj-low",
        threshold=0.58,
        threshold_source="holdout_calibration",
        calibration_sample_count=40,
        score_normalization_version="hybrid-v1",
        feature_schema_version="access-log-v2",
    )

    assert updated is not None
    assert updated.threshold_source == "holdout_calibration"
    assert updated.calibration_sample_count == 40
    assert updated.score_normalization_version == "hybrid-v1"


def test_detector_endpoint_manifest_matches_known_routes_and_internal_probes(tmp_path: Path) -> None:
    pytest = __import__("pytest")
    pytest.importorskip("torch")
    sys.path.insert(0, str(REPO_ROOT / "realtime_anomaly_detection"))
    from models.multi_tenant_detector import MultiTenantDetector

    detector = MultiTenantDetector(
        base_model_dir=tmp_path / "artifacts",
        storage_dir=tmp_path / "runtime",
    )
    detector.ensure_project(
        project_id="proj-manifest",
        project_name="Manifest Seeded",
        warmup_threshold=1000,
        metadata={
            "endpoint_manifest": {
                "service_name": "billing-api",
                "framework": "fastapi",
                "endpoints": [
                    {"method": "GET", "path_template": "/health", "classification": "internal_probe", "baseline_eligible": False},
                    {"method": "GET", "path_template": "/api/v1/orders/{order_id}", "classification": "user_traffic", "baseline_eligible": True},
                ],
            }
        },
    )
    project = detector.project_manager.get_project("proj-manifest")
    assert project is not None

    manifest_match = detector._match_endpoint_manifest(project, "GET", "/api/v1/orders/123")
    assert manifest_match is not None
    assert manifest_match["path_template"] == "/api/v1/orders/{order_id}"
    assert manifest_match["classification"] == "user_traffic"

    probe_match = detector._match_endpoint_manifest(project, "GET", "/health")
    assert probe_match is not None
    assert probe_match["classification"] == "internal_probe"
