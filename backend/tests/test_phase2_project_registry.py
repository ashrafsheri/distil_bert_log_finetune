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


def test_detector_skips_transport_and_signed_asset_paths(tmp_path: Path) -> None:
    pytest = __import__("pytest")
    pytest.importorskip("torch")
    sys.path.insert(0, str(REPO_ROOT / "realtime_anomaly_detection"))
    from models.multi_tenant_detector import MultiTenantDetector

    detector = MultiTenantDetector(
        base_model_dir=tmp_path / "artifacts",
        storage_dir=tmp_path / "runtime",
    )

    transport_policy = detector._classify_path_policy("/socket.io/?EIO=4&transport=polling&t=abc")
    signed_asset_policy = detector._classify_path_policy("/storage/v1/object/sign/admin-assets/banner.png?token=abc")
    normal_policy = detector._classify_path_policy("/communities/123/products")

    assert transport_policy is not None
    assert transport_policy["traffic_class"] == "transport_noise"
    assert transport_policy["baseline_eligible"] is False

    assert signed_asset_policy is not None
    assert signed_asset_policy["traffic_class"] == "signed_asset_access"
    assert signed_asset_policy["baseline_eligible"] is False

    assert normal_policy is None


def test_detector_canonicalizes_volatile_paths(tmp_path: Path) -> None:
    pytest = __import__("pytest")
    pytest.importorskip("torch")
    sys.path.insert(0, str(REPO_ROOT / "realtime_anomaly_detection"))
    from models.multi_tenant_detector import MultiTenantDetector

    detector = MultiTenantDetector(
        base_model_dir=tmp_path / "artifacts",
        storage_dir=tmp_path / "runtime",
    )

    canonical = detector._canonicalize_path(
        "/storage/v1/object/sign/admin-assets/banners/28537468-a3ec-4f88-9ad8-db49fc9cd0ff/file.png?token=verylongvalue&expires=123"
    )

    assert "<UUID>" in canonical
    assert "token=<FILTERED>" in canonical
    assert "expires=<FILTERED>" in canonical


def test_manifest_seeded_teacher_sequence_is_not_treated_as_unknown(tmp_path: Path) -> None:
    pytest = __import__("pytest")
    pytest.importorskip("torch")
    sys.path.insert(0, str(REPO_ROOT / "realtime_anomaly_detection"))
    from models.multi_tenant_detector import MultiTenantDetector

    detector = MultiTenantDetector(
        base_model_dir=tmp_path / "artifacts",
        storage_dir=tmp_path / "runtime",
        window_size=20,
    )
    detector.ensure_project(
        project_id="proj-seeded-chat",
        project_name="Seeded Chat",
        warmup_threshold=1000,
        metadata={
            "endpoint_manifest": {
                "service_name": "barterease-backend",
                "framework": "express",
                "endpoints": [
                    {
                        "method": "GET",
                        "path_template": "/chat/conversations",
                        "classification": "user_traffic",
                        "baseline_eligible": True,
                    }
                ],
            }
        },
    )
    project = detector.project_manager.get_project("proj-seeded-chat")
    assert project is not None

    result = None
    log_line = '135.125.182.34 - - [03/Apr/2026:02:53:33 +0000] "GET /chat/conversations HTTP/1.1" 200 512 "-" "okhttp/4.12.0"'
    for _ in range(3):
        result = detector.detect_single_log(project.api_key, log_line, session_id="chat-seq-1")

    assert result is not None
    assert result["endpoint_manifest_match"] is True
    assert result["unknown_template_ratio"] == 0.0
    assert result["transformer"]["status"] != "insufficient_signal"


def test_transformer_scoring_error_is_exposed_instead_of_flat_threshold(tmp_path: Path) -> None:
    pytest = __import__("pytest")
    pytest.importorskip("torch")
    sys.path.insert(0, str(REPO_ROOT / "realtime_anomaly_detection"))
    from models.multi_tenant_detector import MultiTenantDetector

    detector = MultiTenantDetector(
        base_model_dir=tmp_path / "artifacts",
        storage_dir=tmp_path / "runtime",
        window_size=20,
    )
    project_id, api_key = detector.create_project("Fallback Visibility", warmup_threshold=1000)
    detector.teacher._score_transformer_sequence = lambda sequence: (0.0, "forced_transformer_failure")

    result = None
    log_line = '135.125.182.34 - - [03/Apr/2026:02:53:33 +0000] "GET /chat/conversations HTTP/1.1" 200 512 "-" "okhttp/4.12.0"'
    for _ in range(3):
        result = detector.detect_single_log(api_key, log_line, session_id="error-seq-1")

    assert result is not None
    assert result["project_id"] == project_id
    assert result["transformer"]["status"] == "error"
    assert result["transformer"]["error"] == "forced_transformer_failure"
    assert result["transformer"]["score"] is None
