"""Regression tests for Phase 2 detector project registry state."""

from __future__ import annotations

import os
import sys
from collections import Counter
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


def test_project_manager_tracks_recent_parse_failure_window(tmp_path: Path) -> None:
    previous_window = os.environ.get("MULTI_TENANT_PARSE_FAILURE_WINDOW")
    os.environ["MULTI_TENANT_PARSE_FAILURE_WINDOW"] = "100"
    try:
        manager = ProjectManager(storage_dir=tmp_path / "projects")
        manager.ensure_project(
            project_id="proj-window",
            project_name="Recent Window",
            warmup_threshold=1000,
        )

        updated = manager.record_ingest_stats("proj-window", total_records=100, parse_failures=20)
        assert updated is not None
        assert updated.recent_total_received_count == 100
        assert updated.recent_parse_failure_count == 20

        updated = manager.record_ingest_stats("proj-window", total_records=50, parse_failures=0)
        assert updated is not None
        assert updated.total_received_count == 150
        assert updated.parse_failure_count == 20
        assert updated.recent_total_received_count == 100
        assert updated.recent_parse_failure_count == 10
    finally:
        if previous_window is None:
            os.environ.pop("MULTI_TENANT_PARSE_FAILURE_WINDOW", None)
        else:
            os.environ["MULTI_TENANT_PARSE_FAILURE_WINDOW"] = previous_window

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


def test_recent_parse_failure_rate_can_clear_student_blocker(tmp_path: Path) -> None:
    pytest = __import__("pytest")
    pytest.importorskip("torch")
    sys.path.insert(0, str(REPO_ROOT / "realtime_anomaly_detection"))
    import numpy as np
    from models.multi_tenant_detector import MultiTenantDetector
    from models.student_model import StudentModel

    detector = MultiTenantDetector(
        base_model_dir=tmp_path / "artifacts",
        storage_dir=tmp_path / "runtime",
    )
    detector.ensure_project(
        project_id="proj-recent-quality",
        project_name="Recent Quality",
        warmup_threshold=1000,
        metadata={"traffic_profile": "low_traffic"},
    )
    project = detector.project_manager.get_project("proj-recent-quality")
    assert project is not None
    project.clean_baseline_count = 1000
    project.current_log_count = 1000
    project.observed_hours = [1, 2, 3, 4]
    project.distinct_template_count = 20
    project.total_received_count = 5000
    project.parse_failure_count = 500
    project.recent_total_received_count = 500
    project.recent_parse_failure_count = 0

    student = StudentModel(
        project_id=project.project_id,
        storage_dir=detector.project_manager.get_project_storage_path(project.project_id),
        window_size=detector.window_size,
        device=detector.device,
    )
    student.training_sequences = [[1, 2, 3, 4, 5] for _ in range(35)]
    student.training_features = [np.array([1.0, 2.0, 3.0]) for _ in range(55)]
    student.template_counts = Counter({"GET /users/me": 20, "GET /products/user/:id": 15})
    detector.students[project.project_id] = student

    blockers = detector._student_training_blockers(project)

    assert "parse_failure_rate_too_high" not in blockers


def test_active_trained_student_does_not_report_transient_training_buffer_blockers(tmp_path: Path) -> None:
    pytest = __import__("pytest")
    pytest.importorskip("torch")
    sys.path.insert(0, str(REPO_ROOT / "realtime_anomaly_detection"))
    from models.multi_tenant_detector import MultiTenantDetector
    from models.project_manager import ProjectPhase

    detector = MultiTenantDetector(
        base_model_dir=tmp_path / "artifacts",
        storage_dir=tmp_path / "runtime",
    )
    detector.ensure_project(
        project_id="proj-active-student",
        project_name="Active Student",
        warmup_threshold=200,
        metadata={"traffic_profile": "low_traffic"},
    )
    project = detector.project_manager.get_project("proj-active-student")
    assert project is not None
    project.phase = ProjectPhase.ACTIVE.value
    project.clean_baseline_count = 1000
    project.current_log_count = 1000
    project.observed_hours = [1, 2, 3, 4]
    project.distinct_template_count = 20

    class TrainedStudent:
        is_trained = True
        training_sequences = []
        training_features = []
        template_counts = Counter({"GET /users/me": 50})

    detector.students[project.project_id] = TrainedStudent()

    blockers = detector._student_training_blockers(project)

    assert "insufficient_training_sequences" not in blockers
    assert "insufficient_if_features" not in blockers


def test_warmup_can_continue_collecting_if_features_after_threshold(tmp_path: Path) -> None:
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
        project_id="proj-feature-recovery",
        project_name="Feature Recovery",
        warmup_threshold=10,
        metadata={"traffic_profile": "low_traffic"},
    )
    project = detector.project_manager.get_project("proj-feature-recovery")
    assert project is not None
    project.clean_baseline_count = 12
    project.current_log_count = 12

    log_line = '135.125.182.34 - - [03/Apr/2026:02:53:33 +0000] "GET /users/me HTTP/1.1" 200 512 "-" "okhttp/4.12.0"'
    detector.detect_single_log(project.api_key, log_line, session_id="feature-recovery-1")

    student = detector.students.get(project.project_id)
    assert student is not None
    assert len(student.training_features) == 1


def test_final_decision_does_not_flag_when_all_behavioral_components_are_normal(tmp_path: Path) -> None:
    pytest = __import__("pytest")
    pytest.importorskip("torch")
    sys.path.insert(0, str(REPO_ROOT / "realtime_anomaly_detection"))
    from models.multi_tenant_detector import MultiTenantDetector

    detector = MultiTenantDetector(
        base_model_dir=tmp_path / "artifacts",
        storage_dir=tmp_path / "runtime",
    )
    detector.ensure_project(
        project_id="proj-no-fp",
        project_name="No False Positive",
        warmup_threshold=1000,
        metadata={"traffic_profile": "low_traffic"},
    )
    project = detector.project_manager.get_project("proj-no-fp")
    assert project is not None
    project.calibration_threshold = 0.45

    decision = detector._compose_final_decision(
        project=project,
        traffic_class="user_traffic",
        baseline_eligible=True,
        raw_result={
            "is_anomaly": False,
            "rule_based": {"is_attack": False, "confidence": 0.0},
            "isolation_forest": {"status": "active", "is_anomaly": 0, "score": 0.5, "threshold": 1.0},
            "transformer": {"status": "active", "is_anomaly": 0, "score": 2.485, "threshold": 2.573},
            "anomaly_score": 0.0,
            "unknown_template_ratio": 0.0,
        },
    )

    assert decision["final_decision"] == "not_flagged"
    assert decision["decision_reason"] == "behavioral_normal"
    assert decision["is_anomaly"] is False


def test_final_decision_flags_when_behavioral_component_is_active_anomaly(tmp_path: Path) -> None:
    pytest = __import__("pytest")
    pytest.importorskip("torch")
    sys.path.insert(0, str(REPO_ROOT / "realtime_anomaly_detection"))
    from models.multi_tenant_detector import MultiTenantDetector

    detector = MultiTenantDetector(
        base_model_dir=tmp_path / "artifacts",
        storage_dir=tmp_path / "runtime",
    )
    detector.ensure_project(
        project_id="proj-real-anomaly",
        project_name="Real Anomaly",
        warmup_threshold=1000,
        metadata={"traffic_profile": "low_traffic"},
    )
    project = detector.project_manager.get_project("proj-real-anomaly")
    assert project is not None
    project.calibration_threshold = 0.45

    decision = detector._compose_final_decision(
        project=project,
        traffic_class="user_traffic",
        baseline_eligible=True,
        raw_result={
            "is_anomaly": True,
            "rule_based": {"is_attack": False, "confidence": 0.0},
            "isolation_forest": {"status": "active", "is_anomaly": 1, "score": 1.5, "threshold": 1.0},
            "transformer": {"status": "active", "is_anomaly": 0, "score": 2.0, "threshold": 2.573},
            "anomaly_score": 0.6,
            "unknown_template_ratio": 0.0,
        },
    )

    assert decision["final_decision"] == "threat_detected"
    assert decision["decision_reason"] == "behavioral_anomaly"
    assert decision["is_anomaly"] is True


def test_detect_single_does_not_reflag_clean_component_outputs_after_calibration(tmp_path: Path) -> None:
    pytest = __import__("pytest")
    pytest.importorskip("torch")
    sys.path.insert(0, str(REPO_ROOT / "realtime_anomaly_detection"))
    from models.multi_tenant_detector import MultiTenantDetector
    from models.project_manager import ProjectPhase

    detector = MultiTenantDetector(
        base_model_dir=tmp_path / "artifacts",
        storage_dir=tmp_path / "runtime",
    )
    project_id, api_key = detector.create_project("No Reflag", warmup_threshold=1000)
    project = detector.project_manager.get_project(project_id)
    assert project is not None
    project.phase = ProjectPhase.ACTIVE.value
    project.calibration_threshold = 0.45
    detector.students[project_id] = object()

    detector._detect_with_student = lambda *args, **kwargs: {
        "is_anomaly": False,
        "anomaly_score": 0.0,
        "model_type": "student",
        "rule_based": {"is_attack": False, "confidence": 0.0},
        "isolation_forest": {"status": "active", "is_anomaly": 0, "score": 0.603, "threshold": 0.6},
        "transformer": {"status": "active", "is_anomaly": 0, "score": 2.378, "threshold": 2.573},
        "ensemble": {"score": 0.0},
        "unknown_template_ratio": 0.0,
    }

    log_line = '139.135.32.142 - - [03/Apr/2026:09:03:16 +0000] "GET /communities/af7c7d04-f89d-48ed-83f1-5ad47ede17d3/members?limit=200&offset=0 HTTP/2.0" 304 0 "-" "okhttp/4.12.0"'
    result = detector.detect_single_log(api_key, log_line, session_id="no-reflag-1")

    assert result["final_decision"] == "not_flagged"
    assert result["decision_reason"] == "behavioral_normal"
    assert result["is_anomaly"] is False


def test_teacher_escalation_remaps_entire_session_sequence(tmp_path: Path) -> None:
    pytest = __import__("pytest")
    pytest.importorskip("torch")
    import numpy as np

    sys.path.insert(0, str(REPO_ROOT / "realtime_anomaly_detection"))
    from models.multi_tenant_detector import MultiTenantDetector
    from models.project_manager import ProjectPhase

    detector = MultiTenantDetector(
        base_model_dir=tmp_path / "artifacts",
        storage_dir=tmp_path / "runtime",
        window_size=20,
    )
    detector.escalation_max_rate = 1.1
    project_id, _api_key = detector.create_project("Escalation Mapping", warmup_threshold=1000)
    project = detector.project_manager.get_project(project_id)
    assert project is not None
    project.phase = ProjectPhase.ACTIVE.value

    class FakeStudent:
        def __init__(self) -> None:
            self.sequences = []

        def get_template_id(self, normalized_template: str) -> int:
            return {"/api/users": 101, "/api/orders": 102}[normalized_template]

        def detect(self, log_data, sequence, session_stats, features, known_template_mask=None):
            self.sequences.append(list(sequence))
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "ensemble": {"active_models": 0},
                "transformer": {"status": "insufficient_context"},
                "unknown_template_ratio": 0.0,
            }

    class FakeTeacher:
        def __init__(self) -> None:
            self.sequences = []

        def get_template_id(self, normalized_template: str) -> int:
            return {"/api/users": 1, "/api/orders": 2}[normalized_template]

        def detect(self, log_data, sequence, session_stats, features, known_template_mask=None):
            self.sequences.append(list(sequence))
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "ensemble": {"active_models": 2},
                "transformer": {"status": "active", "score": 0.75, "threshold": 1.5},
                "unknown_template_ratio": 0.0,
            }

    detector.students[project_id] = FakeStudent()
    detector.teacher = FakeTeacher()

    features = np.zeros(7, dtype=float)

    session, session_stats = detector._get_or_create_session(
        project_id,
        "sess-1",
        {"path": "/api/users", "status": 200},
    )
    detector._detect_with_student(
        project_id,
        {"path": "/api/users", "status": 200},
        "/api/users",
        session,
        session_stats,
        features,
    )

    session, session_stats = detector._get_or_create_session(
        project_id,
        "sess-1",
        {"path": "/api/orders", "status": 200},
    )
    detector._detect_with_student(
        project_id,
        {"path": "/api/orders", "status": 200},
        "/api/orders",
        session,
        session_stats,
        features,
    )

    assert list(session["normalized_templates"]) == ["/api/users", "/api/orders"]
    assert detector.students[project_id].sequences[-1] == [101, 102]
    assert detector.teacher.sequences[-1] == [1, 2]
