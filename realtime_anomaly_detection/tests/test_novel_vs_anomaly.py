"""Tests that unknown templates produce novel_score, not auto-anomaly."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from models.teacher_model import TeacherModel


@pytest.fixture
def teacher(tmp_path):
    model_dir = tmp_path / "base"
    model_dir.mkdir()
    storage_dir = tmp_path / "teacher"
    t = TeacherModel(
        model_dir=model_dir,
        storage_dir=storage_dir,
        window_size=10,
        device="cpu",
        auto_load=True,
    )
    return t


class TestNovelVsAnomaly:
    def test_high_unknown_ratio_emits_novel_score(self, teacher):
        """When unknown_template_ratio >= 0.5, result must have novel_score."""
        sequence = [teacher.unknown_id] * 10
        log_data = {"path": "/", "method": "GET", "status": 200}
        session_stats = {"request_count": 10, "error_count": 0, "error_rate": 0.0, "unique_paths": 1}

        result = teacher.detect(log_data, sequence, session_stats)
        transformer = result["transformer"]

        assert transformer["status"] == "novel_penalty"
        assert "novel_score" in transformer
        assert transformer.get("malicious_score", 0.0) == 0.0
        # is_anomaly on the transformer vote should be 0 (novel != malicious)
        assert transformer["is_anomaly"] == 0

    def test_low_unknown_ratio_normal_detection(self, teacher):
        """When unknown ratio is low, standard scoring should apply."""
        known_id = 0
        sequence = [known_id] * 8 + [teacher.unknown_id] * 2  # 20% unknown
        log_data = {"path": "/", "method": "GET", "status": 200}
        session_stats = {"request_count": 10, "error_count": 0, "error_rate": 0.0, "unique_paths": 1}

        result = teacher.detect(log_data, sequence, session_stats)
        transformer = result["transformer"]
        assert transformer["status"] != "novel_penalty"

    def test_result_has_novel_score_field(self, teacher):
        """All detect() results should include novel_score at top level."""
        sequence = [teacher.unknown_id] * 10
        log_data = {"path": "/", "method": "GET", "status": 200}
        session_stats = {"request_count": 10, "error_count": 0, "error_rate": 0.0, "unique_paths": 1}

        result = teacher.detect(log_data, sequence, session_stats)
        assert "novel_score" in result

    def test_novel_penalty_does_not_trigger_anomaly_alone(self, teacher):
        """Novel endpoints should NOT auto-trigger is_anomaly without rule/IF support."""
        sequence = [teacher.unknown_id] * 10
        log_data = {"path": "/new-endpoint", "method": "GET", "status": 200}
        session_stats = {"request_count": 10, "error_count": 0, "error_rate": 0.0, "unique_paths": 1}

        result = teacher.detect(log_data, sequence, session_stats)
        # Without rule hit or iso anomaly, novel alone should NOT flag as anomaly
        assert result["is_anomaly"] is False
