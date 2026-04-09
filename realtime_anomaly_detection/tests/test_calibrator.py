"""Tests for the learned calibration head."""
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from models.calibrator import EnsembleCalibrator


@pytest.fixture
def fitted_calibrator():
    cal = EnsembleCalibrator()
    np.random.seed(42)
    n = 200
    X = np.random.rand(n, 8)
    y = (X[:, 0] + X[:, 1] + X[:, 2] > 1.5).astype(int)
    cal.fit(X, y)
    return cal


class TestEnsembleCalibrator:
    def test_fit_and_predict(self, fitted_calibrator):
        X_test = np.array([[0.9, 0.8, 0.9, 0.1, 5.0, 0.02, 3.0, 3.0]])
        score = fitted_calibrator.predict_proba(X_test)
        assert 0.0 <= score <= 1.0

    def test_predict_before_fit(self):
        cal = EnsembleCalibrator()
        X_test = np.array([[0.5, 0.3, 0.2, 0.1, 3.0, 0.01, 2.0, 2.0]])
        score = cal.predict_proba(X_test)
        assert score is None

    def test_is_fitted(self, fitted_calibrator):
        assert fitted_calibrator.is_fitted is True
        assert EnsembleCalibrator().is_fitted is False

    def test_feature_vector_builder(self):
        cal = EnsembleCalibrator()
        detect_result = {
            "transformer": {"score": 5.2, "threshold": 6.5, "status": "active"},
            "isolation_forest": {"score": 0.3, "status": "active"},
            "rule_based": {"is_attack": True, "confidence": 0.8},
            "unknown_template_ratio": 0.1,
            "ensemble": {"active_models": 3},
        }
        session_stats = {"request_count": 15, "error_rate": 0.05, "unique_paths": 3}
        vec = cal.build_feature_vector(detect_result, session_stats)
        assert vec.shape == (1, 8)
        assert vec[0, 0] == pytest.approx(5.2)  # transformer_nll
        assert vec[0, 2] == pytest.approx(0.8)  # rule_weight

    def test_save_load(self, fitted_calibrator, tmp_path):
        path = tmp_path / "calibrator.pkl"
        fitted_calibrator.save(path)
        loaded = EnsembleCalibrator.load(path)
        assert loaded.is_fitted
        X_test = np.array([[0.9, 0.8, 0.9, 0.1, 5.0, 0.02, 3.0, 3.0]])
        assert abs(loaded.predict_proba(X_test) - fitted_calibrator.predict_proba(X_test)) < 1e-6

    def test_high_score_input(self, fitted_calibrator):
        """High anomaly features should produce high P(anomaly)."""
        X_high = np.array([[0.95, 0.9, 0.95, 0.8, 100.0, 0.5, 50.0, 3.0]])
        X_low = np.array([[0.01, 0.01, 0.0, 0.0, 3.0, 0.0, 1.0, 1.0]])
        assert fitted_calibrator.predict_proba(X_high) > fitted_calibrator.predict_proba(X_low)
