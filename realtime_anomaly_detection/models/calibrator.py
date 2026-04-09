"""
Learned calibration head replacing the hardcoded > 0.5 ensemble threshold.

Fits a logistic regression on features extracted from the ensemble
components: [transformer_nll, iso_score, rule_weight, unknown_fraction,
session_len, error_rate, unique_paths, active_model_count].

Falls back gracefully to the legacy threshold when not fitted.
"""
from __future__ import annotations

import logging
import pickle
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

FEATURE_NAMES = [
    "transformer_nll",
    "iso_score",
    "rule_weight",
    "unknown_fraction",
    "session_len",
    "error_rate",
    "unique_paths",
    "active_model_count",
]


class EnsembleCalibrator:
    """Logistic calibration over ensemble component scores."""

    def __init__(self) -> None:
        self._model: Optional[LogisticRegression] = None
        self._scaler: Optional[StandardScaler] = None

    @property
    def is_fitted(self) -> bool:
        return self._model is not None

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """Fit the calibrator. X shape (n_samples, n_features), y binary labels."""
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)
        self._model = LogisticRegression(
            C=1.0,
            max_iter=1000,
            solver="lbfgs",
            class_weight="balanced",
        )
        self._model.fit(X_scaled, y)
        logger.info("Calibrator fitted on %d samples", len(y))

    def predict_proba(self, X: np.ndarray) -> Optional[float]:
        """Return P(anomaly) for a single sample. None if not fitted."""
        if not self.is_fitted:
            return None
        X_scaled = self._scaler.transform(X)
        proba = self._model.predict_proba(X_scaled)[0]
        # Column 1 is P(anomaly=1)
        if len(proba) > 1:
            return float(proba[1])
        return float(proba[0])

    @staticmethod
    def build_feature_vector(
        detect_result: Dict[str, Any],
        session_stats: Dict[str, Any],
    ) -> np.ndarray:
        """Extract calibration features from a detect() result dict."""
        transformer = detect_result.get("transformer", {})
        iso = detect_result.get("isolation_forest", {})
        rule = detect_result.get("rule_based", {})
        ensemble = detect_result.get("ensemble", {})

        transformer_nll = float(transformer.get("score") or 0.0)
        iso_score = float(iso.get("score", 0.0)) if iso.get("status") == "active" else 0.0
        rule_weight = float(rule.get("confidence", 0.0)) if rule.get("is_attack") else 0.0
        unknown_fraction = float(detect_result.get("unknown_template_ratio", 0.0))
        session_len = float(session_stats.get("request_count", 1))
        error_rate = float(session_stats.get("error_rate", 0.0))
        unique_paths = float(session_stats.get("unique_paths", 1))
        active_models = float(ensemble.get("active_models", 0))

        return np.array(
            [[transformer_nll, iso_score, rule_weight, unknown_fraction,
              session_len, error_rate, unique_paths, active_models]],
            dtype=np.float64,
        )

    def save(self, path: Path) -> None:
        with open(path, "wb") as f:
            pickle.dump({"model": self._model, "scaler": self._scaler}, f)

    @classmethod
    def load(cls, path: Path) -> EnsembleCalibrator:
        cal = cls()
        with open(path, "rb") as f:
            data = pickle.load(f)
        cal._model = data["model"]
        cal._scaler = data["scaler"]
        return cal
