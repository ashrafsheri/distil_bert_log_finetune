"""Tests for scripts.metrics evaluation functions."""

import numpy as np
import pytest

from scripts.metrics import (
    compute_ece,
    compute_latency_histogram,
    compute_per_class_metrics,
    compute_pr_auc,
    compute_roc_auc,
    compute_threshold_sweep,
)


# ── PR-AUC ──────────────────────────────────────────────────────────────────

class TestPrAuc:
    def test_perfect_classifier(self):
        labels = [0, 0, 1, 1]
        scores = [0.1, 0.2, 0.9, 0.95]
        result = compute_pr_auc(labels, scores)
        assert result is not None
        assert result == pytest.approx(1.0)

    def test_random_classifier(self):
        rng = np.random.RandomState(42)
        labels = rng.randint(0, 2, size=1000).tolist()
        scores = rng.rand(1000).tolist()
        result = compute_pr_auc(labels, scores)
        assert result is not None
        # Random classifier should be roughly around prevalence
        assert 0.0 < result < 1.0

    def test_no_positives(self):
        labels = [0, 0, 0]
        scores = [0.1, 0.2, 0.3]
        result = compute_pr_auc(labels, scores)
        assert result is None

    def test_empty_input(self):
        result = compute_pr_auc([], [])
        assert result is None


# ── ROC-AUC ─────────────────────────────────────────────────────────────────

class TestRocAuc:
    def test_perfect_classifier(self):
        labels = [0, 0, 1, 1]
        scores = [0.1, 0.2, 0.9, 0.95]
        result = compute_roc_auc(labels, scores)
        assert result is not None
        assert result == pytest.approx(1.0)

    def test_no_positives(self):
        labels = [0, 0, 0]
        scores = [0.1, 0.2, 0.3]
        result = compute_roc_auc(labels, scores)
        assert result is None

    def test_no_negatives(self):
        labels = [1, 1, 1]
        scores = [0.7, 0.8, 0.9]
        result = compute_roc_auc(labels, scores)
        assert result is None

    def test_empty_input(self):
        result = compute_roc_auc([], [])
        assert result is None


# ── ECE ─────────────────────────────────────────────────────────────────────

class TestEce:
    def test_perfectly_calibrated(self):
        # Scores match empirical probabilities perfectly
        labels = [0] * 50 + [1] * 50
        scores = [0.0] * 50 + [1.0] * 50
        result = compute_ece(labels, scores, n_bins=10)
        assert result is not None
        assert result == pytest.approx(0.0, abs=0.01)

    def test_overconfident(self):
        # All predictions are 0.9, but only half are positive
        labels = [0] * 50 + [1] * 50
        scores = [0.9] * 100
        result = compute_ece(labels, scores, n_bins=10)
        assert result is not None
        # Expected gap: |0.9 - 0.5| = 0.4
        assert result == pytest.approx(0.4, abs=0.05)

    def test_empty(self):
        result = compute_ece([], [])
        assert result is None


# ── Latency Histogram ───────────────────────────────────────────────────────

class TestLatencyHistogram:
    def test_basic(self):
        latencies = [0.01, 0.02, 0.03, 0.04, 0.05]
        result = compute_latency_histogram(latencies)
        assert result["count"] == 5
        assert result["p50"] == pytest.approx(0.03)
        assert result["p95"] is not None
        assert result["p99"] is not None
        assert result["mean"] == pytest.approx(0.03)

    def test_empty(self):
        result = compute_latency_histogram([])
        assert result["count"] == 0
        assert result["p50"] is None
        assert result["p95"] is None
        assert result["p99"] is None
        assert result["mean"] is None


# ── Per-Class Metrics ───────────────────────────────────────────────────────

class TestPerClassMetrics:
    def test_two_classes(self):
        records = [
            {"label": 1, "predicted": 1, "anomaly_score": 0.9, "traffic_class": "web"},
            {"label": 0, "predicted": 0, "anomaly_score": 0.1, "traffic_class": "web"},
            {"label": 1, "predicted": 0, "anomaly_score": 0.3, "traffic_class": "ssh"},
            {"label": 0, "predicted": 0, "anomaly_score": 0.2, "traffic_class": "ssh"},
        ]
        result = compute_per_class_metrics(records)
        assert "web" in result
        assert "ssh" in result
        # Web: perfect predictions
        assert result["web"]["f1"] == pytest.approx(1.0)
        assert result["web"]["precision"] == pytest.approx(1.0)
        assert result["web"]["recall"] == pytest.approx(1.0)
        # SSH: missed the positive
        assert result["ssh"]["recall"] == pytest.approx(0.0)

    def test_degenerate_class(self):
        records = [
            {"label": 0, "predicted": 0, "anomaly_score": 0.1, "traffic_class": "web"},
            {"label": 0, "predicted": 0, "anomaly_score": 0.2, "traffic_class": "web"},
        ]
        result = compute_per_class_metrics(records)
        assert "web" in result
        # No positives — pr_auc should be None
        assert result["web"]["pr_auc"] is None

    def test_empty(self):
        result = compute_per_class_metrics([])
        assert result == {}


# ── Threshold Sweep ─────────────────────────────────────────────────────────

class TestThresholdSweep:
    def test_best_f1(self):
        labels = [0, 0, 0, 1, 1, 1]
        scores = [0.1, 0.2, 0.3, 0.7, 0.8, 0.9]
        result = compute_threshold_sweep(labels, scores, n_points=200)
        assert result["best_f1"] == pytest.approx(1.0)
        assert 0.3 < result["best_threshold"] < 0.7
        assert len(result["thresholds"]) <= 200

    def test_empty(self):
        result = compute_threshold_sweep([], [])
        assert result["best_f1"] is None
        assert result["best_threshold"] is None
