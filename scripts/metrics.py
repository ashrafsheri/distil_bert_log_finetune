"""Evaluation metrics for the LogGuard backtest harness.

Provides research-grade metrics: PR-AUC, ROC-AUC, ECE, latency stats,
per-class breakdowns, and threshold sweeps.
"""

from collections import defaultdict
from typing import Dict, List, Optional

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def compute_pr_auc(labels, scores) -> Optional[float]:
    """Area under Precision-Recall curve. Returns None if degenerate."""
    labels = np.asarray(labels)
    scores = np.asarray(scores)
    if len(labels) == 0 or len(np.unique(labels)) < 2:
        return None
    return float(average_precision_score(labels, scores))


def compute_roc_auc(labels, scores) -> Optional[float]:
    """Area under ROC curve. Returns None if degenerate."""
    labels = np.asarray(labels)
    scores = np.asarray(scores)
    if len(labels) == 0 or len(np.unique(labels)) < 2:
        return None
    return float(roc_auc_score(labels, scores))


def compute_ece(labels, scores, n_bins: int = 15) -> Optional[float]:
    """Expected Calibration Error with equal-width bins. Returns None if empty."""
    labels = np.asarray(labels, dtype=float)
    scores = np.asarray(scores, dtype=float)
    if len(labels) == 0:
        return None

    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    for i in range(n_bins):
        mask = (scores > bin_edges[i]) & (scores <= bin_edges[i + 1])
        # Include left edge for the first bin
        if i == 0:
            mask = (scores >= bin_edges[i]) & (scores <= bin_edges[i + 1])
        bin_count = mask.sum()
        if bin_count == 0:
            continue
        bin_acc = labels[mask].mean()
        bin_conf = scores[mask].mean()
        ece += (bin_count / len(labels)) * abs(bin_acc - bin_conf)

    return float(ece)


def compute_latency_histogram(latencies_seconds) -> Dict:
    """Latency percentiles and stats. Returns None values if empty."""
    latencies = np.asarray(latencies_seconds, dtype=float)
    if len(latencies) == 0:
        return {"p50": None, "p95": None, "p99": None, "mean": None, "count": 0}
    return {
        "p50": float(np.percentile(latencies, 50)),
        "p95": float(np.percentile(latencies, 95)),
        "p99": float(np.percentile(latencies, 99)),
        "mean": float(np.mean(latencies)),
        "count": len(latencies),
    }


def compute_per_class_metrics(records: List[Dict]) -> Dict[str, Dict]:
    """F1/precision/recall and PR-AUC per traffic_class.

    Each record must have: label, predicted, anomaly_score, traffic_class.
    Returns empty dict if no records.
    """
    if not records:
        return {}

    by_class = defaultdict(list)
    for r in records:
        by_class[r["traffic_class"]].append(r)

    result = {}
    for cls, cls_records in by_class.items():
        labels = [r["label"] for r in cls_records]
        predicted = [r["predicted"] for r in cls_records]
        scores = [r["anomaly_score"] for r in cls_records]

        result[cls] = {
            "f1": float(f1_score(labels, predicted, zero_division=0)),
            "precision": float(precision_score(labels, predicted, zero_division=0)),
            "recall": float(recall_score(labels, predicted, zero_division=0)),
            "pr_auc": compute_pr_auc(labels, scores),
            "roc_auc": compute_roc_auc(labels, scores),
            "count": len(cls_records),
        }

    return result


def compute_threshold_sweep(labels, scores, n_points: int = 200) -> Dict:
    """Sweep thresholds and find best F1.

    Returns dict with best_f1, best_threshold, and thresholds list.
    """
    labels = np.asarray(labels)
    scores = np.asarray(scores)

    if len(labels) == 0 or len(np.unique(labels)) < 2:
        return {"best_f1": None, "best_threshold": None, "thresholds": []}

    thresholds = np.linspace(float(scores.min()), float(scores.max()), n_points)
    best_f1 = -1.0
    best_threshold = None
    threshold_results = []

    for t in thresholds:
        predicted = (scores >= t).astype(int)
        f1 = float(f1_score(labels, predicted, zero_division=0))
        threshold_results.append({"threshold": float(t), "f1": f1})
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = float(t)

    return {
        "best_f1": best_f1,
        "best_threshold": best_threshold,
        "thresholds": threshold_results,
    }
