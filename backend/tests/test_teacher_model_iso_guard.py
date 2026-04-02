"""Regression tests for teacher-model Isolation Forest persistence and readiness guards."""

from __future__ import annotations

import pickle
import sys
from pathlib import Path

import numpy as np
import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
pytest.importorskip("torch")
sys.path.insert(0, str(REPO_ROOT / "realtime_anomaly_detection"))

from models.teacher_model import TeacherModel


def _build_minimal_teacher(tmp_path: Path) -> TeacherModel:
    model = TeacherModel(
        model_dir=tmp_path / "artifacts",
        storage_dir=tmp_path / "teacher",
        auto_load=False,
    )
    model.template_to_id = {"GET /health HTTP/1.1 200": 0}
    model.id_to_template = ["GET /health HTTP/1.1 200"]
    model.pad_id = 1
    model.unknown_id = 2
    model.vocab_size = 3
    model._initialize_fresh_transformer()
    model.is_loaded = True
    return model


def test_teacher_save_does_not_persist_unfitted_isolation_forest(tmp_path: Path) -> None:
    model = _build_minimal_teacher(tmp_path)
    model._initialize_fresh_iso_forest()

    model.save()

    assert model.teacher_model_path.exists()
    assert model.teacher_state_path.exists()
    assert not model.teacher_iso_path.exists()


def test_teacher_load_discards_unfitted_saved_isolation_forest(tmp_path: Path) -> None:
    model = _build_minimal_teacher(tmp_path)
    model.save()

    poisoned_iso = model._create_iso_forest()
    with open(model.teacher_iso_path, "wb") as fh:
        pickle.dump(poisoned_iso, fh)

    reloaded = TeacherModel(
        model_dir=tmp_path / "artifacts",
        storage_dir=tmp_path / "teacher",
        auto_load=True,
    )

    assert reloaded.iso_forest is None


def test_teacher_detect_reports_not_fitted_for_unfitted_isolation_forest(tmp_path: Path) -> None:
    model = _build_minimal_teacher(tmp_path)
    model._initialize_fresh_iso_forest()

    result = model.detect(
        log_data={"path": "/health", "method": "GET", "status": 200},
        sequence=[0],
        session_stats={},
        features=np.zeros((1, 11), dtype=np.float64),
    )

    assert result["isolation_forest"]["status"] == "not_fitted"


def test_teacher_rule_hits_are_not_diluted_by_unavailable_models(tmp_path: Path) -> None:
    model = _build_minimal_teacher(tmp_path)

    result = model.detect(
        log_data={
            "path": "/index.php?lang=../../../../../../usr/local/lib/php/pearcmd&+config-create+/&/bin/sh",
            "method": "GET",
            "status": 404,
        },
        sequence=[0],
        session_stats={},
        features=np.zeros((1, 11), dtype=np.float64),
    )

    assert result["rule_based"]["is_attack"] is True
    assert result["is_anomaly"] is True
    assert result["anomaly_score"] >= 0.95
    assert result["transformer"]["status"] == "insufficient_context"
