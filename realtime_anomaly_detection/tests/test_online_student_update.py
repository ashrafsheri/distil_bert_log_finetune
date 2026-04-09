"""Tests for online student model updates from clean_normal_reservoir."""
import sys
from pathlib import Path

import numpy as np
import pytest
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from models.student_model import StudentModel
from models.ensemble_detector import TemplateTransformer


@pytest.fixture
def trained_student(tmp_path):
    """Create a minimally trained student model."""
    student = StudentModel(
        project_id="test-project",
        storage_dir=tmp_path / "student",
        window_size=10,
        device="cpu",
    )
    for i in range(20):
        student.add_template(f"GET /api/v{i} HTTP/1.1 200")
    student.vocab_frozen = True
    base_vocab = len(student.id_to_template)
    student.pad_id = base_vocab
    student.unknown_id = base_vocab + 1
    student.vocab_size = student.unknown_id + 1

    student.transformer = TemplateTransformer(
        vocab_size=student.vocab_size,
        pad_id=student.pad_id,
        d_model=128, n_heads=4, n_layers=2, ffn_dim=512,
        max_length=student.window_size, dropout=0.1,
    ).to(student.device)
    student.transformer.eval()
    student.is_trained = True
    student.transformer_threshold = 5.0

    for _ in range(600):
        seq = list(np.random.randint(0, base_vocab, size=10))
        student.clean_normal_reservoir.append(seq)
    return student


class TestOnlineUpdate:
    def test_online_update_runs(self, trained_student):
        result = trained_student.online_update(min_reservoir_size=500, epochs=1, max_kl_divergence=100.0)
        assert result is True
        assert trained_student.last_trained_at is not None

    def test_online_update_skips_small_reservoir(self, trained_student):
        trained_student.clean_normal_reservoir = trained_student.clean_normal_reservoir[:10]
        result = trained_student.online_update(min_reservoir_size=500)
        assert result is False

    def test_online_update_kl_drift_guard(self, trained_student):
        result = trained_student.online_update(min_reservoir_size=500, max_kl_divergence=0.0, epochs=1)
        assert result is False

    def test_online_update_counter(self, trained_student):
        assert trained_student.online_update_count == 0
        trained_student.online_update(min_reservoir_size=500, epochs=1, max_kl_divergence=100.0)
        assert trained_student.online_update_count >= 1
