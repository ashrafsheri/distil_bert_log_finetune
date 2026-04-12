"""Tests for scripts.train_base_model."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.synthetic_log_generator import SyntheticLogGenerator
from scripts.train_base_model import (
    BaseModelTrainer,
    ModelHyperparameters,
    parse_apache_log_line,
)


def build_manifest() -> dict:
    return {
        "service_name": "trainer-test",
        "base_url": "https://example.com",
        "endpoints": [
            {"method": "GET", "path_template": "/api/users", "weight": 3},
            {"method": "GET", "path_template": "/api/users/{id}", "weight": 4},
            {"method": "POST", "path_template": "/api/auth/login", "weight": 2},
            {"method": "POST", "path_template": "/api/auth/logout", "weight": 1},
            {"method": "GET", "path_template": "/api/products", "weight": 3},
            {"method": "GET", "path_template": "/api/products/{id}", "weight": 4},
            {"method": "POST", "path_template": "/api/orders", "weight": 2},
            {"method": "GET", "path_template": "/api/orders/{id}", "weight": 3},
            {"method": "GET", "path_template": "/api/search", "weight": 2},
            {"method": "GET", "path_template": "/api/teams/{slug}", "weight": 2},
            {"method": "PUT", "path_template": "/api/teams/{id}", "weight": 2},
            {"method": "GET", "path_template": "/health", "classification": "internal_probe", "weight": 1},
        ],
    }


def make_log_file(tmp_path: Path, *, count: int = 600, sessions: int = 30) -> Path:
    import random

    random.seed(1234)
    generator = SyntheticLogGenerator(build_manifest())
    start_time = datetime(2026, 4, 12, 0, 0, 0, tzinfo=timezone.utc)
    lines = generator.generate(
        count=count,
        sessions=sessions,
        start_time=start_time,
        window_hours=12,
    )
    log_path = tmp_path / "synthetic.log"
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return log_path


class TestParseApacheLogLine:
    def test_parses_combined_log_line(self):
        line = (
            '192.168.1.10 - - [12/Apr/2026:10:00:01 +0000] '
            '"GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
        )
        parsed = parse_apache_log_line(line)
        assert parsed is not None
        assert parsed["ip"] == "192.168.1.10"
        assert parsed["method"] == "GET"
        assert parsed["path"] == "/api/users"
        assert parsed["status"] == 200
        assert parsed["size"] == 1234

    def test_invalid_line_returns_none(self):
        assert parse_apache_log_line("not a valid apache log") is None


class TestBaseModelTrainer:
    def test_extract_feature_vector_shape(self):
        trainer = BaseModelTrainer(epochs=1)
        parsed = {
            "method": "POST",
            "status": 401,
            "path": "/api/auth/login?email=a@example.com",
            "size": 256,
            "timestamp": datetime(2026, 4, 12, 10, 30, 0, tzinfo=timezone.utc),
        }
        features = trainer.extract_feature_vector(
            parsed,
            {
                "request_count": 3,
                "error_rate": 1 / 3,
                "unique_paths": 2,
                "error_count": 1,
            },
        )
        assert len(features) == 11
        assert features[0] == 3.0  # request_count
        assert features[3] == 1.0  # error_count
        assert features[5] == 1.0  # POST
        assert features[6] == 1.0  # status >= 400
        assert features[9] == 1.0  # query present
        assert features[10] == 10.0  # hour

    def test_validate_corpus_rejects_too_few_lines(self):
        trainer = BaseModelTrainer(epochs=1)
        trainer.ingest_lines(
            [
                '192.168.1.10 - - [12/Apr/2026:10:00:01 +0000] "GET /api/users HTTP/1.1" 200 123 "-" "Mozilla/5.0"'
            ]
        )
        with pytest.raises(ValueError, match="need at least 500"):
            trainer.validate_corpus()

    def test_train_from_log_file_writes_artifacts(self, tmp_path: Path):
        log_path = make_log_file(tmp_path)
        output_dir = tmp_path / "base_model"
        trainer = BaseModelTrainer(
            epochs=1,
            contamination=0.1,
            hyperparameters=ModelHyperparameters(
                d_model=32,
                n_heads=4,
                n_layers=2,
                ffn_dim=64,
                dropout=0.0,
                batch_size=32,
                learning_rate=1e-3,
            ),
            device="cpu",
        )

        summary = trainer.train_from_log_file(log_path, output_dir)

        assert summary["valid_log_lines"] >= 500
        assert summary["vocab_size"] >= 10
        assert summary["sequence_count"] > 0
        assert summary["threshold"] > 0
        assert summary["iso_threshold"] > 0

        vocab_payload = json.loads((output_dir / "template_vocab.json").read_text(encoding="utf-8"))
        assert "template_to_id" in vocab_payload
        assert len(vocab_payload["template_to_id"]) == summary["vocab_size"]

        config_payload = json.loads((output_dir / "model_config.json").read_text(encoding="utf-8"))
        assert config_payload["window_size"] == 20
        assert config_payload["vocab_size"] == summary["vocab_size"]
        assert config_payload["iso_threshold"] == summary["iso_threshold"]
        assert config_payload["feature_schema_version"] == "access-log-v2"

        checkpoint = torch.load(output_dir / "transformer_model.pt", map_location="cpu")
        assert checkpoint["pad_id"] == summary["vocab_size"]
        assert checkpoint["unknown_id"] == summary["vocab_size"] + 1
        assert "model_state_dict" in checkpoint

        assert (output_dir / "isolation_forest.pkl").exists()
