#!/usr/bin/env python3
"""
Train base model artifacts from synthetic Apache access logs.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import pickle
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional

import numpy as np
import torch
import torch.nn.functional as F
from sklearn.ensemble import IsolationForest
from torch.utils.data import DataLoader, Dataset

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from realtime_anomaly_detection.models.ensemble_detector import ApacheLogNormalizer, TemplateTransformer
from realtime_anomaly_detection.models.multi_tenant_detector import MultiTenantDetector

logger = logging.getLogger("train_base_model")

APACHE_PATTERN = (
    r'^(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)

WINDOW_SIZE = 20
MIN_VALID_LINES = 500
MIN_DISTINCT_TEMPLATES = 10

@dataclass(frozen=True)
class ModelHyperparameters:
    d_model: int = 256
    n_heads: int = 8
    n_layers: int = 4
    ffn_dim: int = 1024
    dropout: float = 0.1
    batch_size: int = 64
    learning_rate: float = 1e-4


class SequenceDataset(Dataset):
    def __init__(self, sequences: List[List[int]], pad_id: int):
        self.sequences = sequences
        self.pad_id = pad_id

    def __len__(self) -> int:
        return len(self.sequences)

    def __getitem__(self, index: int) -> Dict[str, torch.Tensor]:
        sequence = self.sequences[index]
        attention_mask = [1 if token != self.pad_id else 0 for token in sequence]
        return {
            "input_ids": torch.tensor(sequence, dtype=torch.long),
            "attention_mask": torch.tensor(attention_mask, dtype=torch.long),
        }


def parse_apache_log_line(log_line: str) -> Optional[Dict[str, Any]]:
    import re

    match = re.match(APACHE_PATTERN, log_line.strip())
    if not match:
        return None

    groups = match.groupdict()
    size_raw = groups["size"]
    try:
        status = int(groups["status"])
        size = 0 if size_raw == "-" else int(size_raw)
        parsed_ts = datetime.strptime(groups["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
    except (ValueError, TypeError):
        return None

    return {
        "ip": groups["ip"],
        "timestamp": parsed_ts,
        "method": groups["method"].upper(),
        "path": groups["path"],
        "protocol": groups["protocol"],
        "status": status,
        "size": size,
        "raw_line": log_line.strip(),
    }


class BaseModelTrainer:
    def __init__(
        self,
        *,
        window_size: int = WINDOW_SIZE,
        epochs: int = 10,
        contamination: float = 0.05,
        hyperparameters: Optional[ModelHyperparameters] = None,
        device: Optional[str] = None,
    ):
        self.window_size = window_size
        self.epochs = epochs
        self.contamination = contamination
        self.hyperparameters = hyperparameters or ModelHyperparameters()
        resolved_device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.device = torch.device(resolved_device)
        self.normalizer = ApacheLogNormalizer()

        self.template_to_id: Dict[str, int] = {}
        self.id_to_template: List[str] = []
        self.valid_log_count = 0
        self.sequences: List[List[int]] = []
        self.feature_rows: List[List[float]] = []
        self.window_count = 0

    def _normalize_template(self, parsed: Dict[str, Any]) -> str:
        canonical_path = MultiTenantDetector._canonicalize_path(parsed["path"])
        message = f"{parsed['method']} {canonical_path} {parsed['protocol']} {parsed['status']}"
        return self.normalizer.normalize(message)

    def _template_id_for(self, normalized_template: str) -> int:
        existing = self.template_to_id.get(normalized_template)
        if existing is not None:
            return existing
        token_id = len(self.id_to_template)
        self.template_to_id[normalized_template] = token_id
        self.id_to_template.append(normalized_template)
        return token_id

    def extract_feature_vector(self, parsed: Dict[str, Any], session_stats: Dict[str, Any]) -> List[float]:
        method = parsed["method"].upper()
        status = int(parsed["status"])
        path = parsed["path"]
        hour_of_day = parsed["timestamp"].hour
        return [
            float(session_stats.get("request_count", 1)),
            float(session_stats.get("error_rate", 0.0)),
            float(session_stats.get("unique_paths", 1)),
            float(session_stats.get("error_count", 0)),
            1.0 if method == "GET" else 0.0,
            1.0 if method == "POST" else 0.0,
            1.0 if status >= 400 else 0.0,
            float(len(path)),
            float(path.count("/")),
            1.0 if "?" in path else 0.0,
            float(hour_of_day),
        ]

    def ingest_lines(self, lines: Iterable[str]) -> None:
        session_windows: Dict[str, Deque[int]] = defaultdict(lambda: deque(maxlen=self.window_size))
        session_state: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "request_count": 0,
                "error_count": 0,
                "unique_paths": set(),
            }
        )
        logger.info("Starting log ingestion and normalization")
        for line in lines:
            parsed = parse_apache_log_line(line)
            if parsed is None:
                continue

            self.valid_log_count += 1
            normalized_template = self._normalize_template(parsed)
            template_id = self._template_id_for(normalized_template)
            session_key = parsed["ip"]
            state = session_state[session_key]
            state["request_count"] += 1
            if int(parsed["status"]) >= 400:
                state["error_count"] += 1
            state["unique_paths"].add(parsed["path"])
            session_stats = {
                "request_count": state["request_count"],
                "error_count": state["error_count"],
                "error_rate": state["error_count"] / max(state["request_count"], 1),
                "unique_paths": len(state["unique_paths"]),
            }
            self.feature_rows.append(self.extract_feature_vector(parsed, session_stats))

            window = session_windows[session_key]
            window.append(template_id)
            if len(window) == self.window_size:
                self.sequences.append(list(window))

            if self.valid_log_count % 2000 == 0:
                logger.info(
                    "Parsed %d valid lines, %d templates, %d windows",
                    self.valid_log_count,
                    len(self.template_to_id),
                    len(self.sequences),
                )

        logger.info(
            "Finished ingestion: valid_lines=%d templates=%d windows=%d feature_rows=%d",
            self.valid_log_count,
            len(self.template_to_id),
            len(self.sequences),
            len(self.feature_rows),
        )

    def validate_corpus(self) -> None:
        if self.valid_log_count < MIN_VALID_LINES:
            raise ValueError(
                f"Only parsed {self.valid_log_count} valid log lines; need at least {MIN_VALID_LINES}. "
                "Generate more logs with synthetic_log_generator.py."
            )
        if len(self.template_to_id) < MIN_DISTINCT_TEMPLATES:
            raise ValueError(
                f"Only found {len(self.template_to_id)} distinct normalized templates; need at least "
                f"{MIN_DISTINCT_TEMPLATES}."
            )
        if not self.sequences:
            raise ValueError(
                f"No sliding windows of size {self.window_size} were formed. Increase session depth or log count."
            )
        if self.valid_log_count < 15_000:
            print(
                f"[WARNING] Only {self.valid_log_count} valid log lines parsed. Threshold quality will be weak below 15000.",
                file=sys.stderr,
            )

    def _build_model(self, vocab_size: int, pad_id: int) -> TemplateTransformer:
        hp = self.hyperparameters
        return TemplateTransformer(
            vocab_size=vocab_size,
            pad_id=pad_id,
            d_model=hp.d_model,
            n_heads=hp.n_heads,
            n_layers=hp.n_layers,
            ffn_dim=hp.ffn_dim,
            max_length=self.window_size,
            dropout=hp.dropout,
        ).to(self.device)

    def train_transformer(self) -> tuple[TemplateTransformer, float]:
        base_vocab_size = len(self.template_to_id)
        pad_id = base_vocab_size
        unknown_id = base_vocab_size + 1
        full_vocab_size = unknown_id + 1

        logger.info(
            "Initializing transformer: base_vocab=%d full_vocab=%d window_size=%d device=%s",
            base_vocab_size,
            full_vocab_size,
            self.window_size,
            self.device,
        )
        model = self._build_model(full_vocab_size, pad_id)
        dataset = SequenceDataset(self.sequences, pad_id)
        loader = DataLoader(
            dataset,
            batch_size=self.hyperparameters.batch_size,
            shuffle=True,
        )
        optimizer = torch.optim.AdamW(model.parameters(), lr=self.hyperparameters.learning_rate)
        final_loss = 0.0

        logger.info(
            "Starting transformer training: epochs=%d batch_size=%d learning_rate=%s sequences=%d",
            self.epochs,
            self.hyperparameters.batch_size,
            self.hyperparameters.learning_rate,
            len(self.sequences),
        )
        for epoch_index in range(self.epochs):
            model.train()
            epoch_loss = 0.0
            batches = 0
            for batch in loader:
                input_ids = batch["input_ids"].to(self.device)
                attention_mask = batch["attention_mask"].to(self.device)

                optimizer.zero_grad()
                logits = model(input_ids, attention_mask)
                loss = F.cross_entropy(
                    logits[:, :-1, :].reshape(-1, full_vocab_size),
                    input_ids[:, 1:].reshape(-1),
                    ignore_index=pad_id,
                )
                loss.backward()
                optimizer.step()

                epoch_loss += float(loss.item())
                batches += 1

            final_loss = epoch_loss / max(batches, 1)
            logger.info(
                "Epoch %d/%d complete: avg_loss=%.4f batches=%d",
                epoch_index + 1,
                self.epochs,
                final_loss,
                batches,
            )

        model.eval()
        logger.info("Transformer training finished: final_loss=%.4f", final_loss)
        return model, final_loss

    def compute_threshold(self, model: TemplateTransformer) -> float:
        base_vocab_size = len(self.template_to_id)
        pad_id = base_vocab_size
        scores: List[float] = []
        logger.info("Computing transformer NLL threshold from %d sequences", len(self.sequences))
        with torch.no_grad():
            for sequence in self.sequences:
                input_ids = torch.tensor([sequence], dtype=torch.long, device=self.device)
                attention_mask = torch.tensor(
                    [[1 if token != pad_id else 0 for token in sequence]],
                    dtype=torch.long,
                    device=self.device,
                )
                logits = model(input_ids, attention_mask)
                log_probs = F.log_softmax(logits[:, :-1, :], dim=-1)
                targets = input_ids[:, 1:]
                nll = -log_probs.gather(2, targets.unsqueeze(-1)).squeeze(-1)
                valid = attention_mask[:, 1:] == 1
                valid_nll = nll[valid]
                if valid_nll.numel():
                    scores.append(float(valid_nll.mean().item()))

        if not scores:
            raise ValueError("Could not compute sequence NLL scores for threshold estimation.")
        threshold = float(np.percentile(scores, 95))
        logger.info("Computed optimal threshold (95th percentile): %.4f", threshold)
        return threshold

    def train_isolation_forest(self) -> tuple[IsolationForest, float]:
        features = np.asarray(self.feature_rows, dtype=np.float32)
        logger.info(
            "Training IsolationForest: rows=%d features=%d contamination=%.3f",
            features.shape[0],
            features.shape[1] if features.ndim == 2 else 0,
            self.contamination,
        )
        model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42,
        )
        model.fit(features)
        scores = -model.score_samples(features)
        iso_threshold = float(np.percentile(scores, 95))
        logger.info("IsolationForest training finished: threshold=%.4f", iso_threshold)
        return model, iso_threshold

    def _atomic_write_json(self, path: Path, payload: Dict[str, Any]) -> None:
        temp_path = path.with_name(f"{path.name}.tmp")
        temp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(temp_path, path)

    def _atomic_write_pickle(self, path: Path, payload: Any) -> None:
        temp_path = path.with_name(f"{path.name}.tmp")
        with temp_path.open("wb") as handle:
            pickle.dump(payload, handle)
        os.replace(temp_path, path)

    def _atomic_write_torch(self, path: Path, payload: Dict[str, Any]) -> None:
        temp_path = path.with_name(f"{path.name}.tmp")
        torch.save(payload, temp_path)
        os.replace(temp_path, path)

    def save_artifacts(
        self,
        *,
        output_dir: Path,
        transformer: TemplateTransformer,
        isolation_forest: IsolationForest,
        threshold: float,
        iso_threshold: float,
    ) -> Dict[str, Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        base_vocab_size = len(self.template_to_id)
        pad_id = base_vocab_size
        unknown_id = base_vocab_size + 1
        full_vocab_size = unknown_id + 1

        vocab_path = output_dir / "template_vocab.json"
        checkpoint_path = output_dir / "transformer_model.pt"
        iso_path = output_dir / "isolation_forest.pkl"
        config_path = output_dir / "model_config.json"

        logger.info("Writing artifacts to %s", output_dir)
        self._atomic_write_json(
            vocab_path,
            {"template_to_id": self.template_to_id},
        )
        self._atomic_write_torch(
            checkpoint_path,
            {
                "model_state_dict": transformer.state_dict(),
                "vocab_size": full_vocab_size,
                "pad_id": pad_id,
                "unknown_id": unknown_id,
                "threshold": threshold,
                "model_config": {
                    "vocab_size": full_vocab_size,
                    "pad_id": pad_id,
                    "unknown_id": unknown_id,
                    "d_model": self.hyperparameters.d_model,
                    "n_heads": self.hyperparameters.n_heads,
                    "n_layers": self.hyperparameters.n_layers,
                    "ffn_dim": self.hyperparameters.ffn_dim,
                    "max_length": self.window_size,
                    "dropout": self.hyperparameters.dropout,
                },
            },
        )
        self._atomic_write_pickle(iso_path, isolation_forest)
        self._atomic_write_json(
            config_path,
            {
                "optimal_threshold": threshold,
                "iso_threshold": iso_threshold,
                "vocab_size": base_vocab_size,
                "window_size": self.window_size,
                "feature_schema_version": "access-log-v2",
            },
        )
        logger.info(
            "Artifacts written: %s, %s, %s, %s",
            vocab_path.name,
            checkpoint_path.name,
            iso_path.name,
            config_path.name,
        )
        return {
            "template_vocab.json": vocab_path,
            "transformer_model.pt": checkpoint_path,
            "isolation_forest.pkl": iso_path,
            "model_config.json": config_path,
        }

    def train_from_log_file(self, log_path: Path, output_dir: Path) -> Dict[str, Any]:
        logger.info("Loading log file from %s", log_path)
        self.ingest_lines(log_path.read_text(encoding="utf-8").splitlines())
        self.validate_corpus()
        logger.info(
            "Corpus validation passed: valid_lines=%d templates=%d windows=%d",
            self.valid_log_count,
            len(self.template_to_id),
            len(self.sequences),
        )

        transformer, final_loss = self.train_transformer()
        threshold = self.compute_threshold(transformer)
        iso_forest, iso_threshold = self.train_isolation_forest()
        self.save_artifacts(
            output_dir=output_dir,
            transformer=transformer,
            isolation_forest=iso_forest,
            threshold=threshold,
            iso_threshold=iso_threshold,
        )

        return {
            "valid_log_lines": self.valid_log_count,
            "vocab_size": len(self.template_to_id),
            "sequence_count": len(self.sequences),
            "final_loss": final_loss,
            "contamination": self.contamination,
            "threshold": threshold,
            "iso_threshold": iso_threshold,
        }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train base model artifacts from Apache access logs")
    parser.add_argument("--logs", required=True, help="Path to Apache access log file")
    parser.add_argument("--output", required=True, help="Output model directory")
    parser.add_argument("--epochs", type=int, default=10, help="Training epochs")
    parser.add_argument("--contamination", type=float, default=0.05, help="IsolationForest contamination")
    parser.add_argument("--device", default=None, help="Torch device override, e.g. cpu or cuda")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    log_path = Path(args.logs)
    if not log_path.exists():
        print(f"[ERROR] Log file not found: {log_path}", file=sys.stderr)
        raise SystemExit(1)

    logger.info(
        "Starting base model training: logs=%s output=%s epochs=%d device=%s",
        log_path,
        args.output,
        args.epochs,
        args.device or ("cuda" if torch.cuda.is_available() else "cpu"),
    )
    trainer = BaseModelTrainer(
        epochs=args.epochs,
        contamination=args.contamination,
        device=args.device,
    )
    summary = trainer.train_from_log_file(log_path, Path(args.output))
    print(
        "Training complete: "
        f"vocab_size={summary['vocab_size']} "
        f"sequence_count={summary['sequence_count']} "
        f"final_loss={summary['final_loss']:.4f} "
        f"contamination={summary['contamination']:.3f} "
        f"threshold={summary['threshold']:.4f} "
        f"iso_threshold={summary['iso_threshold']:.4f}"
    )


if __name__ == "__main__":
    main()
