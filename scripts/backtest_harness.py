#!/usr/bin/env python3
"""
Chronological backtest and shadow-replay harness for anomaly detectors.

This script replays historical access logs directly against the detector classes
without requiring the backend or anomaly service to be running. It is designed
for:
1. chronological backtests
2. shadow comparisons between detectors
3. incident-level and log-level precision/recall reporting

Supported inputs:
- JSON array
- JSONL / NDJSON
- CSV with headers

Expected fields per record:
- raw_log or log
- event_time / timestamp (optional if parseable from raw log)
- project_id
- project_name (optional)
- log_type (apache or nginx, default apache)
- warmup_threshold (optional)
- label / is_anomaly / infected / expected_anomaly (optional)
- incident_id / label_incident_id (optional)
- flags (optional dict of replay flags)
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.services.log_parser_service import LogParserService


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value: Any) -> datetime:
    """Parse a timestamp into an aware UTC datetime."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return _now_utc()
        try:
            return datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
        except ValueError:
            pass
        try:
            return datetime.strptime(cleaned, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            pass
        try:
            return datetime.fromtimestamp(float(cleaned), tz=timezone.utc)
        except ValueError:
            pass
    return _now_utc()


def parse_optional_bool(value: Any) -> Optional[bool]:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "y", "anomaly", "malicious"}:
            return True
        if lowered in {"0", "false", "no", "n", "normal", "benign", "clean"}:
            return False
    return None


def load_records(path: Path) -> List[Dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        with path.open("r", newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))

    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []

    if suffix in {".jsonl", ".ndjson"}:
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    parsed = json.loads(text)
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        if isinstance(parsed.get("records"), list):
            return parsed["records"]
        return [parsed]
    raise ValueError(f"Unsupported input payload in {path}")


def extract_raw_log(record: Dict[str, Any]) -> Optional[str]:
    for field_name in ("raw_log", "log", "message", "msg", "content", "line"):
        value = record.get(field_name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def extract_flags(record: Dict[str, Any]) -> Dict[str, Any]:
    flags = record.get("flags")
    if isinstance(flags, dict):
        return dict(flags)

    extracted: Dict[str, Any] = {}
    for field_name in (
        "synthetic_attack",
        "manual_malicious_override",
        "rule_hit",
        "parse_failed",
        "allowlisted_synthetic_attack",
    ):
        value = parse_optional_bool(record.get(field_name))
        if value is not None:
            extracted[field_name] = value
    return extracted


def derive_label(record: Dict[str, Any]) -> Optional[bool]:
    for field_name in ("label", "is_anomaly", "infected", "expected_anomaly", "malicious"):
        value = parse_optional_bool(record.get(field_name))
        if value is not None:
            return value
    return None


def derive_session_key(project_id: str, parsed_fields: Dict[str, Any], record: Dict[str, Any]) -> str:
    identity_candidates = [
        parsed_fields.get("auth_user"),
        record.get("session_key"),
        record.get("session_id"),
        record.get("session"),
        record.get("user_id"),
        record.get("userId"),
        record.get("auth_user"),
        parsed_fields.get("ip_address"),
        record.get("ip"),
    ]
    for value in identity_candidates:
        if isinstance(value, str) and value.strip():
            return f"{project_id}:{value.strip()}"
    stable_payload = json.dumps(record, sort_keys=True, default=str)
    return f"{project_id}:{hashlib.sha256(stable_payload.encode('utf-8')).hexdigest()}"


def derive_incident_key(
    *,
    project_id: str,
    normalized_template: str,
    session_key: str,
    event_time: datetime,
    bucket_minutes: int,
    label_incident_id: Optional[str] = None,
) -> str:
    if label_incident_id:
        return label_incident_id
    bucket_minute = (event_time.minute // bucket_minutes) * bucket_minutes
    bucket = event_time.replace(minute=bucket_minute, second=0, microsecond=0)
    return f"{project_id}:{normalized_template}:{session_key}:{bucket.isoformat()}"


def default_eval_start_index(
    total_events: int,
    *,
    eval_start_index: Optional[int],
    train_fraction: float,
) -> int:
    if eval_start_index is not None:
        return max(0, min(eval_start_index, total_events))
    fraction = min(max(train_fraction, 0.0), 1.0)
    return int(total_events * fraction)


@dataclass
class ReplayEvent:
    event_time: datetime
    project_id: str
    project_name: str
    warmup_threshold: int
    log_type: str
    raw_log: str
    parsed_fields: Dict[str, Any]
    normalized_event: str
    session_key: str
    flags: Dict[str, Any]
    label: Optional[bool]
    label_incident_id: Optional[str]
    metadata: Dict[str, Any]


@dataclass
class LoaderStats:
    total_records: int = 0
    parsed_records: int = 0
    parse_failures: int = 0


@dataclass
class ProjectReplayStats:
    project_id: str
    project_name: str
    warmup_threshold: int
    total_records: int = 0
    parse_failures: int = 0
    baseline_eligible: int = 0
    observed_hours: set[int] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self) -> None:
        if self.observed_hours is None:
            self.observed_hours = set()
        if self.metadata is None:
            self.metadata = {}

    def as_detector_payload(self) -> Dict[str, Any]:
        return {
            "project_id": self.project_id,
            "project_name": self.project_name,
            "warmup_threshold": self.warmup_threshold,
            "total_records": self.total_records,
            "parse_failures": self.parse_failures,
            "baseline_eligible": self.baseline_eligible,
            "observed_hours": sorted(self.observed_hours),
            "data_quality_incident_open": (
                (self.parse_failures / self.total_records) > 0.05 if self.total_records else False
            ),
            "metadata": self.metadata,
        }


def summarize_category_counts(records: Sequence[Dict[str, Any]], *, keys: Sequence[str]) -> List[Dict[str, Any]]:
    counter: Counter[str] = Counter()
    for record in records:
        parts: List[str] = []
        for key in keys:
            value = record.get(key)
            if value is None or value == "":
                value = "unknown"
            parts.append(f"{key}={value}")
        counter[" | ".join(parts)] += 1
    return [
        {"category": category, "count": count}
        for category, count in counter.most_common()
    ]


class EventLoader:
    def __init__(self, default_log_type: str, default_warmup_threshold: int) -> None:
        self.parser = LogParserService()
        self.default_log_type = default_log_type
        self.default_warmup_threshold = default_warmup_threshold

    def load(self, path: Path) -> Tuple[List[ReplayEvent], LoaderStats, Dict[str, ProjectReplayStats]]:
        records = load_records(path)
        stats = LoaderStats(total_records=len(records))
        project_stats: Dict[str, ProjectReplayStats] = {}
        events: List[ReplayEvent] = []

        for record in records:
            project_id = str(record.get("project_id") or "default-project")
            project_name = str(record.get("project_name") or project_id)
            warmup_threshold = int(record.get("warmup_threshold") or self.default_warmup_threshold)
            project_entry = project_stats.setdefault(
                project_id,
                ProjectReplayStats(
                    project_id=project_id,
                    project_name=project_name,
                    warmup_threshold=warmup_threshold,
                    metadata={
                        "org_id": record.get("org_id"),
                        "log_type": record.get("log_type") or self.default_log_type,
                    },
                ),
            )
            project_entry.total_records += 1

            raw_log = extract_raw_log(record)
            log_type = str(record.get("log_type") or self.default_log_type)
            event_time = record.get("event_time") or record.get("timestamp")
            flags = extract_flags(record)

            if not raw_log:
                stats.parse_failures += 1
                project_entry.parse_failures += 1
                continue

            parsed_fields = record.get("parsed_fields")
            if not isinstance(parsed_fields, dict):
                parsed_log, parse_error = self.parser.parse_log_with_error(raw_log, log_type, fallback_event_time=event_time)
                if parsed_log is None:
                    stats.parse_failures += 1
                    project_entry.parse_failures += 1
                    continue
                parsed_fields = {
                    "ip_address": parsed_log.get("ip_address"),
                    "method": parsed_log.get("method"),
                    "path": parsed_log.get("path"),
                    "protocol": parsed_log.get("protocol"),
                    "status_code": parsed_log.get("status_code"),
                    "size": parsed_log.get("size"),
                    "auth_user": parsed_log.get("auth_user"),
                    "referer": parsed_log.get("referer"),
                    "user_agent": parsed_log.get("user_agent"),
                }
                normalized_event = parsed_log.get("normalized_event") or self.parser.build_normalized_event(parsed_log)
                resolved_event_time = parse_timestamp(parsed_log.get("timestamp"))
            else:
                normalized_event = str(record.get("normalized_event") or "").strip()
                if not normalized_event:
                    method = parsed_fields.get("method", "GET")
                    path_value = parsed_fields.get("path", "/")
                    protocol = parsed_fields.get("protocol", "HTTP/1.1")
                    status_code = parsed_fields.get("status_code", 0)
                    normalized_event = f"{method} {path_value} {protocol} {status_code}"
                resolved_event_time = parse_timestamp(event_time)

            stats.parsed_records += 1
            baseline_blocked = any(
                bool(flags.get(name))
                for name in (
                    "synthetic_attack",
                    "manual_malicious_override",
                    "rule_hit",
                    "parse_failed",
                    "allowlisted_synthetic_attack",
                )
            )
            project_entry.baseline_eligible += 0 if baseline_blocked else 1
            project_entry.observed_hours.add(resolved_event_time.hour)

            session_key = str(record.get("session_key") or derive_session_key(project_id, parsed_fields, record))
            label = derive_label(record)
            label_incident_id = record.get("label_incident_id") or record.get("incident_id")

            events.append(
                ReplayEvent(
                    event_time=resolved_event_time,
                    project_id=project_id,
                    project_name=project_name,
                    warmup_threshold=warmup_threshold,
                    log_type=log_type,
                    raw_log=raw_log,
                    parsed_fields=parsed_fields,
                    normalized_event=normalized_event,
                    session_key=session_key,
                    flags=flags,
                    label=label,
                    label_incident_id=str(label_incident_id) if label_incident_id else None,
                    metadata={
                        "org_id": record.get("org_id"),
                        "source": record.get("source", "backtest"),
                        "traffic_profile": record.get("traffic_profile", "standard"),
                    },
                )
            )

        events.sort(key=lambda event: event.event_time)
        return events, stats, project_stats


def compute_binary_metrics(records: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    labeled_records = [record for record in records if record.get("label") is not None]
    if not labeled_records:
        return {"available": False}

    tp = fp = tn = fn = 0
    for record in labeled_records:
        predicted = bool(record["predicted"])
        actual = bool(record["label"])
        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and actual:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "available": True,
        "support": len(labeled_records),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def compute_incident_metrics(records: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    labeled_records = [record for record in records if record.get("label") is not None]
    if not labeled_records:
        return {"available": False}

    predicted_incidents = {
        record["predicted_incident_id"]
        for record in labeled_records
        if record["predicted"] and record.get("predicted_incident_id")
    }
    true_incidents = {
        record["label_incident_id"]
        for record in labeled_records
        if record["label"] and record.get("label_incident_id")
    }
    if not true_incidents:
        return {"available": False}

    tp = len(predicted_incidents & true_incidents)
    fp = len(predicted_incidents - true_incidents)
    fn = len(true_incidents - predicted_incidents)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "available": True,
        "predicted_incidents": len(predicted_incidents),
        "true_incidents": len(true_incidents),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


class DetectorAdapter:
    def prime_projects(self, project_stats: Dict[str, ProjectReplayStats]) -> None:
        return None

    def detect(self, event: ReplayEvent) -> Dict[str, Any]:
        raise NotImplementedError


class AdaptiveAdapter(DetectorAdapter):
    def __init__(self, *, model_dir: Path, storage_root: Path, warmup_threshold: int, device: str) -> None:
        sys.path.insert(0, str(REPO_ROOT / "realtime_anomaly_detection"))
        from models.adaptive_detector import AdaptiveEnsembleDetector

        os.environ["ADAPTIVE_STATE_DIR"] = str(storage_root / "adaptive_state")
        self.detector = AdaptiveEnsembleDetector(
            model_dir=model_dir,
            warmup_logs=warmup_threshold,
            window_size=20,
            device=device,
        )

    def detect(self, event: ReplayEvent) -> Dict[str, Any]:
        return self.detector.detect_structured(
            project_id=event.project_id,
            session_key=event.session_key,
            event_time=event.event_time.isoformat(),
            normalized_event=event.normalized_event,
            raw_log=event.raw_log,
            parsed_fields=event.parsed_fields,
            flags=event.flags,
        )


class MultiTenantAdapter(DetectorAdapter):
    def __init__(self, *, model_dir: Path, storage_root: Path, warmup_threshold: int, device: str) -> None:
        sys.path.insert(0, str(REPO_ROOT / "realtime_anomaly_detection"))
        from models.multi_tenant_detector import MultiTenantDetector

        self.detector = MultiTenantDetector(
            base_model_dir=model_dir,
            storage_dir=storage_root / "multi_tenant",
            default_warmup_threshold=warmup_threshold,
            window_size=20,
            device=device,
            teacher_update_interval_days=7,
        )

    def prime_projects(self, project_stats: Dict[str, ProjectReplayStats]) -> None:
        for stats in project_stats.values():
            self.detector.ensure_project(
                project_id=stats.project_id,
                project_name=stats.project_name,
                warmup_threshold=stats.warmup_threshold,
                metadata=stats.metadata,
            )
            self.detector.record_project_ingest_stats(
                stats.project_id,
                total_records=stats.total_records,
                parse_failures=stats.parse_failures,
                baseline_eligible=stats.baseline_eligible,
                observed_hours=sorted(stats.observed_hours),
                data_quality_incident_open=(
                    (stats.parse_failures / stats.total_records) > 0.05 if stats.total_records else False
                ),
            )

    def detect(self, event: ReplayEvent) -> Dict[str, Any]:
        return self.detector.detect_structured(
            project_id=event.project_id,
            project_name=event.project_name,
            warmup_threshold=event.warmup_threshold,
            session_key=event.session_key,
            event_time=event.event_time.isoformat(),
            normalized_event=event.normalized_event,
            raw_log=event.raw_log,
            parsed_fields=event.parsed_fields,
            flags=event.flags,
            metadata=event.metadata,
        )


def build_adapter(name: str, *, model_dir: Path, storage_root: Path, warmup_threshold: int, device: str) -> DetectorAdapter:
    if name == "adaptive":
        return AdaptiveAdapter(model_dir=model_dir, storage_root=storage_root, warmup_threshold=warmup_threshold, device=device)
    if name == "multi_tenant":
        return MultiTenantAdapter(model_dir=model_dir, storage_root=storage_root, warmup_threshold=warmup_threshold, device=device)
    raise ValueError(f"Unsupported detector mode: {name}")


def select_eval_index(
    events: Sequence[ReplayEvent],
    *,
    eval_start_index: Optional[int],
    eval_start_time: Optional[str],
    train_fraction: float,
) -> int:
    if eval_start_time:
        threshold = parse_timestamp(eval_start_time)
        for index, event in enumerate(events):
            if event.event_time >= threshold:
                return index
        return len(events)
    return default_eval_start_index(len(events), eval_start_index=eval_start_index, train_fraction=train_fraction)


def replay_detector(
    adapter_name: str,
    adapter: DetectorAdapter,
    events: Sequence[ReplayEvent],
    *,
    eval_start_index: int,
    bucket_minutes: int,
) -> Dict[str, Any]:
    replay_rows: List[Dict[str, Any]] = []
    start = time.perf_counter()

    for index, event in enumerate(events):
        result = adapter.detect(event)
        predicted = bool(result.get("is_anomaly", False))
        predicted_incident_id = result.get("incident_id") or derive_incident_key(
            project_id=event.project_id,
            normalized_template=event.normalized_event,
            session_key=event.session_key,
            event_time=event.event_time,
            bucket_minutes=bucket_minutes,
        )
        label_incident_id = None
        if event.label is True:
            label_incident_id = derive_incident_key(
                project_id=event.project_id,
                normalized_template=event.normalized_event,
                session_key=event.session_key,
                event_time=event.event_time,
                bucket_minutes=bucket_minutes,
                label_incident_id=event.label_incident_id,
            )

        replay_rows.append(
            {
                "index": index,
                "eval": index >= eval_start_index,
                "event_time": event.event_time.isoformat(),
                "project_id": event.project_id,
                "predicted": predicted,
                "anomaly_score": result.get("anomaly_score", 0.0),
                "policy_score": result.get("policy_score", 0.0),
                "phase": result.get("phase"),
                "model_type": result.get("model_type") or result.get("using_model"),
                "decision_reason": result.get("decision_reason"),
                "final_decision": result.get("final_decision"),
                "traffic_class": result.get("traffic_class"),
                "incident_type": result.get("incident_type"),
                "label": event.label,
                "predicted_incident_id": predicted_incident_id,
                "label_incident_id": label_incident_id,
                "student_training_blockers": result.get("student_training_blockers", []),
            }
        )

    duration = time.perf_counter() - start
    eval_rows = [row for row in replay_rows if row["eval"]]
    false_positive_rows = [row for row in eval_rows if row.get("label") is False and row.get("predicted")]
    false_negative_rows = [row for row in eval_rows if row.get("label") is True and not row.get("predicted")]
    predicted_rows = [row for row in eval_rows if row.get("predicted")]
    return {
        "detector": adapter_name,
        "duration_seconds": round(duration, 3),
        "events_replayed": len(replay_rows),
        "eval_events": len(eval_rows),
        "binary_metrics": compute_binary_metrics(eval_rows),
        "incident_metrics": compute_incident_metrics(eval_rows),
        "projects_seen": sorted({row["project_id"] for row in replay_rows}),
        "avg_events_per_second": round(len(replay_rows) / duration, 2) if duration else None,
        "alert_volume": {
            "predicted_alerts": len(predicted_rows),
            "alert_rate": round((len(predicted_rows) / len(eval_rows)) * 100, 2) if eval_rows else 0.0,
            "alerts_by_project": dict(Counter(row["project_id"] for row in predicted_rows)),
            "alerts_by_reason": dict(Counter((row.get("decision_reason") or "unknown") for row in predicted_rows)),
        },
        "false_positive_categories": summarize_category_counts(
            false_positive_rows,
            keys=("decision_reason", "incident_type", "traffic_class"),
        ),
        "false_negative_categories": summarize_category_counts(
            false_negative_rows,
            keys=("decision_reason", "final_decision"),
        ),
        "final_project_blockers": {
            row["project_id"]: row["student_training_blockers"]
            for row in eval_rows[-50:]
            if row["student_training_blockers"]
        },
    }


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Chronological backtest harness for anomaly detectors")
    parser.add_argument("--input", required=True, help="Path to JSON/JSONL/CSV replay dataset")
    parser.add_argument("--mode", choices=["adaptive", "multi_tenant"], default="multi_tenant")
    parser.add_argument("--shadow-mode", choices=["adaptive", "multi_tenant"], default=None)
    parser.add_argument("--model-dir", default=str(REPO_ROOT / "artifacts" / "ensemble_model_export"))
    parser.add_argument("--storage-root", default=None, help="Optional working directory for detector state")
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--default-log-type", choices=["apache", "nginx"], default="apache")
    parser.add_argument("--warmup-threshold", type=int, default=10000)
    parser.add_argument("--eval-start-time", default=None)
    parser.add_argument("--eval-start-index", type=int, default=None)
    parser.add_argument("--train-fraction", type=float, default=0.7)
    parser.add_argument("--incident-bucket-minutes", type=int, default=15)
    parser.add_argument("--output", default=None, help="Optional JSON report path")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    input_path = Path(args.input).expanduser().resolve()
    model_dir = Path(args.model_dir).expanduser().resolve()
    if not input_path.exists():
        parser.error(f"Input file not found: {input_path}")
    if not model_dir.exists():
        parser.error(f"Model directory not found: {model_dir}")

    loader = EventLoader(
        default_log_type=args.default_log_type,
        default_warmup_threshold=args.warmup_threshold,
    )
    events, loader_stats, project_stats = loader.load(input_path)
    if not events:
        parser.error("No replayable events were loaded from the dataset")

    eval_start_index = select_eval_index(
        events,
        eval_start_index=args.eval_start_index,
        eval_start_time=args.eval_start_time,
        train_fraction=args.train_fraction,
    )

    if args.storage_root:
        storage_root = Path(args.storage_root).expanduser().resolve()
        storage_root.mkdir(parents=True, exist_ok=True)
    else:
        storage_root = Path(tempfile.mkdtemp(prefix="backtest_harness_", dir=str(REPO_ROOT / "scripts")))

    adapter_specs = [(args.mode, build_adapter(args.mode, model_dir=model_dir, storage_root=storage_root / args.mode, warmup_threshold=args.warmup_threshold, device=args.device))]
    if args.shadow_mode:
        adapter_specs.append(
            (
                args.shadow_mode,
                build_adapter(
                    args.shadow_mode,
                    model_dir=model_dir,
                    storage_root=storage_root / args.shadow_mode,
                    warmup_threshold=args.warmup_threshold,
                    device=args.device,
                ),
            )
        )

    for _, adapter in adapter_specs:
        adapter.prime_projects(project_stats)

    reports = [
        replay_detector(
            adapter_name=name,
            adapter=adapter,
            events=events,
            eval_start_index=eval_start_index,
            bucket_minutes=args.incident_bucket_minutes,
        )
        for name, adapter in adapter_specs
    ]

    report = {
        "input": str(input_path),
        "model_dir": str(model_dir),
        "storage_root": str(storage_root),
        "total_events": len(events),
        "eval_start_index": eval_start_index,
        "loader_stats": asdict(loader_stats),
        "project_stats": {
            project_id: stats.as_detector_payload()
            for project_id, stats in project_stats.items()
        },
        "reports": reports,
    }

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
