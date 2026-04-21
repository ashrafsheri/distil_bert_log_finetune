#!/usr/bin/env python3
"""
Replay synthetic logs against the live backend, optionally injecting attacks.
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote, urljoin

import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.log_generator import (
    COMMAND_INJECTION_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    SQL_INJECTION_PAYLOADS,
    XSS_PAYLOADS,
)
from scripts.train_base_model import parse_apache_log_line


ATTACK_PAYLOADS = {
    "sql_injection": SQL_INJECTION_PAYLOADS,
    "xss": XSS_PAYLOADS,
    "path_traversal": PATH_TRAVERSAL_PAYLOADS,
    "command_injection": COMMAND_INJECTION_PAYLOADS,
}


@dataclass
class ReplayRecord:
    raw_log: str
    method: str
    path: str
    timestamp_iso: str
    attack_type: Optional[str] = None

    @property
    def is_attack(self) -> bool:
        return self.attack_type is not None


def _format_terminal_row(record: ReplayRecord, prefix: str) -> str:
    timestamp = record.timestamp_iso[11:19]
    marker = f" [INJECTED ATTACK: {record.attack_type}]" if record.attack_type else ""
    return f"[{timestamp}] {record.method:<6} {record.path:<40} {prefix}{marker}"


def _rebuild_log_line(
    parsed: Dict[str, object],
    *,
    path: Optional[str] = None,
    status: Optional[int] = None,
    timestamp: Optional[datetime] = None,
) -> str:
    ts = (timestamp or parsed["timestamp"]).astimezone(timezone.utc)
    timestamp_str = ts.strftime("%d/%b/%Y:%H:%M:%S %z")
    method = parsed["method"]
    protocol = parsed["protocol"]
    resolved_path = path or str(parsed["path"])
    resolved_status = int(status if status is not None else parsed["status"])
    size = max(int(parsed.get("size", 0) or 0), 128)
    return (
        f'{parsed["ip"]} - - [{timestamp_str}] "{method} {resolved_path} {protocol}" '
        f'{resolved_status} {size} "-" "LogGuard Demo/1.0"'
    )


def _inject_attack(parsed: Dict[str, object]) -> Tuple[str, str]:
    attack_type = random.choice(list(ATTACK_PAYLOADS.keys()))
    payload = random.choice(ATTACK_PAYLOADS[attack_type])

    if attack_type == "sql_injection":
        path = f"/api/users?id={quote(payload, safe='')}"
    elif attack_type == "xss":
        path = f"/api/search?q={quote(payload, safe='')}"
    elif attack_type == "path_traversal":
        path = f"/download?file={quote(payload, safe='')}"
    else:
        path = f"/api/reports/export?target={quote(payload, safe='')}"

    status = random.choice([400, 401, 403, 500])
    return _rebuild_log_line(parsed, path=path, status=status), attack_type


def _restamp_records(records: List[ReplayRecord], *, window_seconds: int = 300) -> List[ReplayRecord]:
    if not records:
        return []

    now = datetime.now(timezone.utc)
    span_seconds = max(0, min(window_seconds, len(records) - 1))
    start = now - timedelta(seconds=span_seconds)
    step = span_seconds / max(len(records) - 1, 1) if len(records) > 1 else 0.0

    restamped: List[ReplayRecord] = []
    for index, record in enumerate(records):
        parsed = parse_apache_log_line(record.raw_log)
        if parsed is None:
            restamped.append(record)
            continue
        restamped_dt = start + timedelta(seconds=step * index)
        restamped.append(
            ReplayRecord(
                raw_log=_rebuild_log_line(parsed, timestamp=restamped_dt),
                method=record.method,
                path=record.path,
                timestamp_iso=restamped_dt.isoformat(),
                attack_type=record.attack_type,
            )
        )
    return restamped


def load_mixed_records(log_path: Path, attack_ratio: float, *, preserve_timestamps: bool = False) -> List[ReplayRecord]:
    records: List[ReplayRecord] = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parsed = parse_apache_log_line(line)
        if parsed is None:
            continue

        raw_log = line
        attack_type: Optional[str] = None
        if random.random() < attack_ratio:
            raw_log, attack_type = _inject_attack(parsed)
            parsed = parse_apache_log_line(raw_log) or parsed

        records.append(
            ReplayRecord(
                raw_log=raw_log,
                method=str(parsed["method"]),
                path=str(parsed["path"]),
                timestamp_iso=parsed["timestamp"].isoformat(),
                attack_type=attack_type,
            )
        )
    if preserve_timestamps:
        return records
    return _restamp_records(records)


def chunked(records: List[ReplayRecord], batch_size: int) -> Iterable[List[ReplayRecord]]:
    for index in range(0, len(records), batch_size):
        yield records[index:index + batch_size]


def send_batch(send_url: str, api_key: str, batch: List[ReplayRecord]) -> Tuple[bool, str]:
    payload = [
        {
            "log": record.raw_log,
            "timestamp": record.timestamp_iso,
            "synthetic_attack": record.is_attack,
            "attack_type": record.attack_type,
        }
        for record in batch
    ]
    response = requests.post(
        send_url,
        headers={"X-API-Key": api_key},
        json=payload,
        timeout=30,
    )
    if response.status_code != 200:
        return False, f"HTTP {response.status_code}: {response.text[:300]}"
    return True, response.text[:300]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Replay synthetic logs against LogGuard backend")
    parser.add_argument("--logs", required=True, help="Path to synthetic log file")
    parser.add_argument("--api-key", required=True, help="Project API key")
    parser.add_argument("--backend-url", required=True, help="Backend base URL, e.g. http://localhost:8000")
    parser.add_argument("--attack-ratio", type=float, default=0.10, help="Fraction of lines to replace with attacks")
    parser.add_argument("--batch-size", type=int, default=10, help="Logs per POST request")
    parser.add_argument("--rate", type=float, default=0.5, help="Seconds to wait between batches")
    parser.add_argument("--dry-run", action="store_true", help="Print mixed stream without sending")
    parser.add_argument(
        "--preserve-timestamps",
        action="store_true",
        help="Use the original log timestamps instead of restamping into a recent replay window",
    )
    parser.add_argument("--seed", type=int, default=None, help="Optional RNG seed")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    if args.seed is not None:
        random.seed(args.seed)

    log_path = Path(args.logs)
    if not log_path.exists():
        print(f"[ERROR] Log file not found: {log_path}", file=sys.stderr)
        raise SystemExit(1)

    send_url = urljoin(args.backend_url.rstrip("/") + "/", "api/v1/logs/agent/send-logs")
    mixed_records = load_mixed_records(
        log_path,
        args.attack_ratio,
        preserve_timestamps=args.preserve_timestamps,
    )

    total_batches = 0
    injected_attacks = 0

    try:
        for batch in chunked(mixed_records, args.batch_size):
            total_batches += 1
            injected_attacks += sum(1 for record in batch if record.is_attack)

            if args.dry_run:
                for record in batch:
                    print(_format_terminal_row(record, "→ dry-run"))
                continue

            ok, detail = send_batch(send_url, args.api_key, batch)
            if not ok:
                print(f"[ERROR] Batch {total_batches} failed: {detail}", file=sys.stderr)
                for record in batch:
                    print(_format_terminal_row(record, "→ send-failed"))
            else:
                for record in batch:
                    print(_format_terminal_row(record, "→ sent"))

            if args.rate > 0:
                time.sleep(args.rate)
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
    finally:
        print(
            f"Summary: batches={total_batches} injected_attacks={injected_attacks} "
            f"dry_run={'yes' if args.dry_run else 'no'}"
        )


if __name__ == "__main__":
    main()
