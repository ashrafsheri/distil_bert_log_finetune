"""Tests for scripts.demo_realtime."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from scripts.demo_realtime import load_mixed_records
from scripts.train_base_model import parse_apache_log_line


def _apache_line(ts: str, path: str = "/api/users") -> str:
    return f'127.0.0.1 - - [{ts}] "GET {path} HTTP/1.1" 200 123 "-" "pytest"'


def test_load_mixed_records_restamps_logs_into_recent_window(tmp_path: Path) -> None:
    log_path = tmp_path / "synthetic.log"
    log_path.write_text(
        "\n".join(
            [
                _apache_line("12/Apr/2026:10:00:01 +0000", "/api/users"),
                _apache_line("12/Apr/2026:10:00:02 +0000", "/api/users/42"),
            ]
        ),
        encoding="utf-8",
    )

    records = load_mixed_records(log_path, 0.0)

    assert len(records) == 2
    now = datetime.now(timezone.utc)
    for record in records:
        parsed = parse_apache_log_line(record.raw_log)
        assert parsed is not None
        delta = abs((now - parsed["timestamp"]).total_seconds())
        assert delta <= 300


def test_load_mixed_records_can_preserve_original_timestamps(tmp_path: Path) -> None:
    log_path = tmp_path / "synthetic.log"
    original_ts = "12/Apr/2026:10:00:01 +0000"
    log_path.write_text(_apache_line(original_ts), encoding="utf-8")

    records = load_mixed_records(log_path, 0.0, preserve_timestamps=True)

    assert len(records) == 1
    parsed = parse_apache_log_line(records[0].raw_log)
    assert parsed is not None
    assert parsed["timestamp"].strftime("%d/%b/%Y:%H:%M:%S %z") == original_ts
