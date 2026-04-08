"""Regression tests for hardened Fluent Bit ingest behavior."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@localhost/test_db",
)

from app.services.log_service import LogService


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string (no microseconds)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def test_extract_log_candidates_rejects_arbitrary_json_records() -> None:
    candidates = LogService.extract_log_candidates(
        [
            {
                "service": "billing",
                "level": "info",
                "message_body": {"status": "ok"},
                "timestamp": "2026-03-31T10:00:00Z",
            }
        ]
    )

    assert len(candidates) == 1
    assert candidates[0]["raw_log"] is None
    assert candidates[0]["extraction_error"] == "unsupported_record_format"


def test_build_session_key_prefers_authenticated_identity_then_ip_then_hash() -> None:
    parsed_with_auth = {"auth_user": "alice", "ip_address": "198.51.100.10"}
    parsed_with_ip_only = {"auth_user": "", "ip_address": "198.51.100.11"}
    parsed_without_identity = {"auth_user": "", "ip_address": ""}

    auth_key = LogService.build_session_key("project-1", parsed_with_auth, {"session_id": "ignored"})
    ip_key = LogService.build_session_key("project-1", parsed_with_ip_only, {"source": "edge"})
    hash_key = LogService.build_session_key("project-1", parsed_without_identity, {"source": "edge", "tag": "a"})

    assert auth_key == "project-1:alice"
    assert ip_key == "project-1:198.51.100.11"
    assert hash_key.startswith("project-1:")
    assert len(hash_key.split(":", maxsplit=1)[1]) == 64


def test_format_parse_failure_for_storage_captures_failure_fields() -> None:
    doc = LogService.format_parse_failure_for_storage(
        raw_log='{"unexpected":"json"}',
        batch_id="batch-1",
        org_id="project-1",
        event_time="2026-03-31T10:00:00+00:00",
        parse_error="unsupported_record_format",
        source_record={"unexpected": "json"},
    )

    assert doc["project_id"] == "project-1"
    assert doc["parse_status"] == "failed"
    assert doc["parse_error"] == "unsupported_record_format"
    assert doc["detection_status"] == "skipped"
    assert doc["detection_error"] == "parse_failed"
    assert doc["session_key_hash"]
    assert doc["event_time"] == "2026-03-31T10:00:00+00:00"


def test_should_skip_detection_for_health_checks() -> None:
    should_skip, reason = LogService.should_skip_detection({"path": "/health"})
    assert should_skip is True
    assert reason == "health_check_skipped"

    should_skip, reason = LogService.should_skip_detection({"path": "/socket.io/?EIO=4&transport=polling"})
    assert should_skip is True
    assert reason == "transport_noise_skipped"

    should_skip, reason = LogService.should_skip_detection({"path": "/storage/v1/object/sign/foo/bar.png?token=abc"})
    assert should_skip is True
    assert reason == "signed_asset_skipped"

    should_skip, reason = LogService.should_skip_detection({"path": "/orders"})
    assert should_skip is False
    assert reason is None


def test_classify_traffic_marks_probe_and_known_attack_flags() -> None:
    now = _now_iso()
    probe = LogService.classify_traffic(
        parsed_log={"path": "/health", "timestamp": now},
        source_record={"path": "/health"},
        raw_log='127.0.0.1 - - [01/Apr/2026:12:00:00 +0000] "GET /health HTTP/1.1" 200 0',
        event_time=now,
    )
    attack = LogService.classify_traffic(
        parsed_log={
            "path": "/index.php?lang=../../../../../../etc/passwd",
            "timestamp": now,
        },
        source_record={"tag": "edge"},
        raw_log='127.0.0.1 - - [01/Apr/2026:12:00:00 +0000] "GET /index.php?lang=../../../../../../etc/passwd HTTP/1.1" 404 0',
        event_time=now,
    )

    assert probe["traffic_class"] == "internal_probe"
    assert probe["baseline_eligible"] is False
    assert probe["flags"]["internal_probe"] is True

    assert attack["traffic_class"] == "user_traffic"
    assert attack["baseline_eligible"] is False
    assert attack["flags"]["rule_hit"] is True


def test_classify_traffic_excludes_transport_and_signed_asset_noise() -> None:
    now = _now_iso()
    transport = LogService.classify_traffic(
        parsed_log={"path": "/socket.io/?EIO=4&transport=polling", "timestamp": now},
        source_record={"path": "/socket.io/?EIO=4&transport=polling"},
        raw_log='127.0.0.1 - - [01/Apr/2026:12:00:00 +0000] "GET /socket.io/?EIO=4&transport=polling HTTP/1.1" 200 0',
        event_time=now,
    )
    signed_asset = LogService.classify_traffic(
        parsed_log={"path": "/storage/v1/object/sign/a/b.png?token=abc", "timestamp": now},
        source_record={"path": "/storage/v1/object/sign/a/b.png?token=abc"},
        raw_log='127.0.0.1 - - [01/Apr/2026:12:00:00 +0000] "GET /storage/v1/object/sign/a/b.png?token=abc HTTP/1.1" 200 0',
        event_time=now,
    )

    assert transport["traffic_class"] == "transport_noise"
    assert transport["baseline_eligible"] is False
    assert transport["detection_status"] == "skipped"

    assert signed_asset["traffic_class"] == "signed_asset_access"
    assert signed_asset["baseline_eligible"] is False
    assert signed_asset["detection_status"] == "skipped"
