"""Regression tests for hardened Fluent Bit ingest behavior."""

from __future__ import annotations

import os
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@localhost/test_db",
)

from app.services.log_service import LogService


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

    should_skip, reason = LogService.should_skip_detection({"path": "/orders"})
    assert should_skip is False
    assert reason is None
