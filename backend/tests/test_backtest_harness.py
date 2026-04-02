"""Regression tests for the chronological backtest harness."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
HARNESS_PATH = REPO_ROOT / "scripts" / "backtest_harness.py"


def load_harness_module():
    spec = importlib.util.spec_from_file_location("backtest_harness", HARNESS_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_derive_session_key_hash_fallback_is_stable() -> None:
    harness = load_harness_module()

    record = {"source": "edge", "tag": "api", "request_id": "abc"}
    session_key = harness.derive_session_key("proj-1", {"auth_user": "", "ip_address": ""}, record)

    assert session_key.startswith("proj-1:")
    assert len(session_key.split(":", maxsplit=1)[1]) == 64
    assert session_key == harness.derive_session_key("proj-1", {"auth_user": "", "ip_address": ""}, record)


def test_event_loader_tracks_parse_failures_and_baseline_eligibility(tmp_path: Path) -> None:
    harness = load_harness_module()
    dataset_path = tmp_path / "replay.jsonl"
    valid_log = '127.0.0.1 - frank [10/Oct/2000:13:55:36 +0000] "GET /orders HTTP/1.1" 200 2326'
    blocked_log = '127.0.0.2 - - [10/Oct/2000:14:10:00 +0000] "POST /login HTTP/1.1" 401 128'
    dataset_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "project_id": "proj-a",
                        "project_name": "Project A",
                        "log_type": "apache",
                        "raw_log": valid_log,
                        "event_time": "2000-10-10T13:55:36Z",
                    }
                ),
                json.dumps(
                    {
                        "project_id": "proj-a",
                        "project_name": "Project A",
                        "log_type": "apache",
                        "raw_log": blocked_log,
                        "event_time": "2000-10-10T14:10:00Z",
                        "allowlisted_synthetic_attack": True,
                    }
                ),
                json.dumps(
                    {
                        "project_id": "proj-a",
                        "project_name": "Project A",
                        "log_type": "apache",
                        "event_time": "2000-10-10T14:11:00Z",
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )

    loader = harness.EventLoader(default_log_type="apache", default_warmup_threshold=10)
    events, loader_stats, project_stats = loader.load(dataset_path)

    assert len(events) == 2
    assert loader_stats.total_records == 3
    assert loader_stats.parsed_records == 2
    assert loader_stats.parse_failures == 1

    project = project_stats["proj-a"]
    assert project.total_records == 3
    assert project.parse_failures == 1
    assert project.baseline_eligible == 1
    assert sorted(project.observed_hours) == [13, 14]


def test_metric_helpers_report_binary_and_incident_scores() -> None:
    harness = load_harness_module()
    rows = [
        {
            "predicted": True,
            "label": True,
            "predicted_incident_id": "incident-a",
            "label_incident_id": "incident-a",
        },
        {
            "predicted": True,
            "label": False,
            "predicted_incident_id": "incident-b",
            "label_incident_id": None,
        },
        {
            "predicted": False,
            "label": True,
            "predicted_incident_id": "incident-c",
            "label_incident_id": "incident-c",
        },
        {
            "predicted": False,
            "label": False,
            "predicted_incident_id": None,
            "label_incident_id": None,
        },
    ]

    binary = harness.compute_binary_metrics(rows)
    incident = harness.compute_incident_metrics(rows)

    assert binary == {
        "available": True,
        "support": 4,
        "tp": 1,
        "fp": 1,
        "tn": 1,
        "fn": 1,
        "precision": 0.5,
        "recall": 0.5,
        "f1": 0.5,
    }
    assert incident == {
        "available": True,
        "predicted_incidents": 2,
        "true_incidents": 2,
        "tp": 1,
        "fp": 1,
        "fn": 1,
        "precision": 0.5,
        "recall": 0.5,
        "f1": 0.5,
    }


def test_summarize_category_counts_groups_rows_by_requested_keys() -> None:
    harness = load_harness_module()
    summary = harness.summarize_category_counts(
        [
            {"decision_reason": "known_attack_policy", "incident_type": "known_exploit", "traffic_class": "user_traffic"},
            {"decision_reason": "known_attack_policy", "incident_type": "known_exploit", "traffic_class": "user_traffic"},
            {"decision_reason": "behavioral_anomaly", "incident_type": "behavioral_anomaly", "traffic_class": "user_traffic"},
        ],
        keys=("decision_reason", "incident_type", "traffic_class"),
    )

    assert summary == [
        {
            "category": "decision_reason=known_attack_policy | incident_type=known_exploit | traffic_class=user_traffic",
            "count": 2,
        },
        {
            "category": "decision_reason=behavioral_anomaly | incident_type=behavioral_anomaly | traffic_class=user_traffic",
            "count": 1,
        },
    ]


def test_select_eval_index_supports_time_cutoff() -> None:
    harness = load_harness_module()
    event_a = harness.ReplayEvent(
        event_time=datetime(2026, 4, 1, 9, 0, tzinfo=timezone.utc),
        project_id="proj-a",
        project_name="Project A",
        warmup_threshold=10,
        log_type="apache",
        raw_log="a",
        parsed_fields={"ip_address": "127.0.0.1"},
        normalized_event="GET /a HTTP/1.1 200",
        session_key="proj-a:127.0.0.1",
        flags={},
        label=None,
        label_incident_id=None,
        metadata={},
    )
    event_b = harness.ReplayEvent(
        event_time=datetime(2026, 4, 1, 10, 0, tzinfo=timezone.utc),
        project_id="proj-a",
        project_name="Project A",
        warmup_threshold=10,
        log_type="apache",
        raw_log="b",
        parsed_fields={"ip_address": "127.0.0.1"},
        normalized_event="GET /b HTTP/1.1 200",
        session_key="proj-a:127.0.0.1",
        flags={},
        label=None,
        label_incident_id=None,
        metadata={},
    )

    eval_index = harness.select_eval_index(
        [event_a, event_b],
        eval_start_index=None,
        eval_start_time="2026-04-01T09:30:00Z",
        train_fraction=0.7,
    )

    assert eval_index == 1
