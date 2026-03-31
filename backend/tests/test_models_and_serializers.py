"""Small unit tests that keep Sonar coverage wiring valid in CI."""

from __future__ import annotations

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.models.project import generate_api_key
from app.serializers.log_serializer import LogSerializer


def test_generate_api_key_has_expected_prefix_and_entropy() -> None:
    first_key = generate_api_key()
    second_key = generate_api_key()

    assert first_key.startswith("sk-")
    assert second_key.startswith("sk-")
    assert first_key != second_key
    assert len(first_key) > 20


def test_convert_elasticsearch_logs_to_entries_maps_anomaly_details() -> None:
    logs = LogSerializer.convert_elasticsearch_logs_to_entries(
        [
            {
                "timestamp": "2026-03-31T10:00:00Z",
                "ip_address": "127.0.0.1",
                "api_accessed": "/api/v1/logs",
                "status_code": 200,
                "infected": True,
                "anomaly_score": 0.97,
                "anomaly_details": {
                    "rule_based": {"is_attack": True},
                    "ensemble": {"score": 0.97},
                },
            },
            {
                "timestamp": "2026-03-31T10:00:01Z",
                "ip_address": "127.0.0.2",
                "api_accessed": "/health",
                "status_code": 200,
                "infected": False,
            },
        ]
    )

    assert len(logs) == 2
    assert logs[0].ipAddress == "127.0.0.1"
    assert logs[0].anomaly_details is not None
    assert logs[0].anomaly_details.rule_based == {"is_attack": True}
    assert logs[1].anomaly_details is None


def test_build_log_response_counts_infected_entries() -> None:
    response = LogSerializer.build_log_response(
        [
            {
                "timestamp": "2026-03-31T10:00:00Z",
                "ip_address": "127.0.0.1",
                "api_accessed": "/api/v1/logs",
                "status_code": 200,
                "infected": True,
            },
            {
                "timestamp": "2026-03-31T10:00:01Z",
                "ip_address": "127.0.0.2",
                "api_accessed": "/health",
                "status_code": 200,
                "infected": False,
            },
        ],
        total_count=2,
    )

    assert response.total_count == 2
    assert response.infected_count == 1
    assert response.websocket_id


def test_serialize_fluent_bit_response_uses_defaults() -> None:
    payload = LogSerializer.serialize_fluent_bit_response(
        message="processed",
        batch_id="batch-1",
        processed_count=12,
        anomalies_detected=3,
    )

    assert payload == {
        "message": "processed",
        "batch_id": "batch-1",
        "processed_count": 12,
        "anomalies_detected": 3,
        "status": "success",
        "source": "fluent_bit",
    }
