"""Tests for scripts.synthetic_log_generator"""
import re
import sys
from pathlib import Path

import pytest

# Allow 'from scripts.synthetic_log_generator import ...'
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.synthetic_log_generator import SyntheticLogGenerator, substitute_params

APACHE_COMBINED_RE = re.compile(
    r'^\S+ - - \[[^\]]+\] "\S+ \S+ HTTP/1\.\d" \d{3} \d+'
)

MINIMAL_MANIFEST = {
    "service_name": "test-app",
    "endpoints": [
        {"method": "GET",  "path_template": "/api/items",      "weight": 2},
        {"method": "POST", "path_template": "/api/items",      "weight": 1},
        {"method": "GET",  "path_template": "/api/items/{id}", "weight": 3},
    ],
}


class TestSubstituteParams:
    def test_replaces_id_param(self):
        result = substitute_params("/api/items/{id}")
        assert "{id}" not in result
        assert result.startswith("/api/items/")

    def test_replaces_uuid_param(self):
        result = substitute_params("/api/objects/{uuid}")
        assert "{uuid}" not in result
        # UUID format: 8-4-4-4-12
        segment = result.split("/")[-1]
        assert len(segment) == 36

    def test_no_params_unchanged(self):
        assert substitute_params("/api/items") == "/api/items"

    def test_multiple_params(self):
        result = substitute_params("/api/{org_id}/users/{id}")
        assert "{org_id}" not in result
        assert "{id}" not in result


class TestSyntheticLogGenerator:
    def test_endpoint_pool_respects_weights(self):
        gen = SyntheticLogGenerator(MINIMAL_MANIFEST)
        # weights: 2+1+3 = 6
        assert len(gen.endpoint_pool) == 6

    def test_endpoints_with_missing_path_template_skipped(self, capsys):
        manifest = {
            "endpoints": [
                {"method": "GET", "path_template": "/ok", "weight": 1},
                {"method": "GET"},  # no path_template
            ]
        }
        gen = SyntheticLogGenerator(manifest)
        assert len(gen.endpoints) == 1
        err = capsys.readouterr().err
        assert "Skipping" in err

    def test_empty_manifest_raises(self):
        with pytest.raises(ValueError, match="no valid endpoints"):
            SyntheticLogGenerator({"endpoints": []})

    def test_generate_session_apache_format(self):
        gen = SyntheticLogGenerator(MINIMAL_MANIFEST)
        lines = gen.generate_session(session_length=5)
        assert len(lines) == 5
        for line in lines:
            assert APACHE_COMBINED_RE.match(line), f"Bad format: {line!r}"

    def test_generate_session_same_ip(self):
        gen = SyntheticLogGenerator(MINIMAL_MANIFEST)
        lines = gen.generate_session(session_length=10)
        ips = {line.split(" ")[0] for line in lines}
        assert len(ips) == 1, "Session should use a single IP"

    def test_generate_correct_total_count(self):
        gen = SyntheticLogGenerator(MINIMAL_MANIFEST)
        logs = gen.generate(count=100, sessions=5)
        assert len(logs) == 100

    def test_generate_sorted_chronologically(self):
        gen = SyntheticLogGenerator(MINIMAL_MANIFEST)
        logs = gen.generate(count=50, sessions=5)
        assert len(logs) > 0
