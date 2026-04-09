"""Tests for Drain3 fallback in LogParserService."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.services.log_parser_service import LogParserService


@pytest.fixture
def parser():
    return LogParserService()


class TestDrain3Fallback:
    def test_syslog_format(self, parser):
        """Syslog-style lines should be parsed by Drain3 fallback."""
        line = "Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4"
        result, error = parser.parse_log_with_error(line, "syslog")
        assert result is not None, f"Expected successful parse, got error: {error}"
        assert "normalized_event" in result
        assert result["log_type"] == "syslog"

    def test_generic_format(self, parser):
        """Generic lines not matching Apache/Nginx should go through Drain3."""
        line = "2025-01-15 10:30:45 ERROR [main] com.example.App - Connection refused to database host=db01 port=5432"
        result, error = parser.parse_log_with_error(line, "generic")
        assert result is not None
        assert "normalized_event" in result

    def test_apache_still_uses_regex(self, parser):
        """Apache format should still use the fast regex path, not Drain3."""
        line = '192.168.1.1 - - [14/Jun/2025:15:16:01 +0000] "GET /api/health HTTP/1.1" 200 1234'
        result, error = parser.parse_log_with_error(line, "apache")
        assert result is not None
        assert result.get("method") == "GET"
        # Should NOT have drain3_template since regex succeeded
        assert result.get("drain3_template") is None

    def test_drain3_template_extraction(self, parser):
        """Multiple similar lines should converge to the same Drain3 template."""
        lines = [
            "2025-01-15 10:30:45 ERROR Connection refused to host=db01 port=5432",
            "2025-01-15 10:31:12 ERROR Connection refused to host=db02 port=5432",
            "2025-01-15 10:32:01 ERROR Connection refused to host=db03 port=5432",
        ]
        templates = set()
        for line in lines:
            result, _ = parser.parse_log_with_error(line, "generic")
            if result:
                templates.add(result["normalized_event"])
        # Drain3 should abstract the host parameter, resulting in <=2 templates
        assert len(templates) <= 2

    def test_apache_fallback_to_drain3(self, parser):
        """Malformed Apache line should fall back to Drain3 instead of failing."""
        line = "this is not apache format at all but still a log line"
        result, error = parser.parse_log_with_error(line, "apache")
        assert result is not None  # Drain3 fallback should catch it
        assert result.get("drain3_template") is not None
