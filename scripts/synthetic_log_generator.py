#!/usr/bin/env python3
"""
Synthetic Log Generator
Generates Apache Combined Log Format entries from a LogGuard manifest.

Usage:
    python scripts/synthetic_log_generator.py \
        --manifest scripts/my_app_manifest.json \
        --count 15000 --sessions 50 \
        --output scripts/synthetic_logs.log
"""

import argparse
import json
import random
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
]

# Status pool weighted: 85% 200, 8% 404, 4% 401, 3% 500
_STATUS_POOL = [200] * 85 + [404] * 8 + [401] * 4 + [500] * 3

_SLUGS = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota", "kappa"]
_PARAM_RE = re.compile(r"\{[^}]+\}")
_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def substitute_params(path_template: str) -> str:
    """Replace {param} segments in a path template with realistic values."""
    def _replace(m: re.Match) -> str:
        name = m.group(0)[1:-1].lower()
        if "uuid" in name:
            return str(uuid.uuid4())
        if any(k in name for k in ("id", "pk", "key", "num", "index", "ref")):
            return str(random.randint(1, 9999))
        if any(k in name for k in ("slug", "name", "tag", "type")):
            return random.choice(_SLUGS)
        return str(random.randint(1, 9999))
    return _PARAM_RE.sub(_replace, path_template)


def _format_apache_timestamp(dt: datetime) -> str:
    return f"{dt.day:02d}/{_MONTHS[dt.month - 1]}/{dt.year}:{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} +0000"


def _random_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _sample_status(method: str) -> int:
    if method in ("POST", "PUT", "PATCH"):
        r = random.randint(0, 99)
        if r < 80:
            return 200
        if r < 88:
            return 201
        if r < 93:
            return 400
        if r < 97:
            return 401
        return 500
    return random.choice(_STATUS_POOL)


class SyntheticLogGenerator:
    def __init__(self, manifest: Dict[str, Any]):
        self.manifest = manifest
        raw_endpoints = manifest.get("endpoints", [])

        self.endpoints: List[Dict[str, Any]] = []
        self.endpoint_pool: List[Dict[str, Any]] = []

        for ep in raw_endpoints:
            path_template = str(ep.get("path_template", "")).strip()
            if not path_template:
                print(f"[WARNING] Skipping endpoint with missing path_template: {ep}", file=sys.stderr)
                continue
            self.endpoints.append(ep)
            weight = max(1, int(ep.get("weight", 1)))
            self.endpoint_pool.extend([ep] * weight)

        if not self.endpoint_pool:
            raise ValueError("Manifest contains no valid endpoints with path_template")

    def _format_line(
        self, ip: str, dt: datetime, method: str, path: str, status: int, size: int, ua: str
    ) -> str:
        ts = _format_apache_timestamp(dt)
        return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'

    def generate_session(
        self,
        session_length: int,
        start_time: Optional[datetime] = None,
    ) -> List[str]:
        """Generate one session: fixed IP + UA, sequential endpoint calls."""
        ip = _random_ip()
        ua = random.choice(USER_AGENTS)
        dt = start_time or datetime.now(timezone.utc).replace(tzinfo=None)
        lines: List[str] = []
        for _ in range(session_length):
            ep = random.choice(self.endpoint_pool)
            method = str(ep.get("method", "GET")).upper()
            path = substitute_params(ep.get("path_template", "/"))
            status = _sample_status(method)
            size = random.randint(64, 8192)
            lines.append(self._format_line(ip, dt, method, path, status, size, ua))
            dt += timedelta(seconds=random.uniform(0.5, 10.0))
        return lines

    def generate(self, count: int, sessions: int) -> List[str]:
        """
        Generate `count` total log lines spread across `sessions` sessions,
        sorted chronologically.
        """
        if sessions <= 0:
            raise ValueError("sessions must be >= 1")
        base = count // sessions
        remainder = count % sessions
        session_lengths = [base + (1 if i < remainder else 0) for i in range(sessions)]

        base_time = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=None)
        all_with_key: List[tuple] = []

        for i, length in enumerate(session_lengths):
            offset = (i / sessions) * 86400 + random.uniform(0, 3600)
            start = base_time + timedelta(seconds=offset)
            lines = self.generate_session(length, start_time=start)
            for j, line in enumerate(lines):
                all_with_key.append((offset + j * 5, line))

        all_with_key.sort(key=lambda x: x[0])
        return [line for _, line in all_with_key]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate synthetic Apache logs from a LogGuard manifest"
    )
    parser.add_argument("--manifest", required=True, help="Path to manifest JSON")
    parser.add_argument("--count", type=int, default=15000, help="Total log lines")
    parser.add_argument("--sessions", type=int, default=50, help="Simulated user sessions")
    parser.add_argument("--output", required=True, help="Output .log file path")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"[ERROR] Manifest not found: {manifest_path}", file=sys.stderr)
        sys.exit(1)

    with open(manifest_path) as f:
        manifest = json.load(f)

    gen = SyntheticLogGenerator(manifest)
    print(f"Loaded {len(gen.endpoints)} endpoints, pool size {len(gen.endpoint_pool)}")

    lines = gen.generate(count=args.count, sessions=args.sessions)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Generated {len(lines)} log lines → {out_path}")


if __name__ == "__main__":
    main()
