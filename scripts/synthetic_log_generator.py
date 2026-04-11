#!/usr/bin/env python3
"""
Synthetic Log Generator

Generate Apache Combined Log Format entries from a LogGuard endpoint manifest.
The output is normal traffic only and is grouped into fixed-IP sessions so the
sequence model sees coherent request windows.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

MANIFEST_INVALID_MARKERS = ("${",)
PARAM_RE = re.compile(r"\{([^}]+)\}")
QUERY_PATH_RE = re.compile(r"(?i)/(search|filter|query|find|lookup)$")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:125.0) Gecko/125.0 Firefox/125.0",
]

STATUS_POOL = [200] * 85 + [404] * 8 + [401] * 4 + [500] * 3
SLUGS = [
    "alpha-team",
    "beta-release",
    "gold-plan",
    "summer-sale",
    "onboarding-guide",
    "priority-order",
    "mobile-app",
    "daily-report",
]
SEARCH_TERMS = ["alice", "tablet", "status", "security", "invoice", "dashboard", "summer", "admin"]
REFERRERS = [
    "-",
    "https://www.google.com/",
    "https://my-app.com/",
    "https://my-app.com/dashboard",
    "https://my-app.com/login",
]

DAY_HOUR_WEIGHTS = {
    0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1,
    6: 2, 7: 4, 8: 8, 9: 10, 10: 10, 11: 9,
    12: 8, 13: 8, 14: 9, 15: 10, 16: 10, 17: 8,
    18: 6, 19: 5, 20: 4, 21: 3, 22: 2, 23: 1,
}


@dataclass(frozen=True)
class ManifestEndpoint:
    method: str
    path_template: str
    classification: str
    weight: int

    @property
    def role(self) -> str:
        path = self.path_template.lower()
        if self.classification == "internal_probe":
            return "probe"
        if "auth" in path or "login" in path or "logout" in path:
            return "auth"
        if self.method in {"POST", "PUT", "PATCH", "DELETE"}:
            return "action"
        if "search" in path or "query" in path or "filter" in path:
            return "search"
        if PARAM_RE.search(self.path_template):
            return "detail"
        return "list"


def substitute_params(path_template: str) -> str:
    """Replace {param} segments in a path template with realistic values."""

    def _replace(match: re.Match[str]) -> str:
        name = match.group(1).lower()
        if "uuid" in name:
            return str(uuid.uuid4())
        if any(key in name for key in ("slug", "name", "tag", "type")):
            return random.choice(SLUGS)
        if any(key in name for key in ("id", "pk", "key", "num", "index", "ref")):
            return str(random.randint(1, 50_000))
        return str(random.randint(1, 9_999))

    rendered = PARAM_RE.sub(_replace, path_template)
    if QUERY_PATH_RE.search(rendered) and "?" not in rendered and random.random() < 0.7:
        rendered = f"{rendered}?q={random.choice(SEARCH_TERMS)}"
    return rendered


def _format_apache_timestamp(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")


def _random_ip() -> str:
    first_octet = random.choice([23, 45, 66, 72, 98, 104, 172, 192])
    return f"{first_octet}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def _weighted_hour() -> int:
    hours = list(DAY_HOUR_WEIGHTS.keys())
    weights = list(DAY_HOUR_WEIGHTS.values())
    return random.choices(hours, weights=weights, k=1)[0]


def _sample_status() -> int:
    return random.choice(STATUS_POOL)


def _sample_response_size(path: str, status: int) -> int:
    if status >= 500:
        return random.randint(80, 1200)
    if status == 404:
        return random.randint(120, 2200)
    if path.startswith("/health") or path.startswith("/metrics"):
        return random.randint(24, 512)
    if path.startswith("/api/auth"):
        return random.randint(180, 1600)
    return random.randint(220, 16_000)


def _session_start(base_time: datetime, window_hours: int) -> datetime:
    max_offset = max(window_hours * 3600 - 1, 0)
    offset_seconds = random.randint(0, max_offset)
    candidate = base_time + timedelta(seconds=offset_seconds)
    # Bias start times toward daytime without forcing sessions outside the window.
    candidate = candidate.replace(hour=_weighted_hour(), minute=random.randint(0, 59), second=random.randint(0, 59))
    upper_bound = base_time + timedelta(hours=window_hours)
    if candidate >= upper_bound:
        candidate = upper_bound - timedelta(seconds=random.randint(1, 300))
    return candidate


class SyntheticLogGenerator:
    def __init__(self, manifest: Dict[str, Any]):
        self.manifest = manifest
        self.endpoints: List[ManifestEndpoint] = []
        self.endpoint_pool: List[ManifestEndpoint] = []
        self._load_manifest(manifest.get("endpoints", []))

    def _load_manifest(self, raw_endpoints: Iterable[Any]) -> None:
        for raw in raw_endpoints:
            if not isinstance(raw, dict):
                print(f"[WARNING] Skipping non-object endpoint entry: {raw!r}", file=sys.stderr)
                continue

            path_template = str(raw.get("path_template") or "").strip()
            if not path_template or any(marker in path_template for marker in MANIFEST_INVALID_MARKERS):
                print(f"[WARNING] Skipping endpoint with invalid path_template: {raw}", file=sys.stderr)
                continue

            method = str(raw.get("method") or "GET").upper()
            classification = str(raw.get("classification") or "user_traffic")
            weight = max(1, int(raw.get("weight", 1)))
            endpoint = ManifestEndpoint(
                method=method,
                path_template=path_template if path_template.startswith("/") else f"/{path_template}",
                classification=classification,
                weight=weight,
            )
            self.endpoints.append(endpoint)
            self.endpoint_pool.extend([endpoint] * weight)

        if not self.endpoint_pool:
            raise ValueError("Manifest contains no valid endpoints with path_template")

    def _choose_next_endpoint(self, history: List[ManifestEndpoint]) -> ManifestEndpoint:
        if not history:
            auth_candidates = [ep for ep in self.endpoints if ep.role == "auth"]
            if auth_candidates and random.random() < 0.7:
                return random.choice(auth_candidates)
            non_probe = [ep for ep in self.endpoint_pool if ep.role != "probe"]
            return random.choice(non_probe or self.endpoint_pool)

        last_role = history[-1].role
        if last_role == "auth":
            follow_ups = [ep for ep in self.endpoint_pool if ep.role in {"list", "detail", "search"}]
            return random.choice(follow_ups or self.endpoint_pool)
        if last_role == "list":
            follow_ups = [ep for ep in self.endpoint_pool if ep.role in {"detail", "search", "action"}]
            return random.choice(follow_ups or self.endpoint_pool)
        if last_role == "detail":
            follow_ups = [ep for ep in self.endpoint_pool if ep.role in {"action", "list", "detail"}]
            return random.choice(follow_ups or self.endpoint_pool)
        if last_role == "action":
            follow_ups = [ep for ep in self.endpoint_pool if ep.role in {"detail", "list", "auth"}]
            return random.choice(follow_ups or self.endpoint_pool)
        if random.random() < 0.03:
            probes = [ep for ep in self.endpoint_pool if ep.role == "probe"]
            if probes:
                return random.choice(probes)
        return random.choice(self.endpoint_pool)

    def _format_line(
        self,
        *,
        ip: str,
        dt: datetime,
        method: str,
        path: str,
        status: int,
        size: int,
        referer: str,
        user_agent: str,
    ) -> str:
        timestamp = _format_apache_timestamp(dt)
        return (
            f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {size} '
            f'"{referer}" "{user_agent}"'
        )

    def generate_session(
        self,
        session_length: int,
        start_time: Optional[datetime] = None,
    ) -> List[str]:
        """Generate a session using a fixed IP and user agent."""
        if session_length <= 0:
            return []

        ip = _random_ip()
        user_agent = random.choice(USER_AGENTS)
        referer = random.choice(REFERRERS)
        timestamp = start_time or datetime.now(timezone.utc)
        history: List[ManifestEndpoint] = []
        lines: List[str] = []

        for _ in range(session_length):
            endpoint = self._choose_next_endpoint(history)
            history.append(endpoint)

            path = substitute_params(endpoint.path_template)
            status = _sample_status()
            size = _sample_response_size(path, status)
            lines.append(
                self._format_line(
                    ip=ip,
                    dt=timestamp,
                    method=endpoint.method,
                    path=path,
                    status=status,
                    size=size,
                    referer=referer,
                    user_agent=user_agent,
                )
            )
            timestamp += timedelta(seconds=random.uniform(0.7, 12.0))

        return lines

    def generate(
        self,
        *,
        count: int,
        sessions: int,
        start_time: Optional[datetime] = None,
        window_hours: int = 24,
    ) -> List[str]:
        """Generate total log lines across several sessions in chronological order."""
        if count <= 0:
            return []
        if sessions <= 0:
            raise ValueError("sessions must be >= 1")
        if window_hours <= 0:
            raise ValueError("window_hours must be >= 1")

        session_lengths = [count // sessions] * sessions
        for index in range(count % sessions):
            session_lengths[index] += 1

        if start_time is None:
            end_time = datetime.now(timezone.utc).replace(microsecond=0)
            base_time = end_time - timedelta(hours=window_hours)
        else:
            base_time = start_time.astimezone(timezone.utc).replace(microsecond=0)

        all_lines: List[str] = []
        for length in session_lengths:
            session_start = _session_start(base_time, window_hours)
            all_lines.extend(self.generate_session(length, start_time=session_start))

        def _sort_key(line: str) -> datetime:
            ts = line.split("[", 1)[1].split("]", 1)[0]
            return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S +0000").replace(tzinfo=timezone.utc)

        return sorted(all_lines, key=_sort_key)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate synthetic Apache access logs from a manifest")
    parser.add_argument("--manifest", required=True, help="Path to manifest JSON")
    parser.add_argument("--count", type=int, default=15_000, help="Total log lines to generate")
    parser.add_argument("--sessions", type=int, default=50, help="Number of simulated sessions")
    parser.add_argument("--window-hours", type=int, default=24, help="Traffic time window in hours")
    parser.add_argument("--output", required=True, help="Output log file path")
    parser.add_argument("--seed", type=int, default=None, help="Optional RNG seed for reproducible output")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    if args.seed is not None:
        random.seed(args.seed)

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"[ERROR] Manifest not found: {manifest_path}", file=sys.stderr)
        raise SystemExit(1)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    generator = SyntheticLogGenerator(manifest)
    lines = generator.generate(
        count=args.count,
        sessions=args.sessions,
        window_hours=args.window_hours,
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Loaded {len(generator.endpoints)} valid endpoints from {manifest_path}")
    print(f"Generated {len(lines)} normal-traffic Apache log lines -> {output_path}")


if __name__ == "__main__":
    main()
