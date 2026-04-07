#!/usr/bin/env python3
"""
Generate authenticated traffic from a seeded endpoint manifest.

Normal mode  : uniform sampling across all endpoints, suitable for baseline warmup.
Low-traffic  : --mode low_traffic
               - defaults to 300 iterations
               - rotates across --sessions simulated clients (distinct User-Agents)
               - cycles through ALL eligible endpoints before repeating (ensures template diversity)
               - shows warmup progress toward --warmup-target
               - warns when temporal spread across clock-hours is insufficient

Session identity note
─────────────────────
The anomaly detector derives session_id from the client IP + User-Agent in the ingested log.
Since test scripts run from a single IP, all requests appear as one session unless User-Agents
are rotated. Use --sessions N to simulate N distinct clients. Each unique client
produces a separate session window and training sequence in the detector.

Low-traffic quickstart
──────────────────────
python generate_authenticated_manifest_traffic.py \\
  --manifest manifest.json \\
  --base-url https://api.example.com \\
  --firebase-api-key YOUR_KEY \\
  --email test@example.com \\
  --password secret \\
  --mode low_traffic \\
  --sessions 10 \\
  --warmup-target 250
"""

from __future__ import annotations

import argparse
import json
import random
import re
import ssl
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib import error, parse, request


PROBE_PATHS = {"/health", "/healthz", "/ready", "/readyz", "/live", "/livez", "/metrics"}
TRANSPORT_NOISE_PREFIXES = ("/socket.io/",)
SIGNED_ASSET_PREFIXES = ("/storage/v1/object/sign/",)
PLACEHOLDER_RE = re.compile(r":([A-Za-z_]\w*)|{([A-Za-z_]\w*)}|<([A-Za-z_]\w*)>")
SUCCESS_STATUSES = {200, 201, 202, 204, 304}
SUPPRESSING_STATUSES = {401, 403, 404, 405, 409, 422, 429, 500, 502, 503, 504}

# Simulated browser User-Agents used to create distinct session identities.
# The anomaly detector keys sessions on IP+User-Agent, so rotating these
# produces separate training sequences even from a single machine.
SESSION_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 Chrome/123.0 Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 Chrome/123.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36 Chrome/122.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; OnePlus 12) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "logguard-traffic-generator/1.0 (internal-test)",
    "logguard-traffic-generator/2.0 (load-test-client-a)",
    "logguard-traffic-generator/2.0 (load-test-client-b)",
    "logguard-traffic-generator/2.0 (load-test-client-c)",
    "logguard-traffic-generator/2.0 (load-test-client-d)",
    "logguard-traffic-generator/2.0 (load-test-client-e)",
]


@dataclass(frozen=True)
class ManifestEndpoint:
    method: str
    path_template: str
    classification: str
    baseline_eligible: bool

    @property
    def placeholders(self) -> list[str]:
        results: list[str] = []
        for match in PLACEHOLDER_RE.finditer(self.path_template):
            name = next(group for group in match.groups() if group)
            results.append(name)
        return results


@dataclass
class EndpointStats:
    successes: int = 0
    failures: int = 0
    suppressed: bool = False
    last_status: int | None = None


@dataclass
class RunStats:
    successes: int = 0
    failures: int = 0
    skipped: int = 0
    start_time: float = field(default_factory=time.time)
    hours_seen: set[int] = field(default_factory=set)

    def elapsed(self) -> float:
        return time.time() - self.start_time

    def progress_line(self, warmup_target: int) -> str:
        pct = min(100, int(self.successes / max(warmup_target, 1) * 100))
        bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
        return (
            f"  [{bar}] {self.successes}/{warmup_target} ({pct}%)  "
            f"ok={self.successes} err={self.failures} skip={self.skipped}  "
            f"hours_seen={sorted(self.hours_seen)}  "
            f"elapsed={self.elapsed():.0f}s"
        )


def _load_manifest(path: Path) -> list[ManifestEndpoint]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    endpoints: list[ManifestEndpoint] = []
    for entry in payload.get("endpoints", []):
        if not isinstance(entry, dict):
            continue
        path_template = str(entry.get("path_template") or "").strip()
        if not path_template or "${" in path_template or any(ch.isspace() for ch in path_template):
            continue
        endpoints.append(
            ManifestEndpoint(
                method=str(entry.get("method", "GET")).upper(),
                path_template=path_template if path_template.startswith("/") else f"/{path_template}",
                classification=str(entry.get("classification", "user_traffic")),
                baseline_eligible=bool(entry.get("baseline_eligible", True)),
            )
        )
    return endpoints


def _default_ssl_context(insecure: bool) -> ssl.SSLContext | None:
    if not insecure:
        return None
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _http_json(
    url: str,
    *,
    method: str = "GET",
    token: str | None = None,
    body: dict[str, Any] | None = None,
    timeout: float = 20.0,
    insecure: bool = False,
    user_agent: str = "logguard-traffic-generator/1.0",
) -> tuple[int, Any]:
    headers = {
        "Accept": "application/json",
        "User-Agent": user_agent,
    }
    data: bytes | None = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")

    req = request.Request(url, data=data, headers=headers, method=method)
    context = _default_ssl_context(insecure)
    try:
        with request.urlopen(req, timeout=timeout, context=context) as response:
            raw = response.read().decode("utf-8")
            if not raw:
                return response.status, None
            try:
                return response.status, json.loads(raw)
            except json.JSONDecodeError:
                return response.status, raw
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="ignore")
        return exc.code, raw


def _sign_in(firebase_api_key: str, email: str, password: str, *, timeout: float, insecure: bool) -> dict[str, Any]:
    url = (
        "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"
        f"?key={parse.quote(firebase_api_key)}"
    )
    status, payload = _http_json(
        url,
        method="POST",
        body={"email": email, "password": password, "returnSecureToken": True},
        timeout=timeout,
        insecure=insecure,
    )
    if status != 200 or not isinstance(payload, dict) or not payload.get("idToken"):
        raise RuntimeError(f"Firebase sign-in failed with status {status}: {payload}")
    return payload


def _normalize_param_name(name: str) -> str:
    lowered = name.strip().lower()
    return re.sub(r"[^a-z0-9]+", "", lowered)


def _merge_params(param_pairs: list[str], params_file: Path | None) -> dict[str, str]:
    merged: dict[str, str] = {}
    if params_file:
        payload = json.loads(params_file.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("--params-file must contain a JSON object")
        for key, value in payload.items():
            merged[_normalize_param_name(str(key))] = str(value)
    for pair in param_pairs:
        key, sep, value = pair.partition("=")
        if not sep:
            raise ValueError(f"Invalid --param value: {pair!r}")
        merged[_normalize_param_name(key)] = value
    return merged


def _collect_ids(payload: Any, discovered: dict[str, list[str]], *, depth: int = 0) -> None:
    if depth > 4:
        return
    if isinstance(payload, dict):
        for key, value in payload.items():
            normalized_key = _normalize_param_name(key)
            if isinstance(value, (str, int)) and normalized_key.endswith("id"):
                discovered.setdefault(normalized_key, [])
                text_value = str(value)
                if text_value not in discovered[normalized_key]:
                    discovered[normalized_key].append(text_value)
                if normalized_key != "id":
                    discovered.setdefault("id", [])
                    if text_value not in discovered["id"]:
                        discovered["id"].append(text_value)
            _collect_ids(value, discovered, depth=depth + 1)
    elif isinstance(payload, list):
        for item in payload[:10]:
            _collect_ids(item, discovered, depth=depth + 1)


def _is_noise_endpoint(endpoint: ManifestEndpoint) -> bool:
    lowered = endpoint.path_template.lower()
    return (
        endpoint.path_template in PROBE_PATHS
        or lowered.startswith(TRANSPORT_NOISE_PREFIXES)
        or lowered.startswith(SIGNED_ASSET_PREFIXES)
    )


def _candidate_endpoints(endpoints: Iterable[ManifestEndpoint], *, include_writes: bool) -> list[ManifestEndpoint]:
    allowed_methods = {"GET"} if not include_writes else {"GET", "POST", "PUT", "PATCH", "DELETE"}
    filtered = [
        endpoint
        for endpoint in endpoints
        if endpoint.method in allowed_methods
        and endpoint.classification == "user_traffic"
        and endpoint.baseline_eligible
        and not _is_noise_endpoint(endpoint)
    ]
    return sorted(filtered, key=lambda item: (len(item.placeholders), item.path_template, item.method))


def _resolve_placeholder(name: str, explicit_params: dict[str, str], discovered: dict[str, list[str]], auth_payload: dict[str, Any]) -> str | None:
    normalized = _normalize_param_name(name)
    if normalized in explicit_params:
        return explicit_params[normalized]
    if normalized in discovered and discovered[normalized]:
        return discovered[normalized][0]
    if normalized == "userid":
        if discovered.get("userid"):
            return discovered["userid"][0]
        if discovered.get("id"):
            return discovered["id"][0]
    if normalized in {"firebaseuid", "uid", "localid"}:
        return str(auth_payload.get("localId") or "")
    return None


def _render_path(endpoint: ManifestEndpoint, explicit_params: dict[str, str], discovered: dict[str, list[str]], auth_payload: dict[str, Any]) -> str | None:
    rendered = endpoint.path_template
    for placeholder in endpoint.placeholders:
        replacement = _resolve_placeholder(placeholder, explicit_params, discovered, auth_payload)
        if not replacement:
            return None
        rendered = re.sub(rf":{placeholder}\b|{{{placeholder}}}|<{placeholder}>", parse.quote(str(replacement)), rendered)
    if any(ch.isspace() for ch in rendered):
        return None
    return rendered


def _bootstrap_discovery(
    base_url: str,
    token: str,
    endpoints: list[ManifestEndpoint],
    explicit_params: dict[str, str],
    auth_payload: dict[str, Any],
    *,
    timeout: float,
    insecure: bool,
) -> dict[str, list[str]]:
    discovered: dict[str, list[str]] = {}
    preferred_paths = ["/users/me", "/users/profile", "/profile", "/me"]
    bootstrap: list[ManifestEndpoint] = []

    for endpoint in endpoints:
        if endpoint.method != "GET" or endpoint.placeholders:
            continue
        if endpoint.path_template in preferred_paths:
            bootstrap.append(endpoint)

    bootstrap.extend(
        endpoint
        for endpoint in endpoints
        if endpoint.method == "GET"
        and not endpoint.placeholders
        and endpoint not in bootstrap
        and endpoint.path_template.count("/") <= 4
    )

    for endpoint in bootstrap[:8]:
        status, payload = _http_json(
            f"{base_url.rstrip('/')}{endpoint.path_template}",
            method="GET",
            token=token,
            timeout=timeout,
            insecure=insecure,
        )
        if 200 <= status < 300:
            _collect_ids(payload, discovered)

    for key, value in explicit_params.items():
        discovered.setdefault(key, [])
        if value not in discovered[key]:
            discovered[key].append(value)
    if auth_payload.get("localId"):
        discovered.setdefault("firebaseuid", []).append(str(auth_payload["localId"]))
        discovered.setdefault("uid", []).append(str(auth_payload["localId"]))
        discovered.setdefault("localid", []).append(str(auth_payload["localId"]))
    return discovered


def _endpoint_key(endpoint: ManifestEndpoint) -> str:
    return f"{endpoint.method} {endpoint.path_template}"


def _choose_endpoint_normal(
    endpoints: list[ManifestEndpoint],
    endpoint_stats: dict[str, EndpointStats],
) -> ManifestEndpoint | None:
    """Original selection: biased toward proven endpoints (good for live testing)."""
    available = [endpoint for endpoint in endpoints if not endpoint_stats[_endpoint_key(endpoint)].suppressed]
    if not available:
        return None

    proven = [endpoint for endpoint in available if endpoint_stats[_endpoint_key(endpoint)].successes > 0]
    neutral = [
        endpoint
        for endpoint in available
        if endpoint_stats[_endpoint_key(endpoint)].successes == 0
        and endpoint_stats[_endpoint_key(endpoint)].failures == 0
    ]
    recoverable = [endpoint for endpoint in available if endpoint not in proven and endpoint not in neutral]

    if proven:
        pool = proven if random.random() < 0.85 else (neutral or recoverable or proven)
    elif neutral:
        pool = neutral
    else:
        pool = recoverable
    return random.choice(pool) if pool else None


def _make_low_traffic_cycle(endpoints: list[ManifestEndpoint]) -> list[ManifestEndpoint]:
    """
    Build a shuffled full-cycle pass over all eligible endpoints.
    Called each time the cycle is exhausted so every endpoint is hit
    before any endpoint repeats. This guarantees min_distinct_templates
    is satisfied as quickly as possible.
    """
    available = list(endpoints)
    random.shuffle(available)
    return available


def _choose_endpoint_low_traffic(
    cycle: list[ManifestEndpoint],
    endpoints: list[ManifestEndpoint],
    endpoint_stats: dict[str, EndpointStats],
) -> tuple[ManifestEndpoint | None, list[ManifestEndpoint]]:
    """
    Full-cycle selection for low-traffic mode.
    Pops from the front of a pre-shuffled cycle; refills when exhausted.
    Suppressed endpoints are skipped but not permanently removed from future cycles
    (a 429 may recover).
    """
    remaining_cycle = list(cycle)
    while remaining_cycle:
        endpoint = remaining_cycle.pop(0)
        if not endpoint_stats[_endpoint_key(endpoint)].suppressed:
            return endpoint, remaining_cycle
    # Cycle exhausted — build a new one
    new_cycle = _make_low_traffic_cycle(endpoints)
    if new_cycle:
        endpoint = new_cycle.pop(0)
        return endpoint, new_cycle
    return None, []


def _record_endpoint_result(
    endpoint: ManifestEndpoint,
    endpoint_stats: dict[str, EndpointStats],
    status: int,
) -> EndpointStats:
    stats = endpoint_stats[_endpoint_key(endpoint)]
    stats.last_status = status
    if status in SUCCESS_STATUSES:
        stats.successes += 1
        return stats

    stats.failures += 1
    if status in SUPPRESSING_STATUSES:
        stats.suppressed = True
    elif stats.failures >= 3 and stats.successes == 0:
        stats.suppressed = True
    return stats


def _print_low_traffic_hints(endpoints: list[ManifestEndpoint], sessions: int, warmup_target: int) -> None:
    """Print a pre-run summary so the user knows what to expect."""
    print(f"\n{'─'*60}", file=sys.stderr)
    print("  LOW-TRAFFIC MODE", file=sys.stderr)
    print(f"{'─'*60}", file=sys.stderr)
    print(f"  Eligible endpoints   : {len(endpoints)}", file=sys.stderr)
    print(f"  Simulated sessions   : {sessions}", file=sys.stderr)
    print(f"  Warmup target        : {warmup_target} successful requests", file=sys.stderr)
    print(f"  Template diversity   : all {len(endpoints)} endpoints cycled before repeat", file=sys.stderr)
    print("", file=sys.stderr)
    if len(endpoints) < 5:
        print(
            "  ⚠  Only found {n} eligible endpoints. The detector needs ≥5 distinct templates.\n"
            "     Add --include-writes or expand baseline_eligible endpoints in your manifest.".format(n=len(endpoints)),
            file=sys.stderr,
        )
    print(
        "  ℹ  Temporal spread: the anomaly detector requires traffic across ≥1 clock-hour.\n"
        "     If this run finishes in <60 min, run it again 1+ hours later (or lower\n"
        "     MULTI_TENANT_LOW_TRAFFIC_MIN_OBSERVED_HOURS=1 in your deployment env).",
        file=sys.stderr,
    )
    print(f"{'─'*60}\n", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--manifest", required=True, help="Path to the manifest JSON file")
    parser.add_argument("--base-url", required=True, help="API base URL, e.g. https://api.example.com")
    parser.add_argument("--firebase-api-key", required=True, help="Firebase Web API key")
    parser.add_argument("--email", required=True, help="Firebase user email")
    parser.add_argument("--password", required=True, help="Firebase user password")

    # Mode
    parser.add_argument(
        "--mode",
        choices=["normal", "low_traffic"],
        default="normal",
        help=(
            "normal: biased toward proven endpoints, suitable for live testing. "
            "low_traffic: full-cycle endpoint rotation + session diversity, "
            "optimized for warming up low-traffic detector projects."
        ),
    )

    # Volume
    parser.add_argument("--iterations", type=int, default=None,
        help="Number of requests. Defaults: normal=25, low_traffic=300.")
    parser.add_argument("--warmup-target", type=int, default=250,
        help="[low_traffic] Keep running until this many successful requests are made. "
             "Set to match MULTI_TENANT_LOW_TRAFFIC_WARMUP_THRESHOLD (default 200). "
             "Overrides --iterations when reached first.")

    # Session diversity
    parser.add_argument("--sessions", type=int, default=10,
        help="[low_traffic] Number of distinct User-Agent identities to rotate across. "
             "Each identity produces a separate session window in the anomaly detector. "
             "Max: {n}. Default: 10.".format(n=len(SESSION_USER_AGENTS)))

    # Timing
    parser.add_argument("--delay-seconds", type=float, default=None,
        help="Base delay between requests. Defaults: normal=0.75, low_traffic=0.3.")
    parser.add_argument("--jitter-seconds", type=float, default=None,
        help="Random extra delay per request. Defaults: normal=0.35, low_traffic=0.15.")
    parser.add_argument("--backoff-seconds", type=float, default=3.0,
        help="Extra sleep after a 429 response.")

    # Endpoint options
    parser.add_argument("--include-writes", action="store_true",
        help="Include POST/PUT/PATCH/DELETE endpoints.")
    parser.add_argument("--param", action="append", default=[],
        help="Placeholder override in key=value form.")
    parser.add_argument("--params-file",
        help="Optional JSON file with placeholder values.")
    parser.add_argument("--timeout", type=float, default=20.0,
        help="HTTP timeout in seconds.")
    parser.add_argument("--insecure", action="store_true",
        help="Disable TLS certificate validation.")
    parser.add_argument("--seed", type=int, default=42,
        help="Random seed for endpoint selection.")

    args = parser.parse_args()

    # Apply mode defaults
    is_low_traffic = args.mode == "low_traffic"
    iterations = args.iterations if args.iterations is not None else (300 if is_low_traffic else 25)
    delay = args.delay_seconds if args.delay_seconds is not None else (0.3 if is_low_traffic else 0.75)
    jitter = args.jitter_seconds if args.jitter_seconds is not None else (0.15 if is_low_traffic else 0.35)
    sessions = min(max(1, args.sessions), len(SESSION_USER_AGENTS))

    random.seed(args.seed)
    manifest_path = Path(args.manifest).expanduser().resolve()
    endpoints = _candidate_endpoints(_load_manifest(manifest_path), include_writes=args.include_writes)
    if not endpoints:
        print("No eligible endpoints found in manifest.", file=sys.stderr)
        return 1

    explicit_params = _merge_params(
        args.param,
        Path(args.params_file).expanduser().resolve() if args.params_file else None,
    )
    auth_payload = _sign_in(
        args.firebase_api_key, args.email, args.password,
        timeout=args.timeout, insecure=args.insecure,
    )
    token = str(auth_payload["idToken"])
    discovered = _bootstrap_discovery(
        args.base_url, token, endpoints, explicit_params, auth_payload,
        timeout=args.timeout, insecure=args.insecure,
    )

    if is_low_traffic:
        _print_low_traffic_hints(endpoints, sessions, args.warmup_target)

    run_stats = RunStats()
    chosen_endpoints: list[dict[str, Any]] = []
    endpoint_stats = {_endpoint_key(ep): EndpointStats() for ep in endpoints}

    # Low-traffic state
    session_agents = SESSION_USER_AGENTS[:sessions]
    session_index = 0
    lt_cycle: list[ManifestEndpoint] = _make_low_traffic_cycle(endpoints) if is_low_traffic else []
    last_progress_print = 0.0

    i = 0
    while i < iterations:
        # Low-traffic: stop early if warmup target reached
        if is_low_traffic and run_stats.successes >= args.warmup_target:
            print(f"\n  ✓ Warmup target {args.warmup_target} reached after {i} iterations.", file=sys.stderr)
            break

        # Select endpoint
        if is_low_traffic:
            endpoint, lt_cycle = _choose_endpoint_low_traffic(lt_cycle, endpoints, endpoint_stats)
        else:
            endpoint = _choose_endpoint_normal(endpoints, endpoint_stats)
        if endpoint is None:
            break

        rendered_path = _render_path(endpoint, explicit_params, discovered, auth_payload)
        if not rendered_path:
            run_stats.skipped += 1
            i += 1
            continue

        # Rotate User-Agent for session diversity in low-traffic mode
        if is_low_traffic:
            ua = session_agents[session_index % sessions]
            session_index += 1
        else:
            ua = "logguard-traffic-generator/1.0"

        status, payload = _http_json(
            f"{args.base_url.rstrip('/')}{rendered_path}",
            method=endpoint.method,
            token=token,
            timeout=args.timeout,
            insecure=args.insecure,
            user_agent=ua,
        )
        chosen_endpoints.append({"method": endpoint.method, "path": rendered_path, "status": status, "ua_index": session_index % sessions})
        _record_endpoint_result(endpoint, endpoint_stats, status)

        if status in SUCCESS_STATUSES:
            run_stats.successes += 1
            run_stats.hours_seen.add(time.localtime().tm_hour)
            _collect_ids(payload, discovered)
        else:
            run_stats.failures += 1
            if status == 429:
                time.sleep(max(args.backoff_seconds, 0.0))

        # Progress output for low-traffic mode
        if is_low_traffic:
            now = time.time()
            if now - last_progress_print >= 5.0 or run_stats.successes % 25 == 0:
                print(run_stats.progress_line(args.warmup_target), file=sys.stderr)
                last_progress_print = now

        time.sleep(max(delay, 0.0) + random.uniform(0.0, max(jitter, 0.0)))
        i += 1

    # Temporal spread warning
    if is_low_traffic and len(run_stats.hours_seen) < 2:
        print(
            "\n  ⚠  All requests landed in the same clock-hour. "
            "The detector's min_observed_hours gate may still block training.\n"
            "  Options:\n"
            "    1. Re-run this script ≥1 hour from now.\n"
            "    2. Set MULTI_TENANT_LOW_TRAFFIC_MIN_OBSERVED_HOURS=1 in your deployment.",
            file=sys.stderr,
        )

    print(
        json.dumps(
            {
                "mode": args.mode,
                "base_url": args.base_url,
                "manifest": str(manifest_path),
                "eligible_endpoint_count": len(endpoints),
                "sessions_rotated": sessions if is_low_traffic else 1,
                "requested_iterations": iterations,
                "actual_iterations": i,
                "successful_requests": run_stats.successes,
                "failed_requests": run_stats.failures,
                "skipped_unresolved": run_stats.skipped,
                "hours_seen": sorted(run_stats.hours_seen),
                "warmup_target": args.warmup_target if is_low_traffic else None,
                "warmup_target_reached": run_stats.successes >= args.warmup_target if is_low_traffic else None,
                "suppressed_endpoint_count": sum(1 for s in endpoint_stats.values() if s.suppressed),
                "discovered_placeholders": {k: v[:3] for k, v in sorted(discovered.items())},
                "endpoint_status_summary": {
                    key: {
                        "successes": stats.successes,
                        "failures": stats.failures,
                        "suppressed": stats.suppressed,
                        "last_status": stats.last_status,
                    }
                    for key, stats in sorted(endpoint_stats.items())
                    if stats.successes or stats.failures
                },
                "sample_requests": chosen_endpoints[:20],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if run_stats.successes > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
