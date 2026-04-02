#!/usr/bin/env python3
"""Generate authenticated traffic from a seeded endpoint manifest."""

from __future__ import annotations

import argparse
import json
import random
import re
import ssl
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib import error, parse, request


PROBE_PATHS = {"/health", "/healthz", "/ready", "/readyz", "/live", "/livez", "/metrics"}
TRANSPORT_NOISE_PREFIXES = ("/socket.io/",)
SIGNED_ASSET_PREFIXES = ("/storage/v1/object/sign/",)
PLACEHOLDER_RE = re.compile(r":([A-Za-z_]\w*)|{([A-Za-z_]\w*)}|<([A-Za-z_]\w*)>")


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


def _load_manifest(path: Path) -> list[ManifestEndpoint]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    endpoints: list[ManifestEndpoint] = []
    for entry in payload.get("endpoints", []):
        if not isinstance(entry, dict):
            continue
        path_template = str(entry.get("path_template") or "").strip()
        if not path_template or "${" in path_template:
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
) -> tuple[int, Any]:
    headers = {
        "Accept": "application/json",
        "User-Agent": "logguard-traffic-generator/1.0",
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


def _request_endpoint(
    base_url: str,
    endpoint: ManifestEndpoint,
    token: str,
    rendered_path: str,
    *,
    timeout: float,
    insecure: bool,
) -> tuple[int, Any]:
    return _http_json(
        f"{base_url.rstrip('/')}{rendered_path}",
        method=endpoint.method,
        token=token,
        timeout=timeout,
        insecure=insecure,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, help="Path to the manifest JSON file")
    parser.add_argument("--base-url", required=True, help="API base URL, e.g. https://api.barterease.co")
    parser.add_argument("--firebase-api-key", required=True, help="Firebase Web API key used for email/password login")
    parser.add_argument("--email", required=True, help="Firebase user email")
    parser.add_argument("--password", required=True, help="Firebase user password")
    parser.add_argument("--iterations", type=int, default=25, help="Number of requests to make")
    parser.add_argument("--delay-seconds", type=float, default=0.2, help="Delay between requests")
    parser.add_argument("--param", action="append", default=[], help="Placeholder override in key=value form")
    parser.add_argument("--params-file", help="Optional JSON file with placeholder values")
    parser.add_argument("--include-writes", action="store_true", help="Include non-GET endpoints from the manifest")
    parser.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout in seconds")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate validation")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for endpoint selection")
    args = parser.parse_args()

    random.seed(args.seed)
    manifest_path = Path(args.manifest).expanduser().resolve()
    endpoints = _candidate_endpoints(_load_manifest(manifest_path), include_writes=args.include_writes)
    if not endpoints:
        print("No eligible endpoints found in manifest.", file=sys.stderr)
        return 1

    explicit_params = _merge_params(args.param, Path(args.params_file).expanduser().resolve() if args.params_file else None)
    auth_payload = _sign_in(
        args.firebase_api_key,
        args.email,
        args.password,
        timeout=args.timeout,
        insecure=args.insecure,
    )
    token = str(auth_payload["idToken"])
    discovered = _bootstrap_discovery(
        args.base_url,
        token,
        endpoints,
        explicit_params,
        auth_payload,
        timeout=args.timeout,
        insecure=args.insecure,
    )

    successes = 0
    skipped = 0
    failures = 0
    chosen_endpoints: list[dict[str, Any]] = []

    for _ in range(args.iterations):
        endpoint = random.choice(endpoints)
        rendered_path = _render_path(endpoint, explicit_params, discovered, auth_payload)
        if not rendered_path:
            skipped += 1
            continue
        status, payload = _request_endpoint(
            args.base_url,
            endpoint,
            token,
            rendered_path,
            timeout=args.timeout,
            insecure=args.insecure,
        )
        chosen_endpoints.append({"method": endpoint.method, "path": rendered_path, "status": status})
        if 200 <= status < 300:
            successes += 1
            _collect_ids(payload, discovered)
        else:
            failures += 1
        time.sleep(max(args.delay_seconds, 0.0))

    print(
        json.dumps(
            {
                "base_url": args.base_url,
                "manifest": str(manifest_path),
                "eligible_endpoint_count": len(endpoints),
                "requested_iterations": args.iterations,
                "successful_requests": successes,
                "failed_requests": failures,
                "skipped_unresolved": skipped,
                "discovered_placeholders": {key: values[:3] for key, values in sorted(discovered.items())},
                "sample_requests": chosen_endpoints[:20],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if successes > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
