#!/usr/bin/env python3
"""Extract a best-effort endpoint manifest from an external backend codebase."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib import request


HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD")
PROBE_PATHS = {"/health", "/healthz", "/ready", "/readyz", "/live", "/livez", "/metrics"}


@dataclass(frozen=True)
class Endpoint:
    method: str
    path_template: str
    framework: str

    def to_manifest_entry(self) -> dict:
        normalized_path = self.path_template if self.path_template.startswith("/") else f"/{self.path_template}"
        classification = "internal_probe" if normalized_path in PROBE_PATHS else "user_traffic"
        return {
            "method": self.method,
            "path_template": normalized_path,
            "classification": classification,
            "baseline_eligible": classification == "user_traffic",
        }


def _iter_source_files(source_root: Path) -> Iterable[Path]:
    for path in source_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in {".py", ".js", ".ts", ".tsx", ".mjs", ".cjs"}:
            yield path


def _join_paths(prefix: str, path: str) -> str:
    raw = f"{prefix.rstrip('/')}/{path.lstrip('/')}" if prefix else path
    if not raw.startswith("/"):
        raw = f"/{raw}"
    return raw.replace("//", "/")


def _python_module_name(source_root: Path, file_path: Path) -> str:
    relative = file_path.relative_to(source_root).with_suffix("")
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _build_fastapi_include_prefixes(source_root: Path) -> dict[str, list[str]]:
    prefix_map: dict[str, list[str]] = {}
    for file_path in source_root.rglob("*.py"):
        text = file_path.read_text(encoding="utf-8", errors="ignore")
        alias_map: dict[str, str] = {}
        for module_name, alias in re.findall(r"from\s+([\w\.]+)\s+import\s+router(?:\s+as\s+(\w+))?", text):
            alias_map[alias or "router"] = module_name
        for alias, prefix in re.findall(r"\w+\.include_router\((\w+),\s*prefix\s*=\s*[\"']([^\"']+)[\"']", text):
            module_name = alias_map.get(alias)
            if module_name:
                prefix_map.setdefault(module_name, []).append(prefix)
    return prefix_map


def _extract_fastapi_routes(file_path: Path, source_root: Path, include_prefixes: dict[str, list[str]]) -> list[Endpoint]:
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    file_prefix = ""
    prefix_match = re.search(r"APIRouter\s*\(\s*prefix\s*=\s*[\"']([^\"']+)[\"']", text)
    if prefix_match:
        file_prefix = prefix_match.group(1)
    module_prefixes = include_prefixes.get(_python_module_name(source_root, file_path), [""])

    routes: list[Endpoint] = []
    for method in HTTP_METHODS:
        pattern = re.compile(rf"@\s*(?:app|router)\.{method.lower()}\(\s*[\"']([^\"']+)[\"']")
        for match in pattern.finditer(text):
            local_path = _join_paths(file_prefix, match.group(1))
            for module_prefix in module_prefixes:
                routes.append(Endpoint(method=method, path_template=_join_paths(module_prefix, local_path), framework="fastapi"))
    return routes


def _extract_express_routes(file_path: Path) -> list[Endpoint]:
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    routes: list[Endpoint] = []
    for method in HTTP_METHODS:
        pattern = re.compile(rf"\b(?:app|router)\.{method.lower()}\(\s*[\"'`]([^\"'`]+)[\"'`]")
        for match in pattern.finditer(text):
            routes.append(Endpoint(method=method, path_template=match.group(1), framework="express"))
    return routes


def build_manifest(source_root: Path, service_name: str) -> dict:
    endpoints: dict[tuple[str, str], Endpoint] = {}
    include_prefixes = _build_fastapi_include_prefixes(source_root)
    for file_path in _iter_source_files(source_root):
        extracted = (
            _extract_fastapi_routes(file_path, source_root, include_prefixes)
            if file_path.suffix.lower() == ".py"
            else _extract_express_routes(file_path)
        )
        for endpoint in extracted:
            endpoints[(endpoint.method, endpoint.path_template)] = endpoint

    manifest_entries = [
        endpoint.to_manifest_entry()
        for endpoint in sorted(endpoints.values(), key=lambda item: (item.path_template, item.method))
    ]
    frameworks = sorted({endpoint.framework for endpoint in endpoints.values()})
    return {
        "service_name": service_name,
        "framework": frameworks[0] if len(frameworks) == 1 else "mixed",
        "frameworks_detected": frameworks,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_root": str(source_root),
        "endpoints": manifest_entries,
    }


def upload_manifest(seed_url: str, token: str | None, manifest: dict) -> dict:
    body = json.dumps({"manifest": manifest}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = request.Request(seed_url, data=body, headers=headers, method="POST")
    with request.urlopen(req, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="Path to the external backend source root")
    parser.add_argument("--service-name", required=True, help="Service name to embed in the manifest")
    parser.add_argument("--output", help="Optional file path to write the manifest JSON")
    parser.add_argument("--seed-url", help="Optional LogGuard backend seed endpoint URL")
    parser.add_argument("--project-id", help="Optional project id for display when seeding")
    parser.add_argument("--token", help="Optional bearer token for the seed request")
    args = parser.parse_args()

    source_root = Path(args.source).expanduser().resolve()
    manifest = build_manifest(source_root, args.service_name)
    rendered = json.dumps(manifest, indent=2, sort_keys=True)

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    if args.seed_url:
        response = upload_manifest(args.seed_url, args.token, manifest)
        print(
            json.dumps(
                {
                    "project_id": args.project_id,
                    "seed_url": args.seed_url,
                    "seed_response": response,
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
