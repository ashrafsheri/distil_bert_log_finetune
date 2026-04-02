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
TRANSPORT_NOISE_PREFIXES = ("/socket.io/",)
SIGNED_ASSET_PREFIXES = ("/storage/v1/object/sign/",)
ROUTE_TARGET_RE = re.compile(r"\b(?:app|router)\.(get|post|put|patch|delete|options|head)\(\s*[\"'`]([^\"'`]+)[\"'`]\s*,", re.IGNORECASE)
IMPORT_REQUIRE_RE = re.compile(
    r"""
    (?:
        const\s+(?P<const_name>\w+)\s*=\s*require\([\"'`](?P<const_target>[^\"'`]+)[\"'`]\)
      |
        const\s*\{\s*(?:router\s*:\s*)?(?P<object_name>\w+)\s*\}\s*=\s*require\([\"'`](?P<object_target>[^\"'`]+)[\"'`]\)
      |
        import\s+(?P<import_name>\w+)\s+from\s+[\"'`](?P<import_target>[^\"'`]+)[\"'`]
      |
        import\s+\{\s*(?:router\s+as\s+)?(?P<named_name>\w+)\s*\}\s+from\s+[\"'`](?P<named_target>[^\"'`]+)[\"'`]
    )
    """,
    re.VERBOSE,
)
USE_RE = re.compile(r"\b(?P<owner>app|router)\.use\(\s*[\"'`](?P<prefix>[^\"'`]+)[\"'`]\s*,(?P<rest>[^;]+)\)", re.MULTILINE)


@dataclass(frozen=True)
class Endpoint:
    method: str
    path_template: str
    framework: str

    def to_manifest_entry(self) -> dict:
        normalized_path = self.path_template if self.path_template.startswith("/") else f"/{self.path_template}"
        classification = "user_traffic"
        baseline_eligible = True
        lowered = normalized_path.lower()
        if normalized_path in PROBE_PATHS:
            classification = "internal_probe"
            baseline_eligible = False
        elif lowered.startswith(TRANSPORT_NOISE_PREFIXES):
            classification = "transport_noise"
            baseline_eligible = False
        elif lowered.startswith(SIGNED_ASSET_PREFIXES):
            classification = "signed_asset_access"
            baseline_eligible = False
        return {
            "method": self.method,
            "path_template": normalized_path,
            "classification": classification,
            "baseline_eligible": baseline_eligible,
        }


def _iter_source_files(source_root: Path) -> Iterable[Path]:
    for path in source_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in {".py", ".js", ".ts", ".tsx", ".mjs", ".cjs"}:
            yield path


def _is_supported_template(path_template: str) -> bool:
    normalized = (path_template or "").strip()
    if not normalized:
        return False
    if "${" in normalized:
        return False
    if any(ch.isspace() for ch in normalized):
        return False
    return True


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


def _js_module_name(source_root: Path, file_path: Path) -> str:
    relative = file_path.relative_to(source_root).with_suffix("")
    parts = list(relative.parts)
    if parts and parts[-1] == "index":
        parts = parts[:-1]
    return "/".join(parts)


def _resolve_js_import(source_root: Path, current_file: Path, target: str) -> str | None:
    if not target.startswith("."):
        return None
    candidate = (current_file.parent / target).resolve()
    possible_files = [
        candidate,
        candidate.with_suffix(".js"),
        candidate.with_suffix(".ts"),
        candidate.with_suffix(".mjs"),
        candidate.with_suffix(".cjs"),
        candidate / "index.js",
        candidate / "index.ts",
    ]
    for path in possible_files:
        if path.is_file() and source_root in path.parents:
            return _js_module_name(source_root, path)
    return None


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


def _parse_js_aliases(source_root: Path, file_path: Path, text: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for match in IMPORT_REQUIRE_RE.finditer(text):
        alias = (
            match.group("const_name")
            or match.group("object_name")
            or match.group("import_name")
            or match.group("named_name")
        )
        target = (
            match.group("const_target")
            or match.group("object_target")
            or match.group("import_target")
            or match.group("named_target")
        )
        if not alias or not target:
            continue
        resolved = _resolve_js_import(source_root, file_path, target)
        if resolved:
            aliases[alias] = resolved
    return aliases


def _extract_last_identifier(expression: str) -> str | None:
    identifiers = re.findall(r"[A-Za-z_]\w*", expression)
    return identifiers[-1] if identifiers else None


def _build_express_include_prefixes(source_root: Path) -> dict[str, list[str]]:
    module_files = {
        _js_module_name(source_root, path): path
        for path in _iter_source_files(source_root)
        if path.suffix.lower() in {".js", ".ts", ".mjs", ".cjs"}
    }
    root_prefixes: dict[str, set[str]] = {}
    child_edges: dict[str, list[tuple[str, str]]] = {}

    for module_name, file_path in module_files.items():
        text = file_path.read_text(encoding="utf-8", errors="ignore")
        aliases = _parse_js_aliases(source_root, file_path, text)
        for match in USE_RE.finditer(text):
            owner = match.group("owner")
            prefix = match.group("prefix")
            target_alias = _extract_last_identifier(match.group("rest"))
            if not target_alias:
                continue
            child_module = aliases.get(target_alias)
            if not child_module:
                continue
            if owner == "app":
                root_prefixes.setdefault(child_module, set()).add(prefix)
            else:
                child_edges.setdefault(module_name, []).append((prefix, child_module))

    resolved: dict[str, set[str]] = {module: set(prefixes) for module, prefixes in root_prefixes.items()}
    queue = list(root_prefixes.keys())
    while queue:
        current_module = queue.pop(0)
        current_prefixes = resolved.get(current_module, {""}) or {""}
        for child_prefix, child_module in child_edges.get(current_module, []):
            child_resolved = resolved.setdefault(child_module, set())
            before = len(child_resolved)
            for prefix in current_prefixes:
                child_resolved.add(_join_paths(prefix, child_prefix))
            if len(child_resolved) != before:
                queue.append(child_module)

    return {module: sorted(prefixes) for module, prefixes in resolved.items()}


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
                routes.append(
                    Endpoint(
                        method=method,
                        path_template=_join_paths(module_prefix, local_path),
                        framework="fastapi",
                    )
                )
    return routes


def _extract_express_routes(file_path: Path, source_root: Path, include_prefixes: dict[str, list[str]]) -> list[Endpoint]:
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    module_prefixes = include_prefixes.get(_js_module_name(source_root, file_path), [""])
    routes: list[Endpoint] = []
    for match in ROUTE_TARGET_RE.finditer(text):
        method = match.group(1).upper()
        path_template = match.group(2)
        for module_prefix in module_prefixes:
            routes.append(
                Endpoint(
                    method=method,
                    path_template=_join_paths(module_prefix, path_template),
                    framework="express",
                )
            )
    return routes


def build_manifest(source_root: Path, service_name: str) -> dict:
    endpoints: dict[tuple[str, str], Endpoint] = {}
    fastapi_prefixes = _build_fastapi_include_prefixes(source_root)
    express_prefixes = _build_express_include_prefixes(source_root)
    for file_path in _iter_source_files(source_root):
        extracted = (
            _extract_fastapi_routes(file_path, source_root, fastapi_prefixes)
            if file_path.suffix.lower() == ".py"
            else _extract_express_routes(file_path, source_root, express_prefixes)
        )
        for endpoint in extracted:
            if not _is_supported_template(endpoint.path_template):
                continue
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
        cleaned_token = token.strip()
        if cleaned_token.lower().startswith("bearer "):
            cleaned_token = cleaned_token[7:].strip()
        headers["Authorization"] = f"Bearer {cleaned_token}"
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
