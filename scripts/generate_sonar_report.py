#!/usr/bin/env python3
"""
Generate a SonarCloud report from the Web API and optionally export it to PDF.

The script always writes:
- raw JSON summary
- Markdown report
- HTML report

If `pandoc` or `wkhtmltopdf` is available, it also writes a PDF.
"""

from __future__ import annotations

import argparse
import html
import json
import math
import os
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests


DEFAULT_HOST_URL = "https://sonarcloud.io"
DEFAULT_PROJECT_KEY = "ashrafsheri_distil_bert_log_finetune"
DEFAULT_METRICS = [
    "alert_status",
    "bugs",
    "code_smells",
    "coverage",
    "duplicated_lines_density",
    "ncloc",
    "reliability_rating",
    "security_hotspots",
    "security_rating",
    "sqale_rating",
    "vulnerabilities",
]


@dataclass
class SonarClient:
    host_url: str
    token: str | None
    timeout: int = 30

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.host_url.rstrip('/')}{path}"
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        response = requests.get(url, params=params, headers=headers, timeout=self.timeout)

        # Public SonarCloud projects can be queried without authentication.
        # If a stale or invalid token is configured, SonarCloud returns 401.
        # Retry once without auth so public-report generation still works.
        if response.status_code == 401 and self.token:
            response = requests.get(url, params=params, timeout=self.timeout)

        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            message = (
                f"Sonar API request failed: {response.status_code} {response.reason} "
                f"for {response.url}"
            )
            if response.status_code == 401:
                message += (
                    ". The configured SONAR_TOKEN is missing, expired, or invalid. "
                    "For public projects, unset SONAR_TOKEN and retry; for private projects, "
                    "export a valid token with access to the project."
                )
            raise requests.HTTPError(message, response=response) from exc
        return response.json()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a SonarCloud report via Web API and export it to Markdown/HTML/PDF."
    )
    parser.add_argument(
        "--project-key",
        default=DEFAULT_PROJECT_KEY,
        help=f"Sonar project key. Default: {DEFAULT_PROJECT_KEY}",
    )
    parser.add_argument(
        "--host-url",
        default=os.getenv("SONAR_HOST_URL", DEFAULT_HOST_URL),
        help=f"Sonar host URL. Default: {DEFAULT_HOST_URL}",
    )
    parser.add_argument(
        "--token",
        default=os.getenv("SONAR_TOKEN"),
        help="Sonar token. Defaults to SONAR_TOKEN.",
    )
    parser.add_argument(
        "--output-dir",
        default="artifacts/sonar-report",
        help="Directory where report files will be written.",
    )
    parser.add_argument(
        "--issue-status",
        default="OPEN,CONFIRMED,REOPENED",
        help="Comma-separated issue statuses to include. Default: OPEN,CONFIRMED,REOPENED",
    )
    parser.add_argument(
        "--branch",
        help="Optional branch name for API queries.",
    )
    parser.add_argument(
        "--pdf-engine",
        choices=["auto", "pandoc", "wkhtmltopdf", "none"],
        default="auto",
        help="PDF generator to use. Default: auto",
    )
    return parser.parse_args()


def fetch_all_issues(
    client: SonarClient,
    project_key: str,
    issue_status: str,
    branch: str | None,
) -> dict[str, Any]:
    page = 1
    page_size = 500
    issues: list[dict[str, Any]] = []
    components: dict[str, dict[str, Any]] = {}

    while True:
        params: dict[str, Any] = {
            "componentKeys": project_key,
            "statuses": issue_status,
            "ps": page_size,
            "p": page,
        }
        if branch:
            params["branch"] = branch

        payload = client.get("/api/issues/search", params=params)
        issues.extend(payload.get("issues", []))
        for component in payload.get("components", []):
            components[component["key"]] = component

        paging = payload.get("paging", {})
        total = paging.get("total", len(issues))
        if page * page_size >= total:
            break
        page += 1

    return {"issues": issues, "components": list(components.values())}


def fetch_all_hotspots(client: SonarClient, project_key: str, branch: str | None) -> list[dict[str, Any]]:
    page = 1
    page_size = 500
    hotspots: list[dict[str, Any]] = []

    while True:
        params: dict[str, Any] = {
            "projectKey": project_key,
            "ps": page_size,
            "p": page,
        }
        if branch:
            params["branch"] = branch

        payload = client.get("/api/hotspots/search", params=params)
        hotspots.extend(payload.get("hotspots", []))
        paging = payload.get("paging", {})
        total = paging.get("total", len(hotspots))
        if page * page_size >= total:
            break
        page += 1

    return hotspots


def rating_letter(value: str | None) -> str:
    mapping = {
        "1.0": "A",
        "2.0": "B",
        "3.0": "C",
        "4.0": "D",
        "5.0": "E",
    }
    return mapping.get(str(value), str(value or "n/a"))


def build_summary(
    project_key: str,
    host_url: str,
    measures: dict[str, Any],
    quality_gate: dict[str, Any],
    issues_payload: dict[str, Any],
    hotspots: list[dict[str, Any]],
) -> dict[str, Any]:
    metric_map = {
        item["metric"]: item.get("value")
        for item in measures.get("component", {}).get("measures", [])
    }
    issues = issues_payload["issues"]

    issues_by_severity = Counter(issue.get("severity", "UNKNOWN") for issue in issues)
    issues_by_type = Counter(issue.get("type", "UNKNOWN") for issue in issues)
    issues_by_rule = Counter(issue.get("rule", "UNKNOWN") for issue in issues)
    hotspot_statuses = Counter(hotspot.get("status", "UNKNOWN") for hotspot in hotspots)

    grouped_issues: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for issue in issues:
        component = issue.get("component", "")
        grouped_issues[component].append(issue)

    sorted_grouped_issues = {
        component: sorted(
            component_issues,
            key=lambda issue: (
                issue.get("severity", ""),
                issue.get("rule", ""),
                issue.get("line") or 0,
            ),
        )
        for component, component_issues in sorted(grouped_issues.items())
    }

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "project_key": project_key,
        "dashboard_url": f"{host_url.rstrip('/')}/dashboard?id={project_key}",
        "metrics": {
            "alert_status": metric_map.get("alert_status"),
            "bugs": int(metric_map.get("bugs", 0)),
            "vulnerabilities": int(metric_map.get("vulnerabilities", 0)),
            "code_smells": int(metric_map.get("code_smells", 0)),
            "coverage": float(metric_map.get("coverage", 0.0)),
            "duplicated_lines_density": float(metric_map.get("duplicated_lines_density", 0.0)),
            "ncloc": int(metric_map.get("ncloc", 0)),
            "security_hotspots": int(metric_map.get("security_hotspots", 0) or 0),
            "reliability_rating": rating_letter(metric_map.get("reliability_rating")),
            "security_rating": rating_letter(metric_map.get("security_rating")),
            "maintainability_rating": rating_letter(metric_map.get("sqale_rating")),
        },
        "quality_gate": quality_gate.get("projectStatus", {}),
        "issue_counts": {
            "total": len(issues),
            "by_severity": dict(issues_by_severity),
            "by_type": dict(issues_by_type),
            "top_rules": issues_by_rule.most_common(20),
        },
        "issues_by_file": sorted_grouped_issues,
        "hotspots": {
            "total": len(hotspots),
            "by_status": dict(hotspot_statuses),
            "sample": hotspots[:50],
        },
    }


def render_markdown(summary: dict[str, Any]) -> str:
    metrics = summary["metrics"]
    qg = summary["quality_gate"]
    issue_counts = summary["issue_counts"]
    hotspot_counts = summary["hotspots"]["by_status"]

    lines = [
        f"# Sonar Report: `{summary['project_key']}`",
        "",
        f"- Generated: `{summary['generated_at_utc']}`",
        f"- Dashboard: {summary['dashboard_url']}",
        "",
        "## Metrics",
        "",
        f"- Quality Gate: `{metrics['alert_status']}`",
        f"- Reliability Rating: `{metrics['reliability_rating']}`",
        f"- Security Rating: `{metrics['security_rating']}`",
        f"- Maintainability Rating: `{metrics['maintainability_rating']}`",
        f"- Bugs: `{metrics['bugs']}`",
        f"- Vulnerabilities: `{metrics['vulnerabilities']}`",
        f"- Code Smells: `{metrics['code_smells']}`",
        f"- Security Hotspots: `{metrics['security_hotspots']}`",
        f"- Coverage: `{metrics['coverage']}%`",
        f"- Duplicated Lines Density: `{metrics['duplicated_lines_density']}%`",
        f"- Lines of Code: `{metrics['ncloc']}`",
        "",
        "## Quality Gate Conditions",
        "",
    ]

    for condition in qg.get("conditions", []):
        lines.append(
            "- "
            f"`{condition.get('metricKey')}`: "
            f"status=`{condition.get('status')}`, "
            f"actual=`{condition.get('actualValue')}`, "
            f"threshold=`{condition.get('errorThreshold')}`"
        )

    lines.extend(
        [
            "",
            "## Issue Summary",
            "",
            f"- Total issues in selected statuses: `{issue_counts['total']}`",
            f"- By severity: `{json.dumps(issue_counts['by_severity'], sort_keys=True)}`",
            f"- By type: `{json.dumps(issue_counts['by_type'], sort_keys=True)}`",
            "",
            "### Top Rules",
            "",
        ]
    )

    for rule, count in issue_counts["top_rules"]:
        lines.append(f"- `{rule}`: `{count}`")

    lines.extend(
        [
            "",
            "## Security Hotspots",
            "",
            f"- Total hotspots returned: `{summary['hotspots']['total']}`",
            f"- By status: `{json.dumps(hotspot_counts, sort_keys=True)}`",
            "",
            "## Issues By File",
            "",
        ]
    )

    for component, issues in summary["issues_by_file"].items():
        lines.append(f"### `{component}`")
        lines.append("")
        for issue in issues[:25]:
            line = issue.get("line", "?")
            lines.append(
                "- "
                f"[{issue.get('severity')}] "
                f"`{issue.get('rule')}` "
                f"(line `{line}`, type `{issue.get('type')}`): "
                f"{issue.get('message')}"
            )
        if len(issues) > 25:
            lines.append(f"- ... `{len(issues) - 25}` more issue(s)")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_html(summary: dict[str, Any]) -> str:
    metrics = summary["metrics"]
    qg = summary["quality_gate"]
    issue_counts = summary["issue_counts"]
    hotspot_counts = summary["hotspots"]["by_status"]

    def esc(value: Any) -> str:
        return html.escape(str(value))

    conditions_html = "\n".join(
        "<tr>"
        f"<td>{esc(condition.get('metricKey'))}</td>"
        f"<td>{esc(condition.get('status'))}</td>"
        f"<td>{esc(condition.get('actualValue'))}</td>"
        f"<td>{esc(condition.get('errorThreshold'))}</td>"
        "</tr>"
        for condition in qg.get("conditions", [])
    )

    top_rules_html = "\n".join(
        f"<tr><td>{esc(rule)}</td><td>{esc(count)}</td></tr>"
        for rule, count in issue_counts["top_rules"]
    )

    issues_by_file_html_parts: list[str] = []
    for component, issues in summary["issues_by_file"].items():
        rows = []
        for issue in issues[:25]:
            rows.append(
                "<tr>"
                f"<td>{esc(issue.get('severity'))}</td>"
                f"<td>{esc(issue.get('type'))}</td>"
                f"<td>{esc(issue.get('rule'))}</td>"
                f"<td>{esc(issue.get('line', '?'))}</td>"
                f"<td>{esc(issue.get('message'))}</td>"
                "</tr>"
            )
        more = ""
        if len(issues) > 25:
            more = f"<p class='muted'>{len(issues) - 25} more issue(s) omitted from this file.</p>"
        issues_by_file_html_parts.append(
            f"""
            <section class="card">
              <h3>{esc(component)}</h3>
              <table>
                <thead>
                  <tr><th>Severity</th><th>Type</th><th>Rule</th><th>Line</th><th>Message</th></tr>
                </thead>
                <tbody>
                  {''.join(rows) or '<tr><td colspan="5">No issues</td></tr>'}
                </tbody>
              </table>
              {more}
            </section>
            """
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Sonar Report - {esc(summary['project_key'])}</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 32px;
      color: #1f2937;
      line-height: 1.45;
    }}
    h1, h2, h3 {{ margin-bottom: 0.4rem; }}
    .meta, .muted {{ color: #6b7280; }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 16px;
      margin: 24px 0;
    }}
    .card {{
      border: 1px solid #d1d5db;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 20px;
      break-inside: avoid;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 12px;
      font-size: 14px;
    }}
    th, td {{
      border: 1px solid #e5e7eb;
      padding: 8px;
      text-align: left;
      vertical-align: top;
    }}
    th {{ background: #f9fafb; }}
    code {{
      background: #f3f4f6;
      padding: 1px 4px;
      border-radius: 4px;
    }}
  </style>
</head>
<body>
  <h1>Sonar Report</h1>
  <p class="meta"><strong>Project:</strong> <code>{esc(summary['project_key'])}</code></p>
  <p class="meta"><strong>Generated:</strong> <code>{esc(summary['generated_at_utc'])}</code></p>
  <p class="meta"><strong>Dashboard:</strong> <a href="{esc(summary['dashboard_url'])}">{esc(summary['dashboard_url'])}</a></p>

  <section class="grid">
    <div class="card"><h3>Quality Gate</h3><p><strong>{esc(metrics['alert_status'])}</strong></p></div>
    <div class="card"><h3>Bugs</h3><p><strong>{esc(metrics['bugs'])}</strong></p></div>
    <div class="card"><h3>Vulnerabilities</h3><p><strong>{esc(metrics['vulnerabilities'])}</strong></p></div>
    <div class="card"><h3>Code Smells</h3><p><strong>{esc(metrics['code_smells'])}</strong></p></div>
    <div class="card"><h3>Coverage</h3><p><strong>{esc(metrics['coverage'])}%</strong></p></div>
    <div class="card"><h3>Security Hotspots</h3><p><strong>{esc(metrics['security_hotspots'])}</strong></p></div>
  </section>

  <section class="card">
    <h2>Ratings</h2>
    <ul>
      <li>Reliability: <strong>{esc(metrics['reliability_rating'])}</strong></li>
      <li>Security: <strong>{esc(metrics['security_rating'])}</strong></li>
      <li>Maintainability: <strong>{esc(metrics['maintainability_rating'])}</strong></li>
      <li>Duplicated Lines Density: <strong>{esc(metrics['duplicated_lines_density'])}%</strong></li>
      <li>Lines of Code: <strong>{esc(metrics['ncloc'])}</strong></li>
    </ul>
  </section>

  <section class="card">
    <h2>Quality Gate Conditions</h2>
    <table>
      <thead>
        <tr><th>Metric</th><th>Status</th><th>Actual</th><th>Threshold</th></tr>
      </thead>
      <tbody>{conditions_html}</tbody>
    </table>
  </section>

  <section class="card">
    <h2>Issue Summary</h2>
    <p><strong>Total issues:</strong> {esc(issue_counts['total'])}</p>
    <p><strong>By severity:</strong> <code>{esc(json.dumps(issue_counts['by_severity'], sort_keys=True))}</code></p>
    <p><strong>By type:</strong> <code>{esc(json.dumps(issue_counts['by_type'], sort_keys=True))}</code></p>
    <table>
      <thead>
        <tr><th>Rule</th><th>Count</th></tr>
      </thead>
      <tbody>{top_rules_html}</tbody>
    </table>
  </section>

  <section class="card">
    <h2>Security Hotspots</h2>
    <p><strong>Total hotspots:</strong> {esc(summary['hotspots']['total'])}</p>
    <p><strong>By status:</strong> <code>{esc(json.dumps(hotspot_counts, sort_keys=True))}</code></p>
  </section>

  <h2>Issues By File</h2>
  {''.join(issues_by_file_html_parts)}
</body>
</html>
"""


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def generate_pdf(markdown_path: Path, html_path: Path, pdf_path: Path, engine: str) -> str | None:
    chosen = engine
    if chosen == "auto":
        if shutil.which("pandoc"):
            chosen = "pandoc"
        elif shutil.which("wkhtmltopdf"):
            chosen = "wkhtmltopdf"
        else:
            chosen = "none"

    if chosen == "none":
        return None

    if chosen == "pandoc":
        subprocess.run(
            ["pandoc", str(markdown_path), "-o", str(pdf_path)],
            check=True,
        )
        return "pandoc"

    if chosen == "wkhtmltopdf":
        subprocess.run(
            ["wkhtmltopdf", str(html_path), str(pdf_path)],
            check=True,
        )
        return "wkhtmltopdf"

    raise ValueError(f"Unsupported PDF engine: {engine}")


def main() -> int:
    args = parse_args()
    client = SonarClient(host_url=args.host_url, token=args.token)
    output_dir = Path(args.output_dir)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = f"sonar-report-{args.project_key}-{timestamp}"

    params: dict[str, Any] = {
        "component": args.project_key,
        "metricKeys": ",".join(DEFAULT_METRICS),
    }
    if args.branch:
        params["branch"] = args.branch

    quality_gate_params: dict[str, Any] = {"projectKey": args.project_key}
    if args.branch:
        quality_gate_params["branch"] = args.branch

    measures = client.get("/api/measures/component", params=params)
    quality_gate = client.get("/api/qualitygates/project_status", params=quality_gate_params)
    issues_payload = fetch_all_issues(client, args.project_key, args.issue_status, args.branch)
    hotspots = fetch_all_hotspots(client, args.project_key, args.branch)

    summary = build_summary(
        project_key=args.project_key,
        host_url=args.host_url,
        measures=measures,
        quality_gate=quality_gate,
        issues_payload=issues_payload,
        hotspots=hotspots,
    )

    json_path = output_dir / f"{stem}.json"
    markdown_path = output_dir / f"{stem}.md"
    html_path = output_dir / f"{stem}.html"
    pdf_path = output_dir / f"{stem}.pdf"

    write_json(json_path, summary)
    write_text(markdown_path, render_markdown(summary))
    write_text(html_path, render_html(summary))

    pdf_engine = None
    try:
        pdf_engine = generate_pdf(markdown_path, html_path, pdf_path, args.pdf_engine)
    except subprocess.CalledProcessError as exc:
        print(f"PDF generation failed using {args.pdf_engine}: {exc}", file=sys.stderr)

    print(f"JSON report: {json_path}")
    print(f"Markdown report: {markdown_path}")
    print(f"HTML report: {html_path}")
    if pdf_engine:
        print(f"PDF report: {pdf_path} (generated with {pdf_engine})")
    else:
        print("PDF report: skipped (install pandoc or wkhtmltopdf, or set --pdf-engine)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
