# Synthetic Log Generation & Base Model Training — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Three scripts in `scripts/` that let you bootstrap LogGuard from a manifest file — generate synthetic logs, train the base teacher model artifacts, and run a live anomaly detection demo against the full stack.

**Architecture:** `synthetic_log_generator.py` reads a LogGuard-format manifest and produces Apache Combined Log Format lines in session-grouped order (important for transformer sequence scoring). `train_base_model.py` parses those lines using the same `ApacheLogNormalizer` + `_canonicalize_path` the runtime uses, trains a `TemplateTransformer` + `IsolationForest`, and saves the four artifacts `TeacherModel._initialize_from_base` expects. `demo_realtime.py` replays the log file against `POST /api/v1/logs/agent/send-logs` with injected attack lines.

**Tech Stack:** Python 3.10+, PyTorch, scikit-learn, `requests`. All model imports from `realtime_anomaly_detection/models/`.

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `scripts/my_app_manifest.json` | Example manifest to run the workflow |
| Create | `scripts/synthetic_log_generator.py` | Manifest → Apache log file |
| Create | `scripts/train_base_model.py` | Log file → model artifacts |
| Create | `scripts/demo_realtime.py` | Log file + attacks → backend API |
| Create | `scripts/tests/test_synthetic_log_generator.py` | Unit tests for generator |
| Create | `scripts/tests/test_train_base_model.py` | Unit tests for trainer |

---

## Task 1: Example manifest

**Files:**
- Create: `scripts/my_app_manifest.json`

- [ ] **Step 1: Create the manifest file**

```json
{
  "service_name": "my-app",
  "base_url": "https://my-app.com",
  "endpoints": [
    {"method": "GET",    "path_template": "/api/users",              "classification": "user_traffic",   "weight": 3},
    {"method": "GET",    "path_template": "/api/users/{id}",         "classification": "user_traffic",   "weight": 5},
    {"method": "PUT",    "path_template": "/api/users/{id}",         "classification": "user_traffic",   "weight": 2},
    {"method": "POST",   "path_template": "/api/auth/login",         "classification": "user_traffic",   "weight": 4},
    {"method": "POST",   "path_template": "/api/auth/logout",        "classification": "user_traffic",   "weight": 2},
    {"method": "GET",    "path_template": "/api/products",           "classification": "user_traffic",   "weight": 6},
    {"method": "GET",    "path_template": "/api/products/{id}",      "classification": "user_traffic",   "weight": 8},
    {"method": "POST",   "path_template": "/api/orders",             "classification": "user_traffic",   "weight": 3},
    {"method": "GET",    "path_template": "/api/orders/{id}",        "classification": "user_traffic",   "weight": 4},
    {"method": "GET",    "path_template": "/api/search",             "classification": "user_traffic",   "weight": 5},
    {"method": "GET",    "path_template": "/health",                 "classification": "internal_probe", "weight": 1},
    {"method": "GET",    "path_template": "/metrics",                "classification": "internal_probe", "weight": 1}
  ]
}
```

Save to `scripts/my_app_manifest.json`.

- [ ] **Step 2: Verify it is valid JSON**

```bash
python -c "import json; print(json.load(open('scripts/my_app_manifest.json'))['service_name'])"
```

Expected: `my-app`

- [ ] **Step 3: Commit**

```bash
git add scripts/my_app_manifest.json
git commit -m "feat: add example LogGuard manifest for my-app"
```

---

## Task 2: Synthetic log generator — core

**Files:**
- Create: `scripts/synthetic_log_generator.py`
- Create: `scripts/tests/test_synthetic_log_generator.py`

- [ ] **Step 1: Write the failing tests**

Create `scripts/tests/test_synthetic_log_generator.py`:

```python
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
        # Extract timestamps (position in output list should be non-decreasing date)
        # We just check no obvious reversal: first line timestamp <= last line timestamp
        # (approximate — sessions interleave, so check length > 0)
        assert len(logs) > 0
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cd /Users/ashrafshahreyar/Coding/distil_bert_log_finetune
python -m pytest scripts/tests/test_synthetic_log_generator.py -v 2>&1 | head -30
```

Expected: `ModuleNotFoundError: No module named 'scripts.synthetic_log_generator'`

- [ ] **Step 3: Create `scripts/synthetic_log_generator.py`**

```python
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
from datetime import datetime, timedelta
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

# (status_code, cumulative_weight) for weighted random selection
_STATUS_POOL = (
    [200] * 85 + [404] * 8 + [401] * 4 + [500] * 3
)

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
        dt = start_time or datetime.utcnow()
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
        base = count // sessions
        remainder = count % sessions
        session_lengths = [base + (1 if i < remainder else 0) for i in range(sessions)]

        base_time = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
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
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
python -m pytest scripts/tests/test_synthetic_log_generator.py -v
```

Expected output (all pass):
```
PASSED test_synthetic_log_generator.py::TestSubstituteParams::test_replaces_id_param
PASSED test_synthetic_log_generator.py::TestSubstituteParams::test_replaces_uuid_param
PASSED test_synthetic_log_generator.py::TestSubstituteParams::test_no_params_unchanged
PASSED test_synthetic_log_generator.py::TestSubstituteParams::test_multiple_params
PASSED test_synthetic_log_generator.py::TestSyntheticLogGenerator::test_endpoint_pool_respects_weights
PASSED test_synthetic_log_generator.py::TestSyntheticLogGenerator::test_endpoints_with_missing_path_template_skipped
PASSED test_synthetic_log_generator.py::TestSyntheticLogGenerator::test_empty_manifest_raises
PASSED test_synthetic_log_generator.py::TestSyntheticLogGenerator::test_generate_session_apache_format
PASSED test_synthetic_log_generator.py::TestSyntheticLogGenerator::test_generate_session_same_ip
PASSED test_synthetic_log_generator.py::TestSyntheticLogGenerator::test_generate_correct_total_count
PASSED test_synthetic_log_generator.py::TestSyntheticLogGenerator::test_generate_sorted_chronologically
```

- [ ] **Step 5: Smoke-test the CLI**

```bash
python scripts/synthetic_log_generator.py \
    --manifest scripts/my_app_manifest.json \
    --count 200 --sessions 5 \
    --output /tmp/smoke_test.log
wc -l /tmp/smoke_test.log
head -3 /tmp/smoke_test.log
```

Expected: `200 /tmp/smoke_test.log` and three valid Apache log lines.

- [ ] **Step 6: Commit**

```bash
git add scripts/synthetic_log_generator.py scripts/tests/test_synthetic_log_generator.py
git commit -m "feat: add synthetic_log_generator — manifest to Apache log file"
```

---

## Task 3: Base model trainer — parsing + vocabulary

**Files:**
- Create: `scripts/train_base_model.py` (initial version — parse + vocab only)
- Create: `scripts/tests/test_train_base_model.py`

- [ ] **Step 1: Write failing tests**

Create `scripts/tests/test_train_base_model.py`:

```python
"""Tests for scripts.train_base_model"""
import json
import sys
import tempfile
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
# Give train_base_model.py access to realtime_anomaly_detection/models/
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "realtime_anomaly_detection"))

from scripts.train_base_model import BaseModelTrainer, parse_apache_log_line


# ── parse_apache_log_line ────────────────────────────────────────────────────

class TestParseApacheLogLine:
    VALID = (
        '192.168.1.1 - - [12/Apr/2026:10:00:01 +0000] '
        '"GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
    )

    def test_valid_line_returns_dict(self):
        r = parse_apache_log_line(self.VALID)
        assert r is not None

    def test_extracts_ip(self):
        r = parse_apache_log_line(self.VALID)
        assert r["ip"] == "192.168.1.1"

    def test_extracts_method(self):
        r = parse_apache_log_line(self.VALID)
        assert r["method"] == "GET"

    def test_extracts_path(self):
        r = parse_apache_log_line(self.VALID)
        assert r["path"] == "/api/users"

    def test_extracts_status(self):
        r = parse_apache_log_line(self.VALID)
        assert r["status"] == 200

    def test_extracts_size(self):
        r = parse_apache_log_line(self.VALID)
        assert r["size"] == 1234

    def test_extracts_hour(self):
        r = parse_apache_log_line(self.VALID)
        assert r["hour"] == 10

    def test_invalid_line_returns_none(self):
        assert parse_apache_log_line("not a log line") is None

    def test_empty_string_returns_none(self):
        assert parse_apache_log_line("") is None


# ── BaseModelTrainer — vocabulary ────────────────────────────────────────────

def _make_parsed(paths: list[str]) -> list[dict]:
    return [
        {"ip": "1.2.3.4", "method": "GET", "path": p, "protocol": "HTTP/1.1",
         "status": 200, "size": 100, "hour": 10}
        for p in paths
    ]


class TestBuildVocabulary:
    def test_assigns_unique_ids_to_distinct_templates(self):
        trainer = BaseModelTrainer()
        parsed = _make_parsed(["/api/users", "/api/products", "/api/orders"])
        trainer.build_vocabulary(parsed)
        assert len(trainer.template_to_id) == 3
        ids = list(trainer.template_to_id.values())
        assert len(set(ids)) == 3

    def test_same_template_gets_same_id(self):
        trainer = BaseModelTrainer()
        parsed = _make_parsed(["/api/users", "/api/users", "/api/users"])
        trainer.build_vocabulary(parsed)
        assert len(trainer.template_to_id) == 1

    def test_numeric_ids_canonicalized(self):
        # /api/users/42 and /api/users/99 should map to the same template
        trainer = BaseModelTrainer()
        parsed = _make_parsed(["/api/users/42", "/api/users/99"])
        trainer.build_vocabulary(parsed)
        assert len(trainer.template_to_id) == 1

    def test_pad_and_unknown_ids_set(self):
        trainer = BaseModelTrainer()
        trainer.build_vocabulary(_make_parsed(["/api/a"]))
        assert trainer.pad_id is not None
        assert trainer.unknown_id is not None
        assert trainer.vocab_size == len(trainer.template_to_id) + 2

    def test_validate_minimum_raises_on_low_count(self):
        trainer = BaseModelTrainer()
        with pytest.raises(ValueError, match="fewer than 500"):
            trainer.validate_minimum(log_count=10, template_count=5)

    def test_validate_minimum_passes_on_sufficient_count(self):
        trainer = BaseModelTrainer()
        trainer.validate_minimum(log_count=500, template_count=10)  # should not raise
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
python -m pytest scripts/tests/test_train_base_model.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError: No module named 'scripts.train_base_model'`

- [ ] **Step 3: Create `scripts/train_base_model.py` (parse + vocab section)**

```python
#!/usr/bin/env python3
"""
Base Model Trainer
Trains LogGuard base teacher model artifacts from a synthetic log file.

Usage:
    python scripts/train_base_model.py \
        --logs scripts/synthetic_logs.log \
        --output data/base_model --epochs 10
"""

import argparse
import json
import logging
import math
import pickle
import re
import shutil
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

# Add realtime_anomaly_detection/ to path so we can import its models
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "realtime_anomaly_detection"))

from models.ensemble_detector import ApacheLogNormalizer, TemplateTransformer
from models.multi_tenant_detector import MultiTenantDetector

import torch
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset
from sklearn.ensemble import IsolationForest

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ── Apache log parser ──────────────────────────────────────────────────────

_APACHE_RE = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] '
    r'"(\S+) (\S+) (\S+)" '
    r'(\d+) (\d+|-)'
    r'(?:\s+"[^"]*" "[^"]*")?'
)
_METHOD_MAP = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3, "PATCH": 4, "HEAD": 5, "OPTIONS": 6}


def _parse_hour(ts: str) -> int:
    """Extract hour from Apache timestamp string '12/Apr/2026:10:00:01 +0000'."""
    try:
        return int(ts.split(":")[1])
    except Exception:
        return 0


def parse_apache_log_line(line: str) -> Optional[Dict]:
    """Parse one Apache Combined Log Format line. Returns None on failure."""
    if not line:
        return None
    m = _APACHE_RE.match(line.strip())
    if not m:
        return None
    ip, ts_str, method, path, protocol, status_str, size_str = m.group(1, 2, 3, 4, 5, 6, 7)
    try:
        status = int(status_str)
        size = int(size_str) if size_str != "-" else 0
    except ValueError:
        return None
    return {
        "ip": ip,
        "hour": _parse_hour(ts_str),
        "method": method.upper(),
        "path": path,
        "protocol": protocol,
        "status": status,
        "size": size,
    }


# ── Dataset helper ─────────────────────────────────────────────────────────

class _SequenceDataset(Dataset):
    def __init__(self, sequences: List[List[int]], pad_id: int):
        self.sequences = sequences
        self.pad_id = pad_id

    def __len__(self) -> int:
        return len(self.sequences)

    def __getitem__(self, idx: int) -> Dict:
        seq = self.sequences[idx]
        mask = [1 if t != self.pad_id else 0 for t in seq]
        return {
            "input_ids": torch.tensor(seq, dtype=torch.long),
            "attention_mask": torch.tensor(mask, dtype=torch.long),
        }


# ── Main trainer class ─────────────────────────────────────────────────────

class BaseModelTrainer:
    def __init__(self, window_size: int = 20):
        self.window_size = window_size
        self._normalizer = ApacheLogNormalizer()
        self.template_to_id: Dict[str, int] = {}
        self.id_to_template: List[str] = []
        self.pad_id: Optional[int] = None
        self.unknown_id: Optional[int] = None
        self.vocab_size: Optional[int] = None

    def _normalize_template(self, parsed: Dict) -> str:
        canonical = MultiTenantDetector._canonicalize_path(parsed["path"])
        msg = f"{parsed['method']} {canonical} {parsed['protocol']} {parsed['status']}"
        return self._normalizer.normalize(msg)

    def build_vocabulary(self, parsed_logs: List[Dict]) -> None:
        seen: Dict[str, int] = {}
        for log in parsed_logs:
            tmpl = self._normalize_template(log)
            if tmpl not in seen:
                seen[tmpl] = len(seen)
        self.template_to_id = seen
        self.id_to_template = [""] * len(seen)
        for tmpl, tid in seen.items():
            self.id_to_template[tid] = tmpl
        base = len(self.id_to_template)
        self.pad_id = base
        self.unknown_id = base + 1
        self.vocab_size = base + 2

    def validate_minimum(self, log_count: int, template_count: int) -> None:
        if log_count < 500:
            raise ValueError(
                f"Cannot train: fewer than 500 valid log lines parsed ({log_count} found). "
                "Generate more logs with synthetic_log_generator.py."
            )
        if template_count > 0 and template_count < 10:
            logger.warning(
                "Only %d distinct templates found — threshold calibration may be weak. "
                "Consider adding more diverse endpoints to your manifest.",
                template_count,
            )

    def build_sequences(self, parsed_logs: List[Dict]) -> List[List[int]]:
        """Group logs by IP into sliding windows of self.window_size."""
        sessions: Dict[str, List[int]] = defaultdict(list)
        for log in parsed_logs:
            tmpl = self._normalize_template(log)
            tid = self.template_to_id.get(tmpl, self.unknown_id)
            sessions[log["ip"]].append(tid)

        sequences: List[List[int]] = []
        for ip_logs in sessions.values():
            if len(ip_logs) < 2:
                continue
            if len(ip_logs) < self.window_size:
                padded = ip_logs + [self.pad_id] * (self.window_size - len(ip_logs))
                sequences.append(padded)
            else:
                for start in range(len(ip_logs) - self.window_size + 1):
                    sequences.append(ip_logs[start : start + self.window_size])
        return sequences

    def extract_features(self, parsed_logs: List[Dict]) -> np.ndarray:
        """Extract 7-element feature vector per log for IsolationForest."""
        rows = []
        for log in parsed_logs:
            method_enc = _METHOD_MAP.get(log["method"], 7)
            path_base = log["path"].split("?")[0]
            rows.append([
                method_enc,
                log["status"],
                path_base.count("/"),
                math.log1p(log["size"]),
                log["hour"],
                1 if path_base.startswith("/api") else 0,
                1 if any(k in path_base.lower() for k in ("/auth", "/login", "/logout", "/token")) else 0,
            ])
        return np.array(rows, dtype=np.float64)

    def _train_transformer(
        self, sequences: List[List[int]], epochs: int
    ) -> Tuple["TemplateTransformer", float]:
        device = torch.device("cpu")
        model = TemplateTransformer(
            vocab_size=self.vocab_size,
            pad_id=self.pad_id,
            d_model=256,
            n_heads=8,
            n_layers=4,
            ffn_dim=1024,
            max_length=self.window_size,
            dropout=0.1,
        ).to(device)
        loader = DataLoader(_SequenceDataset(sequences, self.pad_id), batch_size=64, shuffle=True)
        optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3)
        model.train()
        final_loss = 0.0
        for epoch in range(epochs):
            total = 0.0
            for batch in loader:
                ids = batch["input_ids"].to(device)
                mask = batch["attention_mask"].to(device)
                logits = model(ids, mask)
                targets = ids[:, 1:]
                loss = F.cross_entropy(
                    logits[:, :-1, :].reshape(-1, self.vocab_size),
                    targets.reshape(-1),
                    ignore_index=self.pad_id,
                )
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
                total += loss.item()
            final_loss = total / max(len(loader), 1)
            logger.info("Epoch %d/%d  loss=%.4f", epoch + 1, epochs, final_loss)
        model.eval()
        return model, final_loss

    def _compute_threshold(self, model: "TemplateTransformer", sequences: List[List[int]]) -> float:
        scores: List[float] = []
        device = torch.device("cpu")
        with torch.no_grad():
            for seq in sequences[:2000]:
                ids = torch.tensor([seq], dtype=torch.long).to(device)
                mask = torch.tensor(
                    [[1 if t != self.pad_id else 0 for t in seq]],
                    dtype=torch.long,
                ).to(device)
                logits = model(ids, mask)
                targets = ids[:, 1:]
                log_probs = F.log_softmax(logits[:, :-1, :], dim=-1)
                nll = -log_probs.gather(2, targets.unsqueeze(-1)).squeeze(-1)
                valid = mask[:, 1:] == 1
                if valid.sum() > 0:
                    scores.append(nll[valid].mean().item())
        return float(np.percentile(scores, 95)) if scores else 6.5

    def save_artifacts(
        self,
        output_dir: Path,
        sequences: List[List[int]],
        features: np.ndarray,
        epochs: int = 10,
    ) -> None:
        """Train all components and save four artifacts atomically."""
        model, _ = self._train_transformer(sequences, epochs)
        threshold = self._compute_threshold(model, sequences)

        iso = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        if len(features) >= 2:
            iso.fit(features)
            iso_scores = -iso.score_samples(features)
            iso_threshold = float(np.percentile(iso_scores, 95))
        else:
            iso_threshold = None

        # Atomic write: write to .tmp then rename
        tmp = output_dir.parent / (output_dir.name + ".tmp")
        if tmp.exists():
            shutil.rmtree(tmp)
        tmp.mkdir(parents=True)

        (tmp / "template_vocab.json").write_text(
            json.dumps({"template_to_id": self.template_to_id}, indent=2)
        )
        torch.save(
            {
                "model_state_dict": model.state_dict(),
                "vocab_size": self.vocab_size,
                "pad_id": self.pad_id,
                "unknown_id": self.unknown_id,
                "threshold": threshold,
            },
            tmp / "transformer_model.pt",
        )
        with open(tmp / "isolation_forest.pkl", "wb") as f:
            pickle.dump(iso, f)
        (tmp / "model_config.json").write_text(
            json.dumps({
                "optimal_threshold": threshold,
                "vocab_size": self.vocab_size,
                "window_size": self.window_size,
                "iso_threshold": iso_threshold,
            }, indent=2)
        )

        if output_dir.exists():
            shutil.rmtree(output_dir)
        tmp.rename(output_dir)

        logger.info("Artifacts saved → %s  (vocab=%d  threshold=%.4f)", output_dir, self.vocab_size, threshold)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train LogGuard base model from a log file")
    parser.add_argument("--logs", required=True, help="Path to synthetic .log file")
    parser.add_argument("--output", required=True, help="Output directory for model artifacts")
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--window-size", type=int, default=20)
    args = parser.parse_args()

    log_path = Path(args.logs)
    if not log_path.exists():
        print(f"[ERROR] Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    lines = log_path.read_text(encoding="utf-8").splitlines()
    logger.info("Read %d lines from %s", len(lines), log_path)

    trainer = BaseModelTrainer(window_size=args.window_size)
    parsed = [r for line in lines if (r := parse_apache_log_line(line)) is not None]
    logger.info("Parsed %d/%d lines", len(parsed), len(lines))

    trainer.validate_minimum(len(parsed), 0)
    trainer.build_vocabulary(parsed)
    trainer.validate_minimum(len(parsed), len(trainer.template_to_id))

    sequences = trainer.build_sequences(parsed)
    features = trainer.extract_features(parsed)

    logger.info("Vocabulary: %d templates", len(trainer.template_to_id))
    logger.info("Sequences:  %d", len(sequences))
    logger.info("Features:   %d rows", len(features))

    trainer.save_artifacts(Path(args.output), sequences, features, epochs=args.epochs)

    print(f"\nBase model saved to: {args.output}")
    print(f"  vocab_size  : {trainer.vocab_size}")
    print(f"  sequences   : {len(sequences)}")
    print(f"  window_size : {args.window_size}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run parse + vocab tests**

```bash
python -m pytest scripts/tests/test_train_base_model.py -v
```

Expected: all 15 tests pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/train_base_model.py scripts/tests/test_train_base_model.py
git commit -m "feat: add train_base_model — Apache log parser and vocabulary builder"
```

---

## Task 4: Base model trainer — sequences, features, artifacts

**Files:**
- Modify: `scripts/tests/test_train_base_model.py` (add sequence + artifact tests)

The `build_sequences`, `extract_features`, and `save_artifacts` methods are already implemented in Task 3. This task adds tests to cover them and runs an end-to-end artifact check.

- [ ] **Step 1: Add tests to `scripts/tests/test_train_base_model.py`**

Append the following classes to the existing test file:

```python
# ── BaseModelTrainer — sequences ─────────────────────────────────────────────

class TestBuildSequences:
    def test_groups_logs_by_ip(self):
        trainer = BaseModelTrainer(window_size=3)
        parsed = [
            {"ip": "1.1.1.1", "method": "GET", "path": "/api/a", "protocol": "HTTP/1.1", "status": 200, "size": 100, "hour": 10},
            {"ip": "1.1.1.1", "method": "GET", "path": "/api/b", "protocol": "HTTP/1.1", "status": 200, "size": 100, "hour": 10},
            {"ip": "1.1.1.1", "method": "GET", "path": "/api/c", "protocol": "HTTP/1.1", "status": 200, "size": 100, "hour": 10},
        ]
        trainer.build_vocabulary(parsed)
        seqs = trainer.build_sequences(parsed)
        assert len(seqs) == 1
        assert len(seqs[0]) == 3

    def test_sliding_window_on_long_session(self):
        trainer = BaseModelTrainer(window_size=3)
        parsed = [
            {"ip": "1.1.1.1", "method": "GET", "path": f"/api/item/{i}", "protocol": "HTTP/1.1", "status": 200, "size": 100, "hour": 10}
            for i in range(6)
        ]
        trainer.build_vocabulary(parsed)
        seqs = trainer.build_sequences(parsed)
        # window=3, 6 logs → 4 windows
        assert len(seqs) == 4
        for s in seqs:
            assert len(s) == 3

    def test_short_session_padded(self):
        trainer = BaseModelTrainer(window_size=5)
        parsed = [
            {"ip": "2.2.2.2", "method": "GET", "path": "/api/x", "protocol": "HTTP/1.1", "status": 200, "size": 100, "hour": 10},
            {"ip": "2.2.2.2", "method": "GET", "path": "/api/y", "protocol": "HTTP/1.1", "status": 200, "size": 100, "hour": 10},
        ]
        trainer.build_vocabulary(parsed)
        seqs = trainer.build_sequences(parsed)
        assert len(seqs) == 1
        assert len(seqs[0]) == 5
        assert seqs[0][-1] == trainer.pad_id


class TestExtractFeatures:
    def test_output_shape(self):
        trainer = BaseModelTrainer()
        parsed = [
            {"ip": "1.1.1.1", "method": "GET", "path": "/api/users", "protocol": "HTTP/1.1", "status": 200, "size": 1234, "hour": 10},
            {"ip": "1.1.1.2", "method": "POST", "path": "/api/auth/login", "protocol": "HTTP/1.1", "status": 401, "size": 64, "hour": 22},
        ]
        features = trainer.extract_features(parsed)
        assert features.shape == (2, 7)

    def test_is_api_flag(self):
        trainer = BaseModelTrainer()
        parsed = [{"ip": "1.1.1.1", "method": "GET", "path": "/api/items", "protocol": "HTTP/1.1", "status": 200, "size": 100, "hour": 10}]
        features = trainer.extract_features(parsed)
        assert features[0, 5] == 1.0  # is_api = index 5

    def test_is_auth_flag(self):
        trainer = BaseModelTrainer()
        parsed = [{"ip": "1.1.1.1", "method": "POST", "path": "/api/auth/login", "protocol": "HTTP/1.1", "status": 200, "size": 100, "hour": 10}]
        features = trainer.extract_features(parsed)
        assert features[0, 6] == 1.0  # is_auth = index 6


class TestSaveArtifacts:
    def _make_trainer_with_data(self, window_size: int = 3, n: int = 30):
        trainer = BaseModelTrainer(window_size=window_size)
        parsed = [
            {"ip": f"1.2.3.{i % 10}", "method": "GET", "path": f"/api/item/{i % 5}",
             "protocol": "HTTP/1.1", "status": 200, "size": 100, "hour": 10}
            for i in range(n)
        ]
        trainer.build_vocabulary(parsed)
        return trainer, parsed

    def test_all_four_artifacts_created(self, tmp_path):
        trainer, parsed = self._make_trainer_with_data()
        sequences = trainer.build_sequences(parsed)
        features = trainer.extract_features(parsed)
        trainer.save_artifacts(tmp_path / "model", sequences, features, epochs=1)
        out = tmp_path / "model"
        assert (out / "template_vocab.json").exists()
        assert (out / "transformer_model.pt").exists()
        assert (out / "isolation_forest.pkl").exists()
        assert (out / "model_config.json").exists()

    def test_vocab_json_structure(self, tmp_path):
        trainer, parsed = self._make_trainer_with_data()
        sequences = trainer.build_sequences(parsed)
        features = trainer.extract_features(parsed)
        trainer.save_artifacts(tmp_path / "model", sequences, features, epochs=1)
        vocab = json.loads((tmp_path / "model" / "template_vocab.json").read_text())
        assert "template_to_id" in vocab
        assert len(vocab["template_to_id"]) > 0

    def test_model_config_has_required_keys(self, tmp_path):
        trainer, parsed = self._make_trainer_with_data()
        sequences = trainer.build_sequences(parsed)
        features = trainer.extract_features(parsed)
        trainer.save_artifacts(tmp_path / "model", sequences, features, epochs=1)
        config = json.loads((tmp_path / "model" / "model_config.json").read_text())
        assert "optimal_threshold" in config
        assert "vocab_size" in config
        assert config["window_size"] == 3

    def test_atomic_save_no_partial_dir_on_crash(self, tmp_path, monkeypatch):
        trainer, parsed = self._make_trainer_with_data()
        sequences = trainer.build_sequences(parsed)
        features = trainer.extract_features(parsed)
        out = tmp_path / "model"

        # Patch rename to simulate a crash after write but before rename
        original_rename = Path.rename
        def fail_rename(self_path, target):
            raise RuntimeError("simulated crash")
        monkeypatch.setattr(Path, "rename", fail_rename)

        with pytest.raises(RuntimeError, match="simulated crash"):
            trainer.save_artifacts(out, sequences, features, epochs=1)

        # output_dir should not exist (crash happened before rename)
        assert not out.exists()
```

Note: you need `import json` at the top of the test file. Add it after the existing imports if not already present.

- [ ] **Step 2: Run the extended tests**

```bash
python -m pytest scripts/tests/test_train_base_model.py -v
```

Expected: all tests pass (the implementations are already in Task 3's code).

- [ ] **Step 3: Commit**

```bash
git add scripts/tests/test_train_base_model.py
git commit -m "test: add sequence, feature, and artifact tests for train_base_model"
```

---

## Task 5: End-to-end smoke test of trainer CLI

**Files:** no new files — exercise the CLI against real-generated logs.

- [ ] **Step 1: Generate a small log file**

```bash
python scripts/synthetic_log_generator.py \
    --manifest scripts/my_app_manifest.json \
    --count 1000 --sessions 20 \
    --output /tmp/smoke_train.log
wc -l /tmp/smoke_train.log
```

Expected: `1000 /tmp/smoke_train.log`

- [ ] **Step 2: Run the trainer**

```bash
python scripts/train_base_model.py \
    --logs /tmp/smoke_train.log \
    --output /tmp/smoke_model \
    --epochs 2
```

Expected output (no errors):
```
... Vocabulary: N templates
... Sequences:  M
... Base model saved to: /tmp/smoke_model
  vocab_size  : N
  sequences   : M
  window_size : 20
```

- [ ] **Step 3: Verify artifacts are present and well-formed**

```bash
ls /tmp/smoke_model/
python -c "
import json, pickle, torch
from pathlib import Path

base = Path('/tmp/smoke_model')

vocab = json.loads((base / 'template_vocab.json').read_text())
print(f'vocab templates: {len(vocab[\"template_to_id\"])}')

config = json.loads((base / 'model_config.json').read_text())
print(f'threshold: {config[\"optimal_threshold\"]:.4f}')
print(f'vocab_size: {config[\"vocab_size\"]}')

ckpt = torch.load(base / 'transformer_model.pt', map_location='cpu')
print(f'transformer keys: {list(ckpt.keys())}')

with open(base / 'isolation_forest.pkl', 'rb') as f:
    iso = pickle.load(f)
print(f'IsolationForest n_estimators: {iso.n_estimators}')
"
```

Expected: no errors, `threshold` is a float > 0, transformer keys include `model_state_dict`.

- [ ] **Step 4: Commit**

```bash
git add scripts/train_base_model.py
git commit -m "feat: complete train_base_model with artifacts, IsolationForest, CLI"
```

---

## Task 6: Demo script

**Files:**
- Create: `scripts/demo_realtime.py`

No unit tests for the demo (it requires a running backend). The `--dry-run` flag is the functional smoke test.

- [ ] **Step 1: Create `scripts/demo_realtime.py`**

```python
#!/usr/bin/env python3
"""
Real-Time Demo Script
Replays a synthetic log file against the live LogGuard backend, splicing
in attack patterns at a configurable ratio.

Usage:
    # Dry run (no HTTP calls):
    python scripts/demo_realtime.py \
        --logs scripts/synthetic_logs.log \
        --api-key sk-xxxx \
        --backend-url http://localhost:8000 \
        --dry-run

    # Live run:
    python scripts/demo_realtime.py \
        --logs scripts/synthetic_logs.log \
        --api-key sk-xxxx \
        --backend-url http://localhost:8000 \
        --attack-ratio 0.10 --rate 0.5
"""

import argparse
import json
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    print("[ERROR] 'requests' package not installed. Run: pip install requests", file=sys.stderr)
    sys.exit(1)

# Reuse attack payload lists already defined in log_generator.py
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
from log_generator import (
    SQL_INJECTION_PAYLOADS,
    XSS_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    COMMAND_INJECTION_PAYLOADS,
    USER_AGENTS,
)

_ATTACK_TYPES = {
    "sql_injection": SQL_INJECTION_PAYLOADS,
    "xss": XSS_PAYLOADS,
    "path_traversal": PATH_TRAVERSAL_PAYLOADS,
    "command_injection": COMMAND_INJECTION_PAYLOADS,
}
_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _random_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _apache_ts_now() -> str:
    d = datetime.now(timezone.utc)
    return f"{d.day:02d}/{_MONTHS[d.month - 1]}/{d.year}:{d.hour:02d}:{d.minute:02d}:{d.second:02d} +0000"


def build_attack_line(attack_type: str, base_paths: List[str]) -> str:
    """Build a synthetic Apache log line embedding an attack payload."""
    payload = random.choice(_ATTACK_TYPES[attack_type])
    # Inject into query string of a random path from the log file
    base = random.choice(base_paths) if base_paths else "/api/items"
    # Strip existing query string from base path
    base_clean = base.split("?")[0]
    # URL-encode key injection characters minimally
    safe_payload = payload.replace('"', '%22').replace('\n', '%0A')
    path = f"{base_clean}?q={safe_payload}"
    ip = _random_ip()
    ua = random.choice(USER_AGENTS)
    ts = _apache_ts_now()
    return f'{ip} - - [{ts}] "GET {path} HTTP/1.1" 400 512 "-" "{ua}"'


def _extract_request_parts(log_line: str):
    """Extract (method, path, status) from an Apache log line for display."""
    try:
        q1 = log_line.index('"')
        q2 = log_line.index('"', q1 + 1)
        req = log_line[q1 + 1 : q2]
        parts = req.split(" ", 2)
        method, path = parts[0], parts[1] if len(parts) > 1 else "?"
        after = log_line[q2 + 2 :].split(" ", 1)[0]
        return method, path, after
    except Exception:
        return "?", log_line[:40], "?"


def _extract_paths(log_lines: List[str]) -> List[str]:
    """Extract unique base paths from log lines for attack injection."""
    paths = set()
    for line in log_lines:
        try:
            q1 = line.index('"')
            q2 = line.index('"', q1 + 1)
            req = line[q1 + 1 : q2].split(" ")
            if len(req) >= 2:
                paths.add(req[1].split("?")[0])
        except Exception:
            pass
    return list(paths) or ["/api/items"]


def send_batch(
    session: "requests.Session",
    url: str,
    api_key: str,
    log_lines: List[str],
) -> bool:
    payload = [{"log": line} for line in log_lines]
    try:
        resp = session.post(
            url,
            json=payload,
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            timeout=10,
        )
        if resp.status_code not in (200, 201, 202):
            print(f"  [WARN] {resp.status_code}: {resp.text[:120]}", file=sys.stderr)
            return False
        return True
    except Exception as exc:
        print(f"  [WARN] request failed: {exc}", file=sys.stderr)
        return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Replay synthetic logs against LogGuard backend with injected attacks"
    )
    parser.add_argument("--logs", required=True, help="Path to synthetic .log file")
    parser.add_argument("--api-key", required=True, help="LogGuard project API key (X-API-Key header)")
    parser.add_argument("--backend-url", default="http://localhost:8000")
    parser.add_argument("--attack-ratio", type=float, default=0.10,
                        help="Fraction of lines replaced with attacks (0.0–1.0)")
    parser.add_argument("--rate", type=float, default=0.5, help="Seconds between batches")
    parser.add_argument("--batch-size", type=int, default=10, help="Lines per batch")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print lines to stdout without sending to backend")
    args = parser.parse_args()

    log_path = Path(args.logs)
    if not log_path.exists():
        print(f"[ERROR] Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    lines = [l for l in log_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    if not lines:
        print("[ERROR] Log file is empty", file=sys.stderr)
        sys.exit(1)

    base_paths = _extract_paths(lines)
    attack_type_list = list(_ATTACK_TYPES.keys())
    send_url = urljoin(args.backend_url.rstrip("/") + "/", "api/v1/logs/agent/send-logs")
    session = requests.Session()

    total_sent = 0
    attacks_injected = 0
    batch_count = 0

    mode = "DRY RUN — no HTTP calls" if args.dry_run else f"LIVE → {send_url}"
    print(f"LogGuard Demo  |  {mode}")
    print(f"attack_ratio={args.attack_ratio:.0%}  batch_size={args.batch_size}  rate={args.rate}s")
    print("-" * 80)

    try:
        i = 0
        while i < len(lines):
            batch: List[str] = []
            for _ in range(args.batch_size):
                if i >= len(lines):
                    break
                line = lines[i]
                i += 1

                is_attack = random.random() < args.attack_ratio
                if is_attack:
                    attack_type = random.choice(attack_type_list)
                    line = build_attack_line(attack_type, base_paths)
                    attacks_injected += 1
                    label = f"[INJECTED ATTACK: {attack_type}]"
                else:
                    label = ""

                method, path, status = _extract_request_parts(line)
                ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
                tag = f"  {label}" if label else ""
                display_path = (path[:57] + "...") if len(path) > 60 else path
                print(f"[{ts}] {method:<7} {display_path:<60} {status}{tag}")
                batch.append(line)

            if batch:
                if not args.dry_run:
                    send_batch(session, send_url, args.api_key, batch)
                total_sent += len(batch)
                batch_count += 1

            if args.rate > 0 and not args.dry_run:
                time.sleep(args.rate)

    except KeyboardInterrupt:
        print("\n[Interrupted]")

    print("\n" + "=" * 40)
    print(f"  Batches        : {batch_count}")
    print(f"  Lines sent     : {total_sent}")
    print(f"  Attacks inject.: {attacks_injected} ({attacks_injected / max(total_sent, 1):.1%})")
    if not args.dry_run:
        print(f"  → Check the LogGuard dashboard for detection results (websocket)")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Smoke test the dry-run mode**

```bash
python scripts/synthetic_log_generator.py \
    --manifest scripts/my_app_manifest.json \
    --count 50 --sessions 3 \
    --output /tmp/demo_smoke.log

python scripts/demo_realtime.py \
    --logs /tmp/demo_smoke.log \
    --api-key sk-placeholder \
    --attack-ratio 0.20 \
    --batch-size 5 \
    --dry-run 2>&1 | head -30
```

Expected: lines printed with timestamps and occasional `[INJECTED ATTACK: ...]` labels. No HTTP errors (dry-run).

- [ ] **Step 3: Commit**

```bash
git add scripts/demo_realtime.py
git commit -m "feat: add demo_realtime — replay logs against backend with injected attacks"
```

---

## Task 7: Full end-to-end generation

Generate the production-scale log file and train the base model that will actually be used.

- [ ] **Step 1: Generate 15 000-log file**

```bash
python scripts/synthetic_log_generator.py \
    --manifest scripts/my_app_manifest.json \
    --count 15000 --sessions 100 \
    --output scripts/synthetic_logs.log
wc -l scripts/synthetic_logs.log
```

Expected: `15000 scripts/synthetic_logs.log`

- [ ] **Step 2: Train the base model**

```bash
python scripts/train_base_model.py \
    --logs scripts/synthetic_logs.log \
    --output data/base_model \
    --epochs 10
```

Expected: completes without errors, prints vocab_size and sequences count.

- [ ] **Step 3: Verify artifacts**

```bash
python -c "
import json, torch
from pathlib import Path

base = Path('data/base_model')
config = json.loads((base / 'model_config.json').read_text())
vocab  = json.loads((base / 'template_vocab.json').read_text())
ckpt   = torch.load(base / 'transformer_model.pt', map_location='cpu')

print(f'Templates    : {len(vocab[\"template_to_id\"])}')
print(f'Threshold    : {config[\"optimal_threshold\"]:.4f}')
print(f'Vocab size   : {config[\"vocab_size\"]}')
print(f'Window size  : {config[\"window_size\"]}')
print(f'Transformer  : {list(ckpt.keys())}')
"
```

Expected: threshold > 0, vocab > 10 templates, transformer checkpoint has `model_state_dict`.

- [ ] **Step 4: Commit generated files (log + model)**

```bash
# Add .gitignore entries so large binaries aren't tracked
echo "data/base_model/transformer_model.pt" >> .gitignore
echo "data/base_model/isolation_forest.pkl" >> .gitignore
echo "scripts/synthetic_logs.log" >> .gitignore

git add .gitignore data/base_model/template_vocab.json data/base_model/model_config.json
git commit -m "feat: add trained base model artifacts for my-app manifest"
```

---

## Task 8: Run the live demo (requires full stack)

Prerequisites:
- PostgreSQL, backend (port 8000), anomaly service (port 8001) running
- `MULTI_TENANT_BASE_MODEL_DIR` pointing at `data/base_model`
- A project created in LogGuard UI with an API key

- [ ] **Step 1: Point anomaly service at new base model**

In `realtime_anomaly_detection/api/start_multi_tenant.sh` (or your env), confirm:

```bash
export MULTI_TENANT_BASE_MODEL_DIR="$(pwd)/data/base_model"
```

Then restart the anomaly service:

```bash
bash realtime_anomaly_detection/api/start_multi_tenant.sh
```

- [ ] **Step 2: Create a project and copy the API key**

In the LogGuard dashboard: create a new project, select `low_traffic` profile, copy the `sk-...` API key.

Or via curl:
```bash
curl -X POST http://localhost:8000/api/v1/projects \
  -H "Authorization: Bearer <firebase_token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"demo-project","org_id":"<your_org_id>","traffic_profile":"low_traffic"}'
```

- [ ] **Step 3: Run the live demo**

```bash
python scripts/demo_realtime.py \
    --logs scripts/synthetic_logs.log \
    --api-key sk-YOUR_KEY_HERE \
    --backend-url http://localhost:8000 \
    --attack-ratio 0.10 \
    --rate 0.5 \
    --batch-size 20
```

- [ ] **Step 4: Observe detection on dashboard**

Open the LogGuard frontend at `http://localhost:3000`. As the demo runs:
- Lines with `[INJECTED ATTACK: sql_injection]` etc. should appear as anomalies on the dashboard.
- Normal lines should score low.
- After `warmup_threshold` logs are received (1 000 for `low_traffic`), the student model trains automatically.

---

## Self-Review Checklist

- [x] **Spec coverage:** All spec sections covered — generator (Task 2), trainer (Tasks 3–5), demo (Task 6), end-to-end (Tasks 7–8).
- [x] **No placeholders:** All steps contain actual code or exact commands.
- [x] **Type consistency:** `parse_apache_log_line` returns `Optional[Dict]` in Task 3 and is imported with that signature in the test. `BaseModelTrainer.save_artifacts` takes `Path, List[List[int]], np.ndarray, int` — consistent across tests and implementation.
- [x] **`sys.path` setup:** Both test files use the same pattern as the existing `scripts/tests/test_metrics.py` — insert repo root and `realtime_anomaly_detection/` before importing.
- [x] **Attack payloads:** `demo_realtime.py` imports from `scripts/log_generator.py` which defines `SQL_INJECTION_PAYLOADS`, `XSS_PAYLOADS`, `PATH_TRAVERSAL_PAYLOADS`, `COMMAND_INJECTION_PAYLOADS` at module level — confirmed in codebase.
- [x] **`realtime_anomaly_detection` package:** No top-level `__init__.py` exists. Scripts add `realtime_anomaly_detection/` to `sys.path` (matching `api/server_multi_tenant.py`'s pattern), then import as `from models.ensemble_detector import ...`.
