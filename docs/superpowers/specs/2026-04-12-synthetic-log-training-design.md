# Synthetic Log Generation & Base Model Training

**Date:** 2026-04-12  
**Status:** Approved

## Problem

Without a production system generating real incoming logs, there is no data to train the base teacher model or validate end-to-end anomaly detection. This design introduces a three-script offline workflow that bootstraps the entire pipeline from a manifest file describing a project's API endpoints.

## Scope

Three new scripts in `scripts/`:

1. `synthetic_log_generator.py` — manifest → Apache Combined Log Format file (normal traffic only)
2. `train_base_model.py` — log file → base model artifacts consumed by `TeacherModel`
3. `demo_realtime.py` — log file + attacks → live backend API, prints detection results

One example manifest: `scripts/my_app_manifest.json`

## Manifest Format

Uses the existing LogGuard endpoint manifest format already understood by `MultiTenantDetector._endpoint_manifest_entries`:

```json
{
  "service_name": "my-app",
  "base_url": "https://my-app.com",
  "endpoints": [
    {"method": "GET",  "path_template": "/api/users",        "classification": "user_traffic",   "weight": 3},
    {"method": "GET",  "path_template": "/api/users/{id}",   "classification": "user_traffic",   "weight": 5},
    {"method": "POST", "path_template": "/api/auth/login",   "classification": "user_traffic",   "weight": 2},
    {"method": "GET",  "path_template": "/health",           "classification": "internal_probe", "weight": 1}
  ]
}
```

Fields:
- `path_template` — required. `{param}` segments are substituted with realistic values at generation time.
- `method` — HTTP method. Defaults to `GET` if omitted.
- `classification` — `user_traffic` or `internal_probe`. Passed through to LogGuard at demo time.
- `weight` — relative frequency of this endpoint in generated traffic. Defaults to 1.

## Data Flow

```
my_app_manifest.json
        │
        ▼
synthetic_log_generator.py
        │  Apache Combined Log Format lines (normal traffic only)
        ▼
synthetic_logs.log
        │
        ▼
train_base_model.py
        │  template_vocab.json
        │  transformer_model.pt
        │  isolation_forest.pkl
        │  model_config.json
        ▼
data/base_model/   ← pointed at by MULTI_TENANT_BASE_MODEL_DIR
        │
        ▼
demo_realtime.py
        │  POST /api/v1/logs/agent/send-logs (with injected attack lines)
        ▼
LogGuard backend → anomaly service → Elasticsearch → dashboard
```

## Script Details

### `synthetic_log_generator.py`

**Purpose:** Generate realistic Apache Combined Log Format lines from a manifest, simulating session-based user behaviour.

**Key behaviour:**
- Pools endpoints weighted by `weight` field.
- Generates sessions rather than isolated requests: each session picks a fixed IP + user agent and makes a realistic sequence of calls (e.g. login → list → detail → action). This matters because `TeacherModel` scores sequences, not individual lines.
- `{param}` segments in `path_template` are substituted with realistic values: numeric IDs, UUIDs, or slug strings chosen randomly per call.
- Status codes distributed realistically: ~85% 200, ~8% 404, ~4% 401, ~3% 500.
- Timestamps spread across a configurable time window to simulate realistic hourly distribution.
- Endpoints with missing or invalid `path_template` are skipped with a warning.

**CLI:**
```bash
python scripts/synthetic_log_generator.py \
  --manifest scripts/my_app_manifest.json \
  --count 15000 \
  --sessions 50 \
  --output scripts/synthetic_logs.log
```

**Output format (Apache Combined Log):**
```
192.168.1.42 - - [12/Apr/2026:10:00:01 +0000] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0 ..."
```

### `train_base_model.py`

**Purpose:** Parse synthetic logs and train the four artifacts that `TeacherModel._initialize_from_base` expects.

**Key behaviour:**
- Parses log lines using `ApacheLogNormalizer` from `realtime_anomaly_detection/models/ensemble_detector.py` — same normalizer the runtime uses, so the vocabulary is identical.
- Groups parsed logs into sliding windows of size 20 (matching `TeacherModel.window_size = 20`).
- Trains `TemplateTransformer` (d_model=256, n_heads=8, n_layers=4, ffn_dim=1024) with a causal language modelling objective (cross-entropy on next-token prediction).
- Extracts a 7-element feature vector per log for IsolationForest: HTTP method (encoded), status code, path depth, response size (log-scaled), hour of day, is_api (bool), is_auth_endpoint (bool).
- Sets `optimal_threshold` at the 95th percentile of per-sequence NLL scores on the training set.
- Saves artifacts atomically (`.tmp` → rename) so a crash cannot corrupt an existing model dir.
- Aborts with a clear error if fewer than 500 valid log lines are parsed or fewer than 10 distinct templates are found.
- Prints a completion summary: vocab size, sequence count, final loss, IsolationForest contamination rate, threshold.

**Artifacts saved:**
| File | Contents |
|---|---|
| `template_vocab.json` | `{"template_to_id": {...}}` |
| `transformer_model.pt` | `{model_state_dict, vocab_size, pad_id, unknown_id, threshold}` |
| `isolation_forest.pkl` | Fitted `sklearn.ensemble.IsolationForest` |
| `model_config.json` | `{"optimal_threshold": float, "vocab_size": int, "window_size": 20}` |

**CLI:**
```bash
python scripts/train_base_model.py \
  --logs scripts/synthetic_logs.log \
  --output data/base_model \
  --epochs 10
```

### `demo_realtime.py`

**Purpose:** Replay the synthetic log stream against the live LogGuard backend, splicing in attack patterns at a configurable ratio, and print live detection results.

**Key behaviour:**
- Loads `synthetic_logs.log` as the normal baseline stream.
- At `--attack-ratio` frequency (default 10%), replaces a log line with a synthetic attack line. Attack types reuse the payload lists already defined in `scripts/log_generator.py`: SQL injection, XSS, path traversal, command injection.
- Sends to `POST /api/v1/logs/agent/send-logs` in configurable batch sizes with `--rate` seconds between batches.
- On non-200 response: prints the error and continues — a single failed batch does not abort the demo.
- `--dry-run` flag: prints the mixed stream to stdout without sending, for visual inspection.
- On Ctrl+C: prints a summary — total batches sent, attack lines injected.
- Because `/api/v1/logs/agent/send-logs` returns a batch acknowledgement (not per-log scores — those flow to Elasticsearch and the websocket), the demo marks injected attack lines with `[INJECTED ATTACK]` in the terminal output based on its own knowledge of what it sent. Real detection results are visible on the LogGuard dashboard via websocket.
- Prints a live table per batch:

```
[10:05:32] POST /api/auth/login          → sent (normal)
[10:05:32] GET  /api/users/42            → sent (normal)
[10:05:33] GET  /api/users?id=1 OR 1=1  → sent [INJECTED ATTACK: sql_injection]
```

**CLI:**
```bash
python scripts/demo_realtime.py \
  --logs scripts/synthetic_logs.log \
  --api-key sk-xxxx \
  --backend-url http://localhost:8000 \
  --attack-ratio 0.10 \
  --rate 0.5 \
  --dry-run   # optional
```

## End-to-End Usage

```bash
# 1. Write your manifest
vim scripts/my_app_manifest.json

# 2. Generate synthetic normal traffic
python scripts/synthetic_log_generator.py \
  --manifest scripts/my_app_manifest.json \
  --count 15000 --output scripts/synthetic_logs.log

# 3. Train the base model
python scripts/train_base_model.py \
  --logs scripts/synthetic_logs.log \
  --output data/base_model --epochs 10

# 4. Point LogGuard at the new model dir and start services
export MULTI_TENANT_BASE_MODEL_DIR=data/base_model
bash realtime_anomaly_detection/api/start_multi_tenant.sh

# 5. Create a project in LogGuard, get an API key, then run the demo
python scripts/demo_realtime.py \
  --logs scripts/synthetic_logs.log \
  --api-key sk-xxxx \
  --backend-url http://localhost:8000 \
  --attack-ratio 0.10
```

## Constraints & Known Limitations

- The base model quality depends on log volume and endpoint diversity. Fewer than 15,000 logs or fewer than 10 distinct endpoints will produce a weak threshold. The trainer warns but does not block.
- Session-based generation approximates realistic sequence patterns but cannot capture true user journeys (e.g. "always call /login before /dashboard"). More realistic sequences would require a Markov model over endpoints, which is out of scope here.
- The demo sends logs through the full stack; the backend must be running with a valid Firebase credential and a pre-created project for the API key to be accepted.
- Attack payloads in the demo come from the existing static lists in `scripts/log_generator.py`. They cover the four main OWASP categories but are not exhaustive.
