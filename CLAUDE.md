# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Repo Is

A log anomaly detection system called **LogGuard** consisting of three services:

1. **Backend** (`backend/`) — FastAPI control plane on port `8000`. Owns auth, organizations, projects, log ingest, Elasticsearch writes, and websocket fanout.
2. **Anomaly Detection** (`realtime_anomaly_detection/`) — Separate FastAPI microservice on port `8001`. Owns multi-project detector state, teacher/student model lifecycle, and scoring.
3. **Frontend** (`frontend/`) — React + Vite + Tailwind app on port `3000`. Client only; no local scoring.

Supporting services: PostgreSQL, Elasticsearch, Fluent Bit.

## Development Commands

### Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Anomaly Detection Service
```bash
cd realtime_anomaly_detection
pip install -r requirements.txt
# Single-tenant (dev):
bash api/start_api.sh
# Multi-tenant (production path):
bash api/start_multi_tenant.sh
```

### Frontend
```bash
cd frontend
npm install
npm run dev        # Vite dev server
npm run build      # tsc + vite build
npm run lint       # ESLint
npm run preview    # Preview production build
```

### Production Scripts
```bash
# Check running service health and model performance:
python scripts/check_model_health.py
# Offline model state analysis:
python scripts/evaluate_model_performance.py --storage-dir ./data/detector
```

## Architecture: Main Request Flow

1. Logs posted to `POST /api/v1/logs/agent/send-logs`
2. Backend parses, classifies traffic, builds structured events
3. Backend forwards structured batches to anomaly service at `http://anomaly-detection:8001/detect/batch/structured`
4. Anomaly service scores using rule-based + transformer + Isolation Forest
5. Backend writes scored documents to Elasticsearch index `logguard-logs`
6. Backend broadcasts project-scoped websocket updates to frontend

## Key Service Files

| File | Role |
|---|---|
| `backend/app/main.py` | Backend entrypoint, startup (DB init, Firebase, permissions seeding) |
| `backend/app/api/v1/router.py` | All API route registrations |
| `backend/app/controllers/log_controller.py` | Ingest pipeline |
| `backend/app/controllers/project_controller.py` | Project CRUD, health summary, manifest seeding |
| `backend/app/services/anomaly_detection_service.py` | HTTP client to anomaly service |
| `backend/app/services/elasticsearch_service.py` | Elasticsearch writes; index `logguard-logs` |
| `backend/app/controllers/websocket_controller.py` | Websocket fanout (filtered by project/org) |
| `backend/app/utils/database.py` | SQLAlchemy async engine; URL from `DATABASE_URL` |
| `realtime_anomaly_detection/api/server_multi_tenant.py` | Anomaly service entrypoint |
| `realtime_anomaly_detection/models/multi_tenant_detector.py` | `MultiTenantDetector` — core orchestrator |
| `realtime_anomaly_detection/models/ensemble_detector.py` | Teacher/student model combination |
| `frontend/src/main.tsx` | React entrypoint |
| `frontend/src/App.tsx` | Route wiring, AuthProvider, ThemeProvider |

## Detector Architecture

The detector is a **hybrid system**, not a pure ML classifier:
- **Rule-based layer** — authoritative for known attack patterns
- **Transformer** — sequence novelty scoring; suppressed when unknown-template ratio is too high
- **Isolation Forest** — feature-based scoring

Project phases: `warmup → training → active → suspended/error`. Warmup uses the teacher; active phase uses project-specific student models. When a student has low confidence (high unknown template ratio, few active ensemble models), detection is **escalated to the teacher** at runtime for a second opinion.

**Online learning**: Student models are not frozen after initial training. Every `ONLINE_UPDATE_INTERVAL` logs (default 500), the student fine-tunes on its clean_normal_reservoir with a KL-divergence safety guard that rolls back if the model drifts too far.

Traffic profiles (`standard` / `low_traffic`) control warmup thresholds and minimum training requirements.

## Database / Storage

- **PostgreSQL**: control-plane entities (users, orgs, projects, members). Migrations are **not applied automatically** — run SQL files in `backend/migrations/` manually during deployment.
- **Elasticsearch**: all log documents and detector metadata. Index: `logguard-logs`.
- **PVCs**: detector state and base model artifacts. Missing/incomplete artifacts degrade scoring quality without crashing the service. Check startup logs to confirm clean state load.

Critical migration: `backend/migrations/002_add_project_traffic_profile.sql` is required for `traffic_profile` column on projects.

## CI/CD

CI (`.github/workflows/ci.yml`) builds and pushes three Docker images to GHCR on every push to `main`:
- `ghcr.io/<OWNER>/backend`
- `ghcr.io/<OWNER>/frontend`
- `ghcr.io/<OWNER>/anomaly-detection`

K8s manifests in `k8s/` deploy to namespace `logguard`. The manifests use placeholder `OWNER` in image references — substitution happens in CI or manually before applying.

Safe deployment sequence: build images → apply SQL migrations → apply manifests → restart deployments → check logs → verify PVC-backed state.

## Auth

Backend uses **Firebase Admin SDK** for JWT verification. A Firebase credential file must be mounted at `/app/secrets` in Kubernetes. The backend also seeds a default admin user on startup.

Frontend uses Firebase client SDK (credentials injected as `VITE_FIREBASE_*` build args).

## Operational Caveats

- Restarting a pod does not apply SQL migrations or update detector state on PVCs.
- If the backend image updates but the anomaly service image does not (or vice versa), the API contract may diverge.
- Fluent Bit config in `fluent-bit/` contains hardcoded paths, host, and API key — treat as a concrete environment config, not a template.
- Detector cold-start quality depends on base artifact completeness in the PVC, not just image version.
