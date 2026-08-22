# LogGuard

LogGuard is a full-stack, multi-tenant log monitoring and anomaly detection system for web access logs. It ingests Apache or Nginx-style traffic, parses and classifies each event, scores it with a realtime anomaly service, stores searchable results, and streams live updates to a React dashboard.

The project is split into three runtime services:

- `frontend/`: React/Vite dashboard for auth, projects, users, reports, and live log views.
- `backend/`: FastAPI control plane for Firebase auth, organizations, projects, ingest, PostgreSQL, Elasticsearch, and websockets.
- `realtime_anomaly_detection/`: FastAPI detector service with rule-based checks, Isolation Forest features, transformer-style sequence scoring, and teacher/student project lifecycle.

Supporting directories:

- `fluent-bit/`: safe sample Fluent Bit shipper config.
- `k8s/`: Kubernetes manifests for the full stack.
- `scripts/`: training, backtesting, health checks, synthetic traffic, and reporting utilities.
- `integration_tests/`: API, browser, and stress test scripts that target configurable deployments.
- `documentation/`: deeper code-grounded architecture docs.

## What It Solves

Most web log dashboards show volume, status codes, and search. LogGuard adds project-aware anomaly detection:

1. A project gets an ingest API key.
2. A log shipper posts access logs to the backend.
3. The backend parses the logs and forwards structured events to the detector.
4. The detector scores known attacks, feature outliers, and unusual request sequences.
5. Results are stored in Elasticsearch and pushed to the dashboard over websockets.

This is useful for SaaS products, internal tools, student projects, or research prototypes where each project has different normal traffic and needs its own baseline.

## Architecture

Default local ports:

- Frontend: `3000`
- Backend: `8000`
- Anomaly service: `8001`
- PostgreSQL: `5432`
- Elasticsearch: `9200`

Core data flow:

```text
Fluent Bit or API client
  -> backend /api/v1/logs/agent/send-logs
  -> parser, policy classification, project lookup
  -> anomaly service /detect/structured or /detect/batch/structured
  -> Elasticsearch logguard-logs index
  -> websocket updates
  -> React dashboard
```

## Prerequisites

- Python 3.11
- Node.js 20+
- PostgreSQL
- Elasticsearch 8-compatible endpoint
- Firebase project with Authentication enabled
- Firebase Admin service account JSON for the backend

The repository intentionally does not include real secrets. Start from `.env.example`, then create local `.env` files that are ignored by Git.

## Local Setup

Clone:

```bash
git clone https://github.com/YOUR_GITHUB_ORG_OR_USER/logguard.git
cd logguard
```

Create local environment files:

```bash
cp .env.example .env
cp .env.example frontend/.env
cp fluent-bit/config.env.example fluent-bit/config.env
```

Edit `.env` and `frontend/.env` with your own PostgreSQL URL, Firebase web config, and Firebase Admin service account path.

Install Python dependencies:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
pip install -r realtime_anomaly_detection/requirements.txt
```

Install frontend dependencies:

```bash
cd frontend
npm install
cd ..
```

Run the anomaly service:

```bash
PYTHONPATH="$PWD/realtime_anomaly_detection" \
MODEL_DIR="$PWD/artifacts/ensemble_model_export" \
STORAGE_DIR="$PWD/data/multi_tenant" \
uvicorn realtime_anomaly_detection.api.server_multi_tenant:app --host 0.0.0.0 --port 8001
```

Run the backend:

```bash
PYTHONPATH="$PWD/backend:$PWD/realtime_anomaly_detection" \
DATABASE_URL="postgresql+asyncpg://logguard_user:logguard_password@localhost:5432/logguard_db" \
ANOMALY_DETECTION_URL="http://localhost:8001" \
FIREBASE_SERVICE_ACCOUNT_KEY="$PWD/backend/serviceAccountKey.json" \
uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000 --reload
```

Run the frontend:

```bash
cd frontend
npm run dev
```

Open `http://localhost:3000`.

## Creating the First Admin

The backend no longer seeds a real admin by default. To seed one, set:

```bash
DEFAULT_ADMIN_UID=<firebase-user-uid>
DEFAULT_ADMIN_EMAIL=<admin-email>
```

The UID must exist in Firebase Authentication. If these variables are omitted, startup skips admin seeding.

## Sending Logs

After creating a project in the UI, copy its ingest API key and send logs to:

```text
POST /api/v1/logs/agent/send-logs
X-API-Key: <project-api-key>
```

Example:

```bash
curl -X POST http://localhost:8000/api/v1/logs/agent/send-logs \
  -H "Content-Type: application/json" \
  -H "X-API-Key: replace-with-project-ingest-api-key" \
  -d '[{"log":"127.0.0.1 - - [01/Apr/2026:12:00:00 +0000] \"GET /login HTTP/1.1\" 200 1234","timestamp":"2026-04-01T12:00:00Z"}]'
```

Fluent Bit users can start from `fluent-bit/fluent-bit-simple.conf` and `fluent-bit/config.env.example`.

## Testing

Backend unit tests:

```bash
PYTHONPATH="$PWD/backend:$PWD/realtime_anomaly_detection" \
DATABASE_URL="postgresql+asyncpg://postgres:postgres@localhost/test_db" \
pytest backend/tests
```

Frontend build:

```bash
cd frontend
npm run build
```

Anomaly service tests:

```bash
PYTHONPATH="$PWD/realtime_anomaly_detection" pytest realtime_anomaly_detection/tests
```

Some ML tests skip automatically if optional model dependencies are unavailable.

## Deployment

Dockerfiles exist for all three services:

- `backend/Dockerfile`
- `frontend/Dockerfile`
- `realtime_anomaly_detection/Dockerfile`

Kubernetes manifests are in `k8s/`. Before applying them:

1. Replace `ghcr.io/YOUR_GITHUB_ORG_OR_USER/...` image names.
2. Replace every placeholder in `k8s/postgres-secret.yaml` and `k8s/backend-secret.yaml`.
3. Create `firebase-secret` from your Firebase service account JSON.
4. Create `ghcr-secret` or another image pull secret if your registry needs auth.

Then:

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/
```

The helper `scripts/k8s-deploy.sh` performs the same sequence with guardrails.

## Public Repo Hygiene

Do not commit:

- `.env` files
- Firebase service account JSON
- real project API keys
- Fluent Bit state DBs
- model checkpoints generated during experiments
- Sonar scanner output
- local build metadata

The `.gitignore` is configured for those cases.

## Documentation

Start with:

- `documentation/repository-overview.md`
- `documentation/backend-service.md`
- `documentation/frontend-service.md`
- `documentation/anomaly-detection-service.md`
- `documentation/kubernetes-and-deployment.md`
- `documentation/current-known-realities.md`
