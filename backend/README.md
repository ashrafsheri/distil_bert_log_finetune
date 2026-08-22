# Backend

`backend/` is the FastAPI control plane for LogGuard.

## Responsibilities

- Firebase Admin SDK initialization and JWT verification.
- Role and permission checks for admin, manager, and employee users.
- Organization, project, user, and project-member APIs.
- Project ingest API key validation.
- Access-log parsing and event normalization.
- Calls to the anomaly detection service.
- Elasticsearch writes and dashboard/search reads.
- Websocket fanout for project-scoped live updates.

## Important Modules

- `app/main.py`: FastAPI app, CORS, health, metrics, startup/shutdown.
- `app/api/v1/router.py`: mounts versioned API controllers.
- `app/controllers/`: request handlers for logs, users, organizations, projects, and websockets.
- `app/services/`: business logic for persistence, anomaly-service calls, permissions, email, reports, and Elasticsearch.
- `app/models/`: Pydantic schemas and SQLAlchemy models.
- `app/serializers/`: API serialization helpers.
- `app/utils/`: database, Firebase auth, permissions, runtime metrics.
- `migrations/`: SQL migrations that should be applied explicitly in managed environments.
- `tests/`: backend and detector-integration unit tests.

## Required Environment

- `DATABASE_URL`
- `FIREBASE_SERVICE_ACCOUNT_KEY`
- `ANOMALY_DETECTION_URL` or `ANOMALY_SERVICE_URL`
- `ELASTICSEARCH_URL` if not using the default Kubernetes service name

Optional admin seed:

- `DEFAULT_ADMIN_UID`
- `DEFAULT_ADMIN_EMAIL`
- `DEFAULT_ADMIN_ORG_ID`

If admin seed variables are absent, startup skips default admin creation.

## Run Locally

```bash
PYTHONPATH="$PWD/backend:$PWD/realtime_anomaly_detection" \
DATABASE_URL="postgresql+asyncpg://logguard_user:logguard_password@localhost:5432/logguard_db" \
ANOMALY_DETECTION_URL="http://localhost:8001" \
FIREBASE_SERVICE_ACCOUNT_KEY="$PWD/backend/serviceAccountKey.json" \
uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000 --reload
```

Health check:

```bash
curl http://localhost:8000/health
```
