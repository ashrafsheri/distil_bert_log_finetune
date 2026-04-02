# Repository Overview

## Top-Level Structure

The repository currently contains these major areas:

- `backend/`: FastAPI control plane, ingest API, auth, PostgreSQL models, Elasticsearch writes, websocket fanout
- `frontend/`: React UI for authentication, project management, dashboards, incidents, users, profile, and reports
- `realtime_anomaly_detection/`: separate FastAPI microservice for multi-project anomaly scoring and student/teacher model lifecycle
- `fluent-bit/`: Fluent Bit configuration for shipping access logs to the backend ingest endpoint
- `k8s/`: deployment, service, PVC, and ingress manifests for the stack
- `external system script/`: helper script for extracting route manifests from external backend codebases
- `scripts/`: utility and backtest-oriented code
- `artifacts/`: exported model artifacts used by the anomaly service in development or image build contexts

## Running System Shape

The runtime is split into three main application services:

1. Frontend on port `3000`
2. Backend on port `8000`
3. Anomaly detection service on port `8001`

Supporting services are:

- PostgreSQL
- Elasticsearch
- Fluent Bit or another shipper posting logs into the backend

## Main Request and Data Flow

1. Logs are sent to the backend at `/api/v1/logs/agent/send-logs`.
2. The backend parses, classifies, and stores each event.
3. Parsed structured events are forwarded to the anomaly microservice over internal HTTP.
4. The anomaly service scores the event in either teacher warmup mode or student active mode.
5. The backend writes the scored result into Elasticsearch.
6. The backend broadcasts project-scoped websocket updates to the frontend.
7. The frontend renders dashboard cards, tables, incident details, and project status from backend APIs and websockets.

## Current Design Reality

The system is not a single monolith. It is a control plane plus a detector microservice:

- The backend owns auth, organization and project management, ingest APIs, database access, and search-facing APIs.
- The anomaly service owns scoring and project model state.
- The frontend is only a client and does not score logs locally.

## Important Implementation Themes

- Project-aware detector lifecycle is already implemented.
- Low-traffic project mode exists in code.
- Endpoint manifest seeding exists in code.
- Traffic classification and baseline eligibility metadata are carried through the detector flow.
- Known attack rules remain part of the scoring path.
- The detector still depends on persisted state and artifact quality to perform well.
