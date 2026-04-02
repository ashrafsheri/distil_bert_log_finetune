# Documentation

This folder replaces the deleted repository Markdown with a code-grounded view of the current system.

These documents describe what is implemented in the repository now, not the intended architecture from older planning notes.

## Index

- `repository-overview.md`: repo layout, service boundaries, and main runtime flow
- `backend-service.md`: FastAPI backend, auth, project management, ingest, storage, and websockets
- `frontend-service.md`: React frontend routes, pages, and key data flows
- `anomaly-detection-service.md`: multi-tenant detector, teacher/student lifecycle, scoring, and warmup behavior
- `data-and-storage.md`: PostgreSQL, Elasticsearch, detector state, and artifact storage
- `fluent-bit-and-ingestion.md`: current log shipper config and ingest path realities
- `kubernetes-and-deployment.md`: Kubernetes resources, ports, volumes, and runtime wiring
- `external-endpoint-manifest-seeding.md`: external route extraction script and endpoint manifest bootstrap flow
- `current-known-realities.md`: implementation-level caveats and operational truths that matter when running the repo

## Scope

The docs are grounded in:

- `backend/`
- `frontend/`
- `realtime_anomaly_detection/`
- `fluent-bit/`
- `k8s/`
- `external system script/`

They intentionally avoid describing deleted Markdown, aspirational plans, or architecture that is not present in code.
