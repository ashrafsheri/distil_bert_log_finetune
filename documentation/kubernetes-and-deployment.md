# Kubernetes and Deployment

## Namespace and Topology

The manifests in `k8s/` deploy the stack into the `logguard` namespace.

Main services:

- `frontend`
- `backend`
- `anomaly-detection`
- `postgres`
- `elasticsearch`

## Backend Deployment

`k8s/backend-deployment.yaml` currently defines:

- image: `ghcr.io/OWNER/backend:latest`
- `imagePullPolicy: Always`
- container port `8000`
- readiness and liveness on `/health`
- PostgreSQL environment variables from `postgres-secret`
- SMTP and alert settings from `backend-secret`
- Firebase credential secret mounted at `/app/secrets`

There is an init container that waits for Postgres using `nc -z postgres 5432`.

## Frontend Deployment

`k8s/frontend-deployment.yaml` currently defines:

- image: `ghcr.io/OWNER/frontend:latest`
- `imagePullPolicy: Always`
- container port `3000`
- readiness and liveness on `/`

## Anomaly Detection Deployment

`k8s/anomaly-detection-deployment.yaml` currently defines:

- image: `ghcr.io/OWNER/anomaly-detection:latest`
- `imagePullPolicy: Always`
- container port `8001`
- startup, readiness, and liveness on `/health`

Important environment variables:

- `MODEL_DIR=/app/artifacts/ensemble_model_export`
- `ADAPTIVE_STATE_DIR=/app/logs/adaptive_state`
- `STORAGE_DIR=/app/data/multi_tenant`

Important mounted volumes:

- model artifacts PVC mounted at `/app/artifacts/ensemble_model_export`
- anomaly state PVC mounted at `/app/logs`
- same anomaly state PVC mounted at `/app/data`

## PostgreSQL and Elasticsearch

The stack also deploys:

- PostgreSQL 15 Alpine
- Elasticsearch 8.11.0 in single-node mode

These are persistent-state dependencies and must survive application pod restarts for the system to behave predictably.

## Ingress

`k8s/ingress.yaml` exposes:

- `/` -> frontend
- `/api` -> backend
- `/ws` -> backend
- `/anomaly` -> anomaly-detection
- `/elasticsearch` -> elasticsearch

There is also a separate rewrite ingress that strips the `/anomaly` and `/elasticsearch` prefixes before forwarding.

## Important Deployment Realities

- The manifests use placeholder image names with `OWNER`; production deployment depends on CI or manual substitution producing real GHCR image references.
- Pulling git on a server does not update running pods unless a new image is built and deployed.
- PostgreSQL migrations must be applied separately; restarting the backend alone does not apply SQL files.
- Detector quality depends on PVC contents, not only image version.

## Practical Deployment Sequence

In the current architecture, a safe update requires:

1. build and publish new images
2. ensure deployment manifests reference the intended image
3. apply required SQL migrations
4. restart affected deployments
5. check backend and anomaly logs
6. verify PVC-backed detector state and model artifacts when relevant
