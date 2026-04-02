# Backend Service

## Service Role

The backend in `backend/` is the system control plane. It is a FastAPI app that handles:

- user authentication and authorization
- organizations, projects, users, and memberships
- log ingest APIs
- communication with the anomaly detection microservice
- Elasticsearch reads and writes
- websocket fanout for live dashboard updates

The app entrypoint is `backend/app/main.py`.

## Runtime Basics

- Framework: FastAPI
- Default port: `8000`
- Root health endpoint: `/health`
- Metrics endpoint: `/metrics`
- API router prefix: `/api`
- Websocket router prefix: `/ws`

The main app mounts:

- `api_router` at `/api`
- `websocket.router` at `/ws`

## Startup Behavior

On startup the backend:

- creates database tables through `init_db()`
- initializes Firebase auth support
- seeds permission records
- ensures a default admin exists

This means the backend expects PostgreSQL and Firebase credentials to be ready before it starts serving traffic cleanly.

## Main API Areas

The backend routes are organized under `backend/app/api/v1/router.py`. The important service areas are:

- auth
- organizations
- users
- projects
- project members
- logs
- alerts

## Project Management

Project APIs are implemented in `backend/app/controllers/project_controller.py`.

Implemented project behaviors include:

- create project
- list projects by organization
- list current user's projects
- update project log type
- update project fields
- regenerate API key
- project member management
- project health summary access
- endpoint manifest seeding

The code supports these project properties:

- `log_type`: currently `apache` or `nginx`
- `warmup_threshold`
- `traffic_profile`: `standard` or `low_traffic`

`ProjectHealthSummary` also exposes detector-side fields such as:

- warmup progress
- clean baseline counts
- dirty excluded counts
- probe skipped counts
- parse failure rate
- distinct template count
- calibration threshold metadata
- low-sample calibration flag
- teacher freshness metadata
- reservoir counts

## Detector Integration

The backend talks to the anomaly service through `backend/app/services/anomaly_detection_service.py`.

By default it calls:

- base URL: `http://anomaly-detection:8001`

Implemented detector client calls include:

- `/detect`
- `/detect/batch`
- `/detect/structured`
- `/detect/batch/structured`
- `/internal/projects/register`
- `/internal/projects/ingest-stats`

The backend normalizes detector results before storing or returning them. It already carries through fields such as:

- `policy_score`
- `final_decision`
- `decision_reason`
- `component_status`
- `traffic_class`
- `baseline_eligible`
- `threshold_source`
- `threshold_fitted_at`
- `calibration_sample_count`
- `score_normalization_version`
- `unknown_template_ratio`
- incident metadata

## Log Ingest Path

The ingest controller is in `backend/app/controllers/log_controller.py`.

The backend currently performs these responsibilities before or around detector calls:

- parse raw access logs
- build structured events
- classify traffic
- compute baseline eligibility
- forward structured batches to the anomaly service
- mark failures when the detector is unavailable or results are missing
- persist searchable documents into Elasticsearch
- push project-scoped websocket updates

## Websocket Behavior

Websocket logic lives in `backend/app/controllers/websocket_controller.py`.

Connections store:

- `org_id`
- `user_role`
- `project_id`

Broadcasts can be filtered by:

- project
- organization

This is the path the live dashboard streaming depends on.

## Database Layer

The backend uses SQLAlchemy async access in `backend/app/utils/database.py`.

Key facts:

- async engine
- connection URL from `DATABASE_URL`
- metadata creation on startup
- PostgreSQL is the primary relational store

The `projects` table model in `backend/app/models/project_db.py` currently includes:

- `traffic_profile`
- `model_status`
- `log_count`
- `warmup_threshold`
- `warmup_progress`
- `student_trained_at`

## Search and Analytics Storage

Elasticsearch writes are handled in `backend/app/services/elasticsearch_service.py`.

The main index is:

- `logguard-logs`

The mapping includes detector-aware fields such as:

- `traffic_class`
- `baseline_eligible`
- `decision_reason`
- `policy_score`
- `final_decision`
- `component_status`
- threshold metadata
- `unknown_template_ratio`
- incident metadata

## Current Backend Caveats

- The backend still emits Pydantic protected-namespace warnings for fields like `model_status` unless those models are updated the same way as `DetectionResponse`.
- Detector unavailability still produces real `detection_status=failed` records unless traffic is classified and skipped before scoring.
- The backend is a thin detector client; if the anomaly service image is stale or unreachable, the backend does not hide that failure.
