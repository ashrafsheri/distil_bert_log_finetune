# Data and Storage

## Overview

The repository uses three main storage layers:

1. PostgreSQL for control-plane and relational data
2. Elasticsearch for searchable log and detector documents
3. filesystem/PVC-backed detector state and model artifacts for the anomaly service

## PostgreSQL

PostgreSQL is the backend system of record for:

- users
- organizations
- projects
- project members
- permissions and related control-plane entities

The project table currently includes runtime detector-tracking fields such as:

- `model_status`
- `log_count`
- `warmup_threshold`
- `warmup_progress`
- `student_trained_at`
- `traffic_profile`

The `traffic_profile` column depends on migration `backend/migrations/002_add_project_traffic_profile.sql`.

## Elasticsearch

Elasticsearch is used for log storage and query-driven dashboard views.

The primary index is:

- `logguard-logs`

Stored documents include not just raw ingest data but detector metadata, including:

- parse state
- detection state
- normalized template
- risk score
- decision fields
- traffic classification
- baseline eligibility
- threshold provenance
- incident metadata
- unknown-template ratio

This means dashboard cards and detail panels are backed by Elasticsearch, not PostgreSQL.

## Detector State

The anomaly service uses persistent local state under paths mounted into the container.

Relevant runtime directories from deployment manifests:

- base artifacts: `/app/artifacts/ensemble_model_export`
- adaptive logs/state root: `/app/logs`
- multi-tenant storage root: `/app/data/multi_tenant`

Typical persisted detector state includes:

- teacher transformer weights
- teacher Isolation Forest state
- teacher metadata/state files
- per-project student state

## Artifact Reality

The service expects base teacher artifacts in the model directory, but operationally the system has already shown that:

- the PVC can be incomplete
- the teacher IF can be missing or unfitted
- saved runtime state can matter more than the base bundle

The code is now more defensive, but the storage layer still matters to quality.

## Migrations

Migration files currently visible in the repo include:

- `backend/migrations/001_organization_hierarchy.sql`
- `backend/migrations/002_add_project_traffic_profile.sql`

The backend does not run these SQL files automatically just because they exist in git. They must be applied against the running PostgreSQL instance during deployment.

## Operational Implications

- If PostgreSQL schema lags behind the code, backend project APIs can fail even if the pod starts.
- If Elasticsearch mappings drift from current code expectations, some aggregations and cards will not work as intended.
- If anomaly PVCs are reset without valid base artifacts, the detector can come up in a weaker cold-start state.
