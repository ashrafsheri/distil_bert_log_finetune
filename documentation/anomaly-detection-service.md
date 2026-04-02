# Anomaly Detection Service

## Service Role

The anomaly service in `realtime_anomaly_detection/` is a separate FastAPI application that owns:

- multi-project detector state
- teacher and student models
- project warmup and promotion lifecycle
- scoring of structured and raw log events
- project registration and ingest-stat tracking
- teacher update scheduling

The FastAPI entrypoint is `realtime_anomaly_detection/api/server_multi_tenant.py`.

## Runtime Basics

- Framework: FastAPI
- Default port: `8001`
- App title: `Multi-Tenant Log Anomaly Detection API`
- Current version string in code: `3.0.1`

Implemented service endpoints include:

- `/health`
- `/metrics`
- `/projects`
- `/projects/{project_id}`
- `/detect`
- `/detect/batch`
- `/detect/structured`
- `/detect/batch/structured`
- `/internal/projects/register`
- `/internal/projects/ingest-stats`
- admin teacher info endpoints

## Core Orchestrator

The main scoring engine is `MultiTenantDetector` in `realtime_anomaly_detection/models/multi_tenant_detector.py`.

It manages:

- project registry
- API key validation
- teacher warmup scoring
- student activation
- per-project counters
- manifest-aware template normalization
- threshold metadata
- teacher update integration

## Project Lifecycle

Project phases are represented by `ProjectPhase` and include:

- `warmup`
- `training`
- `active`
- `suspended`
- `error`

Warmup uses the teacher path. Active phase uses project-specific student models when available.

## Teacher and Student Models

The detector uses:

- `TeacherModel`
- `StudentModel`

They combine:

- rule-based detector
- transformer-style sequence scoring
- Isolation Forest over engineered features

## Current Decision Behavior

The implementation has been hardened to behave more like policy plus anomaly scoring:

- known attack rules are authoritative
- probe traffic can be skipped from scoring
- inactive components should not dilute decisions
- transformer can mark `insufficient_signal`
- detector responses now expose component status and decision metadata

The service returns fields such as:

- `is_anomaly`
- `anomaly_score`
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

## Low-Traffic Profile

The code now supports project traffic profiles:

- `standard`
- `low_traffic`

The detector currently applies these profile defaults:

### Standard

- warmup threshold: `10000`
- minimum training sequences: `100`
- minimum IF rows: `100`
- minimum observed hours: `6`
- calibration floor: `50`

### Low Traffic

- warmup threshold: `1000`
- minimum training sequences: `30`
- minimum IF rows: `50`
- minimum observed hours: `3`
- calibration floor: `20`

## Manifest-Aware Bootstrap

`MultiTenantDetector` now includes route-manifest helpers that let it:

- match incoming requests against a seeded endpoint manifest
- normalize routes using manifest templates
- classify manifest-marked infrastructure routes as `internal_probe`
- keep probe traffic out of baseline collection

This is how the external route extraction script can improve cold-start behavior.

## Warmup and Calibration Reality

The anomaly service is stronger than it was originally, but the implementation still has real runtime constraints:

- the teacher path is weaker than a trained project student
- missing or incomplete base artifacts still hurt cold-start quality
- Isolation Forest usefulness depends on having a fitted model or enough project data
- transformer scores are suppressed when unknown-template ratio is too high

## Teacher Update Scheduler

The service starts a background `TeacherUpdateScheduler` during startup.

It is configured from environment and currently requires a significant minimum sample count before updates run. The startup logs are the authoritative place to confirm whether the scheduler actually initialized and whether teacher state was loaded cleanly.

## Important Current Caveats

- A missing or unfitted teacher Isolation Forest does not fully break the service now, but it does reduce scoring richness.
- If most live routes are unknown to the base teacher vocabulary, transformer signals will often be low-signal during warmup.
- Model quality still depends on baseline cleanliness, project-specific traffic, and correct deployment of updated images.
