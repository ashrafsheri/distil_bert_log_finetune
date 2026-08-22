# Realtime Anomaly Detection

`realtime_anomaly_detection/` is the detector microservice. It is separate from the backend so scoring, model state, and project lifecycle can evolve independently.

## Responsibilities

- Register projects and maintain per-project detector state.
- Score raw and structured access-log events.
- Combine rule-based checks, Isolation Forest features, and transformer-style sequence novelty.
- Support warmup, training, active, suspended, and error phases.
- Promote project-specific student models after enough clean baseline data exists.
- Track parse failure rates, calibration metadata, traffic class, and decision reasons.

## Important Modules

- `api/server_multi_tenant.py`: primary FastAPI app used by deployment.
- `api/server.py` and `api/server_adaptive.py`: older/specialized service entrypoints kept for experiments.
- `models/multi_tenant_detector.py`: project-aware detector orchestrator.
- `models/project_manager.py`: project registry, API keys, state persistence.
- `models/teacher_model.py`: shared teacher model.
- `models/student_model.py`: project-specific student model.
- `models/knowledge_distillation.py`: teacher/student update support.
- `models/calibrator.py`: score calibration.
- `streaming/`: demo streamer utilities.
- `tests/`: detector behavior tests.

## Required Environment

- `MODEL_DIR`: base model artifact directory.
- `STORAGE_DIR`: per-project state directory.
- `ADMIN_API_KEY`: optional admin key for protected detector endpoints.
- `WARMUP_THRESHOLD`, `TEACHER_UPDATE_DAYS`, `DEVICE`: lifecycle and runtime tuning.

See `.env.example` for the full tuning surface.

## Run Locally

```bash
PYTHONPATH="$PWD/realtime_anomaly_detection" \
MODEL_DIR="$PWD/artifacts/ensemble_model_export" \
STORAGE_DIR="$PWD/data/multi_tenant" \
uvicorn realtime_anomaly_detection.api.server_multi_tenant:app --host 0.0.0.0 --port 8001
```

Health check:

```bash
curl http://localhost:8001/health
```
