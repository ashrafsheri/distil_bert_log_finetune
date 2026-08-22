# Scripts

`scripts/` contains development and operations utilities. They are not required for the frontend/backend/anomaly services to start.

## Main Utilities

- `train_base_model.py`: train/export a base detector artifact.
- `synthetic_log_generator.py`: generate synthetic logs from endpoint manifests.
- `backtest_harness.py` and `run_backtest.sh`: replay scenarios and compare detector behavior.
- `evaluate_model_performance.py`: inspect saved teacher/student model state.
- `check_model_health.py`: query anomaly service health and model readiness.
- `generate_sonar_report.py`: fetch SonarCloud issue metrics into local reports.
- `preflight_check.sh`: local readiness checks for backend and Fluent Bit.
- `k8s-deploy.sh`: guarded Kubernetes apply flow.

## Safety

Traffic-generating scripts default to `localhost`. Set target URLs explicitly before using them against a real deployment.

Do not commit generated reports, model checkpoints, logs, or API keys.
