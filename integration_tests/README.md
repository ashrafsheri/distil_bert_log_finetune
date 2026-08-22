# Integration Tests

`integration_tests/` contains scripts for testing a running LogGuard deployment.

## Files

- `ai_test_cases_integration_test.py`: posts curated log cases to the ingest API.
- `selenium_integration_test.py`: browser-oriented workflow coverage.
- `stress_test.py`: direct POST load generator for ingest.
- `generate_stress_report.py`: converts stress-test JSON output into a report.

## Environment

Use `.env.example` as the source of test variables. At minimum:

- `TEST_BASE_URL`
- `TEST_API_KEY`
- `TEST_APP_URL`
- `TEST_BACKEND_API`
- `TEST_WS_URL`

Stress tests use:

- `LOGGUARD_BASE_URL`
- `LOGGUARD_ENDPOINT`
- `SAAS_API_KEY`
- `PLAYGROUND_API_KEY`

Defaults point to localhost and dry-run-friendly values.
