# External Endpoint Manifest Seeding

## Purpose

The repository now contains a bootstrap path for external backend systems that lets LogGuard learn route structure earlier than it would from live traffic alone.

The extraction script lives at:

- `external system script/extract_api_manifest.py`

## What the Script Does

The script performs a best-effort scan of another backend codebase and extracts endpoint templates into a manifest.

Supported patterns currently include:

- FastAPI and APIRouter-style Python routes
- Express-style JavaScript and TypeScript routes

It scans source files with these extensions:

- `.py`
- `.js`
- `.ts`
- `.tsx`
- `.mjs`
- `.cjs`

## Manifest Shape

The generated manifest contains:

- `service_name`
- `framework`
- `frameworks_detected`
- `generated_at`
- `source_root`
- `endpoints`

Each endpoint entry currently includes:

- `method`
- `path_template`
- `classification`
- `baseline_eligible`

Known infrastructure paths such as `/health`, `/ready`, `/live`, and `/metrics` are classified as `internal_probe`.

## Backend Seed Endpoint

The backend exposes:

- `POST /api/v1/projects/{project_id}/seed-endpoint-manifest`

The request body model is `EndpointManifestSeedRequest`, which accepts:

- `manifest`

The backend forwards this manifest to the anomaly detector using project metadata.

## Detector Use of the Manifest

The anomaly service uses the seeded manifest to:

- match incoming requests to known route templates
- normalize routes using manifest path templates
- classify manifest-marked infrastructure routes as `internal_probe`
- keep those routes out of baseline and calibration

This directly improves cold-start behavior for:

- new projects
- low-traffic projects
- projects whose live routes are not represented in the base teacher vocabulary

## Example Usage

Generate a manifest file:

```bash
python3 "external system script/extract_api_manifest.py" \
  --source /path/to/external/backend \
  --service-name payments-api \
  --output /tmp/payments-api-manifest.json
```

Generate and seed in one step:

```bash
python3 "external system script/extract_api_manifest.py" \
  --source /path/to/external/backend \
  --service-name payments-api \
  --project-id proj-12345678 \
  --seed-url https://your-host/api/v1/projects/proj-12345678/seed-endpoint-manifest \
  --token "$JWT_TOKEN"
```

## Current Limitations

- Extraction is regex-based and best-effort.
- It will not fully understand framework metaprogramming, nested routers with complex dynamic construction, or generated route code.
- The manifest is a prior, not proof that a route is benign.
- Known-route malicious payloads must still be caught by rules and anomaly logic.
