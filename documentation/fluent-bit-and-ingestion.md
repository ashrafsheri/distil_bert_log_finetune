# Fluent Bit and Ingestion

## Current Role

The repository contains a Fluent Bit configuration in `fluent-bit/fluent-bit-simple.conf`.

Its intended purpose is to tail access logs and forward them to the backend ingest endpoint at:

- `/api/v1/logs/agent/send-logs`

## Current Config Reality

The checked-in file is a safe sample config. It tails an Apache access log from a Linux path and forwards records to a local backend. Before using it in production, change the log path, backend host/port, and `X-API-Key` value.

## Current Active-Looking Input

The uncommented input tails:

- `/var/log/apache2/access.log`

with tag:

- `web.access`

## Current Output

The HTTP output sample sends to:

- host: `localhost`
- port: `8000`
- URI: `/api/v1/logs/agent/send-logs`

and includes a placeholder `X-API-Key` header.

## Service Monitoring

The config also enables the Fluent Bit HTTP server on:

- `0.0.0.0:2020`

## Ingest Flow

The intended path is:

1. Fluent Bit tails access logs
2. Fluent Bit sends records to the backend
3. Backend parses and classifies logs
4. Backend forwards structured batches to anomaly detection
5. Backend stores results in Elasticsearch
6. Backend pushes live updates to dashboards

## Grounded Warnings

- Do not commit a real project API key in `fluent-bit-simple.conf` or `config.env`.
- Keep Fluent Bit state DB files out of Git; they are local cursor state.
- The ingest path described above is real, but this specific config is operationally rough.
