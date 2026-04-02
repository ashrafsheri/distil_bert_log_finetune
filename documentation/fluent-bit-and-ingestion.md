# Fluent Bit and Ingestion

## Current Role

The repository contains a Fluent Bit configuration in `fluent-bit/fluent-bit-simple.conf`.

Its intended purpose is to tail access logs and forward them to the backend ingest endpoint at:

- `/api/v1/logs/agent/send-logs`

## Current Config Reality

The checked-in file is not a clean generic production config. It currently contains:

- duplicate input blocks
- duplicate filter and output directives
- a hardcoded Windows Apache log path
- a hardcoded remote host IP
- a hardcoded API key in the output header

That means the file should be treated as an environment-specific sample or a currently in-use local config, not a reusable default.

## Current Active-Looking Input

The uncommented input tails:

- `C:\Users\hp\Downloads\httpd-2.4.65-250724-Win64-VS17\Apache24\logs\juicebox_access.log`

with tag:

- `apache.access`

## Current Output

The HTTP output currently sends to:

- host: `57.128.223.176`
- port: `80`
- URI: `/api/v1/logs/agent/send-logs`

and includes an `X-API-Key` header directly in the config.

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

- The checked-in Fluent Bit config is not parameterized.
- The hardcoded `X-API-Key` should be treated as sensitive runtime data, not a safe reusable template.
- The file includes repeated directives that should be cleaned before treating it as canonical documentation or infrastructure-as-code.
- The ingest path described above is real, but this specific config is operationally rough.
