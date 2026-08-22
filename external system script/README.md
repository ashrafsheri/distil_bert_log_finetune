# External System Scripts

This directory contains helpers for extracting and testing endpoint manifests from another application.

## Files

- `extract_api_manifest.py`: scans a target codebase and builds an endpoint manifest.
- `generate_authenticated_manifest_traffic.py`: signs in to a Supabase-backed app and exercises manifest endpoints.
- `generate_authenticated_attack_traffic.sh`: sends authenticated attack probes to a configured test target.

These scripts require explicit target URLs and credentials. Keep real values in shell environment variables or local `.env` files, never in Git.
