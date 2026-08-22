# Fluent Bit

`fluent-bit/` contains safe sample configuration for shipping access logs into LogGuard.

## Files

- `fluent-bit-simple.conf`: sample Fluent Bit config that tails `/var/log/apache2/access.log` and posts to `localhost:8000`.
- `config.env.example`: sample environment values for local setup.
- `parsers.conf`: parser definitions.
- `install.sh`: Linux/macOS helper.
- `install.ps1` and `restart-service.ps1`: Windows helpers.

## Setup

```bash
cp fluent-bit/config.env.example fluent-bit/config.env
```

Edit:

- `APACHE_LOG_PATH`
- `BACKEND_URL`
- `API_ENDPOINT`
- `API_KEY`
- `FLUENT_BIT_DB_PATH`

Never commit `fluent-bit/config.env` or Fluent Bit `*.db` state files.

The active backend ingest endpoint is:

```text
/api/v1/logs/agent/send-logs
```
