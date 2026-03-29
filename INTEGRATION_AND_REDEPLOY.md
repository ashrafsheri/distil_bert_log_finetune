# Integration & Redeploy Guide

Quick steps to integrate the per-org model lifecycle on your project server and redeploy the log anomaly (realtime) service when changes are made.

## 1) Prerequisites
- PostgreSQL reachable by the backend
- Docker + docker-compose installed on both backend host and anomaly server
- SMTP credentials configured (for email notifications)

## 2) Backend (API) integration on project server
1) **Pull code**
   - `git pull` on the backend host.
2) **Set environment** (examples)
   - `ANOMALY_DETECTION_URL=http://anomaly-detection:8001`
   - `LOGGUARD_HOST=<public_or_internal_host>` (the host Fluent-bit will call)
   - `LOGGUARD_PORT=<http_port>` (80/443/etc.)
   - `ADMIN_EMAIL=<admin_notify@example.com>`
3) **Run DB migration** (adds model tracking columns)
   - `psql $DATABASE_URL -f backend/migrations/001_add_model_tracking_to_orgs.sql`
4) **Build & start backend**
   - `docker-compose build backend`
   - `docker-compose up -d backend`
5) **Verify API is up**
   - `curl -I http://<LOGGUARD_HOST>:<LOGGUARD_PORT>/api/health` (adjust path if needed)

## 3) Fluent-bit integration (per org)
1) Create org via Admin UI or `POST /api/v1/admin/create-org`.
2) Copy the generated Fluent-bit config from the UI response (or OrgCreationResult modal).
3) On the log source server:
   - Install Fluent-bit
   - Replace/add the provided `[OUTPUT]` block (includes `X-API-Key`)
   - Restart Fluent-bit
4) Logs will flow under that org’s API key. Warmup uses the teacher model until 10k logs; then student model trains automatically.

## 4) Redeploy log anomaly service (realtime_anomaly_detection)
1) **Pull code** on the anomaly server: `git pull`
2) **Set environment** (examples)
   - `BACKEND_WEBHOOK_URL=http://backend:8000/api/v1/webhook/model-status` (backend reachable from anomaly service)
   - `DEFAULT_WARMUP_THRESHOLD=10000` (if configurable)
3) **Build & start**
   - `docker-compose build anomaly-detection`
   - `docker-compose up -d anomaly-detection`
4) **Health check**
   - `curl -I http://localhost:8001/health`
   - Optional: `curl -H "X-API-Key: <org_api_key>" http://localhost:8001/project/status`
5) **Webhook check**
   - Ensure backend can reach `BACKEND_WEBHOOK_URL` (network/DNS). When a student model finishes, the anomaly service POSTs status to that URL.

## 5) End-to-end validation
- Create a new org; confirm email is sent with API key and Fluent-bit config.
- Send sample logs via Fluent-bit; check backend logs for `model_info` and org warmup progress.
- After ~10k logs, confirm webhook updates model status to `active` and notification emails are delivered.
- In Admin Dashboard, verify model badges/progress and log counts update.

## 6) Rollback
- Backend: `docker-compose rollback` (if using compose v2) or `docker-compose up -d backend` with previous image tag.
- Anomaly service: redeploy previous image tag similarly.
- Database: migration is additive; no downgrade script included—snapshot DB before applying if rollback is required.
