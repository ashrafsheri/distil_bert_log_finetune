# Frontend

`frontend/` is the React/Vite dashboard for LogGuard.

## Responsibilities

- Firebase web authentication.
- Protected app routes and role-aware navigation.
- Project creation and project member management.
- Live dashboard, log table, and anomaly detail panels.
- Admin, users, profile, update-password, and reports views.
- Websocket subscription to backend project updates.

## Important Modules

- `src/App.tsx`: route table and protected route wiring.
- `src/pages/`: screen-level pages.
- `src/components/`: reusable UI and dashboard components.
- `src/services/`: backend API clients and Firebase auth helpers.
- `src/context/`: auth and theme providers.
- `src/hooks/useLogs.ts`: log fetching and streaming behavior.
- `src/config/firebase.ts`: Firebase client initialization from `VITE_FIREBASE_*`.

## Required Environment

Vite reads these from `frontend/.env`:

- `VITE_FIREBASE_API_KEY`
- `VITE_FIREBASE_AUTH_DOMAIN`
- `VITE_FIREBASE_PROJECT_ID`
- `VITE_FIREBASE_STORAGE_BUCKET`
- `VITE_FIREBASE_MESSAGING_SENDER_ID`
- `VITE_FIREBASE_APP_ID`
- `VITE_FIREBASE_MEASUREMENT_ID`

The frontend uses relative `/api` and `/ws` paths, so local development expects the backend to be reachable through the same host or a reverse proxy. For direct Vite development, run the backend on `localhost:8000` and adjust proxying if needed.

## Run Locally

```bash
npm install
npm run dev
```

Build:

```bash
npm run build
```
