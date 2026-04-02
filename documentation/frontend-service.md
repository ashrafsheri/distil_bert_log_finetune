# Frontend Service

## Service Role

The frontend in `frontend/` is a React application that provides:

- login and protected navigation
- project management
- project member management
- project dashboards
- incidents and reports views
- admin and user views
- live log streaming over websockets

The main entry is `frontend/src/main.tsx`.

## Runtime Basics

- Framework: React
- Router: React Router
- Default runtime port in Kubernetes: `3000`
- Production serving mode in the container uses `vite preview`

## App Composition

`frontend/src/App.tsx` wires:

- `AuthProvider`
- `ThemeProvider`
- protected routes

## Main Routes

The implemented route set currently includes:

- `/login`
- `/`
- `/projects`
- `/projects/:projectId/members`
- `/dashboard/:projectId`
- `/dashboard`
- `/users`
- `/admin-dashboard`
- `/profile`
- `/reports`
- `/update-password`

There is route-level role gating through `ProtectedRoute`.

## Project Management UI

The Projects dashboard is implemented in `frontend/src/pages/ProjectsDashboard.tsx`.

The project creation UI currently exposes:

- project name
- log type: `apache` or `nginx`
- traffic profile: `standard` or `low_traffic`

This matches the current backend and detector support.

## Live Updates

The frontend subscribes to backend websocket updates for project-specific dashboards.

The important implementation reality is:

- websocket connections include `project_id`
- backend broadcasts are filtered using that project id

Without both sides matching, live dashboard updates do not arrive correctly.

## Detector Data Display

The frontend shows detector details such as:

- rule-based result
- isolation forest result
- transformer result
- final risk score
- final decision

Recent detector-facing UI changes also support low-signal transformer handling when a sequence is dominated by unknown templates.

## Current Frontend Caveats

- The UI quality depends heavily on backend document shape; if older Elasticsearch records are missing newer fields, some panels will show partial detail.
- Frontend route coverage is broader than the documented data contracts, so backend schema changes can break specific pages even if the shell app still loads.
- The app reflects detector state; it does not independently verify detector correctness.
