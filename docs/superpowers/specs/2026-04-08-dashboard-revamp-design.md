# Dashboard Revamp Design

**Date:** 2026-04-08  
**Scope:** `frontend/src/pages/DashboardPage.tsx`, `frontend/src/index.css`  
**Project:** BarterEase project page (`/dashboard/:projectId`)

---

## Summary

Revamp the project dashboard (`DashboardPage`) to improve usability and visual clarity. The core change is moving protection state, stream controls, and hot endpoints out of a right-side panel stack into a permanent left sidebar, freeing the main content area for a full-width traffic chart and a redesigned logs table with inline model detail.

---

## Layout

The dashboard shell becomes a 2-column layout:

```
[Navbar — unchanged, top of page]
[Sidebar 240px sticky] | [Main content area, fluid]
```

`MainLayout.tsx` is not changed. The sidebar is rendered inside `DashboardPage` only.

### Sidebar (240px, sticky, scrollable)

Dark background (`#080f1e`), right border, `position: sticky; top: 56px; height: calc(100vh - 56px)`. Five sections separated by 1px dividers:

1. **Project** — shield icon + project name + "Active project" sub-label
2. **Status pill** — pulsing green dot + "Live stream" (amber + "Stream paused" when paused)
3. **Protection** — rows: Detection mode, Warmup (with gradient fill bar), Student model, Members, Traffic profile
4. **Stream Controls** — Pause/Resume (primary blue button, full width), Show anomalies only (ghost toggle, turns amber when active), Step queue + Apply pending (2-col grid), Clear queue; queue stats card at bottom (Pending events / Threats in queue)
5. **Hot Endpoints** — top 5 endpoint rows: monospace name on left, threat count in red on right

### Main Content Area

Rendered inside `<main>` with `padding: 20px 24px`, flex column, `gap: 16px`:

1. **Page header row** — left: breadcrumbs (`Projects / <name>`) + page title (`Security Dashboard`); right: status chips (Project ID, mode, log type, last update), Export button
2. **KPI row** — 5 cards in a CSS grid (`repeat(5, 1fr)`)
3. **Traffic chart panel**
4. **Filters panel** (admin/manager only, unchanged behavior)
5. **Logs table + detail panel**

---

## Components

### KPI Cards

Five cards: Total Logs (blue), Threats (red), Incidents (amber), Parse Failures (muted), Detection Health (green).

Each card:
- Background: `#0e1930`, border: `1px solid rgba(148,163,184,0.1)`
- Top border: `3px solid <accent-color>`
- Label: 9px uppercase, muted
- Value: 28px bold, colored for red/amber/green cards, white for blue/muted
- Helper text: 10px muted below

### Traffic Chart Panel

- Full-width panel, `border-radius: 12px`
- Bar area height: `120px` (increased from current)
- 6 time buckets, each with 2 bars (threats + clean) side by side
- Legend in header: red dot "Threats", green dot "Clean"
- Footer stats row: window log count, threat rate (red), clean rate (green)

### Log Detail Panel (new)

Triggered by clicking any row in `LogsTable`. Renders as a fixed-width panel (`280px`) that appears to the right of the logs table, sliding in. The logs table shrinks to fill remaining width.

Panel contents:
- Header: "Log detail" title + ✕ close button
- Sub-header: `<ip> → <endpoint>` in monospace
- Divider
- Three model cards (Transformer, Isolation Forest, Rule-based), each showing:
  - Model name (uppercase, blue) + verdict badge (Anomaly / Clean)
  - Score with labeled fill bar
  - Text detail (template name, reason, or matched rule names)
- Selected row in the table gets `border-left: 2px solid #4f8df9` + subtle blue background

State: `selectedLog: LogEntry | null` in `DashboardPage`. Set on row click, cleared by close button or clicking same row again.

The `LogsTable` component receives `onRowClick` and `selectedLogId` props. These are new optional props; existing callers without them continue to work unchanged.

---

## CSS Changes (`index.css`)

**Add:**
- `.dashboard-sidebar` — sticky sidebar shell
- `.sidebar-project`, `.sidebar-status-pill`, `.sidebar-section-label`, `.sidebar-stat-row`, `.sidebar-progress`, `.sidebar-divider` — sidebar structural classes
- `.sidebar-ctrl-btn`, `.sidebar-ctrl-btn--primary`, `.sidebar-ctrl-btn--ghost`, `.sidebar-ctrl-btn--warning` — stream control buttons
- `.sidebar-queue-card` — 2-col queue stats
- `.sidebar-endpoint-item` — hot endpoint row
- `.dash-body` — flex row container for sidebar + main
- `.dash-main` — main content padding and flex column
- `.dash-page-header` — slim breadcrumb + title + meta row
- `.kpi-card--blue`, `.kpi-card--red`, `.kpi-card--amber`, `.kpi-card--muted`, `.kpi-card--green` — top accent border variants
- `.log-detail-panel` — slide-in detail panel shell
- `.log-detail-model` — individual model card within detail panel
- `.log-row--selected` — selected row highlight

**Remove / replace:**
- `.ops-hero` grid layout (replace with `.dash-page-header`)
- `.ops-hero__badge`, `.ops-hero__title-row`, `.ops-hero__subtitle`, `.ops-hero__meta`, `.ops-hero__meta-card` — no longer rendered
- `.ops-main-grid` — replaced by `.dash-body` + sidebar
- `.ops-panel--stack` — no longer rendered (content moved to sidebar)

Classes used exclusively by `DashboardPage` (`ops-kpi-card` family, `ops-hero` family, `ops-main-grid`, `ops-panel--stack`) are removed or replaced. Shared classes used by other pages (`ops-panel`, `ops-filter-grid`, `ops-input`, `ops-chip`, etc.) are preserved unchanged.

---

## Files Changed

| File | Change |
|---|---|
| `frontend/src/pages/DashboardPage.tsx` | New sidebar + main layout structure, new `selectedLog` state, pass `onRowClick`/`selectedLogId` to `LogsTable`, remove hero section JSX |
| `frontend/src/components/LogsTable.tsx` | Add optional `onRowClick?: (log: LogEntry) => void` and `selectedLogId?: string` props; apply selected row styling |
| `frontend/src/index.css` | Add sidebar + detail panel CSS; clean up removed hero classes |

---

## Out of Scope

- Mobile/responsive layout (sidebar collapses or hides on small screens is deferred)
- Other pages (Users, Admin Dashboard, Projects, Reports) — unchanged
- Backend changes — none required
- Filter panel behavior — unchanged
- Logs table columns, pagination, search — unchanged
