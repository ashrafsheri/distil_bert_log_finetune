# Dashboard Revamp Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure the project dashboard with a sticky left sidebar, top-accent KPI cards, full-width chart, and a slide-in log detail panel showing per-model anomaly scores.

**Architecture:** `DashboardPage` gains a 2-column shell (`DashboardSidebar` + main content). Protection state, stream controls, and hot endpoints move from the right panel stack into the sidebar. A new `LogDetailPanel` component opens as a right slide-in when any log row is clicked.

**Tech Stack:** React 18, TypeScript, Vite, Tailwind + custom CSS (`index.css`), no test framework present.

---

## File Map

| Action | Path | Purpose |
|---|---|---|
| Create | `frontend/src/components/DashboardSidebar.tsx` | Sticky left sidebar (project info, protection state, stream controls, hot endpoints) |
| Create | `frontend/src/components/LogDetailPanel.tsx` | Slide-in panel showing per-model anomaly breakdown for a selected log |
| Modify | `frontend/src/components/LogsTable.tsx` | Add optional `onRowClick` + `selectedLogId` props; make rows clickable |
| Modify | `frontend/src/pages/DashboardPage.tsx` | Replace hero + right-panel stack with sidebar + compact header; wire up detail panel |
| Modify | `frontend/src/index.css` | Add sidebar, layout, KPI accent, and detail panel CSS; remove unused hero/main-grid classes |

---

## Task 1: CSS — sidebar, layout, KPI accent variants, detail panel

**Files:**
- Modify: `frontend/src/index.css`

- [ ] **Step 1: Append new CSS classes after the existing `.dashboard-shell__inner` block**

Open `frontend/src/index.css`. Find the line `.dashboard-shell__inner {` (around line 312). After the closing `}` of `.dashboard-shell__inner`, append:

```css
/* ─── Revamped dashboard layout ─── */

.dash-body {
  display: flex;
  min-height: calc(100vh - 56px);
}

.dashboard-sidebar {
  width: 240px;
  flex-shrink: 0;
  background: #080f1e;
  border-right: 1px solid rgba(79, 141, 249, 0.1);
  position: sticky;
  top: 56px;
  height: calc(100vh - 56px);
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  padding: 16px 12px;
  gap: 4px;
  scrollbar-width: thin;
  scrollbar-color: rgba(79,141,249,0.3) transparent;
}

.sidebar-project {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 6px 12px;
}

.sidebar-project__icon {
  width: 30px;
  height: 30px;
  background: linear-gradient(135deg, rgba(79,141,249,0.25), rgba(139,92,246,0.15));
  border: 1px solid rgba(79,141,249,0.3);
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #71c7ff;
  flex-shrink: 0;
}

.sidebar-project__name {
  font-size: 13px;
  font-weight: 700;
  color: #e8f1ff;
}

.sidebar-project__sub {
  font-size: 9px;
  color: #4b5e80;
  text-transform: uppercase;
  letter-spacing: 0.12em;
}

.sidebar-status-pill {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 10px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 500;
  margin-bottom: 4px;
}

.sidebar-status-pill--live {
  background: rgba(34, 211, 166, 0.08);
  border: 1px solid rgba(34, 211, 166, 0.2);
  color: #22d3a6;
}

.sidebar-status-pill--paused {
  background: rgba(244, 193, 93, 0.08);
  border: 1px solid rgba(244, 193, 93, 0.2);
  color: #f4c15d;
}

.sidebar-status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  flex-shrink: 0;
}

.sidebar-status-dot--live {
  background: #22d3a6;
  box-shadow: 0 0 6px rgba(34,211,166,0.7);
  animation: dot-pulse 2s ease-in-out infinite;
}

.sidebar-status-dot--paused {
  background: #f4c15d;
  box-shadow: 0 0 6px rgba(244,193,93,0.6);
}

.sidebar-divider {
  height: 1px;
  background: rgba(148, 163, 184, 0.08);
  margin: 8px 0;
}

.sidebar-section-label {
  font-size: 9px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.15em;
  color: #4f8df9;
  padding: 0 4px;
  margin-bottom: 6px;
}

.sidebar-stat-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 3px 4px;
  font-size: 11px;
}

.sidebar-stat-row__label { color: #6b7a9e; }

.sidebar-stat-row__value { font-weight: 600; color: #e8f1ff; }
.sidebar-stat-row__value--green { color: #22d3a6; }
.sidebar-stat-row__value--blue  { color: #4f8df9; }

.sidebar-progress {
  height: 4px;
  background: rgba(148, 163, 184, 0.1);
  border-radius: 2px;
  margin: 4px 4px 8px;
  overflow: hidden;
}

.sidebar-progress__fill {
  height: 100%;
  background: linear-gradient(90deg, #4f8df9, #22d3a6);
  border-radius: 2px;
}

.sidebar-ctrl-btn {
  width: 100%;
  padding: 7px 10px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 600;
  text-align: center;
  cursor: pointer;
  border: none;
  margin-bottom: 4px;
  transition: opacity 0.15s;
}

.sidebar-ctrl-btn:disabled { opacity: 0.4; cursor: not-allowed; }

.sidebar-ctrl-btn--primary {
  background: #4f8df9;
  color: #fff;
  box-shadow: 0 4px 12px rgba(79,141,249,0.3);
}

.sidebar-ctrl-btn--primary:hover:not(:disabled) { background: #6aa0fb; }

.sidebar-ctrl-btn--resume {
  background: rgba(34,211,166,0.15);
  color: #22d3a6;
  border: 1px solid rgba(34,211,166,0.3);
}

.sidebar-ctrl-btn--resume:hover:not(:disabled) { background: rgba(34,211,166,0.22); }

.sidebar-ctrl-btn--ghost {
  background: rgba(255,255,255,0.04);
  color: #8899bb;
  border: 1px solid rgba(148,163,184,0.1);
}

.sidebar-ctrl-btn--ghost:hover:not(:disabled) { background: rgba(255,255,255,0.07); }

.sidebar-ctrl-btn--warning {
  background: rgba(244,193,93,0.1);
  color: #f4c15d;
  border: 1px solid rgba(244,193,93,0.2);
}

.sidebar-ctrl-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 4px;
  margin-bottom: 4px;
}

.sidebar-ctrl-sm {
  padding: 5px 6px;
  border-radius: 5px;
  font-size: 10px;
  font-weight: 500;
  text-align: center;
  cursor: pointer;
  border: none;
  transition: opacity 0.15s;
}

.sidebar-ctrl-sm:disabled { opacity: 0.35; cursor: not-allowed; }

.sidebar-ctrl-sm--default {
  background: rgba(255,255,255,0.04);
  color: #6b7a9e;
  border: 1px solid rgba(148,163,184,0.1);
}

.sidebar-ctrl-sm--success {
  background: rgba(34,211,166,0.08);
  color: #22d3a6;
  border: 1px solid rgba(34,211,166,0.2);
}

.sidebar-queue-card {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 6px;
  margin-top: 6px;
}

.sidebar-queue-item {
  background: rgba(255,255,255,0.03);
  border: 1px solid rgba(148,163,184,0.08);
  border-radius: 6px;
  padding: 6px 8px;
}

.sidebar-queue-item__label {
  font-size: 8px;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: #4b5e80;
  margin-bottom: 2px;
}

.sidebar-queue-item__value {
  font-size: 18px;
  font-weight: 700;
  color: #e8f1ff;
  line-height: 1.2;
}

.sidebar-endpoint-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 5px 4px;
  border-bottom: 1px solid rgba(148,163,184,0.05);
  font-size: 10px;
}

.sidebar-endpoint-item:last-child { border-bottom: none; }

.sidebar-endpoint-item__name {
  font-family: 'JetBrains Mono', monospace;
  color: #c0cfe8;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 130px;
}

.sidebar-endpoint-item__threats {
  color: #f87171;
  font-weight: 600;
  font-size: 10px;
  flex-shrink: 0;
}

/* ─── Main content area ─── */

.dash-main {
  flex: 1;
  min-width: 0;
  padding: 20px 24px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.dash-page-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.dash-breadcrumb {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.15em;
  color: #4b5e80;
  margin-bottom: 4px;
  display: flex;
  gap: 6px;
  align-items: center;
}

.dash-breadcrumb__sep { color: #2a3a55; }

.dash-page-title {
  font-size: 22px;
  font-weight: 800;
  color: #f0f6ff;
  line-height: 1;
  margin: 0;
}

.dash-header-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

/* ─── KPI card accent variants ─── */

.ops-kpi-card--blue  { border-top: 3px solid #4f8df9 !important; }
.ops-kpi-card--red   { border-top: 3px solid #f87171 !important; }
.ops-kpi-card--amber { border-top: 3px solid #f4c15d !important; }
.ops-kpi-card--muted { border-top: 3px solid #98a4c4 !important; }
.ops-kpi-card--green { border-top: 3px solid #22d3a6 !important; }

.ops-kpi-card--red   .ops-kpi-card__value { color: #f87171; }
.ops-kpi-card--amber .ops-kpi-card__value { color: #f4c15d; }
.ops-kpi-card--green .ops-kpi-card__value { color: #22d3a6; }

/* ─── Log detail panel ─── */

.logs-and-panel {
  display: flex;
  gap: 12px;
  align-items: flex-start;
}

.logs-and-panel .ops-panel {
  flex: 1;
  min-width: 0;
}

.log-detail-panel {
  width: 300px;
  flex-shrink: 0;
  background: #080f1e;
  border: 1px solid rgba(79,141,249,0.15);
  border-radius: 1.5rem;
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 10px;
  position: sticky;
  top: 72px;
  max-height: calc(100vh - 88px);
  overflow-y: auto;
  animation: slideUp 0.2s ease-out;
}

.log-detail-panel__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.log-detail-panel__title {
  font-size: 13px;
  font-weight: 700;
  color: #e8f1ff;
}

.log-detail-panel__close {
  width: 24px;
  height: 24px;
  background: rgba(255,255,255,0.06);
  border: none;
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
  color: #6b7a9e;
  cursor: pointer;
  transition: background 0.15s;
}

.log-detail-panel__close:hover { background: rgba(255,255,255,0.1); color: #e8f1ff; }

.log-detail-panel__sub {
  font-size: 10px;
  font-family: 'JetBrains Mono', monospace;
  color: #6b7a9e;
  word-break: break-all;
}

.log-detail-divider {
  height: 1px;
  background: rgba(148,163,184,0.08);
}

.log-detail-model {
  background: rgba(15,23,42,0.7);
  border: 1px solid rgba(148,163,184,0.1);
  border-radius: 8px;
  padding: 10px 12px;
}

.log-detail-model__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.log-detail-model__name {
  font-size: 9px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: #4f8df9;
}

.log-detail-model__verdict {
  font-size: 10px;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 4px;
}

.log-detail-model__verdict--anomaly {
  background: rgba(248,113,113,0.15);
  color: #f87171;
  border: 1px solid rgba(248,113,113,0.25);
}

.log-detail-model__verdict--clean {
  background: rgba(34,211,166,0.1);
  color: #22d3a6;
  border: 1px solid rgba(34,211,166,0.2);
}

.log-detail-model__verdict--na {
  background: rgba(148,163,184,0.08);
  color: #6b7a9e;
  border: 1px solid rgba(148,163,184,0.15);
}

.log-detail-score-label {
  display: flex;
  justify-content: space-between;
  font-size: 9px;
  color: #4b5e80;
  margin-bottom: 3px;
}

.log-detail-score-track {
  height: 4px;
  background: rgba(148,163,184,0.1);
  border-radius: 2px;
  overflow: hidden;
  margin-bottom: 6px;
}

.log-detail-score-fill {
  height: 100%;
  border-radius: 2px;
}

.log-detail-score-fill--red   { background: linear-gradient(90deg, rgba(248,113,113,0.7), #f87171); }
.log-detail-score-fill--green { background: linear-gradient(90deg, rgba(34,211,166,0.7), #22d3a6); }
.log-detail-score-fill--amber { background: linear-gradient(90deg, rgba(244,193,93,0.7), #f4c15d); }

.log-detail-model__detail {
  font-size: 10px;
  color: #8899bb;
  line-height: 1.5;
}

.log-detail-model__tag {
  display: inline-block;
  font-family: 'JetBrains Mono', monospace;
  font-size: 9px;
  color: #f4c15d;
  background: rgba(244,193,93,0.08);
  border: 1px solid rgba(244,193,93,0.15);
  border-radius: 3px;
  padding: 1px 5px;
  margin: 1px 2px 1px 0;
}

/* selected log row highlight */
.log-row--selected {
  background: rgba(79,141,249,0.06) !important;
  box-shadow: inset 3px 0 0 #4f8df9 !important;
}
```

- [ ] **Step 2: Verify the build compiles**

```bash
cd frontend && npm run build 2>&1 | tail -20
```

Expected: no errors (CSS-only change, should compile cleanly).

- [ ] **Step 3: Commit**

```bash
git add frontend/src/index.css
git commit -m "style: add sidebar, dash layout, KPI accent, and detail panel CSS"
```

---

## Task 2: LogDetailPanel component

**Files:**
- Create: `frontend/src/components/LogDetailPanel.tsx`

- [ ] **Step 1: Create the file**

```tsx
import React from 'react';
import { LogEntry } from '../services/logService';

interface LogDetailPanelProps {
  log: LogEntry;
  onClose: () => void;
}

const ScoreBar: React.FC<{ score: number; variant: 'red' | 'green' | 'amber' }> = ({ score, variant }) => (
  <div className="log-detail-score-track">
    <div
      className={`log-detail-score-fill log-detail-score-fill--${variant}`}
      style={{ width: `${Math.min(score * 100, 100)}%` }}
    />
  </div>
);

const LogDetailPanel: React.FC<LogDetailPanelProps> = ({ log, onClose }) => {
  const transformer    = log.anomaly_details?.transformer;
  const isolationForest = log.anomaly_details?.isolation_forest;
  const ruleBased      = log.anomaly_details?.rule_based;

  const transformerScore = typeof transformer?.score === 'number' ? transformer.score : null;
  const transformerIsAnomaly = transformer?.is_anomaly === 1;
  const transformerSuppressed = transformer?.status === 'insufficient_signal';
  const transformerErrored    = transformer?.status === 'error';

  const ifScore      = typeof isolationForest?.score === 'number' ? isolationForest.score : null;
  const ifIsAnomaly  = isolationForest?.is_anomaly === 1;

  const rbIsAttack   = ruleBased?.is_attack === true;
  const rbConfidence = typeof ruleBased?.confidence === 'number' ? ruleBased.confidence : null;
  const rbTypes      = Array.isArray(ruleBased?.attack_types) ? ruleBased!.attack_types : [];

  return (
    <aside className="log-detail-panel">
      <div className="log-detail-panel__header">
        <span className="log-detail-panel__title">Log detail</span>
        <button className="log-detail-panel__close" onClick={onClose} aria-label="Close panel">✕</button>
      </div>

      <div className="log-detail-panel__sub">
        {log.ipAddress} → {log.apiAccessed}
      </div>

      <div className="log-detail-divider" />

      {/* Transformer */}
      <div className="log-detail-model">
        <div className="log-detail-model__header">
          <span className="log-detail-model__name">Transformer</span>
          {transformerSuppressed || transformerErrored ? (
            <span className="log-detail-model__verdict log-detail-model__verdict--na">
              {transformerSuppressed ? 'Low signal' : 'Error'}
            </span>
          ) : (
            <span className={`log-detail-model__verdict ${transformerIsAnomaly ? 'log-detail-model__verdict--anomaly' : 'log-detail-model__verdict--clean'}`}>
              {transformerIsAnomaly ? 'Anomaly' : 'Normal'}
            </span>
          )}
        </div>
        {transformerScore !== null && !transformerSuppressed && !transformerErrored && (
          <>
            <div className="log-detail-score-label">
              <span>Novelty score</span>
              <span style={{ color: transformerIsAnomaly ? '#f87171' : '#22d3a6' }}>
                {transformerScore.toFixed(3)}
              </span>
            </div>
            <ScoreBar score={transformerScore} variant={transformerIsAnomaly ? 'red' : 'green'} />
          </>
        )}
        {log.normalizedTemplate && (
          <div className="log-detail-model__detail">
            Template: <span className="log-detail-model__tag">{log.normalizedTemplate.slice(0, 40)}</span>
          </div>
        )}
        {(transformerSuppressed || transformerErrored) && (
          <div className="log-detail-model__detail">
            {transformerSuppressed ? 'Unknown-template ratio too high; transformer suppressed.' : 'Scoring error — check detector logs.'}
          </div>
        )}
      </div>

      {/* Isolation Forest */}
      <div className="log-detail-model">
        <div className="log-detail-model__header">
          <span className="log-detail-model__name">Isolation Forest</span>
          <span className={`log-detail-model__verdict ${ifIsAnomaly ? 'log-detail-model__verdict--anomaly' : 'log-detail-model__verdict--clean'}`}>
            {ifScore === null ? 'N/A' : ifIsAnomaly ? 'Anomaly' : 'Normal'}
          </span>
        </div>
        {ifScore !== null && (
          <>
            <div className="log-detail-score-label">
              <span>Outlier score</span>
              <span style={{ color: ifIsAnomaly ? '#f87171' : '#22d3a6' }}>{ifScore.toFixed(3)}</span>
            </div>
            <ScoreBar score={Math.min(ifScore * 0.2, 1)} variant={ifIsAnomaly ? 'red' : 'green'} />
          </>
        )}
        {ifScore === null && (
          <div className="log-detail-model__detail">No isolation forest score available.</div>
        )}
      </div>

      {/* Rule-Based */}
      <div className="log-detail-model">
        <div className="log-detail-model__header">
          <span className="log-detail-model__name">Rule-Based</span>
          <span className={`log-detail-model__verdict ${rbIsAttack ? 'log-detail-model__verdict--anomaly' : 'log-detail-model__verdict--clean'}`}>
            {rbIsAttack ? `${rbTypes.length} rule${rbTypes.length !== 1 ? 's' : ''} matched` : 'No match'}
          </span>
        </div>
        {rbConfidence !== null && (
          <>
            <div className="log-detail-score-label">
              <span>Confidence</span>
              <span style={{ color: rbIsAttack ? '#f87171' : '#22d3a6' }}>{(rbConfidence * 100).toFixed(1)}%</span>
            </div>
            <ScoreBar score={rbConfidence} variant={rbIsAttack ? 'red' : 'green'} />
          </>
        )}
        {rbTypes.length > 0 && (
          <div className="log-detail-model__detail">
            {rbTypes.map((t: string) => (
              <span key={t} className="log-detail-model__tag">{t}</span>
            ))}
          </div>
        )}
        {!rbIsAttack && rbTypes.length === 0 && (
          <div className="log-detail-model__detail">No rule-based attack patterns matched.</div>
        )}
      </div>

      {/* Incident / raw fields */}
      {log.incidentId && (
        <>
          <div className="log-detail-divider" />
          <div className="log-detail-model__detail">
            Incident: <span className="log-detail-model__tag">{log.incidentId}</span>
          </div>
        </>
      )}
    </aside>
  );
};

export default LogDetailPanel;
```

- [ ] **Step 2: Verify build**

```bash
cd frontend && npm run build 2>&1 | tail -20
```

Expected: no TypeScript errors.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/components/LogDetailPanel.tsx
git commit -m "feat: add LogDetailPanel component for per-model anomaly breakdown"
```

---

## Task 3: DashboardSidebar component

**Files:**
- Create: `frontend/src/components/DashboardSidebar.tsx`

The types `ProjectHealthSummary` and `ProjectSummary` are imported from `projectService`; `EndpointInsight` is defined locally here (same shape as in `DashboardPage`).

- [ ] **Step 1: Create the file**

```tsx
import React from 'react';
import { ProjectHealthSummary, ProjectSummary } from '../services/projectService';

type EndpointInsight = {
  endpoint: string;
  total: number;
  threats: number;
};

interface DashboardSidebarProps {
  projectName: string | undefined;
  streamIsPaused: boolean;
  streamLockedByPagination: boolean;
  projectHealth: ProjectHealthSummary | null;
  currentProject: ProjectSummary | null;
  projectMode: string;
  projectWarmupProgress: number;
  showAnomaliesOnly: boolean;
  pendingCount: number;
  pendingThreatCount: number;
  endpointInsights: EndpointInsight[];
  onToggleStreamPause: () => void;
  onToggleAnomalies: () => void;
  onStepPending: () => void;
  onApplyPending: () => void;
  onDiscardPending: () => void;
}

const DashboardSidebar: React.FC<DashboardSidebarProps> = ({
  projectName,
  streamIsPaused,
  streamLockedByPagination,
  projectHealth,
  currentProject,
  projectMode,
  projectWarmupProgress,
  showAnomaliesOnly,
  pendingCount,
  pendingThreatCount,
  endpointInsights,
  onToggleStreamPause,
  onToggleAnomalies,
  onStepPending,
  onApplyPending,
  onDiscardPending,
}) => {
  const formatPercent = (v: number) => `${v.toFixed(v >= 10 ? 1 : 2)}%`;

  return (
    <aside className="dashboard-sidebar">

      {/* Project */}
      <div className="sidebar-project">
        <div className="sidebar-project__icon">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <div>
          <div className="sidebar-project__name">{projectName || 'No project'}</div>
          <div className="sidebar-project__sub">Active project</div>
        </div>
      </div>

      {/* Live / paused status */}
      <div className={`sidebar-status-pill ${streamIsPaused ? 'sidebar-status-pill--paused' : 'sidebar-status-pill--live'}`}>
        <div className={`sidebar-status-dot ${streamIsPaused ? 'sidebar-status-dot--paused' : 'sidebar-status-dot--live'}`} />
        {streamIsPaused ? 'Stream paused' : 'Live stream'}
      </div>

      <div className="sidebar-divider" />

      {/* Protection state */}
      <div className="sidebar-section-label">Protection</div>
      <div className="sidebar-stat-row">
        <span className="sidebar-stat-row__label">Detection mode</span>
        <span className="sidebar-stat-row__value sidebar-stat-row__value--green">{projectMode}</span>
      </div>
      <div className="sidebar-stat-row">
        <span className="sidebar-stat-row__label">Warmup</span>
        <span className="sidebar-stat-row__value sidebar-stat-row__value--blue">
          {projectHealth ? formatPercent(projectWarmupProgress) : 'N/A'}
        </span>
      </div>
      <div className="sidebar-progress">
        <div className="sidebar-progress__fill" style={{ width: `${projectWarmupProgress}%` }} />
      </div>
      <div className="sidebar-stat-row">
        <span className="sidebar-stat-row__label">Student model</span>
        <span className={`sidebar-stat-row__value ${projectHealth?.has_student_model ? 'sidebar-stat-row__value--green' : ''}`}>
          {projectHealth?.has_student_model ? 'Ready' : 'Not ready'}
        </span>
      </div>
      <div className="sidebar-stat-row">
        <span className="sidebar-stat-row__label">Members</span>
        <span className="sidebar-stat-row__value">{currentProject?.member_count ?? 'N/A'}</span>
      </div>
      <div className="sidebar-stat-row">
        <span className="sidebar-stat-row__label">Traffic profile</span>
        <span className="sidebar-stat-row__value">
          {currentProject?.traffic_profile || projectHealth?.traffic_profile || 'standard'}
        </span>
      </div>

      <div className="sidebar-divider" />

      {/* Stream controls */}
      <div className="sidebar-section-label">Stream Controls</div>

      {streamLockedByPagination ? (
        <div className="ops-chip ops-chip--warning" style={{ marginBottom: 8, fontSize: 10 }}>
          Live stream locked on older pages
        </div>
      ) : null}

      <button
        type="button"
        onClick={onToggleStreamPause}
        disabled={streamLockedByPagination}
        className={`sidebar-ctrl-btn ${streamIsPaused ? 'sidebar-ctrl-btn--resume' : 'sidebar-ctrl-btn--primary'}`}
      >
        {streamIsPaused ? 'Resume stream' : 'Pause stream'}
      </button>

      <button
        type="button"
        onClick={onToggleAnomalies}
        className={`sidebar-ctrl-btn ${showAnomaliesOnly ? 'sidebar-ctrl-btn--warning' : 'sidebar-ctrl-btn--ghost'}`}
      >
        {showAnomaliesOnly ? 'Showing anomalies only' : 'Show anomalies only'}
      </button>

      <div className="sidebar-ctrl-grid">
        <button
          type="button"
          onClick={onStepPending}
          disabled={pendingCount === 0}
          className="sidebar-ctrl-sm sidebar-ctrl-sm--default"
        >
          Step queue
        </button>
        <button
          type="button"
          onClick={onApplyPending}
          disabled={pendingCount === 0}
          className="sidebar-ctrl-sm sidebar-ctrl-sm--success"
        >
          Apply pending
        </button>
      </div>

      <button
        type="button"
        onClick={onDiscardPending}
        disabled={pendingCount === 0}
        className="sidebar-ctrl-btn sidebar-ctrl-btn--ghost"
        style={{ marginTop: 0 }}
      >
        Clear queue
      </button>

      <div className="sidebar-queue-card">
        <div className="sidebar-queue-item">
          <div className="sidebar-queue-item__label">Pending</div>
          <div className="sidebar-queue-item__value">{pendingCount.toLocaleString()}</div>
        </div>
        <div className="sidebar-queue-item">
          <div className="sidebar-queue-item__label">In queue</div>
          <div className="sidebar-queue-item__value">{pendingThreatCount.toLocaleString()}</div>
        </div>
      </div>

      {endpointInsights.length > 0 && (
        <>
          <div className="sidebar-divider" />
          <div className="sidebar-section-label">Hot Endpoints</div>
          {endpointInsights.map(item => (
            <div key={item.endpoint} className="sidebar-endpoint-item">
              <span className="sidebar-endpoint-item__name" title={item.endpoint}>{item.endpoint}</span>
              <span className="sidebar-endpoint-item__threats">{item.threats.toLocaleString()}</span>
            </div>
          ))}
        </>
      )}
    </aside>
  );
};

export default DashboardSidebar;
```

- [ ] **Step 2: Verify build**

```bash
cd frontend && npm run build 2>&1 | tail -20
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/components/DashboardSidebar.tsx
git commit -m "feat: add DashboardSidebar component"
```

---

## Task 4: LogsTable — add onRowClick and selectedLogId props

**Files:**
- Modify: `frontend/src/components/LogsTable.tsx`

The `LogsTable` currently accepts 7 props (lines 271–278). We add two optional ones. Clicking anywhere on a row fires `onRowClick`; the Actions `<td>` stops propagation so button clicks don't also fire it.

- [ ] **Step 1: Add props to the interface (line ~271)**

Find this block:
```typescript
interface LogsTableProps {
  logs: LogEntry[];
  sourceLogs?: LogEntry[];
  focusedIp?: string | null;
  onFocusIp?: (ip: string | null) => void;
  highlightTransformerTrail?: boolean;
  onCorrectLog?: (ip: string, status: 'clean' | 'malicious') => Promise<void>;
  canCorrectLogs?: boolean; // Whether user has permission to correct logs
}
```

Replace with:
```typescript
interface LogsTableProps {
  logs: LogEntry[];
  sourceLogs?: LogEntry[];
  focusedIp?: string | null;
  onFocusIp?: (ip: string | null) => void;
  highlightTransformerTrail?: boolean;
  onCorrectLog?: (ip: string, status: 'clean' | 'malicious') => Promise<void>;
  canCorrectLogs?: boolean;
  onRowClick?: (log: LogEntry) => void;
  selectedLogId?: string;
}
```

- [ ] **Step 2: Destructure the new props in the component (line ~281)**

Find:
```typescript
const LogsTable: React.FC<LogsTableProps> = ({
  logs,
  sourceLogs,
  focusedIp = null,
  onFocusIp,
  highlightTransformerTrail = false,
  onCorrectLog,
  canCorrectLogs = false,
}) => {
```

Replace with:
```typescript
const LogsTable: React.FC<LogsTableProps> = ({
  logs,
  sourceLogs,
  focusedIp = null,
  onFocusIp,
  highlightTransformerTrail = false,
  onCorrectLog,
  canCorrectLogs = false,
  onRowClick,
  selectedLogId,
}) => {
```

- [ ] **Step 3: Apply selected-row class and click handler on the `<tr>` (line ~416)**

Find:
```tsx
return (
  <React.Fragment key={rowKey}>
    <tr className={rowClasses}>
```

Replace with:
```tsx
const isSelected = selectedLogId === rowId;
return (
  <React.Fragment key={rowKey}>
    <tr
      className={[rowClasses, isSelected ? 'log-row--selected' : ''].filter(Boolean).join(' ')}
      style={onRowClick ? { cursor: 'pointer' } : undefined}
      onClick={onRowClick ? () => onRowClick(log) : undefined}
    >
```

- [ ] **Step 4: Stop propagation in the Actions `<td>` so button clicks don't bubble to the row (line ~515)**

Find:
```tsx
<td className="px-3 sm:px-4 lg:px-6 py-4 whitespace-nowrap">
  <ActionButtons
```

Replace with:
```tsx
<td
  className="px-3 sm:px-4 lg:px-6 py-4 whitespace-nowrap"
  onClick={e => e.stopPropagation()}
>
  <ActionButtons
```

- [ ] **Step 5: Verify build**

```bash
cd frontend && npm run build 2>&1 | tail -20
```

Expected: no TypeScript errors. No existing behaviour changes — `onRowClick` and `selectedLogId` are optional.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/LogsTable.tsx
git commit -m "feat: add onRowClick and selectedLogId props to LogsTable"
```

---

## Task 5: DashboardPage — full layout restructure

**Files:**
- Modify: `frontend/src/pages/DashboardPage.tsx`

This is the largest change. We: import new components, add `selectedLog` state, replace the `dashboard-shell__inner` grid with the sidebar + main layout, replace the hero with a compact header, update KPI cards to use accent variants, remove the `ops-main-grid` right panel (protection state + stream controls + hot endpoints), wire the log detail panel.

- [ ] **Step 1: Add imports at the top of the file (after existing imports, around line 12)**

Find:
```typescript
import { isThreatDetected } from '../utils/helpers';
```

Replace with:
```typescript
import { isThreatDetected } from '../utils/helpers';
import DashboardSidebar from '../components/DashboardSidebar';
import LogDetailPanel from '../components/LogDetailPanel';
```

- [ ] **Step 2: Add selectedLog state (after the existing `correctionSuccess` state, around line 198)**

Find:
```typescript
const [correctionSuccess, setCorrectionSuccess] = useState<{ ip: string; status: string; count: number } | null>(null);
```

Replace with:
```typescript
const [correctionSuccess, setCorrectionSuccess] = useState<{ ip: string; status: string; count: number } | null>(null);
const [selectedLog, setSelectedLog] = useState<import('../services/logService').LogEntry | null>(null);
```

- [ ] **Step 3: Add handler for log row click (after the `handleCorrectLog` callback, around line 343)**

Find:
```typescript
  const handleSearch = useCallback(async () => {
```

Add before that line:
```typescript
  const handleRowClick = useCallback((log: import('../services/logService').LogEntry) => {
    setSelectedLog(prev => {
      const rowId = `${log.timestamp}-${log.ipAddress}-${log.apiAccessed}-${log.statusCode}`;
      const prevId = prev ? `${prev.timestamp}-${prev.ipAddress}-${prev.apiAccessed}-${prev.statusCode}` : null;
      return prevId === rowId ? null : log;
    });
  }, []);

  const selectedLogId = selectedLog
    ? `${selectedLog.timestamp}-${selectedLog.ipAddress}-${selectedLog.apiAccessed}-${selectedLog.statusCode}`
    : undefined;

  const handleSearch = useCallback(async () => {
```

- [ ] **Step 4: Replace the outer JSX shell — swap `dashboard-shell__inner` grid for `dash-body`**

Find:
```tsx
  return (
    <div className="dashboard-shell">
      <div className="dashboard-shell__inner">
        <section className="ops-hero">
```

Replace with:
```tsx
  return (
    <div className="dashboard-shell">
      <div className="dash-body">
        <DashboardSidebar
          projectName={currentProject?.name}
          streamIsPaused={streamIsPaused}
          streamLockedByPagination={streamLockedByPagination}
          projectHealth={projectHealth}
          currentProject={currentProject}
          projectMode={projectMode}
          projectWarmupProgress={projectWarmupProgress}
          showAnomaliesOnly={showAnomaliesOnly}
          pendingCount={pendingCount}
          pendingThreatCount={pendingThreatCount}
          endpointInsights={endpointInsights}
          onToggleStreamPause={handleToggleStreamPause}
          onToggleAnomalies={() => setShowAnomaliesOnly(current => !current)}
          onStepPending={stepPending}
          onApplyPending={applyPending}
          onDiscardPending={discardPending}
        />
        <div className="dash-main">
        <section className="ops-hero" style={{ display: 'none' }}>
```

- [ ] **Step 5: Replace the hero section with a compact page header**

Find the entire `<section className="ops-hero">` block. It starts at:
```tsx
        <section className="ops-hero">
          <div>
            <div className="ops-breadcrumbs">
```
and ends at:
```tsx
        </section>
```
(closing tag after the `ops-hero__action` Export button, around line 564).

Replace the entire `<section className="ops-hero">...</section>` block with:
```tsx
        <div className="dash-page-header">
          <div>
            <div className="dash-breadcrumb">
              <span>Projects</span>
              <span className="dash-breadcrumb__sep">/</span>
              <span>{currentProject?.name || 'Security Dashboard'}</span>
            </div>
            <h1 className="dash-page-title">Security Dashboard</h1>
          </div>
          <div className="dash-header-meta">
            {projectId && <span className="ops-chip">Project ID: {projectId.slice(0, 8)}</span>}
            <span className="ops-chip">{projectMode}</span>
            {currentProject?.log_type && <span className="ops-chip">Log type: {currentProject.log_type}</span>}
            <span className="ops-chip">{lastUpdate ? lastUpdate.toLocaleTimeString() : 'N/A'}</span>
            <Button variant="secondary" size="md" onClick={handleExport} isLoading={exportLoading}>
              <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              Export
            </Button>
          </div>
        </div>
```

- [ ] **Step 6: Update KPI cards to use accent variant classes**

Find the `<section className="ops-kpi-grid">` block. Inside it, each `<MetricCard ... accent="..." />` needs an extra wrapper class. The `MetricCard` component uses `ops-kpi-card ops-kpi-card--${accent}` internally. We add the new top-accent classes by passing them via a new `className` prop on `MetricCard`.

First, update the `MetricCard` component definition (around line 120) to accept `className`:

Find:
```tsx
const MetricCard: React.FC<{
  label: string;
  value: string;
  accent: 'primary' | 'danger' | 'warning' | 'success' | 'muted';
  helper: string;
  icon: React.ReactNode;
}> = ({ label, value, accent, helper, icon }) => (
  <div className={cx('ops-kpi-card', `ops-kpi-card--${accent}`)}>
```

Replace with:
```tsx
const MetricCard: React.FC<{
  label: string;
  value: string;
  accent: 'primary' | 'danger' | 'warning' | 'success' | 'muted';
  topAccent?: 'blue' | 'red' | 'amber' | 'muted' | 'green';
  helper: string;
  icon: React.ReactNode;
}> = ({ label, value, accent, topAccent, helper, icon }) => (
  <div className={cx('ops-kpi-card', `ops-kpi-card--${accent}`, topAccent && `ops-kpi-card--${topAccent}`)}>
```

Then update each `<MetricCard>` call inside `<section className="ops-kpi-grid">`:
- Total Logs: add `topAccent="blue"`
- Threats: add `topAccent="red"`
- Incidents: add `topAccent="amber"`
- Parse Failures: add `topAccent="muted"`
- Detection Health: add `topAccent="green"`

- [ ] **Step 7: Replace the `ops-main-grid` section with a full-width chart**

Find:
```tsx
        <section className="ops-main-grid">
          <div className="ops-panel ops-panel--chart">
```

The entire `ops-main-grid` section goes from that line to its closing `</section>` tag (which comes after the `ops-panel--stack` div, around line 781). Replace the entire block with just the chart content directly as a panel:

```tsx
        <section className="ops-panel">
          <div className="ops-section-head">
            <div>
              <p className="ops-overline">Traffic analysis</p>
              <h2>Threat versus clean traffic</h2>
            </div>
            <div className="ops-inline-stats">
              <span className="ops-legend ops-legend--danger">Threats</span>
              <span className="ops-legend ops-legend--success">Clean</span>
            </div>
          </div>

          <div className="ops-chart" style={{ minHeight: '10rem' }}>
            {timelineBuckets.map(bucket => (
              <div key={bucket.label} className="ops-chart__column">
                <div className="ops-chart__bars">
                  <div
                    className="ops-chart__bar ops-chart__bar--danger"
                    style={{ height: `${Math.max(bucket.threats > 0 ? 12 : 0, (bucket.threats / chartPeak) * 100)}%` }}
                  />
                  <div
                    className="ops-chart__bar ops-chart__bar--success"
                    style={{ height: `${Math.max(bucket.clean > 0 ? 12 : 0, (bucket.clean / chartPeak) * 100)}%` }}
                  />
                </div>
                <div className="ops-chart__meta">
                  <span>{bucket.label}</span>
                  <span>{bucket.threats + bucket.clean}</span>
                </div>
              </div>
            ))}
          </div>

          <div className="ops-chart__footer">
            <div>
              <p className="ops-overline">Window</p>
              <strong>{formatCompactNumber(analysisDataset.length)}</strong>
              <span> logs in active window</span>
            </div>
            <div>
              <p className="ops-overline">Threat rate</p>
              <strong>{formatPercent(threatRate)}</strong>
              <span> across current slice</span>
            </div>
            <div>
              <p className="ops-overline">Clean</p>
              <strong>{formatPercent(liveCoverage)}</strong>
              <span> classified safe</span>
            </div>
          </div>
        </section>
```

- [ ] **Step 8: Wrap the logs table section + detail panel, and pass new props to LogsTable**

Find:
```tsx
        <section className="ops-panel">
          <div className="ops-section-head">
            <div>
              <p className="ops-overline">Live review</p>
```

Replace from that line down to the closing `</section>` tag of the logs panel (around line 1001):
```tsx
        <div className="logs-and-panel">
          <section className="ops-panel">
            <div className="ops-section-head">
              <div>
                <p className="ops-overline">Live review</p>
                <h2>Recent activity</h2>
                <p className="ops-muted-copy">Deep row details, correction actions, IP focus mode, and detector explainability remain available.</p>
              </div>
              <div className="ops-inline-stats">
                <span className="ops-chip">{totalResults.toLocaleString()} total results</span>
                <span className={cx('ops-chip', displayedInfectedCount > 0 && 'ops-chip--danger')}>
                  {displayedInfectedCount.toLocaleString()} flagged in current view
                </span>
              </div>
            </div>

            {isLoading && !browseResults && !searchResults ? (
              <LoadingSpinner text="Loading logs..." />
            ) : error ? (
              <div className="ops-error-state">
                <div className="ops-empty-state__icon">
                  <svg className="h-7 w-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <h3>Failed to load logs</h3>
                <p>{error}</p>
              </div>
            ) : (
              <LogsTable
                logs={displayLogs}
                sourceLogs={logs}
                focusedIp={focusedIp}
                onFocusIp={handleFocusIp}
                highlightTransformerTrail
                onCorrectLog={handleCorrectLog}
                canCorrectLogs={isPrivileged}
                onRowClick={handleRowClick}
                selectedLogId={selectedLogId}
              />
            )}
          </section>
          {selectedLog && (
            <LogDetailPanel
              log={selectedLog}
              onClose={() => setSelectedLog(null)}
            />
          )}
        </div>
```

- [ ] **Step 9: Close the `dash-main` div and `dash-body` div correctly**

The original closing tags were:
```tsx
      </div>  {/* dashboard-shell__inner */}
    </div>    {/* dashboard-shell */}
```

These need to become:
```tsx
        </div>  {/* dash-main */}
      </div>    {/* dash-body */}
    </div>      {/* dashboard-shell */}
```

Find the last two closing `</div>` tags at the bottom of the return statement (lines 1030–1031) and ensure the nesting is correct. The return now ends with:
```tsx
        </div> {/* logs-and-panel */}

        </div> {/* dash-main */}
      </div>   {/* dash-body */}
    </div>     {/* dashboard-shell */}
  );
```

- [ ] **Step 10: Verify build with no TypeScript errors**

```bash
cd frontend && npm run build 2>&1 | tail -30
```

Expected: build succeeds, no TS errors.

- [ ] **Step 11: Commit**

```bash
git add frontend/src/pages/DashboardPage.tsx
git commit -m "feat: revamp dashboard layout — sidebar, compact header, full-width chart, log detail panel"
```

---

## Task 6: Smoke-test in browser

- [ ] **Step 1: Start the dev server**

```bash
cd frontend && npm run dev
```

- [ ] **Step 2: Open http://localhost:3000, log in, navigate to the BarterEase project**

Verify:
- Left sidebar appears with project name, live status pill, protection state, stream controls, hot endpoints
- Page header shows breadcrumb + "Security Dashboard" title + chips + Export button
- KPI cards have colored top accent borders
- Traffic chart is full-width
- Clicking any log row in the table opens the `LogDetailPanel` on the right
- Panel shows Transformer, Isolation Forest, Rule-based sections with score bars
- Clicking ✕ closes the panel
- Clicking the same row again closes the panel
- ActionButtons (expand ▼, focus, correct) still work correctly and don't accidentally open the panel when clicked

- [ ] **Step 3: Final commit**

```bash
git add -A
git commit -m "chore: final smoke-test pass — dashboard revamp complete"
```
