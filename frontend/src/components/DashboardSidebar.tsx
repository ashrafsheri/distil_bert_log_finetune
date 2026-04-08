import React from 'react';
import { ProjectHealthSummary, ProjectSummary } from '../services/projectService';

type EndpointInsight = {
  endpoint: string;
  total: number;
  threats: number;
};

interface DashboardSidebarProps {
  currentProject: ProjectSummary | null;
  projectHealth: ProjectHealthSummary | null;
  projectMode: string;
  projectWarmupProgress: number;
  streamIsPaused: boolean;
  streamLockedByPagination: boolean;
  showAnomaliesOnly: boolean;
  pendingCount: number;
  pendingThreatCount: number;
  endpointInsights: EndpointInsight[];
  onToggleStreamPause: () => void;
  onToggleAnomaliesOnly: () => void;
  onStepPending: () => void;
  onApplyPending: () => void;
  onDiscardPending: () => void;
}

const DashboardSidebar: React.FC<DashboardSidebarProps> = ({
  currentProject,
  projectHealth,
  projectMode,
  projectWarmupProgress,
  streamIsPaused,
  streamLockedByPagination,
  showAnomaliesOnly,
  pendingCount,
  pendingThreatCount,
  endpointInsights,
  onToggleStreamPause,
  onToggleAnomaliesOnly,
  onStepPending,
  onApplyPending,
  onDiscardPending,
}) => {
  return (
    <aside className="dashboard-sidebar">
      <div className="sidebar-project">
        <div className="sidebar-project__icon" aria-hidden="true">
          <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
            />
          </svg>
        </div>
        <div className="min-w-0">
          <div className="sidebar-project__name">{currentProject?.name || 'Security Dashboard'}</div>
          <div className="sidebar-project__sub">Active project</div>
        </div>
      </div>

      <div className={`sidebar-status-pill ${streamIsPaused ? 'sidebar-status-pill--paused' : 'sidebar-status-pill--live'}`}>
        <span className={`sidebar-status-dot ${streamIsPaused ? 'sidebar-status-dot--paused' : 'sidebar-status-dot--live'}`} />
        {streamIsPaused ? 'Stream paused' : 'Live stream'}
      </div>

      <div className="sidebar-divider" />

      <section>
        <div className="sidebar-section-label">Protection</div>
        <div className="sidebar-stat-row">
          <span className="sidebar-stat-row__label">Detection mode</span>
          <span className="sidebar-stat-row__value">{projectMode}</span>
        </div>
        <div className="sidebar-stat-row">
          <span className="sidebar-stat-row__label">Warmup</span>
          <span className="sidebar-stat-row__value sidebar-stat-row__value--blue">{projectHealth ? `${projectWarmupProgress.toFixed(0)}%` : 'N/A'}</span>
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
          <span className="sidebar-stat-row__value">{projectHealth?.traffic_profile || currentProject?.traffic_profile || 'standard'}</span>
        </div>
      </section>

      <div className="sidebar-divider" />

      <section>
        <div className="sidebar-section-label">Stream Controls</div>
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
          onClick={onToggleAnomaliesOnly}
          className={`sidebar-ctrl-btn ${showAnomaliesOnly ? 'sidebar-ctrl-btn--warning' : 'sidebar-ctrl-btn--ghost'}`}
        >
          {showAnomaliesOnly ? 'Showing anomalies only' : 'Show anomalies only'}
        </button>
        <div className="sidebar-ctrl-grid">
          <button type="button" onClick={onStepPending} disabled={pendingCount === 0} className="sidebar-ctrl-btn sidebar-ctrl-btn--ghost">
            Step queue
          </button>
          <button type="button" onClick={onApplyPending} disabled={pendingCount === 0} className="sidebar-ctrl-btn sidebar-ctrl-btn--resume">
            Apply pending
          </button>
        </div>
        <button type="button" onClick={onDiscardPending} disabled={pendingCount === 0} className="sidebar-ctrl-btn sidebar-ctrl-btn--ghost">
          Clear queue
        </button>
        <div className="sidebar-queue-card">
          <div>
            <div className="sidebar-queue-card__label">Pending events</div>
            <div className="sidebar-queue-card__value">{pendingCount.toLocaleString()}</div>
          </div>
          <div>
            <div className="sidebar-queue-card__label">Threats in queue</div>
            <div className="sidebar-queue-card__value sidebar-queue-card__value--warning">{pendingThreatCount.toLocaleString()}</div>
          </div>
        </div>
        {streamLockedByPagination && (
          <p className="sidebar-note">Realtime streaming stays locked while you review older pages.</p>
        )}
      </section>

      <div className="sidebar-divider" />

      <section>
        <div className="sidebar-section-label">Hot Endpoints</div>
        <div className="sidebar-endpoint-list">
          {endpointInsights.length === 0 ? (
            <div className="sidebar-empty">No endpoint activity for the current slice.</div>
          ) : (
            endpointInsights.map((item) => (
              <div key={item.endpoint} className="sidebar-endpoint-item">
                <div className="sidebar-endpoint-item__path" title={item.endpoint}>
                  {item.endpoint}
                </div>
                <div className="sidebar-endpoint-item__value">{item.threats.toLocaleString()}</div>
              </div>
            ))
          )}
        </div>
      </section>
    </aside>
  );
};

export default DashboardSidebar;
