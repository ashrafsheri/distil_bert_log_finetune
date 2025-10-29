import React from 'react';

interface StreamControlsProps {
  isPaused: boolean;
  pendingCount: number;
  pendingThreatCount: number;
  onTogglePause: () => void;
  onStep: () => void;
  onApplyAll: () => void;
  onDiscard: () => void;
  showAnomaliesOnly: boolean;
  onToggleAnomalies: () => void;
  lastUpdate?: Date | null;
}

const StreamControls: React.FC<StreamControlsProps> = ({
  isPaused,
  pendingCount,
  pendingThreatCount,
  onTogglePause,
  onStep,
  onApplyAll,
  onDiscard,
  showAnomaliesOnly,
  onToggleAnomalies,
  lastUpdate,
}) => {
  const hasPending = pendingCount > 0;
  const lastUpdatedLabel = lastUpdate
    ? lastUpdate.toLocaleTimeString()
    : '—';

  return (
    <div className="glass px-4 py-4 rounded-2xl border border-vt-primary/20 grid gap-4 xl:flex xl:items-center xl:justify-between">
      <div className="flex items-center gap-3 flex-wrap md:flex-nowrap">
        <button
          onClick={onTogglePause}
          className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold shadow-sm transition-all duration-200 w-full sm:w-auto justify-center ${
            isPaused
              ? 'bg-vt-error/20 text-vt-error border border-vt-error/30 hover:bg-vt-error/30'
              : 'bg-vt-primary/20 text-vt-primary border border-vt-primary/30 hover:bg-vt-primary/30'
          }`}
        >
          {isPaused ? (
            <>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 3l14 9-14 9V3z" />
              </svg>
              Resume Stream
            </>
          ) : (
            <>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 9v6m4-6v6M5 5h14v14H5z" />
              </svg>
              Pause Stream
            </>
          )}
        </button>

        <button
          onClick={onToggleAnomalies}
          className={`inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-semibold transition-all duration-200 w-full sm:w-auto justify-center ${
            showAnomaliesOnly
              ? 'bg-vt-warning/20 text-vt-warning border border-vt-warning/40'
              : 'bg-vt-muted/10 text-vt-light border border-transparent'
          }`}
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5-1a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          {showAnomaliesOnly ? 'Showing Anomalies' : 'Show Anomalies Only'}
        </button>
      </div>

      <div className="flex items-center gap-3 flex-wrap text-xs sm:text-sm">
        <div
          className={`inline-flex items-center gap-2 px-3 py-2 rounded-lg border min-w-[220px] ${
            hasPending ? 'border-vt-warning/40 bg-vt-warning/10 text-vt-warning' : 'border-transparent bg-vt-surface text-vt-muted'
          }`}
        >
          <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8m-9 12V10" />
          </svg>
          <div className="flex items-center gap-2">
            <span className="font-semibold">{pendingCount}</span>
            <span className="text-vt-muted">queued</span>
            {pendingThreatCount > 0 && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-vt-error/20 text-vt-error rounded-full">
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                {pendingThreatCount} threats
              </span>
            )}
          </div>
        </div>

        <div className="inline-flex items-center gap-2">
          <button
            onClick={onStep}
            disabled={!hasPending}
            className="px-3 py-2 rounded-lg border border-vt-primary/30 text-vt-primary hover:bg-vt-primary/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-200 w-full sm:w-auto"
          >
            Step
          </button>
          <button
            onClick={onApplyAll}
            disabled={!hasPending}
            className="px-3 py-2 rounded-lg border border-vt-success/40 text-vt-success hover:bg-vt-success/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-200 w-full sm:w-auto"
          >
            Apply All
          </button>
          <button
            onClick={onDiscard}
            disabled={!hasPending}
            className="px-3 py-2 rounded-lg border border-vt-error/40 text-vt-error hover:bg-vt-error/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-200 w-full sm:w-auto"
          >
            Clear
          </button>
        </div>

        <div className="hidden sm:flex items-center gap-2 text-vt-muted">
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span>Last update:</span>
          <span className="font-mono text-vt-light">{lastUpdatedLabel}</span>
        </div>
      </div>
    </div>
  );
};

export default StreamControls;
