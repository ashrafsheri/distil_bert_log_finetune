import React from 'react';
import { LogEntry } from '../services/logService';

interface LogDetailPanelProps {
  log: LogEntry;
  onClose: () => void;
}

const clampPercent = (value: number): number => Math.max(0, Math.min(100, value));

const formatScore = (value: number | null | undefined, digits = 3): string => {
  if (typeof value !== 'number' || Number.isNaN(value)) return 'N/A';
  return value.toFixed(digits);
};

const verdictClass = (isAnomaly: boolean): string =>
  isAnomaly
    ? 'log-detail-model__badge log-detail-model__badge--anomaly'
    : 'log-detail-model__badge log-detail-model__badge--clean';

const LogDetailPanel: React.FC<LogDetailPanelProps> = ({ log, onClose }) => {
  const ruleBased = log.anomaly_details?.rule_based;
  const isolationForest = log.anomaly_details?.isolation_forest;
  const transformer = log.anomaly_details?.transformer;

  const transformerIsAnomaly = transformer?.is_anomaly === 1;
  const isolationIsAnomaly = isolationForest?.is_anomaly === 1;
  const ruleIsAnomaly = Boolean(ruleBased?.is_attack);
  const isWarmupTeacher = log.detectorPhase === 'warmup' && log.modelType === 'teacher';
  const transformerSuppressed = transformer?.status === 'insufficient_signal';
  const transformerErrored = transformer?.status === 'error';

  const transformerFill = transformer?.threshold && typeof transformer.score === 'number'
    ? clampPercent((transformer.score / transformer.threshold) * 100)
    : clampPercent((transformer?.score || 0) * 10);
  const isolationFill = clampPercent((isolationForest?.score || 0) * 20);
  const ruleFill = clampPercent((ruleBased?.confidence || 0) * 100);

  const transformerScoreLabel = transformerSuppressed
    ? 'Suppressed'
    : transformerErrored
      ? 'Unavailable'
      : formatScore(transformer?.score);

  const isolationDetail = isolationForest?.status || log.incidentReason || 'Evaluated against current baseline.';
  const ruleDetail = ruleBased?.attack_types?.length
    ? `Matched rules: ${ruleBased.attack_types.join(', ')}`
    : log.topContributingSignals?.length
      ? `Signals: ${log.topContributingSignals.join(', ')}`
      : 'No rule signature attached to this event.';

  return (
    <aside className="log-detail-panel">
      <div className="log-detail-panel__header">
        <div>
          <div className="log-detail-panel__eyebrow">Selected event</div>
          <h3 className="log-detail-panel__title">Log detail</h3>
        </div>
        <button type="button" onClick={onClose} className="log-detail-panel__close" aria-label="Close log detail panel">
          <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <div className="log-detail-panel__route">
        <span>{log.ipAddress}</span>
        <span aria-hidden="true">→</span>
        <span>{log.apiAccessed}</span>
      </div>

      <div className="log-detail-panel__meta">
        <span>{log.eventTime || log.timestamp}</span>
        <span>{log.statusCode}</span>
        {log.incidentId && <span>{log.incidentId}</span>}
      </div>

      <div className="log-detail-panel__divider" />

      {/* Transformer */}
      <div className="log-detail-model">
        <div className="log-detail-model__head">
          <span className="log-detail-model__name">Transformer</span>
          <span className={verdictClass(transformerIsAnomaly)}>
            {transformerIsAnomaly ? 'Anomaly' : 'Clean'}
          </span>
        </div>

        <div className="log-detail-model__score-row">
          <span>{isWarmupTeacher ? 'Warmup score' : 'NLL score'}</span>
          <strong>{transformerScoreLabel}</strong>
        </div>

        {transformer?.threshold && (
          <div className="log-detail-model__score-row">
            <span>Threshold</span>
            <strong>{formatScore(transformer.threshold)}</strong>
          </div>
        )}

        <div className="log-detail-model__bar">
          <div
            className={`log-detail-model__fill ${transformerIsAnomaly ? 'log-detail-model__fill--anomaly' : 'log-detail-model__fill--clean'}`}
            style={{ width: (transformerSuppressed || transformerErrored) ? '0%' : `${transformerFill}%` }}
          />
        </div>

        {(transformer?.sequence_length || transformer?.context) && (
          <>
            <div className="log-detail-model__stat-divider" />
            {transformer.sequence_length != null && (
              <div className="log-detail-model__stat-row">
                <span>Sequence length</span>
                <strong>{transformer.sequence_length}</strong>
              </div>
            )}
            {transformer.context && (
              <div className="log-detail-model__stat-row">
                <span>Context</span>
                <strong>{transformer.context}</strong>
              </div>
            )}
          </>
        )}

        {typeof log.unknownTemplateRatio === 'number' && (
          <>
            <div className="log-detail-model__stat-divider" />
            <div className="log-detail-model__stat-row">
              <span>Unknown template ratio</span>
              <strong style={{ color: log.unknownTemplateRatio >= 0.5 ? '#f4c15d' : undefined }}>
                {(log.unknownTemplateRatio * 100).toFixed(1)}%
              </strong>
            </div>
          </>
        )}

        {transformer?.status && (
          <div className="log-detail-model__stat-row" style={{ marginTop: '0.4rem' }}>
            <span>Status</span>
            <strong>{transformer.status}</strong>
          </div>
        )}

        {isWarmupTeacher && (
          <p className="log-detail-model__note log-detail-model__note--info">
            Warmup teacher score — treat as low-confidence until a student model is trained.
          </p>
        )}
        {transformerSuppressed && (
          <p className="log-detail-model__note log-detail-model__note--warning">
            Suppressed: sequence dominated by unseen templates.
          </p>
        )}
        {transformerErrored && (
          <p className="log-detail-model__note log-detail-model__note--error">
            {transformer?.error || 'Transformer scoring failed for this event.'}
          </p>
        )}
        {!transformerSuppressed && !transformerErrored && !isWarmupTeacher && (
          <p className="log-detail-model__detail">
            {log.normalizedTemplate || log.decisionReason || 'Scored against the active sequence model.'}
          </p>
        )}
      </div>

      {/* Isolation Forest */}
      <div className="log-detail-model">
        <div className="log-detail-model__head">
          <span className="log-detail-model__name">Isolation Forest</span>
          <span className={verdictClass(isolationIsAnomaly)}>
            {isolationIsAnomaly ? 'Anomaly' : 'Clean'}
          </span>
        </div>
        <div className="log-detail-model__score-row">
          <span>Score</span>
          <strong>{formatScore(isolationForest?.score)}</strong>
        </div>
        <div className="log-detail-model__bar">
          <div
            className={`log-detail-model__fill ${isolationIsAnomaly ? 'log-detail-model__fill--anomaly' : 'log-detail-model__fill--clean'}`}
            style={{ width: `${isolationFill}%` }}
          />
        </div>
        <p className="log-detail-model__detail">{isolationDetail}</p>
      </div>

      {/* Rule-Based */}
      <div className="log-detail-model">
        <div className="log-detail-model__head">
          <span className="log-detail-model__name">Rule-Based</span>
          <span className={verdictClass(ruleIsAnomaly)}>
            {ruleIsAnomaly ? 'Anomaly' : 'Clean'}
          </span>
        </div>
        <div className="log-detail-model__score-row">
          <span>Confidence</span>
          <strong>{`${((ruleBased?.confidence || 0) * 100).toFixed(1)}%`}</strong>
        </div>
        <div className="log-detail-model__bar">
          <div
            className={`log-detail-model__fill ${ruleIsAnomaly ? 'log-detail-model__fill--anomaly' : 'log-detail-model__fill--clean'}`}
            style={{ width: `${ruleFill}%` }}
          />
        </div>
        <p className="log-detail-model__detail">{ruleDetail}</p>
      </div>
    </aside>
  );
};

export default LogDetailPanel;
