import React from 'react';

const ModelLegend: React.FC = () => {
  return (
    <div className="bg-vt-blue/30 backdrop-blur-sm rounded-xl border border-vt-muted/20 p-6">
      <h3 className="text-lg font-semibold text-vt-light mb-4">Ensemble Model Guide</h3>
      
      <div className="space-y-4">
        {/* Rule-Based */}
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 bg-vt-primary/20 rounded-lg flex items-center justify-center flex-shrink-0">
            <svg className="w-5 h-5 text-vt-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <div>
            <h4 className="text-sm font-semibold text-vt-light">Rule-Based Detection</h4>
            <p className="text-xs text-vt-muted mt-1">
              Pattern matching for known attack signatures (SQL injection, XSS, path traversal, command injection).
              High precision but limited to known patterns.
            </p>
            <div className="mt-2 flex flex-wrap gap-1">
              <span className="px-2 py-0.5 bg-vt-error/20 text-vt-error rounded text-xs">SQL Injection</span>
              <span className="px-2 py-0.5 bg-vt-error/20 text-vt-error rounded text-xs">XSS</span>
              <span className="px-2 py-0.5 bg-vt-error/20 text-vt-error rounded text-xs">Path Traversal</span>
            </div>
          </div>
        </div>

        {/* Isolation Forest */}
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 bg-vt-warning/20 rounded-lg flex items-center justify-center flex-shrink-0">
            <svg className="w-5 h-5 text-vt-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
          </div>
          <div>
            <h4 className="text-sm font-semibold text-vt-light">Isolation Forest</h4>
            <p className="text-xs text-vt-muted mt-1">
              Statistical anomaly detection based on request features (rate, unique paths, error patterns).
              Detects unusual behavior without knowing specific attacks.
            </p>
            <p className="text-xs text-vt-muted mt-1">
              <span className="text-vt-warning">Score Range:</span> 0.0 (normal) to 5.0+ (highly anomalous)
            </p>
          </div>
        </div>

        {/* Transformer */}
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 bg-vt-success/20 rounded-lg flex items-center justify-center flex-shrink-0">
            <svg className="w-5 h-5 text-vt-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </div>
          <div>
            <h4 className="text-sm font-semibold text-vt-light">Transformer (Deep Learning)</h4>
            <p className="text-xs text-vt-muted mt-1">
              Sequence-based anomaly detection using attention mechanisms. Learns normal request patterns
              and flags deviations. Uses Negative Log-Likelihood (NLL) scoring.
            </p>
            <p className="text-xs text-vt-muted mt-1">
              <span className="text-vt-success">NLL Range:</span> 0.0-6.5 (normal) | 6.5+ (anomalous)
            </p>
          </div>
        </div>

        {/* Ensemble */}
        <div className="flex items-start gap-3 pt-3 border-t border-vt-muted/20">
          <div className="w-10 h-10 bg-vt-primary/20 rounded-lg flex items-center justify-center flex-shrink-0">
            <svg className="w-5 h-5 text-vt-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 5a1 1 0 011-1h4a1 1 0 011 1v7a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM14 5a1 1 0 011-1h4a1 1 0 011 1v7a1 1 0 01-1 1h-4a1 1 0 01-1-1V5zM4 16a1 1 0 011-1h4a1 1 0 011 1v3a1 1 0 01-1 1H5a1 1 0 01-1-1v-3zM14 16a1 1 0 011-1h4a1 1 0 011 1v3a1 1 0 01-1 1h-4a1 1 0 01-1-1v-3z" />
            </svg>
          </div>
          <div>
            <h4 className="text-sm font-semibold text-vt-light">Ensemble Decision</h4>
            <p className="text-xs text-vt-muted mt-1">
              Combines all three models using weighted voting. Each model votes (0 or 1), weighted by importance,
              producing a final score from 0% to 100%.
            </p>
            <div className="mt-2 bg-vt-blue/40 rounded p-2 text-xs font-mono text-vt-light">
              Score = (Rule×0.3 + ISO×0.6 + Trans×0.7) / 1.6
            </div>
            <p className="text-xs text-vt-muted mt-1">
              <span className="text-vt-primary">Threshold:</span> Default 50% (configurable)
            </p>
          </div>
        </div>
      </div>

      <div className="mt-6 p-4 bg-vt-blue/50 rounded-lg border border-vt-primary/30">
        <div className="flex items-start gap-2">
          <svg className="w-5 h-5 text-vt-primary flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div>
            <h5 className="text-sm font-semibold text-vt-light">How to Use</h5>
            <ul className="text-xs text-vt-muted mt-1 space-y-1 list-disc list-inside">
              <li>Click the ▼ button in the Details column to view model scores</li>
              <li>Use Threshold Settings (⚙️) to adjust detection sensitivity</li>
              <li>Higher threshold = fewer false alarms, but may miss attacks</li>
              <li>Lower threshold = catch more threats, but more false positives</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ModelLegend;
