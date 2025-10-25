import React from 'react';

const ModelLegend: React.FC = () => {
  return (
    <div className="glass-strong rounded-2xl border border-vt-primary/30 p-8 shadow-2xl animate-slide-up">
      <div className="flex items-center gap-3 mb-6">
        <div className="w-12 h-12 bg-gradient-to-br from-vt-primary to-vt-success rounded-xl flex items-center justify-center shadow-lg">
          <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </div>
        <div>
          <h3 className="text-2xl font-bold gradient-text">Ensemble Detection System</h3>
          <p className="text-sm text-vt-muted mt-1">Three-layer AI-powered threat analysis</p>
        </div>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Rule-Based */}
        <div className="glass rounded-xl p-6 border border-vt-primary/20 card-hover group">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 bg-gradient-to-br from-vt-primary/30 to-vt-primary/10 rounded-xl flex items-center justify-center flex-shrink-0 group-hover:scale-110 transition-transform duration-300">
              <svg className="w-6 h-6 text-vt-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <div className="flex-1">
              <h4 className="text-base font-bold text-vt-light mb-2">Rule-Based Detection</h4>
              <p className="text-sm text-vt-muted leading-relaxed mb-3">
                Pattern matching for known attack signatures using predefined rules and heuristics.
              </p>
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-xs text-vt-muted">
                  <svg className="w-4 h-4 text-vt-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  High precision for known threats
                </div>
                <div className="flex items-center gap-2 text-xs text-vt-muted">
                  <svg className="w-4 h-4 text-vt-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  Fast real-time detection
                </div>
              </div>
              <div className="mt-4 pt-4 border-t border-vt-muted/20">
                <span className="text-xs font-semibold text-vt-muted mb-2 block">Detects:</span>
                <div className="flex flex-wrap gap-1.5">
                  <span className="px-2 py-1 bg-vt-error/20 text-vt-error rounded-lg text-xs font-semibold border border-vt-error/30">
                    SQL Injection
                  </span>
                  <span className="px-2 py-1 bg-vt-error/20 text-vt-error rounded-lg text-xs font-semibold border border-vt-error/30">
                    XSS
                  </span>
                  <span className="px-2 py-1 bg-vt-error/20 text-vt-error rounded-lg text-xs font-semibold border border-vt-error/30">
                    Path Traversal
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Isolation Forest */}
        <div className="glass rounded-xl p-6 border border-vt-warning/20 card-hover group">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 bg-gradient-to-br from-vt-warning/30 to-vt-warning/10 rounded-xl flex items-center justify-center flex-shrink-0 group-hover:scale-110 transition-transform duration-300">
              <svg className="w-6 h-6 text-vt-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
            </div>
            <div className="flex-1">
              <h4 className="text-base font-bold text-vt-light mb-2">Isolation Forest</h4>
              <p className="text-sm text-vt-muted leading-relaxed mb-3">
                Statistical anomaly detection analyzing request patterns without prior knowledge of attacks.
              </p>
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-xs text-vt-muted">
                  <svg className="w-4 h-4 text-vt-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  Detects unknown threats
                </div>
                <div className="flex items-center gap-2 text-xs text-vt-muted">
                  <svg className="w-4 h-4 text-vt-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  Unsupervised learning
                </div>
              </div>
              <div className="mt-4 pt-4 border-t border-vt-muted/20">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-vt-muted">Score Range:</span>
                  <span className="text-xs font-mono text-vt-warning font-semibold">0.0 → 5.0+</span>
                </div>
                <div className="w-full bg-vt-muted/20 rounded-full h-2 mt-2 overflow-hidden border border-vt-muted/30">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: '75%',
                      background: 'linear-gradient(90deg, #10B981 0%, #F59E0B 50%, #e94560 100%)',
                    }}
                  ></div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Transformer */}
        <div className="glass rounded-xl p-6 border border-vt-success/20 card-hover group">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 bg-gradient-to-br from-vt-success/30 to-vt-success/10 rounded-xl flex items-center justify-center flex-shrink-0 group-hover:scale-110 transition-transform duration-300">
              <svg className="w-6 h-6 text-vt-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
            <div className="flex-1">
              <h4 className="text-base font-bold text-vt-light mb-2">Transformer Network</h4>
              <p className="text-sm text-vt-muted leading-relaxed mb-3">
                Deep learning model using attention mechanisms to identify sequence-based anomalies.
              </p>
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-xs text-vt-muted">
                  <svg className="w-4 h-4 text-vt-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  Context-aware detection
                </div>
                <div className="flex items-center gap-2 text-xs text-vt-muted">
                  <svg className="w-4 h-4 text-vt-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  Learns normal patterns
                </div>
              </div>
              <div className="mt-4 pt-4 border-t border-vt-muted/20">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-vt-muted">NLL Threshold:</span>
                  <span className="text-xs font-mono text-vt-success font-semibold">6.5</span>
                </div>
                <p className="text-xs text-vt-muted mt-1">
                  Higher scores indicate anomalous sequences
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Ensemble Decision */}
      <div className="mt-6 glass-strong rounded-xl p-6 border border-vt-primary/40 bg-gradient-to-r from-vt-primary/10 to-transparent">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 bg-gradient-to-br from-vt-primary to-vt-success rounded-xl flex items-center justify-center flex-shrink-0 shadow-lg">
            <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 5a1 1 0 011-1h4a1 1 0 011 1v7a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM14 5a1 1 0 011-1h4a1 1 0 011 1v7a1 1 0 01-1 1h-4a1 1 0 01-1-1V5zM4 16a1 1 0 011-1h4a1 1 0 011 1v3a1 1 0 01-1 1H5a1 1 0 01-1-1v-3zM14 16a1 1 0 011-1h4a1 1 0 011 1v3a1 1 0 01-1 1h-4a1 1 0 01-1-1v-3z" />
            </svg>
          </div>
          <div className="flex-1">
            <h4 className="text-lg font-bold text-vt-light mb-2">Ensemble Voting System</h4>
            <p className="text-sm text-vt-muted mb-4">
              Combines all three models using weighted voting for maximum accuracy. Each model votes (0 or 1), weighted by importance.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="glass rounded-lg p-4 border border-vt-primary/30">
                <h5 className="text-xs font-semibold text-vt-primary mb-2 uppercase tracking-wide">Formula</h5>
                <div className="bg-vt-blue/40 rounded-lg p-3 font-mono text-sm text-vt-light border border-vt-primary/20">
                  Score = (Rule×0.3 + ISO×0.6 + Trans×0.7) / 1.6
                </div>
              </div>
              <div className="glass rounded-lg p-4 border border-vt-primary/30">
                <h5 className="text-xs font-semibold text-vt-primary mb-2 uppercase tracking-wide">Decision</h5>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-vt-muted">Default Threshold:</span>
                    <span className="font-mono font-semibold text-vt-light">50%</span>
                  </div>
                  <div className="w-full bg-vt-muted/20 rounded-full h-2 overflow-hidden border border-vt-muted/30">
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: '50%',
                        background: 'linear-gradient(90deg, #7B9EFF 0%, #0ef6cc 100%)',
                      }}
                    ></div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Usage Info */}
      <div className="mt-6 glass rounded-xl p-5 border border-vt-primary/20 bg-vt-primary/5">
        <div className="flex items-start gap-3">
          <svg className="w-6 h-6 text-vt-primary flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div>
            <h5 className="text-sm font-bold text-vt-light mb-2">Quick Guide</h5>
            <ul className="text-sm text-vt-muted space-y-1.5">
              <li className="flex items-start gap-2">
                <span className="text-vt-primary mt-1">•</span>
                <span>Click the <strong className="text-vt-light">▼</strong> button in any log row to view detailed model scores</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-vt-primary mt-1">•</span>
                <span>Adjust detection sensitivity using <strong className="text-vt-light">⚙️ Threshold Settings</strong></span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-vt-primary mt-1">•</span>
                <span>Higher thresholds reduce false positives, lower thresholds catch more threats</span>
              </li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ModelLegend;
