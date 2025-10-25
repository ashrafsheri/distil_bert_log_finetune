import React, { useState } from 'react';
import { getStatusIcon } from '../utils/helpers';

export interface AnomalyDetails {
  rule_based?: {
    is_attack: boolean;
    attack_types?: string[];
    confidence: number;
  };
  isolation_forest?: {
    is_anomaly: number;
    score: number;
  };
  transformer?: {
    is_anomaly: number;
    score: number;
  };
  ensemble?: {
    score: number;
    votes?: {
      rule: number;
      iso: number;
      transformer: number;
    };
    weights?: {
      rule: number;
      iso: number;
      transformer: number;
    };
  };
}

export interface LogEntry {
  timestamp: string;
  ipAddress: string;
  apiAccessed: string;
  statusCode: number;
  infected: boolean;
  anomaly_score?: number;
  anomaly_details?: AnomalyDetails;
}

interface LogsTableProps {
  logs: LogEntry[];
}

const LogsTable: React.FC<LogsTableProps> = ({ logs }) => {
  const [expandedRow, setExpandedRow] = useState<number | null>(null);

  const toggleRow = (index: number) => {
    setExpandedRow(expandedRow === index ? null : index);
  };

  if (logs.length === 0) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-center animate-fade-in">
          <div className="w-20 h-20 bg-gradient-to-br from-vt-muted/20 to-vt-muted/10 rounded-2xl flex items-center justify-center mx-auto mb-6 shadow-lg">
            <svg className="w-10 h-10 text-vt-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          </div>
          <p className="text-vt-light font-semibold text-lg mb-2">No logs available yet</p>
          <p className="text-vt-muted text-sm">Waiting for log entries to be processed...</p>
          <div className="mt-6 flex items-center justify-center gap-2">
            <div className="w-2 h-2 bg-vt-primary rounded-full animate-pulse"></div>
            <div className="w-2 h-2 bg-vt-primary rounded-full animate-pulse" style={{ animationDelay: '0.2s' }}></div>
            <div className="w-2 h-2 bg-vt-primary rounded-full animate-pulse" style={{ animationDelay: '0.4s' }}></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead className="bg-vt-blue/30 sticky top-0">
          <tr className="border-b border-vt-primary/20">
            <th className="px-6 py-4 text-left text-xs font-semibold text-vt-primary uppercase tracking-wider">
              Timestamp
            </th>
            <th className="px-6 py-4 text-left text-xs font-semibold text-vt-primary uppercase tracking-wider">
              IP Address
            </th>
            <th className="px-6 py-4 text-left text-xs font-semibold text-vt-primary uppercase tracking-wider">
              API Endpoint
            </th>
            <th className="px-6 py-4 text-left text-xs font-semibold text-vt-primary uppercase tracking-wider">
              Status
            </th>
            <th className="px-6 py-4 text-left text-xs font-semibold text-vt-primary uppercase tracking-wider">
              Risk Score
            </th>
            <th className="px-6 py-4 text-left text-xs font-semibold text-vt-primary uppercase tracking-wider">
              Threat
            </th>
            <th className="px-6 py-4 text-left text-xs font-semibold text-vt-primary uppercase tracking-wider">
              Actions
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-vt-muted/10">
          {logs.map((log, index) => (
            <React.Fragment key={index}>
              <tr
                className={`group hover:bg-vt-primary/5 transition-all duration-200 ${
                  log.infected ? 'bg-vt-error/10 border-l-4 border-l-vt-error' : ''
                } ${expandedRow === index ? 'bg-vt-primary/5' : ''}`}
              >
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex items-center gap-2">
                    <svg className="w-4 h-4 text-vt-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <div 
                      className="text-sm font-mono"
                      style={{ color: log.infected ? '#e94560' : '#f5f5f5' }}
                    >
                      {log.timestamp}
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex items-center gap-2">
                    <svg className="w-4 h-4 text-vt-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                    </svg>
                    <div 
                      className="text-sm font-mono px-2 py-1 rounded bg-vt-blue/30"
                      style={{ color: log.infected ? '#e94560' : '#f5f5f5' }}
                    >
                      {log.ipAddress}
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <div 
                    className="text-sm font-mono truncate max-w-xs group-hover:max-w-none group-hover:whitespace-normal transition-all"
                    style={{ color: log.infected ? '#e94560' : '#A0A8C0' }}
                    title={log.apiAccessed}
                  >
                    {log.apiAccessed}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span 
                    className="inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold"
                    style={{ 
                      backgroundColor: log.infected ? 'rgba(233, 69, 96, 0.15)' : 'rgba(123, 158, 255, 0.15)',
                      color: log.infected ? '#e94560' : (log.statusCode >= 200 && log.statusCode < 300 ? '#10B981' : log.statusCode >= 400 ? '#e94560' : '#A0A8C0'),
                      border: `1px solid ${log.infected ? 'rgba(233, 69, 96, 0.3)' : 'rgba(123, 158, 255, 0.3)'}`
                    }}
                  >
                    {getStatusIcon(log.statusCode)}
                    <span className="ml-1.5">{log.statusCode}</span>
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex items-center gap-3">
                    <div className="flex-1 bg-vt-muted/20 rounded-full h-2.5 overflow-hidden border border-vt-muted/30">
                      <div
                        className="h-full rounded-full transition-all duration-500 shadow-sm"
                        style={{
                          width: `${Math.min((log.anomaly_score || 0) * 100, 100)}%`,
                          background: log.infected 
                            ? 'linear-gradient(90deg, #e94560 0%, #c73752 100%)' 
                            : 'linear-gradient(90deg, #10B981 0%, #059669 100%)',
                        }}
                      ></div>
                    </div>
                    <span 
                      className="text-xs font-mono font-semibold min-w-[3.5rem] text-right px-2 py-1 rounded bg-vt-blue/30"
                      style={{ color: log.infected ? '#e94560' : '#10B981' }}
                    >
                      {((log.anomaly_score || 0) * 100).toFixed(1)}%
                    </span>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  {log.infected ? (
                    <span 
                      className="inline-flex items-center px-3 py-1.5 rounded-lg text-xs font-semibold shadow-sm"
                      style={{ 
                        backgroundColor: 'rgba(233, 69, 96, 0.15)', 
                        color: '#e94560',
                        border: '1px solid rgba(233, 69, 96, 0.3)'
                      }}
                    >
                      <svg className="w-4 h-4 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-1.964-1.333-2.732 0L3.732 16c-.77 1.333.192 3 1.732 3z" />
                      </svg>
                      Threat Detected
                    </span>
                  ) : (
                    <span 
                      className="inline-flex items-center px-3 py-1.5 rounded-lg text-xs font-semibold shadow-sm"
                      style={{ 
                        backgroundColor: 'rgba(16, 185, 129, 0.15)', 
                        color: '#10B981',
                        border: '1px solid rgba(16, 185, 129, 0.3)'
                      }}
                    >
                      <svg className="w-4 h-4 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                      </svg>
                      Safe
                    </span>
                  )}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <button
                    onClick={() => toggleRow(index)}
                    className="p-2 text-vt-primary hover:text-vt-primary/80 hover:bg-vt-primary/10 rounded-lg transition-all duration-200"
                    title={expandedRow === index ? "Hide details" : "Show details"}
                  >
                    {expandedRow === index ? (
                      <svg className="w-5 h-5 transform rotate-180 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                      </svg>
                    ) : (
                      <svg className="w-5 h-5 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                      </svg>
                    )}
                  </button>
                </td>
              </tr>
              {expandedRow === index && log.anomaly_details && (
                <tr className="bg-gradient-to-r from-vt-blue/20 to-transparent animate-slide-down">
                  <td colSpan={7} className="px-6 py-6">
                    <div className="space-y-6">
                      <div className="flex items-center gap-3 mb-4">
                        <div className="w-1 h-6 bg-gradient-to-b from-vt-primary to-vt-success rounded-full"></div>
                        <h4 className="text-lg font-bold text-vt-light">Ensemble Model Analysis</h4>
                      </div>
                      
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                        {/* Rule-Based Detection */}
                        <div className="glass-strong rounded-xl p-5 border border-vt-primary/30 card-hover">
                          <div className="flex items-center justify-between mb-4">
                            <div className="flex items-center gap-2">
                              <div className="w-8 h-8 bg-gradient-to-br from-vt-primary/30 to-vt-primary/10 rounded-lg flex items-center justify-center">
                                <svg className="w-4 h-4 text-vt-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                              </div>
                              <h5 className="text-xs font-bold text-vt-light uppercase tracking-wide">Rule-Based</h5>
                            </div>
                            <span className={`px-2.5 py-1 rounded-lg text-xs font-bold shadow-sm ${
                              log.anomaly_details.rule_based?.is_attack 
                                ? 'bg-vt-error/20 text-vt-error border border-vt-error/30' 
                                : 'bg-vt-success/20 text-vt-success border border-vt-success/30'
                            }`}>
                              {log.anomaly_details.rule_based?.is_attack ? '⚠ Attack' : '✓ Clean'}
                            </span>
                          </div>
                          <div className="space-y-3">
                            <div className="flex justify-between items-center text-sm">
                              <span className="text-vt-muted">Confidence</span>
                              <span className="text-vt-light font-mono font-semibold">
                                {((log.anomaly_details.rule_based?.confidence || 0) * 100).toFixed(1)}%
                              </span>
                            </div>
                            {log.anomaly_details.rule_based?.attack_types && log.anomaly_details.rule_based.attack_types.length > 0 && (
                              <div className="pt-3 border-t border-vt-muted/20">
                                <span className="text-xs font-semibold text-vt-muted mb-2 block">Detected Attacks</span>
                                <div className="flex flex-wrap gap-1.5">
                                  {log.anomaly_details.rule_based.attack_types.map((type, i) => (
                                    <span 
                                      key={i}
                                      className="px-2.5 py-1 bg-vt-error/20 text-vt-error rounded-lg text-xs font-semibold border border-vt-error/30"
                                    >
                                      {type}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        </div>

                        {/* Isolation Forest */}
                        <div className="glass-strong rounded-xl p-5 border border-vt-warning/30 card-hover">
                          <div className="flex items-center justify-between mb-4">
                            <div className="flex items-center gap-2">
                              <div className="w-8 h-8 bg-gradient-to-br from-vt-warning/30 to-vt-warning/10 rounded-lg flex items-center justify-center">
                                <svg className="w-4 h-4 text-vt-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                                </svg>
                              </div>
                              <h5 className="text-xs font-bold text-vt-light uppercase tracking-wide">Isolation Forest</h5>
                            </div>
                            <span className={`px-2.5 py-1 rounded-lg text-xs font-bold shadow-sm ${
                              log.anomaly_details.isolation_forest?.is_anomaly === 1
                                ? 'bg-vt-error/20 text-vt-error border border-vt-error/30' 
                                : 'bg-vt-success/20 text-vt-success border border-vt-success/30'
                            }`}>
                              {log.anomaly_details.isolation_forest?.is_anomaly === 1 ? '⚠ Anomaly' : '✓ Normal'}
                            </span>
                          </div>
                          <div className="space-y-3">
                            <div className="flex justify-between items-center text-sm">
                              <span className="text-vt-muted">Score</span>
                              <span className="text-vt-light font-mono font-semibold">
                                {(log.anomaly_details.isolation_forest?.score || 0).toFixed(3)}
                              </span>
                            </div>
                            <div className="w-full bg-vt-muted/20 rounded-full h-3 overflow-hidden border border-vt-muted/30">
                              <div
                                className="h-full rounded-full transition-all duration-500 shadow-sm"
                                style={{
                                  width: `${Math.min((log.anomaly_details.isolation_forest?.score || 0) * 20, 100)}%`,
                                  background: log.anomaly_details.isolation_forest?.is_anomaly === 1 
                                    ? 'linear-gradient(90deg, #e94560 0%, #c73752 100%)' 
                                    : 'linear-gradient(90deg, #10B981 0%, #059669 100%)',
                                }}
                              ></div>
                            </div>
                          </div>
                        </div>

                        {/* Transformer */}
                        <div className="glass-strong rounded-xl p-5 border border-vt-success/30 card-hover">
                          <div className="flex items-center justify-between mb-4">
                            <div className="flex items-center gap-2">
                              <div className="w-8 h-8 bg-gradient-to-br from-vt-success/30 to-vt-success/10 rounded-lg flex items-center justify-center">
                                <svg className="w-4 h-4 text-vt-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                                </svg>
                              </div>
                              <h5 className="text-xs font-bold text-vt-light uppercase tracking-wide">Transformer</h5>
                            </div>
                            <span className={`px-2.5 py-1 rounded-lg text-xs font-bold shadow-sm ${
                              log.anomaly_details.transformer?.is_anomaly === 1
                                ? 'bg-vt-error/20 text-vt-error border border-vt-error/30' 
                                : 'bg-vt-success/20 text-vt-success border border-vt-success/30'
                            }`}>
                              {log.anomaly_details.transformer?.is_anomaly === 1 ? '⚠ Anomaly' : '✓ Normal'}
                            </span>
                          </div>
                          <div className="space-y-3">
                            <div className="flex justify-between items-center text-sm">
                              <span className="text-vt-muted">NLL Score</span>
                              <span className="text-vt-light font-mono font-semibold">
                                {(log.anomaly_details.transformer?.score || 0).toFixed(3)}
                              </span>
                            </div>
                            <div className="w-full bg-vt-muted/20 rounded-full h-3 overflow-hidden border border-vt-muted/30">
                              <div
                                className="h-full rounded-full transition-all duration-500 shadow-sm"
                                style={{
                                  width: `${Math.min((log.anomaly_details.transformer?.score || 0) * 10, 100)}%`,
                                  background: log.anomaly_details.transformer?.is_anomaly === 1 
                                    ? 'linear-gradient(90deg, #e94560 0%, #c73752 100%)' 
                                    : 'linear-gradient(90deg, #10B981 0%, #059669 100%)',
                                }}
                              ></div>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Ensemble Voting */}
                      {log.anomaly_details.ensemble && (
                        <div className="glass-strong rounded-xl p-6 border border-vt-primary/40 shadow-lg">
                          <div className="flex items-center gap-3 mb-5">
                            <div className="w-10 h-10 bg-gradient-to-br from-vt-primary to-vt-success rounded-xl flex items-center justify-center shadow-md">
                              <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 5a1 1 0 011-1h4a1 1 0 011 1v7a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM14 5a1 1 0 011-1h4a1 1 0 011 1v7a1 1 0 01-1 1h-4a1 1 0 01-1-1V5zM4 16a1 1 0 011-1h4a1 1 0 011 1v3a1 1 0 01-1 1H5a1 1 0 01-1-1v-3zM14 16a1 1 0 011-1h4a1 1 0 011 1v3a1 1 0 01-1 1h-4a1 1 0 01-1-1v-3z" />
                              </svg>
                            </div>
                            <h5 className="text-sm font-bold text-vt-light uppercase tracking-wide">Ensemble Decision</h5>
                          </div>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div>
                              <span className="text-xs font-semibold text-vt-muted mb-3 block">Final Anomaly Score</span>
                              <div className="flex items-center gap-3">
                                <div className="flex-1 bg-vt-muted/20 rounded-full h-4 overflow-hidden border border-vt-muted/30">
                                  <div
                                    className="h-full rounded-full transition-all duration-500 shadow-sm"
                                    style={{
                                      width: `${(log.anomaly_details.ensemble.score * 100)}%`,
                                      background: log.infected 
                                        ? 'linear-gradient(90deg, #e94560 0%, #c73752 100%)' 
                                        : 'linear-gradient(90deg, #10B981 0%, #059669 100%)',
                                    }}
                                  ></div>
                                </div>
                                <span className="text-lg font-mono font-bold" style={{ color: log.infected ? '#e94560' : '#10B981' }}>
                                  {(log.anomaly_details.ensemble.score * 100).toFixed(1)}%
                                </span>
                              </div>
                            </div>
                            {log.anomaly_details.ensemble.votes && (
                              <div>
                                <span className="text-xs font-semibold text-vt-muted mb-3 block">Model Voting</span>
                                <div className="flex gap-3">
                                  <div className="flex-1 glass rounded-lg px-3 py-2 text-center border border-vt-primary/30">
                                    <div className="text-xs text-vt-muted mb-1">Rule</div>
                                    <div className="text-lg font-bold text-vt-primary">{log.anomaly_details.ensemble.votes.rule}</div>
                                  </div>
                                  <div className="flex-1 glass rounded-lg px-3 py-2 text-center border border-vt-warning/30">
                                    <div className="text-xs text-vt-muted mb-1">ISO</div>
                                    <div className="text-lg font-bold text-vt-warning">{log.anomaly_details.ensemble.votes.iso}</div>
                                  </div>
                                  <div className="flex-1 glass rounded-lg px-3 py-2 text-center border border-vt-success/30">
                                    <div className="text-xs text-vt-muted mb-1">Trans</div>
                                    <div className="text-lg font-bold text-vt-success">{log.anomaly_details.ensemble.votes.transformer}</div>
                                  </div>
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  </td>
                </tr>
              )}
            </React.Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default LogsTable;
