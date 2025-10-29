import React, { useMemo, useState } from 'react';
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
    status?: string;
  };
  transformer?: {
    is_anomaly: number;
    score: number;
    threshold?: number;
    sequence_length?: number;
    context?: string;
    status?: string;
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
  transformer_ready?: boolean;
  logs_processed?: number;
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
  sourceLogs?: LogEntry[];
  focusedIp?: string | null;
  onFocusIp?: (ip: string | null) => void;
  highlightTransformerTrail?: boolean;
}

const LogsTable: React.FC<LogsTableProps> = ({
  logs,
  sourceLogs,
  focusedIp = null,
  onFocusIp,
  highlightTransformerTrail = false,
}) => {
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const datasetForTrail = sourceLogs ?? logs;

  const trailLookup = useMemo(() => {
    const map = new Map<string, LogEntry[]>();
    datasetForTrail.forEach(entry => {
      const existing = map.get(entry.ipAddress) ?? [];
      if (existing.length < 20) {
        existing.push(entry);
      }
      map.set(entry.ipAddress, existing);
    });
    return map;
  }, [datasetForTrail]);

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
    <div className="w-full">
      <div className="overflow-x-auto">
        <table className="w-full min-w-full table-auto">
          <thead className="bg-vt-blue/30 sticky top-0 z-10">
            <tr className="border-b border-vt-primary/20">
              <th className="px-3 sm:px-4 lg:px-6 py-4 text-left text-xs font-semibold text-vt-primary uppercase tracking-wider whitespace-nowrap">
                Timestamp
              </th>
              <th className="px-3 sm:px-4 lg:px-6 py-4 text-left text-xs font-semibold text-vt-primary uppercase tracking-wider whitespace-nowrap">
                IP Address
              </th>
              <th className="px-3 sm:px-4 lg:px-6 py-4 text-left text-xs font-semibold text-vt-primary uppercase tracking-wider">
                API Endpoint
              </th>
              <th className="px-3 sm:px-4 lg:px-6 py-4 text-left text-xs font-semibold text-vt-primary uppercase tracking-wider whitespace-nowrap">
                Status
              </th>
              <th className="px-3 sm:px-4 lg:px-6 py-4 text-left text-xs font-semibold text-vt-primary uppercase tracking-wider whitespace-nowrap">
                Risk Score
              </th>
              <th className="px-3 sm:px-4 lg:px-6 py-4 text-left text-xs font-semibold text-vt-primary uppercase tracking-wider whitespace-nowrap">
                Threat
              </th>
              <th className="px-3 sm:px-4 lg:px-6 py-4 text-left text-xs font-semibold text-vt-primary uppercase tracking-wider whitespace-nowrap">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-vt-muted/10">
            {logs.map((log, index) => {
              const isTransformerAnomaly = log.anomaly_details?.transformer?.is_anomaly === 1;
              const transformerSequenceLength = log.anomaly_details?.transformer?.sequence_length ?? 0;
              const transformerContext = log.anomaly_details?.transformer?.context;
              const isFocused = focusedIp ? log.ipAddress === focusedIp : false;
              const relatedActivity = trailLookup.get(log.ipAddress) ?? [];
              const rowClasses = [
                'group hover:bg-vt-primary/5 transition-all duration-200',
                log.infected ? 'bg-vt-error/10 border-l-4 border-l-vt-error' : '',
                expandedRow === index ? 'bg-vt-primary/5' : '',
                isFocused ? 'ring-2 ring-vt-warning/40 bg-vt-warning/5' : '',
                highlightTransformerTrail && isTransformerAnomaly ? 'shadow-inner shadow-vt-warning/20' : '',
              ]
                .filter(Boolean)
                .join(' ');

              return (
                <React.Fragment key={index}>
                  <tr className={rowClasses}>
                  <td className="px-3 sm:px-4 lg:px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center gap-2">
                      <svg className="w-4 h-4 text-vt-muted flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <div 
                        className="text-xs sm:text-sm font-mono"
                        style={{ color: log.infected ? 'var(--vt-error)' : 'var(--vt-text)' }}
                      >
                        {log.timestamp}
                      </div>
                    </div>
                  </td>
                  <td className="px-3 sm:px-4 lg:px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center gap-2">
                      <svg className="w-4 h-4 text-vt-muted flex-shrink-0 hidden sm:block" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                      </svg>
                      <div 
                        className="text-xs sm:text-sm font-mono px-2 py-1 rounded bg-vt-blue/40"
                        style={{ color: log.infected ? 'var(--vt-error)' : 'var(--vt-text)' }}
                      >
                        {log.ipAddress}
                      </div>
                      {isFocused && (
                        <span className="px-2 py-0.5 rounded-full bg-vt-warning/20 text-vt-warning text-[10px] font-semibold uppercase tracking-wide">
                          focusing
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-3 sm:px-4 lg:px-6 py-4 max-w-xs">
                    <div 
                      className="text-xs sm:text-sm font-mono break-all line-clamp-2 group-hover:line-clamp-none transition-all"
                      style={{ color: log.infected ? 'var(--vt-error)' : 'var(--vt-muted)' }}
                      title={log.apiAccessed}
                    >
                      {log.apiAccessed}
                    </div>
                    {(highlightTransformerTrail && (transformerSequenceLength > 0 || transformerContext)) && (
                      <div className="mt-2 inline-flex items-center gap-2 rounded-full bg-vt-primary/10 px-2 py-1 text-[10px] font-semibold uppercase tracking-wide text-vt-primary">
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                        </svg>
                        Seq {transformerSequenceLength || transformerContext}
                      </div>
                    )}
                  </td>
                  <td className="px-3 sm:px-4 lg:px-6 py-4 whitespace-nowrap">
                    <span 
                      className="inline-flex items-center px-2 sm:px-3 py-1 rounded-full text-xs font-semibold"
                      style={{ 
                        backgroundColor: log.infected ? 'rgba(248, 113, 113, 0.18)' : 'rgba(79, 141, 249, 0.18)',
                        color: log.infected
                          ? 'var(--vt-error)'
                          : (log.statusCode >= 200 && log.statusCode < 300 ? 'var(--vt-success)' : log.statusCode >= 400 ? 'var(--vt-warning)' : 'var(--vt-muted)'),
                        border: `1px solid ${log.infected ? 'rgba(248, 113, 113, 0.32)' : 'rgba(79, 141, 249, 0.28)'}`
                      }}
                    >
                      {getStatusIcon(log.statusCode)}
                      <span className="ml-1.5">{log.statusCode}</span>
                    </span>
                  </td>
                  <td className="px-3 sm:px-4 lg:px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center gap-2 sm:gap-3 min-w-[120px]">
                      <div className="flex-1 bg-vt-muted/20 rounded-full h-2.5 overflow-hidden border border-vt-muted/30">
                        <div
                          className="h-full rounded-full transition-all duration-500 shadow-sm"
                          style={{
                            width: `${Math.min((log.anomaly_score || 0) * 100, 100)}%`,
                            background: log.infected 
                              ? 'linear-gradient(90deg, rgba(248,113,113,1) 0%, rgba(239,68,68,1) 100%)' 
                              : 'linear-gradient(90deg, rgba(45,212,191,1) 0%, rgba(13,148,136,1) 100%)',
                          }}
                        ></div>
                      </div>
                      <span 
                        className="text-xs font-mono font-semibold min-w-[3rem] text-right px-2 py-1 rounded bg-vt-blue/30 flex-shrink-0"
                        style={{ color: log.infected ? 'var(--vt-error)' : 'var(--vt-success)' }}
                      >
                        {((log.anomaly_score || 0) * 100).toFixed(1)}%
                      </span>
                    </div>
                  </td>
                  <td className="px-3 sm:px-4 lg:px-6 py-4 whitespace-nowrap">
                    {log.infected ? (
                      <span 
                        className="inline-flex items-center px-2 sm:px-3 py-1.5 rounded-lg text-xs font-semibold shadow-sm"
                        style={{ 
                          backgroundColor: 'rgba(248, 113, 113, 0.16)', 
                          color: 'var(--vt-error)',
                          border: '1px solid rgba(248, 113, 113, 0.32)'
                        }}
                      >
                        <svg className="w-4 h-4 mr-1.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-1.964-1.333-2.732 0L3.732 16c-.77 1.333.192 3 1.732 3z" />
                        </svg>
                        <span className="hidden sm:inline">Threat Detected</span>
                        <span className="sm:hidden">Threat</span>
                      </span>
                    ) : (
                      <span 
                        className="inline-flex items-center px-2 sm:px-3 py-1.5 rounded-lg text-xs font-semibold shadow-sm"
                        style={{ 
                          backgroundColor: 'rgba(34, 211, 166, 0.18)', 
                          color: 'var(--vt-success)',
                          border: '1px solid rgba(34, 211, 166, 0.32)'
                        }}
                      >
                        <svg className="w-4 h-4 mr-1.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                        Safe
                      </span>
                    )}
                  </td>
                  <td className="px-3 sm:px-4 lg:px-6 py-4 whitespace-nowrap">
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
                    <button
                      onClick={() => {
                        if (onFocusIp) {
                          onFocusIp(isFocused ? null : log.ipAddress);
                        }
                      }}
                      className={`ml-2 p-2 rounded-lg transition-all duration-200 ${
                        isFocused
                          ? 'bg-vt-warning/20 text-vt-warning hover:bg-vt-warning/30'
                          : 'text-vt-muted hover:text-vt-primary hover:bg-vt-primary/10'
                      }`}
                      title={isFocused ? 'Clear focus' : 'Focus on this IP trail'}
                    >
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 10l4.553-2.276a1 1 0 011.447.894V15.38a1 1 0 01-.553.894L15 18m0-8l-4.553-2.276A1 1 0 009 8.618V15.38a1 1 0 00.553.894L15 18m0-8v8m-6-6H5m4-6H5" />
                      </svg>
                    </button>
                  </td>
                </tr>
                {expandedRow === index && log.anomaly_details && (
                  <tr className="bg-gradient-to-r from-vt-blue/20 to-transparent animate-slide-down">
                    <td colSpan={7} className="px-3 sm:px-4 lg:px-6 py-6">
                      <div className="space-y-6">
                        <div className="flex items-center gap-3 mb-4">
                          <div className="w-1 h-6 bg-gradient-to-b from-vt-primary to-vt-success rounded-full"></div>
                          <h4 className="text-lg font-bold text-vt-light">Ensemble Model Analysis</h4>
                          {log.anomaly_details.logs_processed && (
                            <span className="ml-auto text-xs text-vt-muted px-3 py-1 glass rounded-lg">
                              Total Logs Processed: {log.anomaly_details.logs_processed.toLocaleString()}
                            </span>
                          )}
                        </div>
                        
                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 sm:gap-6">
                          {/* Rule-Based Detection */}
                          <div className="glass-strong rounded-xl p-4 sm:p-5 border border-vt-primary/30 card-hover">
                            <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
                              <div className="flex items-center gap-2">
                                <div className="w-8 h-8 bg-gradient-to-br from-vt-primary/30 to-vt-primary/10 rounded-lg flex items-center justify-center flex-shrink-0">
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
                              <div className="w-full bg-vt-muted/20 rounded-full h-2 overflow-hidden">
                                <div
                                  className="h-full rounded-full transition-all duration-500"
                                  style={{
                                    width: `${(log.anomaly_details.rule_based?.confidence || 0) * 100}%`,
                                    background: log.anomaly_details.rule_based?.is_attack 
                                      ? 'linear-gradient(90deg, #e94560 0%, #c73752 100%)' 
                                      : 'linear-gradient(90deg, #10B981 0%, #059669 100%)',
                                  }}
                                ></div>
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
                          <div className="glass-strong rounded-xl p-4 sm:p-5 border border-vt-warning/30 card-hover">
                            <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
                              <div className="flex items-center gap-2">
                                <div className="w-8 h-8 bg-gradient-to-br from-vt-warning/30 to-vt-warning/10 rounded-lg flex items-center justify-center flex-shrink-0">
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
                              <div className="w-full bg-vt-muted/20 rounded-full h-2 overflow-hidden border border-vt-muted/30">
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
                              {log.anomaly_details.isolation_forest?.status && (
                                <div className="pt-2">
                                  <span className="text-xs text-vt-muted">Status: {log.anomaly_details.isolation_forest.status}</span>
                                </div>
                              )}
                            </div>
                          </div>

                          {/* Transformer */}
                          <div className="glass-strong rounded-xl p-4 sm:p-5 border border-vt-success/30 card-hover">
                            <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
                              <div className="flex items-center gap-2">
                                <div className="w-8 h-8 bg-gradient-to-br from-vt-success/30 to-vt-success/10 rounded-lg flex items-center justify-center flex-shrink-0">
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
                              {log.anomaly_details.transformer?.threshold && (
                                <div className="flex justify-between items-center text-sm">
                                  <span className="text-vt-muted">Threshold</span>
                                  <span className="text-vt-light font-mono font-semibold">
                                    {log.anomaly_details.transformer.threshold.toFixed(3)}
                                  </span>
                                </div>
                              )}
                              <div className="w-full bg-vt-muted/20 rounded-full h-2 overflow-hidden border border-vt-muted/30">
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
                              {(log.anomaly_details.transformer?.sequence_length || log.anomaly_details.transformer?.context) && (
                                <div className="pt-3 border-t border-vt-muted/20 space-y-2">
                                  {log.anomaly_details.transformer.sequence_length && (
                                    <div className="flex justify-between items-center text-xs">
                                      <span className="text-vt-muted">Sequence Length</span>
                                      <span className="text-vt-light font-mono">{log.anomaly_details.transformer.sequence_length}</span>
                                    </div>
                                  )}
                                  {log.anomaly_details.transformer.context && (
                                    <div className="flex justify-between items-center text-xs">
                                      <span className="text-vt-muted">Context</span>
                                      <span className="text-vt-primary font-semibold">{log.anomaly_details.transformer.context}</span>
                                    </div>
                                  )}
                                </div>
                              )}
                              {log.anomaly_details.transformer?.status && (
                                <div className="pt-2">
                                  <span className="text-xs text-vt-muted">Status: {log.anomaly_details.transformer.status}</span>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>

                        {/* Ensemble Voting */}
                        {log.anomaly_details.ensemble && (
                          <div className="glass-strong rounded-xl p-4 sm:p-6 border border-vt-primary/40 shadow-lg">
                            <div className="flex items-center gap-3 mb-5">
                              <div className="w-10 h-10 bg-gradient-to-br from-vt-primary to-vt-success rounded-xl flex items-center justify-center shadow-md flex-shrink-0">
                                <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 5a1 1 0 011-1h4a1 1 0 011 1v7a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM14 5a1 1 0 011-1h4a1 1 0 011 1v7a1 1 0 01-1 1h-4a1 1 0 01-1-1V5zM4 16a1 1 0 011-1h4a1 1 0 011 1v3a1 1 0 01-1 1H5a1 1 0 01-1-1v-3zM14 16a1 1 0 011-1h4a1 1 0 011 1v3a1 1 0 01-1 1h-4a1 1 0 01-1-1v-3z" />
                                </svg>
                              </div>
                              <h5 className="text-sm font-bold text-vt-light uppercase tracking-wide">Ensemble Decision</h5>
                            </div>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6">
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
                                  <span className="text-lg font-mono font-bold flex-shrink-0" style={{ color: log.infected ? '#e94560' : '#10B981' }}>
                                    {(log.anomaly_details.ensemble.score * 100).toFixed(1)}%
                                  </span>
                                </div>
                              </div>
                              {log.anomaly_details.ensemble.votes && (
                                <div>
                                  <span className="text-xs font-semibold text-vt-muted mb-3 block">Model Voting</span>
                                  <div className="grid grid-cols-3 gap-2 sm:gap-3">
                                    <div className="glass rounded-lg px-2 sm:px-3 py-2 text-center border border-vt-primary/30">
                                      <div className="text-xs text-vt-muted mb-1">Rule</div>
                                      <div className="text-base sm:text-lg font-bold text-vt-primary">{log.anomaly_details.ensemble.votes.rule}</div>
                                    </div>
                                    <div className="glass rounded-lg px-2 sm:px-3 py-2 text-center border border-vt-warning/30">
                                      <div className="text-xs text-vt-muted mb-1">ISO</div>
                                      <div className="text-base sm:text-lg font-bold text-vt-warning">{log.anomaly_details.ensemble.votes.iso}</div>
                                    </div>
                                    <div className="glass rounded-lg px-2 sm:px-3 py-2 text-center border border-vt-success/30">
                                      <div className="text-xs text-vt-muted mb-1">Trans</div>
                                      <div className="text-base sm:text-lg font-bold text-vt-success">{log.anomaly_details.ensemble.votes.transformer}</div>
                                    </div>
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        )}

                        {/* Transformer Deep Dive - Only show if transformer detected anomaly */}
                        {log.anomaly_details.transformer?.is_anomaly === 1 && log.anomaly_details.transformer_ready && (
                          <div className="glass-strong rounded-xl p-4 sm:p-6 border border-vt-error/40 shadow-lg bg-vt-error/5">
                            <div className="flex items-center gap-3 mb-5">
                              <div className="w-10 h-10 bg-gradient-to-br from-vt-error to-vt-warning rounded-xl flex items-center justify-center shadow-md flex-shrink-0 animate-pulse">
                                <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-1.964-1.333-2.732 0L3.732 16c-.77 1.333.192 3 1.732 3z" />
                                </svg>
                              </div>
                              <div className="flex-1">
                                <h5 className="text-sm font-bold text-vt-error uppercase tracking-wide">🔍 Transformer Anomaly Detected</h5>
                                <p className="text-xs text-vt-muted mt-1">Contextual sequence analysis flagged this log as suspicious</p>
                              </div>
                            </div>
                            
                            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                              <div className="glass rounded-lg p-4 border border-vt-error/30">
                                <div className="text-xs text-vt-muted mb-1">Anomaly Score</div>
                                <div className="text-2xl font-bold text-vt-error font-mono">
                                  {(log.anomaly_details.transformer.score || 0).toFixed(3)}
                                </div>
                                <div className="text-xs text-vt-muted mt-1">NLL Value</div>
                              </div>
                              
                              <div className="glass rounded-lg p-4 border border-vt-warning/30">
                                <div className="text-xs text-vt-muted mb-1">Threshold</div>
                                <div className="text-2xl font-bold text-vt-warning font-mono">
                                  {(log.anomaly_details.transformer.threshold || 0).toFixed(3)}
                                </div>
                                <div className="text-xs text-vt-muted mt-1">
                                  {log.anomaly_details.transformer.score && log.anomaly_details.transformer.threshold && 
                                    `+${((log.anomaly_details.transformer.score / log.anomaly_details.transformer.threshold - 1) * 100).toFixed(1)}% above`
                                  }
                                </div>
                              </div>
                              
                              <div className="glass rounded-lg p-4 border border-vt-primary/30">
                                <div className="text-xs text-vt-muted mb-1">Sequence Length</div>
                                <div className="text-2xl font-bold text-vt-primary font-mono">
                                  {log.anomaly_details.transformer.sequence_length || 0}
                                </div>
                                <div className="text-xs text-vt-muted mt-1">Log Templates</div>
                              </div>
                              
                              <div className="glass rounded-lg p-4 border border-vt-success/30">
                                <div className="text-xs text-vt-muted mb-1">Context Type</div>
                                <div className="text-base font-bold text-vt-success uppercase tracking-wide mt-2">
                                  {log.anomaly_details.transformer.context || 'N/A'}
                                </div>
                                <div className="text-xs text-vt-muted mt-1">
                                  {log.anomaly_details.transformer.sequence_length === 1 ? 'Single Log' : 'Sequential Batch'}
                                </div>
                              </div>
                            </div>
                            
                            <div className="mt-4 p-4 bg-vt-blue/20 rounded-lg border border-vt-blue/30">
                              <div className="flex items-start gap-3">
                                <svg className="w-5 h-5 text-vt-primary flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                                <div className="text-xs text-vt-light leading-relaxed">
                                  <strong className="text-vt-primary">Why flagged:</strong> The transformer model analyzes the sequence of recent log templates from this IP address. 
                                  A high NLL score (above threshold) indicates this log's pattern is unusual compared to training data, suggesting potential attack behavior or anomalous access patterns.
                                  {log.anomaly_details.transformer.sequence_length && log.anomaly_details.transformer.sequence_length > 1 && (
                                    <span className="block mt-2">
                                      <strong className="text-vt-warning">Batch Context:</strong> Analyzed within a sequence of {log.anomaly_details.transformer.sequence_length} logs, 
                                      providing deeper contextual understanding than single-log analysis.
                                    </span>
                                  )}
                                </div>
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                      
                      {relatedActivity.length > 0 && (
                        <div className="pt-5 border-t border-vt-muted/20">
                          <div className="flex items-center gap-2 mb-3">
                            <div className="w-1 h-4 bg-vt-primary rounded-full"></div>
                            <h5 className="text-sm font-semibold text-vt-light uppercase tracking-wide">Recent Activity Trail</h5>
                            <span className="text-[10px] text-vt-muted uppercase">
                              Showing last {Math.min(relatedActivity.length, 6)} events
                            </span>
                          </div>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            {relatedActivity.slice(0, 6).map((activity, idx) => {
                              const activityTransformer = activity.anomaly_details?.transformer?.is_anomaly === 1;
                              const isCurrentLog =
                                activity.timestamp === log.timestamp &&
                                activity.apiAccessed === log.apiAccessed &&
                                activity.statusCode === log.statusCode;
                              return (
                                <div
                                  key={`${activity.timestamp}-${idx}`}
                                  className={`rounded-lg px-3 py-2 border ${
                                    isCurrentLog
                                      ? 'border-vt-primary/50 bg-vt-primary/10'
                                      : activity.infected || activityTransformer
                                        ? 'border-vt-error/40 bg-vt-error/10'
                                        : 'border-vt-muted/20 bg-vt-muted/5'
                                  }`}
                                >
                                  <div className="flex items-center justify-between gap-2">
                                    <span className="text-[11px] font-mono text-vt-muted">{activity.timestamp}</span>
                                    <span className={`text-[11px] font-semibold ${activity.infected ? 'text-vt-error' : 'text-vt-muted'}`}>
                                      {activity.statusCode}
                                    </span>
                                  </div>
                                  <div className="mt-1 text-xs text-vt-light font-mono break-all">{activity.apiAccessed}</div>
                                  <div className="mt-2 flex items-center gap-2 text-[10px] uppercase tracking-wide">
                                    {activity.infected && (
                                      <span className="inline-flex items-center gap-1 text-vt-error">
                                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01" />
                                        </svg>
                                        Ensemble
                                      </span>
                                    )}
                                    {activityTransformer && (
                                      <span className="inline-flex items-center gap-1 text-vt-warning">
                                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                                        </svg>
                                        Transformer
                                      </span>
                                    )}
                                    <span className="text-vt-muted">{((activity.anomaly_score || 0) * 100).toFixed(1)}%</span>
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}
                    </td>
                  </tr>
                )}
              </React.Fragment>
            );
          })}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default LogsTable;
