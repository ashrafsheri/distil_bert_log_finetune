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
      <div className="flex items-center justify-center py-12">
        <div className="text-center">
          <div className="w-12 h-12 bg-vt-muted/20 rounded-lg flex items-center justify-center mx-auto mb-4">
            <svg className="w-6 h-6 text-vt-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          </div>
          <p className="text-vt-muted font-medium">No logs available</p>
          <p className="text-vt-muted text-sm mt-1">Logs will appear here when they are received</p>
        </div>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-vt-muted/20">
            <th className="px-6 py-4 text-left text-xs font-medium text-vt-muted uppercase tracking-wider">
              Timestamp
            </th>
            <th className="px-6 py-4 text-left text-xs font-medium text-vt-muted uppercase tracking-wider">
              IP Address
            </th>
            <th className="px-6 py-4 text-left text-xs font-medium text-vt-muted uppercase tracking-wider">
              API Accessed
            </th>
            <th className="px-6 py-4 text-left text-xs font-medium text-vt-muted uppercase tracking-wider">
              Status
            </th>
            <th className="px-6 py-4 text-left text-xs font-medium text-vt-muted uppercase tracking-wider">
              Anomaly Score
            </th>
            <th className="px-6 py-4 text-left text-xs font-medium text-vt-muted uppercase tracking-wider">
              Threat Status
            </th>
            <th className="px-6 py-4 text-left text-xs font-medium text-vt-muted uppercase tracking-wider">
              Details
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-vt-muted/10">
          {logs.map((log, index) => (
            <React.Fragment key={index}>
              <tr
                className={`hover:bg-vt-blue/20 transition-colors ${
                  log.infected ? 'bg-vt-error/20 border-l-4 border-l-vt-error' : ''
                }`}
              >
                <td className="px-6 py-4 whitespace-nowrap">
                  <div 
                    className="text-sm font-medium"
                    style={{ color: log.infected ? '#e94560' : '#f5f5f5' }}
                  >
                    {log.timestamp}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div 
                    className="text-sm font-mono"
                    style={{ color: log.infected ? '#e94560' : '#f5f5f5' }}
                  >
                    {log.ipAddress}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div 
                    className="text-sm font-mono truncate max-w-xs"
                    style={{ color: log.infected ? '#e94560' : '#f5f5f5' }}
                    title={log.apiAccessed}
                  >
                    {log.apiAccessed}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex items-center">
                    <span 
                      className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium"
                      style={{ 
                        backgroundColor: log.infected ? 'rgba(233, 69, 96, 0.2)' : 'transparent',
                        color: log.infected ? '#e94560' : (log.statusCode >= 200 && log.statusCode < 300 ? '#10B981' : log.statusCode >= 400 ? '#e94560' : '#A0A8C0')
                      }}
                    >
                      {getStatusIcon(log.statusCode)}
                      <span className="ml-1">{log.statusCode}</span>
                    </span>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex items-center">
                    <div className="flex-1 bg-vt-muted/20 rounded-full h-2 mr-2 overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-300"
                        style={{
                          width: `${Math.min((log.anomaly_score || 0) * 100, 100)}%`,
                          backgroundColor: log.infected ? '#e94560' : '#10B981',
                        }}
                      ></div>
                    </div>
                    <span 
                      className="text-xs font-mono min-w-[3rem] text-right"
                      style={{ color: log.infected ? '#e94560' : '#A0A8C0' }}
                    >
                      {((log.anomaly_score || 0) * 100).toFixed(1)}%
                    </span>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex items-center">
                    {log.infected ? (
                      <span 
                        className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium"
                        style={{ backgroundColor: 'rgba(233, 69, 96, 0.2)', color: '#e94560' }}
                      >
                        <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                        </svg>
                        Threat Detected
                      </span>
                    ) : (
                      <span 
                        className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium"
                        style={{ backgroundColor: 'rgba(16, 185, 129, 0.2)', color: '#10B981' }}
                      >
                        <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                        </svg>
                        Safe
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <button
                    onClick={() => toggleRow(index)}
                    className="text-vt-primary hover:text-vt-primary/80 transition-colors text-sm font-medium"
                  >
                    {expandedRow === index ? (
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
                      </svg>
                    ) : (
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                      </svg>
                    )}
                  </button>
                </td>
              </tr>
              {expandedRow === index && log.anomaly_details && (
                <tr className="bg-vt-blue/10">
                  <td colSpan={7} className="px-6 py-4">
                    <div className="space-y-4">
                      <h4 className="text-sm font-semibold text-vt-light mb-3">Ensemble Model Scores</h4>
                      
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        {/* Rule-Based Detection */}
                        <div className="bg-vt-blue/30 rounded-lg p-4 border border-vt-muted/20">
                          <div className="flex items-center justify-between mb-2">
                            <h5 className="text-xs font-semibold text-vt-muted uppercase">Rule-Based</h5>
                            <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                              log.anomaly_details.rule_based?.is_attack 
                                ? 'bg-vt-error/20 text-vt-error' 
                                : 'bg-vt-success/20 text-vt-success'
                            }`}>
                              {log.anomaly_details.rule_based?.is_attack ? 'Attack' : 'Clean'}
                            </span>
                          </div>
                          <div className="space-y-2">
                            <div className="flex justify-between text-sm">
                              <span className="text-vt-muted">Confidence:</span>
                              <span className="text-vt-light font-mono">
                                {((log.anomaly_details.rule_based?.confidence || 0) * 100).toFixed(1)}%
                              </span>
                            </div>
                            {log.anomaly_details.rule_based?.attack_types && log.anomaly_details.rule_based.attack_types.length > 0 && (
                              <div className="mt-2">
                                <span className="text-xs text-vt-muted">Attack Types:</span>
                                <div className="flex flex-wrap gap-1 mt-1">
                                  {log.anomaly_details.rule_based.attack_types.map((type, i) => (
                                    <span 
                                      key={i}
                                      className="px-2 py-0.5 bg-vt-error/20 text-vt-error rounded text-xs"
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
                        <div className="bg-vt-blue/30 rounded-lg p-4 border border-vt-muted/20">
                          <div className="flex items-center justify-between mb-2">
                            <h5 className="text-xs font-semibold text-vt-muted uppercase">Isolation Forest</h5>
                            <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                              log.anomaly_details.isolation_forest?.is_anomaly === 1
                                ? 'bg-vt-error/20 text-vt-error' 
                                : 'bg-vt-success/20 text-vt-success'
                            }`}>
                              {log.anomaly_details.isolation_forest?.is_anomaly === 1 ? 'Anomaly' : 'Normal'}
                            </span>
                          </div>
                          <div className="space-y-2">
                            <div className="flex justify-between text-sm">
                              <span className="text-vt-muted">Score:</span>
                              <span className="text-vt-light font-mono">
                                {(log.anomaly_details.isolation_forest?.score || 0).toFixed(3)}
                              </span>
                            </div>
                            <div className="w-full bg-vt-muted/20 rounded-full h-2 mt-2">
                              <div
                                className="h-full rounded-full transition-all"
                                style={{
                                  width: `${Math.min((log.anomaly_details.isolation_forest?.score || 0) * 20, 100)}%`,
                                  backgroundColor: log.anomaly_details.isolation_forest?.is_anomaly === 1 ? '#e94560' : '#10B981',
                                }}
                              ></div>
                            </div>
                          </div>
                        </div>

                        {/* Transformer */}
                        <div className="bg-vt-blue/30 rounded-lg p-4 border border-vt-muted/20">
                          <div className="flex items-center justify-between mb-2">
                            <h5 className="text-xs font-semibold text-vt-muted uppercase">Transformer</h5>
                            <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                              log.anomaly_details.transformer?.is_anomaly === 1
                                ? 'bg-vt-error/20 text-vt-error' 
                                : 'bg-vt-success/20 text-vt-success'
                            }`}>
                              {log.anomaly_details.transformer?.is_anomaly === 1 ? 'Anomaly' : 'Normal'}
                            </span>
                          </div>
                          <div className="space-y-2">
                            <div className="flex justify-between text-sm">
                              <span className="text-vt-muted">NLL Score:</span>
                              <span className="text-vt-light font-mono">
                                {(log.anomaly_details.transformer?.score || 0).toFixed(3)}
                              </span>
                            </div>
                            <div className="w-full bg-vt-muted/20 rounded-full h-2 mt-2">
                              <div
                                className="h-full rounded-full transition-all"
                                style={{
                                  width: `${Math.min((log.anomaly_details.transformer?.score || 0) * 10, 100)}%`,
                                  backgroundColor: log.anomaly_details.transformer?.is_anomaly === 1 ? '#e94560' : '#10B981',
                                }}
                              ></div>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Ensemble Voting */}
                      {log.anomaly_details.ensemble && (
                        <div className="bg-vt-blue/30 rounded-lg p-4 border border-vt-muted/20 mt-4">
                          <h5 className="text-xs font-semibold text-vt-muted uppercase mb-3">Ensemble Decision</h5>
                          <div className="grid grid-cols-2 gap-4">
                            <div>
                              <span className="text-xs text-vt-muted">Final Score:</span>
                              <div className="flex items-center mt-1">
                                <div className="flex-1 bg-vt-muted/20 rounded-full h-3 mr-2 overflow-hidden">
                                  <div
                                    className="h-full rounded-full transition-all"
                                    style={{
                                      width: `${(log.anomaly_details.ensemble.score * 100)}%`,
                                      backgroundColor: log.infected ? '#e94560' : '#10B981',
                                    }}
                                  ></div>
                                </div>
                                <span className="text-sm font-mono text-vt-light">
                                  {(log.anomaly_details.ensemble.score * 100).toFixed(1)}%
                                </span>
                              </div>
                            </div>
                            {log.anomaly_details.ensemble.votes && (
                              <div>
                                <span className="text-xs text-vt-muted">Model Votes:</span>
                                <div className="flex gap-2 mt-1">
                                  <span className="px-2 py-1 bg-vt-blue/40 rounded text-xs text-vt-light">
                                    Rule: {log.anomaly_details.ensemble.votes.rule}
                                  </span>
                                  <span className="px-2 py-1 bg-vt-blue/40 rounded text-xs text-vt-light">
                                    ISO: {log.anomaly_details.ensemble.votes.iso}
                                  </span>
                                  <span className="px-2 py-1 bg-vt-blue/40 rounded text-xs text-vt-light">
                                    Trans: {log.anomaly_details.ensemble.votes.transformer}
                                  </span>
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
