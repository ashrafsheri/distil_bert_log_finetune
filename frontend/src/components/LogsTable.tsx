import React from 'react';
import { getStatusIcon } from '../utils/helpers';

export interface LogEntry {
  timestamp: string;
  ipAddress: string;
  apiAccessed: string;
  statusCode: number;
  infected: boolean;
}

interface LogsTableProps {
  logs: LogEntry[];
}

const LogsTable: React.FC<LogsTableProps> = ({ logs }) => {

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
              Threat Status
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-vt-muted/10">
          {logs.map((log, index) => (
            <tr
              key={index}
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
                  className="text-sm font-mono"
                  style={{ color: log.infected ? '#e94560' : '#f5f5f5' }}
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
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default LogsTable;
