import React, { useState, useEffect } from 'react';
import LogsTable from '../components/LogsTable';
import LoadingSpinner from '../components/LoadingSpinner';
import ThresholdSettings from '../components/ThresholdSettings';
import ModelLegend from '../components/ModelLegend';
import { useLogs } from '../hooks/useLogs';

const DashboardPage: React.FC = () => {
  const { logs, isLoading, error, totalCount, infectedCount, safeCount } = useLogs();
  const [statsUpdated, setStatsUpdated] = useState(false);
  const [previousLogCount, setPreviousLogCount] = useState(0);

  // Track when counts change to show update indicator
  useEffect(() => {
    if (totalCount !== previousLogCount) {
      setStatsUpdated(true);
      setPreviousLogCount(totalCount);
      
      // Reset the update indicator after 2 seconds
      const timer = setTimeout(() => {
        setStatsUpdated(false);
      }, 2000);
      
      return () => clearTimeout(timer);
    }
  }, [totalCount, previousLogCount]);

  return (
    <div className="min-h-screen bg-vt-dark">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-vt-light mb-2">Log Dashboard</h1>
              <p className="text-vt-muted">Real-time monitoring of system logs and threat detection</p>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <div className={`w-3 h-3 rounded-full transition-all duration-300 ${
                  statsUpdated ? 'bg-vt-success animate-pulse' : 'bg-vt-muted'
                }`}></div>
                <span className="text-sm text-vt-muted">
                  {statsUpdated ? 'Live Updates' : 'Connected'}
                </span>
              </div>
              <ThresholdSettings />
            </div>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className={`bg-vt-blue/50 backdrop-blur-sm rounded-xl p-6 border transition-all duration-500 ${
            statsUpdated ? 'border-vt-primary/50 shadow-lg shadow-vt-primary/20' : 'border-vt-muted/20'
          }`}>
            <div className="flex items-center">
              <div className="w-12 h-12 bg-vt-primary/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-vt-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-vt-muted">Total Logs</p>
                <p className={`text-2xl font-bold text-vt-light transition-all duration-300 ${
                  statsUpdated ? 'scale-110 text-vt-primary' : ''
                }`}>{totalCount}</p>
              </div>
            </div>
          </div>

          <div className={`bg-vt-blue/50 backdrop-blur-sm rounded-xl p-6 border transition-all duration-500 ${
            statsUpdated ? 'border-vt-error/50 shadow-lg shadow-vt-error/20' : 'border-vt-muted/20'
          }`}>
            <div className="flex items-center">
              <div className="w-12 h-12 bg-vt-error/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-vt-error" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                </svg>
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-vt-muted">Threats Detected</p>
                <p className={`text-2xl font-bold text-vt-error transition-all duration-300 ${
                  statsUpdated ? 'scale-110' : ''
                }`}>
                  {infectedCount}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-vt-blue/50 backdrop-blur-sm rounded-xl p-6 border border-vt-muted/20">
            <div className="flex items-center">
              <div className="w-12 h-12 bg-vt-success/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-vt-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-vt-muted">Safe Logs</p>
                <p className="text-2xl font-bold text-vt-success">
                  {safeCount}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-vt-blue/50 backdrop-blur-sm rounded-xl p-6 border border-vt-muted/20">
            <div className="flex items-center">
              <div className="w-12 h-12 bg-vt-warning/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-vt-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-vt-muted">Threat Rate</p>
                <p className="text-2xl font-bold text-vt-warning">
                  {totalCount > 0 ? ((infectedCount / totalCount) * 100).toFixed(1) : 0}%
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Model Legend */}
        <div className="mb-8">
          <ModelLegend />
        </div>

        {/* Logs Table */}
        <div className="bg-vt-blue/30 backdrop-blur-sm rounded-xl border border-vt-muted/20 overflow-hidden">
          <div className="px-6 py-4 border-b border-vt-muted/20">
            <h2 className="text-xl font-semibold text-vt-light">Recent Logs</h2>
            <p className="text-sm text-vt-muted mt-1">Real-time log monitoring and threat detection</p>
          </div>
          
          {isLoading ? (
            <LoadingSpinner text="Loading logs..." />
          ) : error ? (
            <div className="flex items-center justify-center py-12">
              <div className="text-center">
                <div className="w-12 h-12 bg-vt-error/20 rounded-lg flex items-center justify-center mx-auto mb-4">
                  <svg className="w-6 h-6 text-vt-error" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <p className="text-vt-error font-medium">Failed to load logs</p>
                <p className="text-vt-muted text-sm mt-1">{error}</p>
              </div>
            </div>
          ) : (
            <LogsTable logs={logs} />
          )}
        </div>
      </div>
    </div>
  );
};

export default DashboardPage;
