import React, { useState, useEffect, useMemo, useCallback } from 'react';
import LogsTable from '../components/LogsTable';
import LoadingSpinner from '../components/LoadingSpinner';
import { useLogs } from '../hooks/useLogs';
import StreamControls from '../components/StreamControls';
import { useAuth } from '../context/AuthContext';
import Select from '../components/Select';
import Button from '../components/Button';
import { logService } from '../services/logService';

const DashboardPage: React.FC = () => {
  const {
    logs,
    isLoading,
    error,
    totalCount,
    infectedCount,
    safeCount,
    isStreamPaused,
    pendingCount,
    pendingThreatCount,
    lastUpdate,
    pauseStream,
    resumeStream,
    stepPending,
    applyPending,
    discardPending,
  } = useLogs();
  const [statsUpdated, setStatsUpdated] = useState(false);
  const [previousLogCount, setPreviousLogCount] = useState(0);
  const [showAnomaliesOnly, setShowAnomaliesOnly] = useState(false);
  const [focusedIp, setFocusedIp] = useState<string | null>(null);
  const { userInfo } = useAuth();
  const isPrivileged = userInfo?.role === 'admin' || userInfo?.role === 'manager';

  // Search state
  const [searchIp, setSearchIp] = useState('');
  const [searchApi, setSearchApi] = useState('');
  const [searchStatus, setSearchStatus] = useState('');
  const [searchMalicious, setSearchMalicious] = useState(''); // '', 'malicious', 'clean'
  const [searchLoading, setSearchLoading] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [searchResults, setSearchResults] = useState<typeof logs | null>(null);
  const [searchTotal, setSearchTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const [browseResults, setBrowseResults] = useState<typeof logs | null>(null);
  const [browseTotal, setBrowseTotal] = useState(0);
  const [showAdvanced, setShowAdvanced] = useState(false);

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

  const displayLogs = useMemo(() => {
    if (searchResults) return searchResults;
    
    // When page = 1 and browseResults exist, combine live logs + browseResults
    if (browseResults && page === 1) {
      // Combine browseResults with live logs, avoiding duplicates
      const browseIds = new Set(browseResults.map(log => `${log.timestamp}-${log.ipAddress}-${log.apiAccessed}`));
      const uniqueLiveLogs = logs.filter(log => {
        const logId = `${log.timestamp}-${log.ipAddress}-${log.apiAccessed}`;
        return !browseIds.has(logId);
      });
      
      // Apply showAnomaliesOnly filter to live logs if needed
      let filteredLiveLogs = uniqueLiveLogs;
      if (showAnomaliesOnly) {
        filteredLiveLogs = uniqueLiveLogs.filter(log => {
          const transformerAnomaly = log.anomaly_details?.transformer?.is_anomaly === 1;
          return log.infected || transformerAnomaly;
        });
      }
      
      // Combine: live logs first (newest), then browseResults
      return [...filteredLiveLogs, ...browseResults];
    }
    
    // When page > 1, only show browseResults
    if (browseResults) return browseResults;
    
    // Fallback: show live logs (when no browseResults yet)
    if (!showAnomaliesOnly) return logs;
    return logs.filter(log => {
      const transformerAnomaly = log.anomaly_details?.transformer?.is_anomaly === 1;
      return log.infected || transformerAnomaly;
    });
  }, [logs, showAnomaliesOnly, searchResults, browseResults, page]);

  const focusedLogs = useMemo(() => {
    if (!focusedIp) {
      return [];
    }
    return logs.filter(log => log.ipAddress === focusedIp).slice(0, 12);
  }, [logs, focusedIp]);

  const handleTogglePause = useCallback(() => {
    if (isStreamPaused) {
      resumeStream();
    } else {
      pauseStream();
    }
  }, [isStreamPaused, pauseStream, resumeStream]);

  const handleToggleAnomalies = useCallback(() => {
    setShowAnomaliesOnly(prev => !prev);
  }, []);

  const handleFocusIp = useCallback((ip: string | null) => {
    setFocusedIp(ip);
  }, []);

  const handleSearch = useCallback(async () => {
    if (!isPrivileged) return;
    try {
      setSearchLoading(true);
      setSearchError(null);
      const currentOffset = (page - 1) * pageSize;
      const params: Record<string, unknown> = {};
      if (searchIp.trim()) params.ip = searchIp.trim();
      if (searchApi.trim()) params.api = searchApi.trim();
      if (searchStatus.trim()) params.status_code = Number(searchStatus.trim());
      if (searchMalicious === 'malicious') params.malicious = true;
      if (searchMalicious === 'clean') params.malicious = false;
      if (fromDate) params.from_date = fromDate;
      if (toDate) params.to_date = toDate;
      params.limit = pageSize;
      params.offset = currentOffset;

      const res = await logService.searchLogs(params);
      const mapped = res.logs.map(l => ({
        ...l,
      }));
      setSearchResults(mapped);
      setSearchTotal(res.total_count || 0);
      setBrowseResults(null);
      setBrowseTotal(0);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Search failed';
      setSearchError(msg);
      setSearchResults([]);
      setSearchTotal(0);
    } finally {
      setSearchLoading(false);
    }
  }, [isPrivileged, searchIp, searchApi, searchStatus, searchMalicious, fromDate, toDate, page, pageSize]);

  const clearSearch = useCallback(() => {
    setSearchIp('');
    setSearchApi('');
    setSearchStatus('');
    setSearchMalicious('');
    setSearchResults(null);
    setSearchError(null);
    setFromDate('');
    setToDate('');
    setPage(1);
    setPageSize(25);
    setSearchTotal(0);
    // Load browse defaults
    (async () => {
      const res = await logService.fetchLogs(25, 0);
      setBrowseResults(res.logs as typeof logs);
      setBrowseTotal(res.total_count || 0);
    })();
  }, []);

  // Pause/resume stream based on page number
  useEffect(() => {
    if (searchResults) return; // Don't control stream in search mode
    
    if (page === 1) {
      // Resume stream on page 1
      if (isStreamPaused) {
        resumeStream();
      }
    } else {
      // Pause stream on other pages
      if (!isStreamPaused) {
        pauseStream();
      }
    }
  }, [page, searchResults, isStreamPaused, pauseStream, resumeStream]);

  // Browse pagination loader when not searching
  useEffect(() => {
    if (searchResults) return; // search mode controls its own fetch
    (async () => {
      const offset = (page - 1) * pageSize;
      const res = await logService.fetchLogs(pageSize, offset);
      setBrowseResults(res.logs as typeof logs);
      setBrowseTotal(res.total_count || 0);
    })();
  }, [searchResults, page, pageSize]);

  return (
    <div className="min-h-screen">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8 animate-slide-down">
          <div className="flex flex-col items-center text-center gap-4">
            <div className="flex flex-col">
              <h1 className="text-4xl font-bold gradient-text mb-2">Security Dashboard</h1>
              <p className="text-vt-muted text-lg">Real-time log monitoring and threat detection analytics</p>
            </div>
          </div>
        </div>

        {/* Search (Admin/Manager only) */}
        {isPrivileged && (
          <div className="glass-strong rounded-2xl p-6 border border-vt-primary/20 mb-8 animate-slide-up">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
              <div className="flex-1">
                <label className="block text-xs text-vt-muted mb-2">IP Address</label>
                <input
                  value={searchIp}
                  onChange={(e) => setSearchIp(e.target.value)}
                  placeholder="e.g. 192.168.1.5"
                  className="w-full px-4 py-2 bg-vt-dark/50 border border-vt-muted/30 rounded-lg text-vt-light placeholder-vt-muted focus:outline-none focus:ring-2 focus:ring-vt-primary focus:border-transparent"
                />
              </div>
              <div className="flex-1">
                <label className="block text-xs text-vt-muted mb-2">API URL</label>
                <input
                  value={searchApi}
                  onChange={(e) => setSearchApi(e.target.value)}
                  placeholder="e.g. /api/v1/users"
                  className="w-full px-4 py-2 bg-vt-dark/50 border border-vt-muted/30 rounded-lg text-vt-light placeholder-vt-muted focus:outline-none focus:ring-2 focus:ring-vt-primary focus:border-transparent"
                />
              </div>
              <div className="w-40">
                <label className="block text-xs text-vt-muted mb-2">Type</label>
                <Select
                  value={searchMalicious}
                  onChange={(val) => setSearchMalicious(val as string)}
                  options={[
                    { label: 'All', value: '' },
                    { label: 'Malicious', value: 'malicious' },
                    { label: 'Clean', value: 'clean' },
                  ]}
                  density="sm"
                />
              </div>
              <div className="flex gap-3">
                <Button
                  onClick={handleSearch}
                  isLoading={searchLoading}
                  variant="primary"
                  size="md"
                >
                  Search
                </Button>
                <Button
                  onClick={clearSearch}
                  variant="secondary"
                  size="md"
                >
                  Clear
                </Button>
                <Button
                  type="button"
                  onClick={() => setShowAdvanced((v) => !v)}
                  variant="secondary"
                  size="md"
                >
                  {showAdvanced ? 'Hide Advanced' : 'Advanced Filters'}
                </Button>
              </div>
            </div>
            {showAdvanced && (
              <div className="mt-4 grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
                <div className="w-36">
                  <label className="block text-xs text-vt-muted mb-2">Status Code</label>
                  <input
                    value={searchStatus}
                    onChange={(e) => setSearchStatus(e.target.value.replace(/[^0-9]/g, ''))}
                    placeholder="e.g. 404"
                    inputMode="numeric"
                    className="w-full px-4 py-2 bg-vt-dark/50 border border-vt-muted/30 rounded-lg text-vt-light placeholder-vt-muted focus:outline-none focus:ring-2 focus:ring-vt-primary focus:border-transparent"
                  />
                </div>
                <div className="w-44">
                  <label className="block text-xs text-vt-muted mb-2">From</label>
                  <input
                    type="date"
                    value={fromDate}
                    onChange={(e) => setFromDate(e.target.value)}
                    className="w-full px-4 py-2 bg-vt-dark/50 border border-vt-muted/30 rounded-lg text-vt-light focus:outline-none focus:ring-2 focus:ring-vt-primary focus:border-transparent"
                  />
                </div>
                <div className="w-44">
                  <label className="block text-xs text-vt-muted mb-2">To</label>
                  <input
                    type="date"
                    value={toDate}
                    onChange={(e) => setToDate(e.target.value)}
                    className="w-full px-4 py-2 bg-vt-dark/50 border border-vt-muted/30 rounded-lg text-vt-light focus:outline-none focus:ring-2 focus:ring-vt-primary focus:border-transparent"
                  />
                </div>
              </div>
            )}
            {searchError && (
              <p className="mt-3 text-sm text-vt-error">{searchError}</p>
            )}
          </div>
        )}

        {/* Stats Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className={`glass-strong rounded-2xl p-6 border card-hover animate-scale-in ${
            statsUpdated ? 'border-vt-primary/50 shadow-lg shadow-vt-primary/20' : 'border-vt-primary/20'
          }`}>
            <div className="flex items-center justify-between">
              <div className="flex-1">
                <p className="text-sm font-medium text-vt-muted uppercase tracking-wider mb-2">Total Logs</p>
                <p className={`text-3xl font-bold transition-all duration-300 ${
                  statsUpdated ? 'scale-110 text-vt-primary' : 'text-vt-light'
                }`}>{totalCount.toLocaleString()}</p>
                <div className="mt-3 flex items-center gap-2 text-xs text-vt-success">
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
                  </svg>
                  <span>Tracking</span>
                </div>
              </div>
              <div className="w-14 h-14 bg-gradient-to-br from-vt-primary/30 to-vt-primary/10 rounded-xl flex items-center justify-center">
                <svg className="w-7 h-7 text-vt-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
              </div>
            </div>
          </div>

          <div className={`glass-strong rounded-2xl p-6 border card-hover animate-scale-in stagger-1 ${
            statsUpdated && infectedCount > 0 ? 'border-vt-error/50 shadow-lg shadow-vt-error/20' : 'border-vt-error/20'
          }`}>
            <div className="flex items-center justify-between">
              <div className="flex-1">
                <p className="text-sm font-medium text-vt-muted uppercase tracking-wider mb-2">Threats</p>
                <p className={`text-3xl font-bold transition-all duration-300 ${
                  statsUpdated && infectedCount > 0 ? 'scale-110 text-vt-error' : 'text-vt-error'
                }`}>
                  {infectedCount.toLocaleString()}
                </p>
                <div className="mt-3 flex items-center gap-2 text-xs text-vt-error">
                  {infectedCount > 0 ? (
                    <>
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-1.964-1.333-2.732 0L3.732 16c-.77 1.333.192 3 1.732 3z" />
                      </svg>
                      <span>Active Threats</span>
                    </>
                  ) : (
                    <>
                      <svg className="w-4 h-4 text-vt-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <span className="text-vt-success">All Clear</span>
                    </>
                  )}
                </div>
              </div>
              <div className="w-14 h-14 bg-gradient-to-br from-vt-error/30 to-vt-error/10 rounded-xl flex items-center justify-center">
                <svg className="w-7 h-7 text-vt-error" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-1.964-1.333-2.732 0L3.732 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
            </div>
          </div>

          <div className="glass-strong rounded-2xl p-6 border border-vt-success/20 card-hover animate-scale-in stagger-2">
            <div className="flex items-center justify-between">
              <div className="flex-1">
                <p className="text-sm font-medium text-vt-muted uppercase tracking-wider mb-2">Safe Logs</p>
                <p className="text-3xl font-bold text-vt-success">
                  {safeCount.toLocaleString()}
                </p>
                <div className="mt-3 flex items-center gap-2 text-xs text-vt-success">
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                  <span>Verified</span>
                </div>
              </div>
              <div className="w-14 h-14 bg-gradient-to-br from-vt-success/30 to-vt-success/10 rounded-xl flex items-center justify-center">
                <svg className="w-7 h-7 text-vt-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
            </div>
          </div>

          <div className="glass-strong rounded-2xl p-6 border border-vt-warning/20 card-hover animate-scale-in stagger-3">
            <div className="flex items-center justify-between">
              <div className="flex-1">
                <p className="text-sm font-medium text-vt-muted uppercase tracking-wider mb-2">Threat Rate</p>
                <p className="text-3xl font-bold text-vt-warning">
                  {totalCount > 0 ? ((infectedCount / totalCount) * 100).toFixed(1) : 0}%
                </p>
                <div className="mt-3 w-full bg-vt-muted/20 rounded-full h-1.5 overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-vt-warning to-vt-error rounded-full transition-all duration-500"
                    style={{ width: `${totalCount > 0 ? ((infectedCount / totalCount) * 100) : 0}%` }}
                  ></div>
                </div>
              </div>
              <div className="w-14 h-14 bg-gradient-to-br from-vt-warning/30 to-vt-warning/10 rounded-xl flex items-center justify-center">
                <svg className="w-7 h-7 text-vt-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </div>
            </div>
          </div>
        </div>

        {/* Stream Controls */}
        <div className="mb-6">
          <StreamControls
            isPaused={isStreamPaused}
            pendingCount={pendingCount}
            pendingThreatCount={pendingThreatCount}
            onTogglePause={handleTogglePause}
            onStep={stepPending}
            onApplyAll={applyPending}
            onDiscard={discardPending}
            showAnomaliesOnly={showAnomaliesOnly}
            onToggleAnomalies={handleToggleAnomalies}
            lastUpdate={lastUpdate}
          />
        </div>

        {/* Focused Trail Summary */}
        {focusedIp && (
          <div className="mb-6 glass-strong rounded-2xl border border-vt-warning/30 p-6 animate-slide-up stagger-1">
            <div className="flex items-center justify-between mb-4 gap-3 flex-wrap">
              <div>
                <p className="text-xs uppercase tracking-wider text-vt-warning/70">Focused Trail</p>
                <h3 className="text-2xl font-bold text-vt-light">Activity for {focusedIp}</h3>
              </div>
              <button
                onClick={() => setFocusedIp(null)}
                className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-vt-muted/10 text-xs text-vt-muted hover:bg-vt-muted/20 transition"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
                Clear Focus
              </button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {focusedLogs.length === 0 ? (
                <div className="text-vt-muted text-sm">No recent activity in current window.</div>
              ) : (
                focusedLogs.map((log, index) => {
                  const isTransformerAnomaly = log.anomaly_details?.transformer?.is_anomaly === 1;
                  return (
                    <div
                      key={`${log.timestamp}-${index}`}
                      className={`rounded-xl px-4 py-3 border ${
                        log.infected || isTransformerAnomaly
                          ? 'border-vt-error/40 bg-vt-error/10'
                          : 'border-vt-muted/20 bg-vt-muted/5'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-mono text-vt-muted">{log.timestamp}</span>
                        <span className={`text-xs font-semibold ${log.infected ? 'text-vt-error' : 'text-vt-success'}`}>
                          {log.statusCode}
                        </span>
                      </div>
                      <p className="text-sm text-vt-light font-mono break-all mb-2">{log.apiAccessed}</p>
                      <div className="flex items-center gap-3 text-xs text-vt-muted">
                        {log.infected && (
                          <span className="inline-flex items-center gap-1 text-vt-error">
                            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01" />
                            </svg>
                            Ensemble
                          </span>
                        )}
                        {isTransformerAnomaly && (
                          <span className="inline-flex items-center gap-1 text-vt-warning">
                            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                            </svg>
                            Transformer
                          </span>
                        )}
                        <span>{((log.anomaly_score || 0) * 100).toFixed(1)}% risk</span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        )}

        {/* Logs Table */}
        <div className="glass-strong rounded-2xl border border-vt-muted/20 overflow-hidden shadow-2xl animate-slide-up stagger-1">
          <div className="px-6 py-5 border-b border-vt-muted/20 bg-gradient-to-r from-vt-blue/50 to-transparent">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold text-vt-light">Recent Activity</h2>
                <p className="text-sm text-vt-muted mt-1">Real-time log entries with anomaly detection results</p>
              </div>
              <div className="flex items-center gap-3">
                <div className="text-right">
                  <p className="text-xs text-vt-muted uppercase tracking-wider">Last Update</p>
                  <p className="text-sm font-mono text-vt-light">{new Date().toLocaleTimeString()}</p>
                </div>
              </div>
            </div>
          </div>
          
          {isLoading && !browseResults && !searchResults ? (
            <LoadingSpinner text="Loading logs..." />
          ) : error ? (
            <div className="flex items-center justify-center py-16">
              <div className="text-center max-w-md">
                <div className="w-16 h-16 bg-vt-error/20 rounded-2xl flex items-center justify-center mx-auto mb-4">
                  <svg className="w-8 h-8 text-vt-error" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <p className="text-vt-error font-semibold text-lg mb-2">Failed to load logs</p>
                <p className="text-vt-muted text-sm">{error}</p>
              </div>
            </div>
          ) : (
            <LogsTable
              logs={displayLogs}
              sourceLogs={logs}
              focusedIp={focusedIp}
              onFocusIp={handleFocusIp}
              highlightTransformerTrail
            />
          )}
        </div>

        {/* Bottom Pagination (works for both normal fetch and search) */}
        <div className="mt-4 flex items-center justify-between text-sm text-vt-muted">
          <span>
            {searchResults ? searchTotal : browseTotal} total results
          </span>
          <div className="flex items-center gap-3">
            <Button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1 || searchLoading}
              variant="secondary"
              size="sm"
            >
              Prev
            </Button>
            <span>Page {page}</span>
            <Button
              onClick={() => setPage((p) => p * pageSize < (searchResults ? searchTotal : browseTotal) ? p + 1 : p)}
              disabled={page * pageSize >= (searchResults ? searchTotal : browseTotal) || searchLoading}
              variant="secondary"
              size="sm"
            >
              Next
            </Button>
            <Select
              value={String(pageSize)}
              onChange={(val) => { setPage(1); setPageSize(Number(val)); }}
              options={[
                { label: '10', value: '10' },
                { label: '25', value: '25' },
                { label: '50', value: '50' },
                { label: '100', value: '100' },
              ]}
              density="sm"
              className="w-24"
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardPage;
