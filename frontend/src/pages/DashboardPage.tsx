import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useParams } from 'react-router-dom';
import LogsTable from '../components/LogsTable';
import LoadingSpinner from '../components/LoadingSpinner';
import { useLogs } from '../hooks/useLogs';
// import StreamControls from '../components/StreamControls';
import { useAuth } from '../context/AuthContext';
import Select from '../components/Select';
import Button from '../components/Button';
import { logService } from '../services/logService';
import { projectService, ProjectSummary } from '../services/projectService';

const DashboardPage: React.FC = () => {
  const { projectId } = useParams<{ projectId?: string }>();
  const [currentProject, setCurrentProject] = useState<ProjectSummary | null>(null);
  const [projectLoading, setProjectLoading] = useState(false);
  
  const {
    logs,
    isLoading,
    error,
    totalCount,
    infectedCount,
    safeCount,
    isStreamPaused,
    refetch,
    // pendingCount,
    // pendingThreatCount,
    // lastUpdate,
    pauseStream,
    resumeStream,
    // stepPending,
    // applyPending,
    // discardPending,
  } = useLogs(projectId); // Pass projectId to useLogs hook
  
  const [statsUpdated, setStatsUpdated] = useState(false);
  const [previousLogCount, setPreviousLogCount] = useState(0);
  // showAnomaliesOnly is still used in displayLogs logic
  const showAnomaliesOnly = false; // Set to constant since StreamControls is commented out
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

  // Load project information
  useEffect(() => {
    if (projectId) {
      loadProjectInfo();
    }
  }, [projectId]);

  const loadProjectInfo = async () => {
    if (!projectId) return;
    
    try {
      setProjectLoading(true);
      const project = await projectService.getProject(projectId);
      setCurrentProject(project);
    } catch (err) {
      console.error('Error loading project:', err);
    } finally {
      setProjectLoading(false);
    }
  };
  const [browseResults, setBrowseResults] = useState<typeof logs | null>(null);
  const [browseTotal, setBrowseTotal] = useState(0);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [exportLoading, setExportLoading] = useState(false);
  const [correctionSuccess, setCorrectionSuccess] = useState<{ip: string, status: string, count: number} | null>(null);

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

  // Calculate detection rate
  const detectionRate = useMemo(() => {
    if (totalCount === 0) return 0;
    return ((infectedCount / totalCount) * 100).toFixed(1);
  }, [totalCount, infectedCount]);

  // const handleTogglePause = useCallback(() => {
  //   if (isStreamPaused) {
  //     resumeStream();
  //   } else {
  //     pauseStream();
  //   }
  // }, [isStreamPaused, pauseStream, resumeStream]);

  // const handleToggleAnomalies = useCallback(() => {
  //   setShowAnomaliesOnly(prev => !prev);
  // }, []);

  const handleFocusIp = useCallback((ip: string | null) => {
    setFocusedIp(ip);
  }, []);

  const handleCorrectLog = useCallback(async (ip: string, status: 'clean' | 'malicious') => {
    try {
      const result = await logService.correctLog(ip, status, projectId);
      
      // Show success notification with details
      setCorrectionSuccess({
        ip,
        status,
        count: result.logs_updated_count || 0
      });
      
      // Auto-hide notification after 5 seconds
      setTimeout(() => {
        setCorrectionSuccess(null);
      }, 5000);
      
      // Refetch logs after successful correction
      refetch();
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to correct log status';
      setSearchError(errorMessage);
    }
  }, [refetch, projectId]);

  const handleSearch = useCallback(async () => {
    if (!isPrivileged) return;
    try {
      setSearchLoading(true);
      setSearchError(null);
      const currentOffset = (page - 1) * pageSize;
      const params: Record<string, unknown> = {};
      if (projectId) params.project_id = projectId;
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
  }, [isPrivileged, projectId, searchIp, searchApi, searchStatus, searchMalicious, fromDate, toDate, page, pageSize]);

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
      const res = await logService.fetchLogs(25, 0, projectId);
      setBrowseResults(res.logs as typeof logs);
      setBrowseTotal(res.total_count || 0);
    })();
  }, [projectId]);

  const handleExport = useCallback(async () => {
    if (!isPrivileged) {
      setSearchError('Export requires admin or manager role');
      return;
    }
    try {
      setExportLoading(true);
      setSearchError(''); // Clear any previous errors
      const params: Record<string, unknown> = {};
      if (projectId) params.project_id = projectId;
      if (searchIp.trim()) params.ip = searchIp.trim();
      if (searchApi.trim()) params.api = searchApi.trim();
      if (searchStatus.trim()) params.status_code = Number(searchStatus.trim());
      if (searchMalicious === 'malicious') params.malicious = true;
      if (searchMalicious === 'clean') params.malicious = false;
      if (fromDate) params.from_date = fromDate;
      if (toDate) params.to_date = toDate;

      const blob = await logService.exportLogs(params);
      
      // Create download link
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      const projectName = currentProject?.name || 'project';
      link.download = `logguard_${projectName}_${new Date().toISOString().split('T')[0]}.csv`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Export failed';
      setSearchError(msg);
    } finally {
      setExportLoading(false);
    }
  }, [isPrivileged, projectId, currentProject, searchIp, searchApi, searchStatus, searchMalicious, fromDate, toDate]);

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
      const res = await logService.fetchLogs(pageSize, offset, projectId);
      setBrowseResults(res.logs as typeof logs);
      setBrowseTotal(res.total_count || 0);
    })();
  }, [searchResults, page, pageSize, projectId]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-vt-dark via-vt-dark to-vt-blue/5">
      <div className="max-w-full mx-auto px-4 sm:px-6 lg:px-8 xl:px-12 py-6 lg:py-10">
        {/* Header */}
        <div className="mb-10 animate-slide-down">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
            <div className="flex flex-col">
              <div className="flex items-center gap-4 mb-3">
                <div className="w-12 h-12 lg:w-14 lg:h-14 bg-gradient-to-br from-vt-primary to-vt-success rounded-2xl flex items-center justify-center shadow-lg shadow-vt-primary/30">
                  <svg className="w-7 h-7 lg:w-8 lg:h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <div>
                  <h1 className="text-3xl lg:text-5xl font-bold gradient-text">Security Dashboard</h1>
                  {currentProject && (
                    <p className="text-sm text-vt-primary mt-1">{currentProject.name}</p>
                  )}
                </div>
              </div>
              <p className="text-vt-muted text-base lg:text-lg ml-16 lg:ml-18">Real-time log monitoring with AI-powered threat detection</p>
            </div>
            <div className="flex items-center gap-3 ml-16 lg:ml-0">
              <div className="glass-strong px-4 py-2 rounded-xl border border-vt-primary/30">
                <div className="text-xs text-vt-muted uppercase tracking-wider mb-1">Status</div>
                <div className="flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${isStreamPaused ? 'bg-vt-warning animate-pulse' : 'bg-vt-success'}`}></div>
                  <span className="text-sm font-semibold text-vt-light">{isStreamPaused ? 'Paused' : 'Active'}</span>
                </div>
              </div>
              <div className="glass-strong px-4 py-2 rounded-xl border border-vt-muted/30">
                <div className="text-xs text-vt-muted uppercase tracking-wider mb-1">User</div>
                <span className="text-sm font-semibold text-vt-light">{userInfo?.email?.split('@')[0] || 'Guest'}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Project Not Selected Message */}
        {!projectId && !projectLoading && (
          <div className="glass-strong rounded-2xl p-8 border border-vt-warning/30 mb-8 text-center">
            <svg className="mx-auto h-12 w-12 text-vt-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <h3 className="mt-4 text-lg font-medium text-vt-light">No Project Selected</h3>
            <p className="mt-2 text-sm text-vt-muted">Please select a project from the Projects page to view logs.</p>
            <Button
              onClick={() => window.location.href = '/projects'}
              className="mt-4"
            >
              Go to Projects
            </Button>
          </div>
        )}

        {/* Search (Admin/Manager only) */}
        {isPrivileged && projectId && (
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
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 lg:gap-6 mb-8 lg:mb-10">
          <div className={`glass-strong rounded-2xl p-5 lg:p-6 border card-hover animate-scale-in transition-all duration-300 ${
            statsUpdated ? 'border-vt-primary/60 shadow-xl shadow-vt-primary/30 scale-105' : 'border-vt-primary/20'
          }`}>
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-2">
                  <p className="text-xs lg:text-sm font-semibold text-vt-muted uppercase tracking-wider">Total Logs</p>
                  {statsUpdated && (
                    <span className="inline-flex items-center px-2 py-0.5 rounded-full bg-vt-primary/20 text-vt-primary text-[10px] font-bold animate-pulse">
                      NEW
                    </span>
                  )}
                </div>
                <p className={`text-3xl lg:text-4xl font-bold transition-all duration-300 ${
                  statsUpdated ? 'text-vt-primary' : 'text-vt-light'
                }`}>{totalCount.toLocaleString()}</p>
                <div className="mt-3 flex items-center gap-2 text-xs text-vt-success">
                  <div className="w-1.5 h-1.5 rounded-full bg-vt-success animate-pulse"></div>
                  <span className="font-medium">Live Tracking</span>
                </div>
              </div>
              <div className="w-12 h-12 lg:w-14 lg:h-14 bg-gradient-to-br from-vt-primary/40 to-vt-primary/20 rounded-xl flex items-center justify-center shadow-lg">
                <svg className="w-6 h-6 lg:w-7 lg:h-7 text-vt-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
              </div>
            </div>
          </div>

          <div className={`glass-strong rounded-2xl p-5 lg:p-6 border card-hover animate-scale-in stagger-1 transition-all duration-300 ${
            statsUpdated && infectedCount > 0 ? 'border-vt-error/60 shadow-xl shadow-vt-error/30' : 'border-vt-error/20'
          }`}>
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <p className="text-xs lg:text-sm font-semibold text-vt-muted uppercase tracking-wider mb-2">Threats Detected</p>
                <p className={`text-3xl lg:text-4xl font-bold transition-all duration-300 ${
                  statsUpdated && infectedCount > 0 ? 'text-vt-error' : 'text-vt-error'
                }`}>
                  {infectedCount.toLocaleString()}
                </p>
                <div className="mt-3 flex items-center gap-2 text-xs">
                  {infectedCount > 0 ? (
                    <>
                      <div className="w-1.5 h-1.5 rounded-full bg-vt-error animate-pulse"></div>
                      <span className="text-vt-error font-medium">Active Threats</span>
                    </>
                  ) : (
                    <>
                      <div className="w-1.5 h-1.5 rounded-full bg-vt-success"></div>
                      <span className="text-vt-success font-medium">All Clear</span>
                    </>
                  )}
                </div>
              </div>
              <div className="w-12 h-12 lg:w-14 lg:h-14 bg-gradient-to-br from-vt-error/40 to-vt-error/20 rounded-xl flex items-center justify-center shadow-lg">
                <svg className="w-6 h-6 lg:w-7 lg:h-7 text-vt-error" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-1.964-1.333-2.732 0L3.732 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
            </div>
          </div>

          <div className="glass-strong rounded-2xl p-5 lg:p-6 border border-vt-success/20 card-hover animate-scale-in stagger-2 transition-all duration-300">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <p className="text-xs lg:text-sm font-semibold text-vt-muted uppercase tracking-wider mb-2">Safe Logs</p>
                <p className="text-3xl lg:text-4xl font-bold text-vt-success">
                  {safeCount.toLocaleString()}
                </p>
                <div className="mt-3 flex items-center gap-2 text-xs">
                  <div className="w-1.5 h-1.5 rounded-full bg-vt-success"></div>
                  <span className="text-vt-success font-medium">Verified Clean</span>
                </div>
              </div>
              <div className="w-12 h-12 lg:w-14 lg:h-14 bg-gradient-to-br from-vt-success/40 to-vt-success/20 rounded-xl flex items-center justify-center shadow-lg">
                <svg className="w-6 h-6 lg:w-7 lg:h-7 text-vt-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
            </div>
          </div>

          <div className="glass-strong rounded-2xl p-5 lg:p-6 border border-vt-warning/20 card-hover animate-scale-in stagger-3 transition-all duration-300">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <p className="text-xs lg:text-sm font-semibold text-vt-muted uppercase tracking-wider mb-2">Detection Rate</p>
                <p className="text-3xl lg:text-4xl font-bold text-vt-accent">
                  {detectionRate}%
                </p>
                <div className="mt-3 flex items-center gap-2 text-xs">
                  <div className="w-1.5 h-1.5 rounded-full bg-vt-accent"></div>
                  <span className="text-vt-accent font-medium">Model Accuracy</span>
                </div>
              </div>
              <div className="w-12 h-12 lg:w-14 lg:h-14 bg-gradient-to-br from-vt-accent/40 to-vt-accent/20 rounded-xl flex items-center justify-center shadow-lg">
                <svg className="w-6 h-6 lg:w-7 lg:h-7 text-vt-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
              </div>
            </div>
          </div>
        </div>

        {/* Success Notification for Human Corrections */}
        {correctionSuccess && (
          <div className="mb-6 glass-strong rounded-xl border border-vt-success/40 bg-gradient-to-r from-vt-success/20 to-vt-success/5 p-5 animate-slide-up shadow-xl shadow-vt-success/20">
            <div className="flex items-start gap-4">
              <div className="w-10 h-10 bg-gradient-to-br from-vt-success/50 to-vt-success/30 rounded-lg flex items-center justify-center flex-shrink-0">
                <svg className="w-5 h-5 text-vt-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <div className="flex-1">
                <h4 className="text-sm font-semibold text-vt-success mb-1">Human Correction Recorded</h4>
                <p className="text-sm text-vt-light/80">
                  IP <span className="font-mono font-semibold text-vt-light">{correctionSuccess.ip}</span> marked as{' '}
                  <span className={`font-semibold ${correctionSuccess.status === 'clean' ? 'text-vt-success' : 'text-vt-error'}`}>
                    {correctionSuccess.status.toUpperCase()}
                  </span>
                  {' '}• {correctionSuccess.count} log{correctionSuccess.count !== 1 ? 's' : ''} updated
                </p>
              </div>
              <button
                onClick={() => setCorrectionSuccess(null)}
                className="text-vt-muted hover:text-vt-light transition-colors p-1"
                aria-label="Dismiss notification"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          </div>
        )}

        {/* Stream Controls */}
        {/* <div className="mb-6">
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
        </div> */}

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
              <div className="flex items-center gap-4">
                <div>
                  <h2 className="text-2xl font-bold text-vt-light">Recent Activity</h2>
                  <p className="text-sm text-vt-muted mt-1">Real-time log entries with anomaly detection results</p>
                </div>
                {isPrivileged && (
                  <Button
                    onClick={handleExport}
                    isLoading={exportLoading}
                    variant="secondary"
                    size="sm"
                    title="Export logs to CSV"
                    className="ml-4"
                  >
                    <svg className="w-4 h-4 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    Export CSV
                  </Button>
                )}
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
              onCorrectLog={handleCorrectLog}
              canCorrectLogs={isPrivileged}
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
