import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useParams } from 'react-router-dom';
import LogsTable from '../components/LogsTable';
import LoadingSpinner from '../components/LoadingSpinner';
import { useLogs } from '../hooks/useLogs';
import { useAuth } from '../context/AuthContext';
import Select from '../components/Select';
import Button from '../components/Button';
import { logService } from '../services/logService';
import { projectService, ProjectHealthSummary, ProjectSummary } from '../services/projectService';
import { LogEntry } from '../services/logService';
import { isThreatDetected } from '../utils/helpers';

type TimelineBucket = {
  label: string;
  clean: number;
  threats: number;
};

type EndpointInsight = {
  endpoint: string;
  total: number;
  threats: number;
};

const cx = (...values: Array<string | false | null | undefined>) => values.filter(Boolean).join(' ');

const formatCompactNumber = (value: number): string => {
  return new Intl.NumberFormat('en-US', {
    notation: value >= 1000 ? 'compact' : 'standard',
    maximumFractionDigits: value >= 1000 ? 1 : 0,
  }).format(value);
};

const formatPercent = (value: number): string => `${value.toFixed(value >= 10 ? 1 : 2)}%`;

const resolveLogDate = (log: Pick<LogEntry, 'eventTime' | 'timestamp' | 'ingestTime'>): Date | null => {
  const candidate = log.eventTime || log.timestamp || log.ingestTime;
  if (!candidate) return null;

  const parsed = new Date(candidate);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
};

const buildTimelineBuckets = (logs: LogEntry[]): TimelineBucket[] => {
  const bucketCount = 6;
  if (!logs.length) {
    return Array.from({ length: bucketCount }, (_, index) => ({
      label: `-${(bucketCount - index) * 5}m`,
      clean: 0,
      threats: 0,
    }));
  }

  const resolvedDates = logs
    .map(log => ({ log, date: resolveLogDate(log) }))
    .filter((item): item is { log: LogEntry; date: Date } => item.date !== null);

  if (!resolvedDates.length) {
    return Array.from({ length: bucketCount }, (_, index) => ({
      label: `T${index + 1}`,
      clean: 0,
      threats: 0,
    }));
  }

  const latest = Math.max(...resolvedDates.map(item => item.date.getTime()));
  const bucketDuration = 5 * 60 * 1000;
  const buckets = Array.from({ length: bucketCount }, (_, index) => {
    const bucketStart = new Date(latest - bucketDuration * (bucketCount - index - 1));
    return {
      label: bucketStart.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      clean: 0,
      threats: 0,
    };
  });

  resolvedDates.forEach(({ log, date }) => {
    const offset = Math.floor((latest - date.getTime()) / bucketDuration);
    const bucketIndex = bucketCount - 1 - Math.min(bucketCount - 1, Math.max(0, offset));
    if (bucketIndex < 0 || bucketIndex >= bucketCount) return;

    if (isThreatDetected(log)) {
      buckets[bucketIndex].threats += 1;
    } else {
      buckets[bucketIndex].clean += 1;
    }
  });

  return buckets;
};

const buildEndpointInsights = (logs: LogEntry[]): EndpointInsight[] => {
  const counters = new Map<string, EndpointInsight>();

  logs.forEach(log => {
    const endpoint = log.apiAccessed || 'Unknown endpoint';
    const existing = counters.get(endpoint) ?? { endpoint, total: 0, threats: 0 };
    existing.total += 1;
    if (isThreatDetected(log)) {
      existing.threats += 1;
    }
    counters.set(endpoint, existing);
  });

  return [...counters.values()]
    .sort((left, right) => {
      if (right.threats !== left.threats) return right.threats - left.threats;
      return right.total - left.total;
    })
    .slice(0, 5);
};

const getProjectModeLabel = (health: ProjectHealthSummary | null): string => {
  if (!health?.phase) return 'Pending setup';
  return health.phase
    .replace(/_/g, ' ')
    .replace(/\b\w/g, character => character.toUpperCase());
};

const MetricCard: React.FC<{
  label: string;
  value: string;
  accent: 'primary' | 'danger' | 'warning' | 'success' | 'muted';
  helper: string;
  icon: React.ReactNode;
}> = ({ label, value, accent, helper, icon }) => (
  <div className={cx('ops-kpi-card', `ops-kpi-card--${accent}`)}>
    <div className="ops-kpi-card__header">
      <div>
        <p className="ops-kpi-card__label">{label}</p>
        <p className="ops-kpi-card__value">{value}</p>
      </div>
      <div className="ops-kpi-card__icon">{icon}</div>
    </div>
    <p className="ops-kpi-card__helper">{helper}</p>
  </div>
);

const DashboardPage: React.FC = () => {
  const { projectId } = useParams<{ projectId?: string }>();
  const [currentProject, setCurrentProject] = useState<ProjectSummary | null>(null);
  const [projectHealth, setProjectHealth] = useState<ProjectHealthSummary | null>(null);
  const [projectLoading, setProjectLoading] = useState(false);

  const {
    logs,
    isLoading,
    error,
    totalCount,
    infectedCount,
    parseFailureCount,
    detectionFailureCount,
    incidentCount,
    isStreamPaused,
    pendingCount,
    pendingThreatCount,
    lastUpdate,
    refetch,
    pauseStream,
    resumeStream,
    stepPending,
    applyPending,
    discardPending,
  } = useLogs(projectId);

  const [statsUpdated, setStatsUpdated] = useState(false);
  const [previousLogCount, setPreviousLogCount] = useState(0);
  const [focusedIp, setFocusedIp] = useState<string | null>(null);
  const { userInfo } = useAuth();
  const isPrivileged = userInfo?.role === 'admin' || userInfo?.role === 'manager';

  const [searchIp, setSearchIp] = useState('');
  const [searchApi, setSearchApi] = useState('');
  const [searchStatus, setSearchStatus] = useState('');
  const [searchMalicious, setSearchMalicious] = useState('');
  const [searchParseStatus, setSearchParseStatus] = useState('');
  const [searchDetectionStatus, setSearchDetectionStatus] = useState('');
  const [searchIncidentId, setSearchIncidentId] = useState('');
  const [searchLoading, setSearchLoading] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [searchResults, setSearchResults] = useState<typeof logs | null>(null);
  const [searchTotal, setSearchTotal] = useState(0);
  const [searchInfectedCount, setSearchInfectedCount] = useState(0);
  const [searchParseFailureCount, setSearchParseFailureCount] = useState(0);
  const [searchDetectionFailureCount, setSearchDetectionFailureCount] = useState(0);
  const [searchIncidentCount, setSearchIncidentCount] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const [browseResults, setBrowseResults] = useState<typeof logs | null>(null);
  const [browseTotal, setBrowseTotal] = useState(0);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showAnomaliesOnly, setShowAnomaliesOnly] = useState(false);
  const [exportLoading, setExportLoading] = useState(false);
  const [manualStreamPaused, setManualStreamPaused] = useState(false);
  const [correctionSuccess, setCorrectionSuccess] = useState<{ ip: string; status: string; count: number } | null>(null);

  useEffect(() => {
    if (totalCount !== previousLogCount) {
      setStatsUpdated(true);
      setPreviousLogCount(totalCount);

      const timer = setTimeout(() => {
        setStatsUpdated(false);
      }, 1600);

      return () => clearTimeout(timer);
    }
  }, [totalCount, previousLogCount]);

  const loadProjectContext = useCallback(async () => {
    if (!projectId) {
      setCurrentProject(null);
      setProjectHealth(null);
      return;
    }

    try {
      setProjectLoading(true);
      const [projectResult, healthResult] = await Promise.allSettled([
        projectService.getProject(projectId),
        projectService.getProjectHealth(projectId),
      ]);

      if (projectResult.status === 'fulfilled') {
        setCurrentProject(projectResult.value);
      }

      if (healthResult.status === 'fulfilled') {
        setProjectHealth(healthResult.value);
      }
    } catch (err) {
      console.error('Error loading project context:', err);
    } finally {
      setProjectLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    loadProjectContext();
  }, [loadProjectContext]);

  const displayLogs = useMemo(() => {
    const filterLogs = (items: typeof logs) => {
      if (!showAnomaliesOnly) return items;
      return items.filter(log => {
        const transformerAnomaly = log.anomaly_details?.transformer?.is_anomaly === 1;
        return isThreatDetected(log) || transformerAnomaly;
      });
    };

    if (searchResults) {
      return filterLogs(searchResults);
    }

    if (browseResults && page === 1) {
      const browseIds = new Set(browseResults.map(log => `${log.timestamp}-${log.ipAddress}-${log.apiAccessed}`));
      const uniqueLiveLogs = logs.filter(log => {
        const logId = `${log.timestamp}-${log.ipAddress}-${log.apiAccessed}`;
        return !browseIds.has(logId);
      });

      return [...filterLogs(uniqueLiveLogs), ...browseResults];
    }

    if (browseResults) return filterLogs(browseResults);
    return filterLogs(logs);
  }, [browseResults, logs, page, searchResults, showAnomaliesOnly]);

  const focusedLogs = useMemo(() => {
    if (!focusedIp) return [];
    return logs.filter(log => log.ipAddress === focusedIp).slice(0, 12);
  }, [focusedIp, logs]);

  const isSearchMode = searchResults !== null;
  const displayedTotalCount = isSearchMode ? searchTotal : totalCount;
  const displayedInfectedCount = isSearchMode ? searchInfectedCount : infectedCount;
  const displayedSafeCount = Math.max(0, displayedTotalCount - displayedInfectedCount);
  const displayedParseFailureCount = isSearchMode ? searchParseFailureCount : parseFailureCount;
  const displayedDetectionFailureCount = isSearchMode ? searchDetectionFailureCount : detectionFailureCount;
  const displayedIncidentCount = isSearchMode ? searchIncidentCount : incidentCount;
  const totalResults = isSearchMode ? searchTotal : browseTotal;
  const canGoNext = page * pageSize < totalResults;
  const totalPages = Math.max(1, Math.ceil(totalResults / pageSize));
  const streamLockedByPagination = page > 1 && !isSearchMode;
  const streamIsPaused = streamLockedByPagination || manualStreamPaused || isStreamPaused;
  const correctionCountSuffix = correctionSuccess?.count === 1 ? '' : 's';

  useEffect(() => {
    if (isSearchMode) return;

    const shouldPause = streamLockedByPagination || manualStreamPaused;
    if (shouldPause && !isStreamPaused) {
      pauseStream();
    } else if (!shouldPause && isStreamPaused) {
      resumeStream();
    }
  }, [isSearchMode, isStreamPaused, manualStreamPaused, pauseStream, resumeStream, streamLockedByPagination]);

  useEffect(() => {
    if (isSearchMode) return;

    (async () => {
      const offset = (page - 1) * pageSize;
      const res = await logService.fetchLogs(pageSize, offset, projectId);
      setBrowseResults(res.logs as typeof logs);
      setBrowseTotal(res.total_count || 0);
    })();
    // NOTE: `logs` is intentionally excluded from deps — including it would
    // trigger a server fetch on every websocket event, causing a request storm.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isSearchMode, page, pageSize, projectId]);

  const handleFocusIp = useCallback((ip: string | null) => {
    setFocusedIp(ip);
  }, []);

  const handleToggleStreamPause = useCallback(() => {
    if (streamLockedByPagination) return;
    setManualStreamPaused(current => !current);
  }, [streamLockedByPagination]);

  const handleCorrectLog = useCallback(async (ip: string, status: 'clean' | 'malicious') => {
    try {
      const result = await logService.correctLog(ip, status, projectId);
      setCorrectionSuccess({
        ip,
        status,
        count: result.logs_updated_count || 0,
      });

      setTimeout(() => {
        setCorrectionSuccess(null);
      }, 5000);

      refetch();
    } catch (correctionError) {
      const errorMessage = correctionError instanceof Error ? correctionError.message : 'Failed to correct log status';
      setSearchError(errorMessage);
    }
  }, [projectId, refetch]);

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
      if (searchParseStatus) params.parse_status = searchParseStatus;
      if (searchDetectionStatus) params.detection_status = searchDetectionStatus;
      if (searchIncidentId.trim()) params.incident_id = searchIncidentId.trim();
      if (fromDate) params.from_date = fromDate;
      if (toDate) params.to_date = toDate;
      params.limit = pageSize;
      params.offset = currentOffset;

      const res = await logService.searchLogs(params);
      setSearchResults(res.logs.map(log => ({ ...log })));
      setSearchTotal(res.total_count || 0);
      setSearchInfectedCount(res.infected_count || 0);
      setSearchParseFailureCount(res.parse_failure_count || 0);
      setSearchDetectionFailureCount(res.detection_failure_count || 0);
      setSearchIncidentCount(res.incident_count || 0);
      setBrowseResults(null);
      setBrowseTotal(0);
    } catch (searchFailure) {
      const message = searchFailure instanceof Error ? searchFailure.message : 'Search failed';
      setSearchError(message);
      setSearchResults([]);
      setSearchTotal(0);
      setSearchInfectedCount(0);
      setSearchParseFailureCount(0);
      setSearchDetectionFailureCount(0);
      setSearchIncidentCount(0);
    } finally {
      setSearchLoading(false);
    }
  }, [
    fromDate,
    isPrivileged,
    page,
    pageSize,
    projectId,
    searchApi,
    searchDetectionStatus,
    searchIncidentId,
    searchIp,
    searchMalicious,
    searchParseStatus,
    searchStatus,
    toDate,
  ]);

  const clearSearch = useCallback(() => {
    setSearchIp('');
    setSearchApi('');
    setSearchStatus('');
    setSearchMalicious('');
    setSearchParseStatus('');
    setSearchDetectionStatus('');
    setSearchIncidentId('');
    setSearchResults(null);
    setSearchError(null);
    setFromDate('');
    setToDate('');
    setPage(1);
    setPageSize(25);
    setSearchTotal(0);
    setSearchInfectedCount(0);
    setSearchParseFailureCount(0);
    setSearchDetectionFailureCount(0);
    setSearchIncidentCount(0);

    (async () => {
      const res = await logService.fetchLogs(25, 0, projectId);
      setBrowseResults(res.logs as typeof logs);
      setBrowseTotal(res.total_count || 0);
    })();
  }, [logs, projectId]);

  const handleExport = useCallback(async () => {
    if (!isPrivileged) {
      setSearchError('Export requires admin or manager role');
      return;
    }

    try {
      setExportLoading(true);
      setSearchError('');

      const params: Record<string, unknown> = {};
      if (projectId) params.project_id = projectId;
      if (searchIp.trim()) params.ip = searchIp.trim();
      if (searchApi.trim()) params.api = searchApi.trim();
      if (searchStatus.trim()) params.status_code = Number(searchStatus.trim());
      if (searchMalicious === 'malicious') params.malicious = true;
      if (searchMalicious === 'clean') params.malicious = false;
      if (searchParseStatus) params.parse_status = searchParseStatus;
      if (searchDetectionStatus) params.detection_status = searchDetectionStatus;
      if (searchIncidentId.trim()) params.incident_id = searchIncidentId.trim();
      if (fromDate) params.from_date = fromDate;
      if (toDate) params.to_date = toDate;

      const blob = await logService.exportLogs(params);
      const url = globalThis.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      const projectName = currentProject?.name || 'project';
      link.download = `logguard_${projectName}_${new Date().toISOString().split('T')[0]}.csv`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      globalThis.URL.revokeObjectURL(url);
    } catch (exportFailure) {
      const message = exportFailure instanceof Error ? exportFailure.message : 'Export failed';
      setSearchError(message);
    } finally {
      setExportLoading(false);
    }
  }, [
    currentProject,
    fromDate,
    isPrivileged,
    projectId,
    searchApi,
    searchDetectionStatus,
    searchIncidentId,
    searchIp,
    searchMalicious,
    searchParseStatus,
    searchStatus,
    toDate,
  ]);

  const analysisDataset = useMemo(() => {
    if (searchResults) return searchResults;
    if (page > 1 && browseResults) return browseResults;
    return logs;
  }, [browseResults, logs, page, searchResults]);

  const timelineBuckets = useMemo(() => buildTimelineBuckets(analysisDataset.slice(0, 200)), [analysisDataset]);
  const endpointInsights = useMemo(() => buildEndpointInsights(analysisDataset.slice(0, 200)), [analysisDataset]);

  const chartPeak = useMemo(() => {
    return Math.max(1, ...timelineBuckets.map(bucket => Math.max(bucket.clean, bucket.threats)));
  }, [timelineBuckets]);

  const threatRate = displayedTotalCount > 0 ? (displayedInfectedCount / displayedTotalCount) * 100 : 0;
  const parseSuccessRate = displayedTotalCount > 0 ? ((displayedTotalCount - displayedParseFailureCount) / displayedTotalCount) * 100 : 100;
  const detectionRate = displayedTotalCount > 0 ? ((displayedTotalCount - displayedDetectionFailureCount) / displayedTotalCount) * 100 : 100;
  const liveCoverage = displayedTotalCount > 0 ? (displayedSafeCount / displayedTotalCount) * 100 : 0;

  const protectionHelper = projectHealth
    ? `${projectHealth.has_student_model ? 'Student model active' : 'Teacher warmup'} • ${projectHealth.traffic_profile || currentProject?.traffic_profile || 'standard'} traffic`
    : 'Awaiting project health telemetry';

  const projectMode = getProjectModeLabel(projectHealth);
  const projectWarmupProgress = Math.max(0, Math.min(100, projectHealth?.warmup_progress ?? 0));

  return (
    <div className="dashboard-shell">
      <div className="dashboard-shell__inner">
        <section className="ops-hero">
          <div>
            <div className="ops-breadcrumbs">
              <span>Projects</span>
              <span>/</span>
              <span>{currentProject?.name || 'Security Dashboard'}</span>
            </div>
            <div className="ops-hero__title-row">
              <div className="ops-hero__badge">
                <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <div>
                <h1 className="ops-hero__title">Security Dashboard</h1>
                <p className="ops-hero__subtitle">
                  Live SOC-grade monitoring for anomalies, incidents, parse drift, and detector health.
                </p>
              </div>
            </div>
            <div className="ops-chip-row">
              <span className={cx('ops-chip', streamIsPaused ? 'ops-chip--warning' : 'ops-chip--success')}>
                <span className={cx('ops-chip__dot', streamIsPaused ? 'ops-chip__dot--warning' : 'ops-chip__dot--success ops-chip__dot--pulse')} />
                {streamIsPaused ? 'Stream paused' : 'Live'}
              </span>
              {projectId && <span className="ops-chip">Project ID: {projectId}</span>}
              <span className="ops-chip">{projectMode}</span>
              {currentProject?.log_type && <span className="ops-chip">Log type: {currentProject.log_type}</span>}
              <span className="ops-chip">{protectionHelper}</span>
            </div>
          </div>

          <div className="ops-hero__meta">
            <div className="ops-hero__meta-card">
              <p className="ops-overline">Operator</p>
              <p className="ops-hero__meta-value">{userInfo?.email?.split('@')[0] || 'Guest'}</p>
              <p className="ops-hero__meta-copy">{userInfo?.role || 'observer'}</p>
            </div>
            <div className="ops-hero__meta-card">
              <p className="ops-overline">Last update</p>
              <p className="ops-hero__meta-value">{lastUpdate ? lastUpdate.toLocaleTimeString() : 'N/A'}</p>
              <p className="ops-hero__meta-copy">{streamLockedByPagination ? 'Older page review mode' : 'Realtime stream window'}</p>
            </div>
            <Button variant="secondary" size="md" onClick={handleExport} isLoading={exportLoading} className="ops-hero__action">
              <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              Export current view
            </Button>
          </div>
        </section>

        {!projectId && !projectLoading && (
          <section className="ops-panel ops-empty-state">
            <div className="ops-empty-state__icon">
              <svg className="h-7 w-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <h3>No project selected</h3>
            <p>Please choose a project first so the dashboard can connect to its live log stream.</p>
            <Button onClick={() => { globalThis.location.href = '/projects'; }}>Go to Projects</Button>
          </section>
        )}

        <section className="ops-kpi-grid">
          <MetricCard
            label="Total Logs"
            value={displayedTotalCount.toLocaleString()}
            accent="primary"
            helper={statsUpdated ? 'Fresh traffic arrived in the current window' : `${formatPercent(liveCoverage)} classified as clean`}
            icon={
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
            }
          />
          <MetricCard
            label="Threats"
            value={displayedInfectedCount.toLocaleString()}
            accent="danger"
            helper={`${formatPercent(threatRate)} of the current result set flagged`}
            icon={
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-1.964-1.333-2.732 0L3.732 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            }
          />
          <MetricCard
            label="Incidents"
            value={displayedIncidentCount.toLocaleString()}
            accent="warning"
            helper="Grouped events with shared attack behavior"
            icon={
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7h8m-8 5h8m-8 5h5M6 4h12a2 2 0 012 2v12a2 2 0 01-2 2H6a2 2 0 01-2-2V6a2 2 0 012-2z" />
              </svg>
            }
          />
          <MetricCard
            label="Parse Failures"
            value={displayedParseFailureCount.toLocaleString()}
            accent="muted"
            helper={`${formatPercent(parseSuccessRate)} parse success across this view`}
            icon={
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M5 4h14a1 1 0 011 1v14a1 1 0 01-1 1H5a1 1 0 01-1-1V5a1 1 0 011-1z" />
              </svg>
            }
          />
          <MetricCard
            label="Detection Health"
            value={formatPercent(detectionRate)}
            accent="success"
            helper={`${displayedDetectionFailureCount.toLocaleString()} detector failures observed`}
            icon={
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
            }
          />
        </section>

        <section className="ops-main-grid">
          <div className="ops-panel ops-panel--chart">
            <div className="ops-section-head">
              <div>
                <p className="ops-overline">Traffic analysis</p>
                <h2>Threat versus clean traffic</h2>
              </div>
              <div className="ops-inline-stats">
                <span className="ops-legend ops-legend--danger">Threats</span>
                <span className="ops-legend ops-legend--success">Clean</span>
              </div>
            </div>

            <div className="ops-chart">
              {timelineBuckets.map(bucket => (
                <div key={bucket.label} className="ops-chart__column">
                  <div className="ops-chart__bars">
                    <div
                      className="ops-chart__bar ops-chart__bar--danger"
                      style={{ height: `${Math.max(bucket.threats > 0 ? 12 : 0, (bucket.threats / chartPeak) * 100)}%` }}
                    />
                    <div
                      className="ops-chart__bar ops-chart__bar--success"
                      style={{ height: `${Math.max(bucket.clean > 0 ? 12 : 0, (bucket.clean / chartPeak) * 100)}%` }}
                    />
                  </div>
                  <div className="ops-chart__meta">
                    <span>{bucket.label}</span>
                    <span>{bucket.threats + bucket.clean}</span>
                  </div>
                </div>
              ))}
            </div>

            <div className="ops-chart__footer">
              <div>
                <p className="ops-overline">Recent stream</p>
                <strong>{formatCompactNumber(analysisDataset.length)}</strong>
                <span> logs rendered in the active window</span>
              </div>
              <div>
                <p className="ops-overline">Threat rate</p>
                <strong>{formatPercent(threatRate)}</strong>
                <span> across the current slice</span>
              </div>
            </div>
          </div>

          <div className="ops-panel ops-panel--stack">
            <div>
              <p className="ops-overline">Protection state</p>
              <h2>Project readiness</h2>
            </div>

            <div className="ops-status-block">
              <div className="ops-status-row">
                <span>Detection mode</span>
                <strong>{projectMode}</strong>
              </div>
              <div className="ops-status-row">
                <span>Warmup progress</span>
                <strong>{projectHealth ? formatPercent(projectWarmupProgress) : 'N/A'}</strong>
              </div>
              <div className="ops-progress">
                <div className="ops-progress__fill" style={{ width: `${projectWarmupProgress}%` }} />
              </div>
              <div className="ops-status-row">
                <span>Student model</span>
                <strong>{projectHealth?.has_student_model ? 'Ready' : 'Not ready'}</strong>
              </div>
              <div className="ops-status-row">
                <span>Members</span>
                <strong>{currentProject?.member_count ?? 'N/A'}</strong>
              </div>
            </div>

            <div className="ops-stack-section">
              <div className="ops-section-head">
                <div>
                  <p className="ops-overline">Stream controls</p>
                  <h3>Live ingestion</h3>
                </div>
                <span className={cx('ops-chip', streamLockedByPagination && 'ops-chip--warning')}>
                  {streamLockedByPagination ? 'Live stream locks on older pages' : 'Queue controls ready'}
                </span>
              </div>

              <div className="ops-action-grid">
                <button type="button" onClick={handleToggleStreamPause} disabled={streamLockedByPagination} className={cx('ops-action-button', streamIsPaused ? 'ops-action-button--danger' : 'ops-action-button--primary')}>
                  {streamIsPaused ? 'Resume stream' : 'Pause stream'}
                </button>
                <button type="button" onClick={() => setShowAnomaliesOnly(current => !current)} className={cx('ops-action-button', showAnomaliesOnly && 'ops-action-button--warning')}>
                  {showAnomaliesOnly ? 'Showing anomalies' : 'Show anomalies only'}
                </button>
                <button type="button" onClick={stepPending} disabled={pendingCount === 0} className="ops-action-button">
                  Step queue
                </button>
                <button type="button" onClick={applyPending} disabled={pendingCount === 0} className="ops-action-button ops-action-button--success">
                  Apply pending
                </button>
                <button type="button" onClick={discardPending} disabled={pendingCount === 0} className="ops-action-button">
                  Clear queue
                </button>
              </div>

              <div className="ops-queue-card">
                <div>
                  <p className="ops-overline">Pending events</p>
                  <h3>{pendingCount.toLocaleString()}</h3>
                </div>
                <div>
                  <p className="ops-overline">Threats in queue</p>
                  <h3>{pendingThreatCount.toLocaleString()}</h3>
                </div>
              </div>
            </div>

            <div className="ops-stack-section">
              <div className="ops-section-head">
                <div>
                  <p className="ops-overline">Hot endpoints</p>
                  <h3>Most active surfaces</h3>
                </div>
              </div>
              <div className="ops-list">
                {endpointInsights.length === 0 ? (
                  <p className="ops-muted-copy">No endpoint activity available for the current filter set.</p>
                ) : (
                  endpointInsights.map(item => (
                    <div key={item.endpoint} className="ops-list__item">
                      <div>
                        <p className="ops-list__title">{item.endpoint}</p>
                        <p className="ops-list__copy">{item.total.toLocaleString()} events</p>
                      </div>
                      <div className="ops-list__meta">
                        <strong>{item.threats.toLocaleString()}</strong>
                        <span>threats</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </section>

        {isPrivileged && projectId && (
          <section className="ops-panel ops-panel--filters">
            <div className="ops-section-head">
              <div>
                <p className="ops-overline">Search and review</p>
                <h2>Event filters</h2>
              </div>
              <div className="ops-inline-actions">
                <Button onClick={handleSearch} isLoading={searchLoading} variant="primary" size="md">
                  Search
                </Button>
                <Button onClick={clearSearch} variant="secondary" size="md">
                  Clear
                </Button>
                <Button type="button" onClick={() => setShowAdvanced(current => !current)} variant="secondary" size="md">
                  {showAdvanced ? 'Hide advanced' : 'Advanced filters'}
                </Button>
              </div>
            </div>

            <div className="ops-filter-grid">
              <label className="ops-field">
                <span>IP address</span>
                <input
                  value={searchIp}
                  onChange={event => setSearchIp(event.target.value)}
                  placeholder="192.168.1.45"
                  className="ops-input"
                />
              </label>
              <label className="ops-field">
                <span>API endpoint</span>
                <input
                  value={searchApi}
                  onChange={event => setSearchApi(event.target.value)}
                  placeholder="/api/auth/login"
                  className="ops-input"
                />
              </label>
              <label className="ops-field">
                <span>Decision state</span>
                <Select
                  value={searchMalicious}
                  onChange={value => setSearchMalicious(value as string)}
                  options={[
                    { label: 'All traffic', value: '' },
                    { label: 'Malicious', value: 'malicious' },
                    { label: 'Clean', value: 'clean' },
                  ]}
                  density="sm"
                />
              </label>
              <label className="ops-field">
                <span>Status code</span>
                <input
                  value={searchStatus}
                  onChange={event => setSearchStatus(event.target.value.replace(/\D/g, ''))}
                  placeholder="403"
                  inputMode="numeric"
                  className="ops-input"
                />
              </label>
            </div>

            {showAdvanced && (
              <div className="ops-filter-grid ops-filter-grid--advanced">
                <label className="ops-field">
                  <span>Parse status</span>
                  <Select
                    value={searchParseStatus}
                    onChange={value => setSearchParseStatus(value as string)}
                    options={[
                      { label: 'All', value: '' },
                      { label: 'Parsed', value: 'parsed' },
                      { label: 'Failed', value: 'failed' },
                    ]}
                    density="sm"
                  />
                </label>
                <label className="ops-field">
                  <span>Detection status</span>
                  <Select
                    value={searchDetectionStatus}
                    onChange={value => setSearchDetectionStatus(value as string)}
                    options={[
                      { label: 'All', value: '' },
                      { label: 'Scored', value: 'scored' },
                      { label: 'Failed', value: 'failed' },
                      { label: 'Skipped', value: 'skipped' },
                    ]}
                    density="sm"
                  />
                </label>
                <label className="ops-field">
                  <span>Incident ID</span>
                  <input
                    value={searchIncidentId}
                    onChange={event => setSearchIncidentId(event.target.value)}
                    placeholder="INC-2847"
                    className="ops-input"
                  />
                </label>
                <label className="ops-field">
                  <span>From</span>
                  <input type="date" value={fromDate} onChange={event => setFromDate(event.target.value)} className="ops-input" />
                </label>
                <label className="ops-field">
                  <span>To</span>
                  <input type="date" value={toDate} onChange={event => setToDate(event.target.value)} className="ops-input" />
                </label>
              </div>
            )}

            {searchError && <p className="ops-error-copy">{searchError}</p>}
          </section>
        )}

        {correctionSuccess && (
          <section className="ops-panel ops-panel--success">
            <div className="ops-alert">
              <div className="ops-alert__icon">
                <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <div className="ops-alert__copy">
                <h3>Human correction recorded</h3>
                <p>
                  IP <strong>{correctionSuccess.ip}</strong> marked as <strong>{correctionSuccess.status.toUpperCase()}</strong>.{' '}
                  {correctionSuccess.count} log{correctionCountSuffix} updated.
                </p>
              </div>
              <button type="button" onClick={() => setCorrectionSuccess(null)} className="ops-alert__dismiss" aria-label="Dismiss notification">
                <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          </section>
        )}

        {focusedIp && (
          <section className="ops-panel">
            <div className="ops-section-head">
              <div>
                <p className="ops-overline">Focused trail</p>
                <h2>Activity for {focusedIp}</h2>
              </div>
              <button type="button" onClick={() => setFocusedIp(null)} className="ops-action-button">
                Clear focus
              </button>
            </div>

            <div className="ops-activity-grid">
              {focusedLogs.length === 0 ? (
                <p className="ops-muted-copy">No recent activity in the active stream window.</p>
              ) : (
                focusedLogs.map(log => {
                  const transformerAnomaly = log.anomaly_details?.transformer?.is_anomaly === 1;
                  const focusedLogKey = `${log.timestamp}-${log.ipAddress}-${log.apiAccessed}-${log.statusCode}`;
                  return (
                    <article key={focusedLogKey} className={cx('ops-activity-card', (isThreatDetected(log) || transformerAnomaly) && 'ops-activity-card--danger')}>
                      <div className="ops-activity-card__head">
                        <span>{log.eventTime || log.timestamp}</span>
                        <strong>{log.statusCode}</strong>
                      </div>
                      <p>{log.apiAccessed}</p>
                      <div className="ops-activity-card__meta">
                        {isThreatDetected(log) && <span>Ensemble threat</span>}
                        {transformerAnomaly && <span>Transformer anomaly</span>}
                        <span>{((log.anomaly_score || 0) * 100).toFixed(1)}% risk</span>
                      </div>
                    </article>
                  );
                })
              )}
            </div>
          </section>
        )}

        <section className="ops-panel">
          <div className="ops-section-head">
            <div>
              <p className="ops-overline">Live review</p>
              <h2>Recent activity</h2>
              <p className="ops-muted-copy">Deep row details, correction actions, IP focus mode, and detector explainability remain available.</p>
            </div>
            <div className="ops-inline-stats">
              <span className="ops-chip">{totalResults.toLocaleString()} total results</span>
              <span className={cx('ops-chip', displayedInfectedCount > 0 && 'ops-chip--danger')}>
                {displayedInfectedCount.toLocaleString()} flagged in current view
              </span>
            </div>
          </div>

          {isLoading && !browseResults && !searchResults ? (
            <LoadingSpinner text="Loading logs..." />
          ) : error ? (
            <div className="ops-error-state">
              <div className="ops-empty-state__icon">
                <svg className="h-7 w-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <h3>Failed to load logs</h3>
              <p>{error}</p>
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
        </section>

        <section className="ops-pagination">
          <span>{totalResults.toLocaleString()} total results</span>
          <div className="ops-pagination__controls">
            <Button onClick={() => setPage(current => Math.max(1, current - 1))} disabled={page === 1 || searchLoading} variant="secondary" size="sm">
              Prev
            </Button>
            <span>Page {page} of {totalPages}</span>
            <Button onClick={() => setPage(current => (canGoNext ? current + 1 : current))} disabled={!canGoNext || searchLoading} variant="secondary" size="sm">
              Next
            </Button>
            <Select
              value={String(pageSize)}
              onChange={value => {
                setPage(1);
                setPageSize(Number(value));
              }}
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
        </section>
      </div>
    </div>
  );
};

export default DashboardPage;
