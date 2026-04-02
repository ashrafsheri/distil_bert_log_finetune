import { useState, useEffect, useCallback, useRef } from 'react';
import { LogEntry, LogSearchResponse } from '../services/logService';
import { API_ENDPOINTS, WEBSOCKET_RECONNECT_DELAY, MAX_LOGS_DISPLAY } from '../utils/constants';
import { apiService, websocketService } from '../services/apiService';

interface UseLogsReturn {
  logs: LogEntry[];
  isLoading: boolean;
  error: string | null;
  refetch: () => void;
  totalCount: number;
  infectedCount: number;
  safeCount: number;
  parseFailureCount: number;
  detectionFailureCount: number;
  incidentCount: number;
  isStreamPaused: boolean;
  pendingCount: number;
  pendingThreatCount: number;
  lastUpdate?: Date | null;
  pauseStream: () => void;
  resumeStream: () => void;
  stepPending: () => void;
  applyPending: () => void;
  discardPending: () => void;
}

export const useLogs = (projectId?: string): UseLogsReturn => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [ws, setWs] = useState<WebSocket | null>(null);
  const [totalCount, setTotalCount] = useState(0);
  const [infectedCount, setInfectedCount] = useState(0);
  const [parseFailureCount, setParseFailureCount] = useState(0);
  const [detectionFailureCount, setDetectionFailureCount] = useState(0);
  const [incidentCount, setIncidentCount] = useState(0);
  const [isStreamPaused, setIsStreamPaused] = useState(false);
  const [pendingLogs, setPendingLogs] = useState<LogEntry[]>([]);
  const [pendingThreatCount, setPendingThreatCount] = useState(0);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const isStreamPausedRef = useRef(false);
  const seenLogKeysRef = useRef<Set<string>>(new Set());
  const seenIncidentIdsRef = useRef<Set<string>>(new Set());

  const getLogKey = useCallback((log: LogEntry): string => {
    return [
      log.eventTime || '',
      log.timestamp || '',
      log.ipAddress || '',
      log.apiAccessed || '',
      String(log.statusCode ?? ''),
      log.parseStatus || '',
      log.detectionStatus || '',
    ].join('|');
  }, []);

  const rebuildSeenRefs = useCallback((items: LogEntry[]) => {
    seenLogKeysRef.current = new Set(items.map(getLogKey));
    seenIncidentIdsRef.current = new Set(
      items
        .map(item => item.incidentId)
        .filter((incidentId): incidentId is string => Boolean(incidentId))
    );
  }, [getLogKey]);

  const resolveLogTimestamp = useCallback((log: LogEntry): Date => {
    const candidate = log.eventTime || log.timestamp || log.ingestTime;
    const parsed = candidate ? new Date(candidate) : null;
    if (parsed && !Number.isNaN(parsed.getTime())) {
      return parsed;
    }
    return new Date();
  }, []);

  const fetchInitialLogs = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);
      
      // Build URL with projectId if provided
      let url = API_ENDPOINTS.FETCH_LOGS;
      if (projectId) {
        url += `?project_id=${encodeURIComponent(projectId)}`;
      }
      
      // Use apiService for authenticated request
      const response = await apiService.get<LogSearchResponse>(url);
      const data = response.data;
      
      if (Array.isArray(data.logs)) {
        setLogs(data.logs);
        rebuildSeenRefs(data.logs);
        
        // Set counts from backend response
        setTotalCount(data.total_count || 0);
        setInfectedCount(data.infected_count || 0);
        setParseFailureCount(data.parse_failure_count || 0);
        setDetectionFailureCount(data.detection_failure_count || 0);
        setIncidentCount(data.incident_count || 0);
        setLastUpdate(data.logs[0] ? resolveLogTimestamp(data.logs[0]) : new Date());
        
        // If we get a websocket ID, establish WebSocket connection
        if (data.websocket_id) {
          establishWebSocketConnection(data.websocket_id);
        }
      } else {
        throw new TypeError('Invalid data format received');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch logs');
    } finally {
      setIsLoading(false);
    }
  }, [projectId, resolveLogTimestamp]);

  const enqueuePendingLog = useCallback((log: LogEntry) => {
    setPendingLogs(prev => [log, ...prev].slice(0, MAX_LOGS_DISPLAY));
    if (log.infected) {
      setPendingThreatCount(prev => prev + 1);
    }
  }, []);

  const applyLogToDisplay = useCallback((log: LogEntry) => {
    setLogs(prevLogs => [log, ...prevLogs].slice(0, MAX_LOGS_DISPLAY));
    setLastUpdate(resolveLogTimestamp(log));
  }, [resolveLogTimestamp]);

  const applyAllPending = useCallback(() => {
    setPendingLogs(currentPending => {
      if (currentPending.length === 0) {
        return currentPending;
      }
      setLogs(prevLogs => [...currentPending, ...prevLogs].slice(0, MAX_LOGS_DISPLAY));
      setLastUpdate(resolveLogTimestamp(currentPending[0]));
      setPendingThreatCount(0);
      return [];
    });
  }, [resolveLogTimestamp]);

  const discardPending = useCallback(() => {
    setPendingLogs([]);
    setPendingThreatCount(0);
  }, []);

  const stepPending = useCallback(() => {
    setPendingLogs(prev => {
      if (prev.length === 0) {
        return prev;
      }
      const [next, ...rest] = prev;
      applyLogToDisplay(next);
      if (next.infected) {
        setPendingThreatCount(count => Math.max(0, count - 1));
      }
      return rest;
    });
  }, [applyLogToDisplay]);

  const establishWebSocketConnection = useCallback(async (websocketId: string) => {
    try {
      // Close existing connection if any
      if (ws) {
        ws.close();
      }

      // Create authenticated WebSocket connection
      const websocketUrl = projectId
        ? `${API_ENDPOINTS.WEBSOCKET_BASE}/${websocketId}?project_id=${encodeURIComponent(projectId)}`
        : `${API_ENDPOINTS.WEBSOCKET_BASE}/${websocketId}`;
      
      const websocket = await websocketService.createConnection(
        websocketUrl,
        () => {
          setError(null);
        },
        (event) => {
          try {
            const message = JSON.parse(event.data);
            
            // Handle wrapped WebSocket message format
            if (message?.type === 'log_update' && message.data) {
              const newLog = message.data;
              const logKey = getLogKey(newLog);
              if (seenLogKeysRef.current.has(logKey)) {
                return;
              }
              seenLogKeysRef.current.add(logKey);
              
              // Update logs array
              if (isStreamPausedRef.current) {
                enqueuePendingLog(newLog);
              } else {
                applyLogToDisplay(newLog);
              }
              
              // Update counts
              setTotalCount(prev => prev + 1);
              if (newLog.infected) {
                setInfectedCount(prev => prev + 1);
              }
              if (newLog.parseStatus === 'failed') {
                setParseFailureCount(prev => prev + 1);
              }
              if (newLog.detectionStatus === 'failed') {
                setDetectionFailureCount(prev => prev + 1);
              }
              if (newLog.infected && newLog.incidentId && !seenIncidentIdsRef.current.has(newLog.incidentId)) {
                seenIncidentIdsRef.current.add(newLog.incidentId);
                setIncidentCount(prev => prev + 1);
              }
            } else if (message && typeof message === 'object' && message.ipAddress) {
              // Handle direct log format (fallback)
              const logKey = getLogKey(message);
              if (seenLogKeysRef.current.has(logKey)) {
                return;
              }
              seenLogKeysRef.current.add(logKey);
              
              // Update logs array
              if (isStreamPausedRef.current) {
                enqueuePendingLog(message);
              } else {
                applyLogToDisplay(message);
              }
              
              // Update counts
              setTotalCount(prev => prev + 1);
              if (message.infected) {
                setInfectedCount(prev => prev + 1);
              }
              if (message.parseStatus === 'failed') {
                setParseFailureCount(prev => prev + 1);
              }
              if (message.detectionStatus === 'failed') {
                setDetectionFailureCount(prev => prev + 1);
              }
              if (message.infected && message.incidentId && !seenIncidentIdsRef.current.has(message.incidentId)) {
                seenIncidentIdsRef.current.add(message.incidentId);
                setIncidentCount(prev => prev + 1);
              }
            }
          } catch {
            // Silently handle parsing errors
          }
        },
        () => {
          setError('WebSocket connection failed');
        },
        () => {
          setWs(null);
          // Attempt to reconnect after delay
          setTimeout(() => {
            establishWebSocketConnection(websocketId);
          }, WEBSOCKET_RECONNECT_DELAY);
        }
      );

      setWs(websocket);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to establish real-time connection';
      setError(errorMessage);
      setWs(null);
      
      // Attempt to reconnect after delay if it's an auth error
      if (errorMessage.includes('Authentication') || errorMessage.includes('token')) {
        setTimeout(() => {
          establishWebSocketConnection(websocketId);
        }, WEBSOCKET_RECONNECT_DELAY);
      }
    }
  }, [ws, enqueuePendingLog, applyLogToDisplay, projectId]);

  const refetch = useCallback(() => {
    fetchInitialLogs();
  }, [fetchInitialLogs]);

  useEffect(() => {
    fetchInitialLogs();

    // Cleanup WebSocket on unmount
    return () => {
      if (ws) {
        ws.close();
      }
    };
  }, [fetchInitialLogs, projectId]);

  // Cleanup WebSocket when component unmounts
  useEffect(() => {
    return () => {
      if (ws) {
        ws.close();
      }
    };
  }, [ws]);

  useEffect(() => {
    isStreamPausedRef.current = isStreamPaused;
  }, [isStreamPaused]);

  const pauseStream = useCallback(() => {
    setIsStreamPaused(true);
    isStreamPausedRef.current = true;
  }, []);

  const resumeStream = useCallback(() => {
    setIsStreamPaused(false);
    isStreamPausedRef.current = false;
    applyAllPending();
  }, [applyAllPending]);

  const pendingCount = pendingLogs.length;

  // Calculate safe count
  const safeCount = totalCount - infectedCount;

  return {
    logs,
    isLoading,
    error,
    refetch,
    totalCount,
    infectedCount,
    safeCount,
    parseFailureCount,
    detectionFailureCount,
    incidentCount,
    isStreamPaused,
    pendingCount,
    pendingThreatCount,
    lastUpdate,
    pauseStream,
    resumeStream,
    stepPending,
    applyPending: applyAllPending,
    discardPending,
  };
};
