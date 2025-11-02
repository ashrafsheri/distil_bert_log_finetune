import { useState, useEffect, useCallback, useRef } from 'react';
import { LogEntry } from '../components/LogsTable';
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

export const useLogs = (): UseLogsReturn => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [ws, setWs] = useState<WebSocket | null>(null);
  const [totalCount, setTotalCount] = useState(0);
  const [infectedCount, setInfectedCount] = useState(0);
  const [isStreamPaused, setIsStreamPaused] = useState(false);
  const [pendingLogs, setPendingLogs] = useState<LogEntry[]>([]);
  const [pendingThreatCount, setPendingThreatCount] = useState(0);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const isStreamPausedRef = useRef(false);

  const fetchInitialLogs = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);
      
      // Use apiService for authenticated request
      const response = await apiService.get<{ logs: LogEntry[]; total_count: number; infected_count: number; websocket_id?: string }>(API_ENDPOINTS.FETCH_LOGS);
      const data = response.data;
      
      console.log('📡 Fetch response received:', data);
      console.log('🔍 Checking for websocketId:', data.websocket_id);
      
      if (Array.isArray(data.logs)) {
        setLogs(data.logs);
        console.log('📋 Logs set, count:', data.logs.length);
        
        // Set counts from backend response
        setTotalCount(data.total_count || 0);
        setInfectedCount(data.infected_count || 0);
        setLastUpdate(new Date());
        console.log('📊 Backend counts - Total:', data.total_count, 'Infected:', data.infected_count);
        
        // If we get a websocket ID, establish WebSocket connection
        if (data.websocket_id) {
          console.log('🔌 WebSocket ID found, establishing connection:', data.websocket_id);
          establishWebSocketConnection(data.websocket_id);
        } else {
          console.log('❌ No websocket_id in response');
        }
      } else {
        throw new Error('Invalid data format received');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch logs');
      console.error('Error fetching logs:', err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const enqueuePendingLog = useCallback((log: LogEntry) => {
    setPendingLogs(prev => [log, ...prev].slice(0, MAX_LOGS_DISPLAY));
    if (log.infected) {
      setPendingThreatCount(prev => prev + 1);
    }
  }, []);

  const applyLogToDisplay = useCallback((log: LogEntry) => {
    setLogs(prevLogs => [log, ...prevLogs].slice(0, MAX_LOGS_DISPLAY));
    setLastUpdate(new Date());
  }, []);

  const applyAllPending = useCallback(() => {
    setPendingLogs(currentPending => {
      if (currentPending.length === 0) {
        return currentPending;
      }
      setLogs(prevLogs => [...currentPending, ...prevLogs].slice(0, MAX_LOGS_DISPLAY));
      setLastUpdate(new Date());
      setPendingThreatCount(0);
      return [];
    });
  }, []);

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
      console.log('🚀 Starting WebSocket connection establishment...');
      console.log('🔗 WebSocket ID:', websocketId);
      console.log('🌐 WebSocket Base URL:', API_ENDPOINTS.WEBSOCKET_BASE);
      
      // Close existing connection if any
      if (ws) {
        console.log('🔄 Closing existing WebSocket connection');
        ws.close();
      }

      // Create authenticated WebSocket connection
      const websocketUrl = `${API_ENDPOINTS.WEBSOCKET_BASE}/${websocketId}`;
      console.log('🔌 Creating authenticated WebSocket connection to:', websocketUrl);
      
      const websocket = await websocketService.createConnection(
        websocketUrl,
        () => {
          console.log('✅ Authenticated WebSocket connection established successfully!');
          setError(null);
        },
        (event) => {
          console.log('📨 WebSocket message received:', event.data);
          try {
            const message = JSON.parse(event.data);
            
            // Handle wrapped WebSocket message format
            if (message && message.type === 'log_update' && message.data) {
              const newLog = message.data;
              console.log('📝 New log added via WebSocket (wrapped):', newLog);
              console.log('🔍 WebSocket log fields - IP:', newLog.ipAddress, 'API:', newLog.apiAccessed, 'Status:', newLog.statusCode);
              
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
              
              console.log('📊 Counts updated - Total:', totalCount + 1, 'Infected:', infectedCount + (newLog.infected ? 1 : 0));
            } else if (message && typeof message === 'object' && message.ipAddress) {
              // Handle direct log format (fallback)
              console.log('📝 New log added via WebSocket (direct):', message);
              console.log('🔍 WebSocket log fields - IP:', message.ipAddress, 'API:', message.apiAccessed, 'Status:', message.statusCode);
              
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
              
              console.log('📊 Counts updated - Total:', totalCount + 1, 'Infected:', infectedCount + (message.infected ? 1 : 0));
            } else {
              console.log('⚠️ Unknown WebSocket message format:', message);
            }
          } catch (err) {
            console.error('❌ Error parsing WebSocket message:', err);
          }
        },
        (err) => {
          console.error('❌ WebSocket error:', err);
          setError('WebSocket connection failed');
        },
        (event) => {
          console.log('🔌 WebSocket connection closed:', event.code, event.reason);
          setWs(null);
          // Attempt to reconnect after delay
          setTimeout(() => {
            console.log('🔄 Attempting to reconnect WebSocket...');
            establishWebSocketConnection(websocketId);
          }, WEBSOCKET_RECONNECT_DELAY);
        }
      );

      setWs(websocket);
      console.log('🎯 WebSocket object created and set in state');
    } catch (err) {
      console.error('❌ Error establishing WebSocket connection:', err);
      const errorMessage = err instanceof Error ? err.message : 'Failed to establish real-time connection';
      setError(errorMessage);
      setWs(null);
      
      // Attempt to reconnect after delay if it's an auth error
      if (errorMessage.includes('Authentication') || errorMessage.includes('token')) {
        console.log('🔄 Authentication error - will retry after delay');
        setTimeout(() => {
          console.log('🔄 Retrying WebSocket connection...');
          establishWebSocketConnection(websocketId);
        }, WEBSOCKET_RECONNECT_DELAY);
      }
    }
  }, [ws, enqueuePendingLog, applyLogToDisplay]);

  const refetch = useCallback(() => {
    fetchInitialLogs();
  }, [fetchInitialLogs]);

  useEffect(() => {
    console.log('🎬 useLogs hook initialized, fetching initial logs...');
    fetchInitialLogs();

    // Cleanup WebSocket on unmount
    return () => {
      console.log('🧹 Cleaning up WebSocket on unmount');
      if (ws) {
        ws.close();
      }
    };
  }, []);

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
