import { useState, useEffect, useCallback } from 'react';
import { LogEntry } from '../components/LogsTable';
import { API_ENDPOINTS, WEBSOCKET_RECONNECT_DELAY, MAX_LOGS_DISPLAY } from '../utils/constants';

interface UseLogsReturn {
  logs: LogEntry[];
  isLoading: boolean;
  error: string | null;
  refetch: () => void;
  totalCount: number;
  infectedCount: number;
  safeCount: number;
}

export const useLogs = (): UseLogsReturn => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [ws, setWs] = useState<WebSocket | null>(null);
  const [totalCount, setTotalCount] = useState(0);
  const [infectedCount, setInfectedCount] = useState(0);

  const fetchInitialLogs = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);
      
      const response = await fetch(API_ENDPOINTS.FETCH_LOGS);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data = await response.json();
      console.log('📡 Fetch response received:', data);
      console.log('🔍 Checking for websocketId:', data.websocketId);
      
      if (Array.isArray(data.logs)) {
        setLogs(data.logs);
        console.log('📋 Logs set, count:', data.logs.length);
        
        // Set counts from backend response
        setTotalCount(data.total_count || 0);
        setInfectedCount(data.infected_count || 0);
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

  const establishWebSocketConnection = useCallback((websocketId: string) => {
    try {
      console.log('🚀 Starting WebSocket connection establishment...');
      console.log('🔗 WebSocket ID:', websocketId);
      console.log('🌐 WebSocket Base URL:', API_ENDPOINTS.WEBSOCKET_BASE);
      
      // Close existing connection if any
      if (ws) {
        console.log('🔄 Closing existing WebSocket connection');
        ws.close();
      }

      // Create new WebSocket connection
      const websocketUrl = `${API_ENDPOINTS.WEBSOCKET_BASE}/${websocketId}`;
      console.log('🔌 Creating WebSocket connection to:', websocketUrl);
      const websocket = new WebSocket(websocketUrl);
      
      websocket.onopen = () => {
        console.log('✅ WebSocket connection established successfully!');
        setError(null);
      };

       websocket.onmessage = (event) => {
         console.log('📨 WebSocket message received:', event.data);
         try {
           const message = JSON.parse(event.data);
           
           // Handle wrapped WebSocket message format
           if (message && message.type === 'log_update' && message.data) {
             const newLog = message.data;
             console.log('📝 New log added via WebSocket (wrapped):', newLog);
             console.log('🔍 WebSocket log fields - IP:', newLog.ipAddress, 'API:', newLog.apiAccessed, 'Status:', newLog.statusCode);
             
             // Update logs array
             setLogs(prevLogs => {
               const updatedLogs = [newLog, ...prevLogs].slice(0, MAX_LOGS_DISPLAY);
               return updatedLogs;
             });
             
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
             setLogs(prevLogs => {
               const updatedLogs = [message, ...prevLogs].slice(0, MAX_LOGS_DISPLAY);
               return updatedLogs;
             });
             
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
       };

      websocket.onclose = (event) => {
        console.log('🔌 WebSocket connection closed:', event.code, event.reason);
        // Attempt to reconnect after delay
        setTimeout(() => {
          if (websocket.readyState === WebSocket.CLOSED) {
            console.log('🔄 Attempting to reconnect WebSocket...');
            establishWebSocketConnection(websocketId);
          }
        }, WEBSOCKET_RECONNECT_DELAY);
      };

      websocket.onerror = (err) => {
        console.error('❌ WebSocket error:', err);
        setError('WebSocket connection failed');
      };

      setWs(websocket);
      console.log('🎯 WebSocket object created and set in state');
    } catch (err) {
      console.error('❌ Error establishing WebSocket connection:', err);
      setError('Failed to establish real-time connection');
    }
  }, [ws]);

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
  };
};
