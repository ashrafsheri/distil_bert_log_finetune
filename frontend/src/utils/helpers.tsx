import { LogEntry } from '../components/LogsTable';

export const formatTimestamp = (timestamp: string): string => {
  try {
    const date = new Date(timestamp);
    return date.toLocaleString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      day: 'numeric',
      month: 'short',
      year: 'numeric',
    });
  } catch (error) {
    return timestamp;
  }
};

export const getStatusColor = (statusCode: number): string => {
  if (statusCode >= 200 && statusCode < 300) return 'text-vt-success';
  if (statusCode >= 300 && statusCode < 400) return 'text-vt-warning';
  if (statusCode >= 400) return 'text-vt-error';
  return 'text-vt-muted';
};

export const getStatusIcon = (statusCode: number) => {
  if (statusCode >= 200 && statusCode < 300) {
    return (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
      </svg>
    );
  }
  if (statusCode >= 400) {
    return (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
      </svg>
    );
  }
  return (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
    </svg>
  );
};

export const calculateThreatRate = (logs: LogEntry[]): number => {
  if (logs.length === 0) return 0;
  const infectedCount = logs.filter(log => log.infected).length;
  return (infectedCount / logs.length) * 100;
};

export const validateLogEntry = (log: any): log is LogEntry => {
  return (
    log &&
    typeof log === 'object' &&
    typeof log.timestamp === 'string' &&
    typeof log.ipAddress === 'string' &&
    typeof log.apiAccessed === 'string' &&
    typeof log.statusCode === 'number' &&
    typeof log.infected === 'boolean'
  );
};

export const debounce = <T extends (...args: any[]) => any>(
  func: T,
  wait: number
): ((...args: Parameters<T>) => void) => {
  let timeout: NodeJS.Timeout;
  return (...args: Parameters<T>) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
};
