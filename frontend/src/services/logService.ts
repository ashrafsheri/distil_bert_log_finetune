import { apiService } from './apiService';

export interface LogSearchParams {
  ip?: string;
  api?: string;
  status_code?: number;
  malicious?: boolean; // true=malicious, false=clean
  from_date?: string; // YYYY-MM-DD
  to_date?: string;   // YYYY-MM-DD
  limit?: number;
  offset?: number;
}

export interface LogEntry {
  timestamp: string;
  ipAddress: string;
  apiAccessed: string;
  statusCode: number;
  infected: boolean;
  anomaly_score?: number;
  anomaly_details?: Record<string, unknown>;
}

export interface LogSearchResponse {
  logs: LogEntry[];
  websocket_id: string;
  total_count: number;
  infected_count: number;
}

export const logService = {
  async fetchLogs(limit: number, offset: number): Promise<LogSearchResponse> {
    const qs = new URLSearchParams();
    qs.set('limit', String(limit));
    qs.set('offset', String(offset));
    const response = await apiService.get<LogSearchResponse>(`/api/v1/fetch?${qs.toString()}`);
    return response.data;
  },
  async searchLogs(params: LogSearchParams): Promise<LogSearchResponse> {
    const qs = new URLSearchParams();
    if (params.ip) qs.set('ip', params.ip);
    if (params.api) qs.set('api', params.api);
    if (typeof params.status_code === 'number') qs.set('status_code', String(params.status_code));
    if (typeof params.malicious === 'boolean') qs.set('malicious', String(params.malicious));
    if (params.from_date) qs.set('from_date', params.from_date);
    if (params.to_date) qs.set('to_date', params.to_date);
    if (typeof params.limit === 'number') qs.set('limit', String(params.limit));
    if (typeof params.offset === 'number') qs.set('offset', String(params.offset));
    const url = qs.toString() ? `/api/v1/search?${qs.toString()}` : '/api/v1/search';
    const response = await apiService.get<LogSearchResponse>(url);
    return response.data;
  },
};


