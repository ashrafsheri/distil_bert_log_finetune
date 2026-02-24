import { apiService } from './apiService';

export interface LogSearchParams {
  project_id?: string; // NEW: Project ID for filtering logs
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
  async fetchLogs(limit: number, offset: number, projectId?: string): Promise<LogSearchResponse> {
    const qs = new URLSearchParams();
    qs.set('limit', String(limit));
    qs.set('offset', String(offset));
    if (projectId) qs.set('project_id', projectId);
    const response = await apiService.get<LogSearchResponse>(`/api/v1/logs/fetch?${qs.toString()}`);
    return response.data;
  },
  async searchLogs(params: LogSearchParams): Promise<LogSearchResponse> {
    const qs = new URLSearchParams();
    if (params.project_id) qs.set('project_id', params.project_id);
    if (params.ip) qs.set('ip', params.ip);
    if (params.api) qs.set('api', params.api);
    if (typeof params.status_code === 'number') qs.set('status_code', String(params.status_code));
    if (typeof params.malicious === 'boolean') qs.set('malicious', String(params.malicious));
    if (params.from_date) qs.set('from_date', params.from_date);
    if (params.to_date) qs.set('to_date', params.to_date);
    if (typeof params.limit === 'number') qs.set('limit', String(params.limit));
    if (typeof params.offset === 'number') qs.set('offset', String(params.offset));
    const url = qs.toString() ? `/api/v1/logs/search?${qs.toString()}` : '/api/v1/logs/search';
    const response = await apiService.get<LogSearchResponse>(url);
    return response.data;
  },
  async exportLogs(params: LogSearchParams): Promise<Blob> {
    const qs = new URLSearchParams();
    if (params.project_id) qs.set('project_id', params.project_id);
    if (params.ip) qs.set('ip', params.ip);
    if (params.api) qs.set('api', params.api);
    if (typeof params.status_code === 'number') qs.set('status_code', String(params.status_code));
    if (typeof params.malicious === 'boolean') qs.set('malicious', String(params.malicious));
    if (params.from_date) qs.set('from_date', params.from_date);
    if (params.to_date) qs.set('to_date', params.to_date);
    const url = qs.toString() ? `/api/v1/logs/export?${qs.toString()}` : '/api/v1/logs/export';
    const response = await apiService.getBlob(url);
    return response.data;
  },
  async correctLog(ip: string, status: 'clean' | 'malicious', projectId?: string): Promise<{ message: string; ip: string; status: string; database_updated: boolean; elasticsearch_updated: boolean; logs_updated_count: number }> {
    const response = await apiService.post<{ message: string; ip: string; status: string; database_updated: boolean; elasticsearch_updated: boolean; logs_updated_count: number }>(
      '/api/v1/logs/correctLog',
      { ip, status, project_id: projectId }
    );
    return response.data;
  },
};


