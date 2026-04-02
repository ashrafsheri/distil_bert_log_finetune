import { apiService } from './apiService';

export interface LogSearchParams {
  project_id?: string; // NEW: Project ID for filtering logs
  ip?: string;
  api?: string;
  status_code?: number;
  malicious?: boolean; // true=malicious, false=clean
  parse_status?: string;
  detection_status?: string;
  incident_id?: string;
  from_date?: string; // YYYY-MM-DD
  to_date?: string;   // YYYY-MM-DD
  limit?: number;
  offset?: number;
}

export interface LogAnomalyDetails {
  rule_based?: {
    is_attack: boolean;
    attack_types?: string[];
    confidence: number;
  };
  isolation_forest?: {
    is_anomaly: number;
    score: number;
    status?: string;
  };
  transformer?: {
    is_anomaly: number;
    score: number;
    threshold?: number;
    sequence_length?: number;
    context?: string;
    status?: string;
  };
  ensemble?: {
    score: number;
    votes?: {
      rule: number;
      iso: number;
      transformer: number;
    };
    weights?: {
      rule: number;
      iso: number;
      transformer: number;
    };
  };
  transformer_ready?: boolean;
  logs_processed?: number;
}

export interface LogEntry {
  timestamp: string;
  eventTime?: string;
  ingestTime?: string;
  ipAddress: string;
  apiAccessed: string;
  statusCode: number;
  infected: boolean;
  anomaly_score?: number;
  anomaly_details?: LogAnomalyDetails;
  parseStatus?: string;
  parseError?: string | null;
  detectionStatus?: string;
  detectionError?: string | null;
  incidentId?: string | null;
  incidentType?: string | null;
  incidentGroupedEventCount?: number | null;
  incidentReason?: string | null;
  topContributingSignals?: string[] | null;
  normalizedTemplate?: string | null;
  sessionKeyHash?: string | null;
  modelVersion?: string | null;
  featureSchemaVersion?: string | null;
  detectorPhase?: string | null;
  modelType?: string | null;
  rawAnomalyScore?: number | null;
  calibration?: Record<string, unknown> | null;
  trafficClass?: string | null;
  baselineEligible?: boolean | null;
  decisionReason?: string | null;
  policyScore?: number | null;
  finalDecision?: string | null;
  componentStatus?: Record<string, unknown> | null;
  thresholdSource?: string | null;
  thresholdFittedAt?: string | null;
  calibrationSampleCount?: number | null;
  scoreNormalizationVersion?: string | null;
  unknownTemplateRatio?: number | null;
}

export interface LogSearchResponse {
  logs: LogEntry[];
  websocket_id: string;
  total_count: number;
  infected_count: number;
  safe_count: number;
  threat_rate: number;
  parse_failure_count: number;
  detection_failure_count: number;
  incident_count: number;
  skipped_count: number;
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
    if (params.parse_status) qs.set('parse_status', params.parse_status);
    if (params.detection_status) qs.set('detection_status', params.detection_status);
    if (params.incident_id) qs.set('incident_id', params.incident_id);
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
    if (params.parse_status) qs.set('parse_status', params.parse_status);
    if (params.detection_status) qs.set('detection_status', params.detection_status);
    if (params.incident_id) qs.set('incident_id', params.incident_id);
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
