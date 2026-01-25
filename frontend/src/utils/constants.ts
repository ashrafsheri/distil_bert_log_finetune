export const API_ENDPOINTS = {
  FETCH_LOGS: '/api/v1/logs/fetch',
  WEBSOCKET_BASE: `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`,
} as const;

export const WEBSOCKET_RECONNECT_DELAY = 5000; // 5 seconds
export const MAX_LOGS_DISPLAY = 1000;
export const REFRESH_INTERVAL = 30000; // 30 seconds

export const STATUS_CODES = {
  SUCCESS: [200, 201, 202, 204],
  REDIRECT: [300, 301, 302, 303, 304, 307, 308],
  CLIENT_ERROR: [400, 401, 403, 404, 405, 408, 409, 410, 422, 429],
  SERVER_ERROR: [500, 501, 502, 503, 504, 505],
} as const;
