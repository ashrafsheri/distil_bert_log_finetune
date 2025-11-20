/**
 * API Service
 * Provides a centralized service for making HTTP requests to the backend
 * Automatically includes Firebase JWT token in Authorization header
 */

import { auth } from '../config/firebase';

export interface ApiRequestOptions extends RequestInit {
  requireAuth?: boolean; // Whether to require authentication (default: true)
}

export interface ApiResponse<T = unknown> {
  data: T;
  status: number;
  statusText: string;
}

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public statusText: string,
    public data?: unknown
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

/**
 * Get Firebase ID token for authenticated user
 */
async function getIdToken(): Promise<string | null> {
  try {
    if (!auth) {
      return null;
    }
    
    const currentUser = auth.currentUser;
    if (!currentUser) {
      return null;
    }
    
    // Get fresh ID token
    const token = await currentUser.getIdToken();
    return token;
  } catch (error) {
    console.error('Error getting ID token:', error);
    return null;
  }
}

/**
 * Make an authenticated API request
 */
async function makeRequest<T = unknown>(
  url: string,
  options: ApiRequestOptions = {}
): Promise<ApiResponse<T>> {
  const { requireAuth = true, headers = {}, ...fetchOptions } = options;
  
  // Build headers
  const requestHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(headers as Record<string, string>),
  };
  
  // Add authorization header if auth is required
  if (requireAuth) {
    const token = await getIdToken();
    if (token) {
      requestHeaders['Authorization'] = `Bearer ${token}`;
    } else {
      throw new ApiError(
        'Authentication required. Please log in.',
        401,
        'Unauthorized'
      );
    }
  }
  
  // Make the request
  try {
    const response = await fetch(url, {
      ...fetchOptions,
      headers: requestHeaders,
    });
    
    // Parse response
    let data: T;
    const contentType = response.headers.get('content-type');
    
    if (contentType && contentType.includes('application/json')) {
      try {
        data = await response.json();
      } catch {
        // Empty response or invalid JSON
        data = {} as T;
      }
    } else {
      // Non-JSON response
      const text = await response.text();
      data = text as unknown as T;
    }
    
    // Handle error responses
    if (!response.ok) {
      const errorData = data as { detail?: string; message?: string };
      throw new ApiError(
        errorData?.detail || errorData?.message || `HTTP error! status: ${response.status}`,
        response.status,
        response.statusText,
        data
      );
    }
    
    return {
      data,
      status: response.status,
      statusText: response.statusText,
    };
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    
    // Network or other errors
    throw new ApiError(
      error instanceof Error ? error.message : 'Network error occurred',
      0,
      'Network Error',
      error
    );
  }
}

/**
 * API Service with methods for HTTP requests
 */
export const apiService = {
  /**
   * GET request
   */
  async get<T = unknown>(url: string, options: Omit<ApiRequestOptions, 'method'> = {}): Promise<ApiResponse<T>> {
    return makeRequest<T>(url, {
      ...options,
      method: 'GET',
    });
  },

  /**
   * POST request
   */
  async post<T = unknown>(
    url: string,
    body?: unknown,
    options: Omit<ApiRequestOptions, 'method' | 'body'> = {}
  ): Promise<ApiResponse<T>> {
    return makeRequest<T>(url, {
      ...options,
      method: 'POST',
      body: body ? JSON.stringify(body) : undefined,
    });
  },

  /**
   * PUT request
   */
  async put<T = unknown>(
    url: string,
    body?: unknown,
    options: Omit<ApiRequestOptions, 'method' | 'body'> = {}
  ): Promise<ApiResponse<T>> {
    return makeRequest<T>(url, {
      ...options,
      method: 'PUT',
      body: body ? JSON.stringify(body) : undefined,
    });
  },

  /**
   * DELETE request
   */
  async delete<T = unknown>(
    url: string,
    options: Omit<ApiRequestOptions, 'method'> = {}
  ): Promise<ApiResponse<T>> {
    return makeRequest<T>(url, {
      ...options,
      method: 'DELETE',
    });
  },

  /**
   * PATCH request
   */
  async patch<T = unknown>(
    url: string,
    body?: unknown,
    options: Omit<ApiRequestOptions, 'method' | 'body'> = {}
  ): Promise<ApiResponse<T>> {
    return makeRequest<T>(url, {
      ...options,
      method: 'PATCH',
      body: body ? JSON.stringify(body) : undefined,
    });
  },

  /**
   * GET request for Blob data (file downloads)
   */
  async getBlob(url: string, options: Omit<ApiRequestOptions, 'method'> = {}): Promise<ApiResponse<Blob>> {
    const { requireAuth = true, headers = {}, ...fetchOptions } = options;
    
    // Build headers
    const requestHeaders: Record<string, string> = {
      ...(headers as Record<string, string>),
    };
    
    // Add authorization header if auth is required
    if (requireAuth) {
      const token = await getIdToken();
      if (token) {
        requestHeaders['Authorization'] = `Bearer ${token}`;
      } else {
        throw new ApiError(
          'Authentication required. Please log in.',
          401,
          'Unauthorized'
        );
      }
    }
    
    // Make the request
    try {
      const response = await fetch(url, {
        ...fetchOptions,
        method: 'GET',
        headers: requestHeaders,
      });
      
      // Handle error responses
      if (!response.ok) {
        const text = await response.text();
        throw new ApiError(
          text || `HTTP error! status: ${response.status}`,
          response.status,
          response.statusText
        );
      }
      
      const blob = await response.blob();
      
      return {
        data: blob,
        status: response.status,
        statusText: response.statusText,
      };
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      
      // Network or other errors
      throw new ApiError(
        error instanceof Error ? error.message : 'Network error occurred',
        0,
        'Network Error',
        error
      );
    }
  },
};

/**
 * Create WebSocket connection with authentication
 */
export function createAuthenticatedWebSocket(
  url: string,
  onOpen?: (event: Event) => void,
  onMessage?: (event: MessageEvent) => void,
  onError?: (event: Event) => void,
  onClose?: (event: CloseEvent) => void
): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    // Get ID token for WebSocket authentication
    getIdToken()
      .then((token) => {
        if (!token) {
          reject(new Error('Authentication required for WebSocket connection'));
          return;
        }
        
        // Append token to WebSocket URL as query parameter or use Authorization header
        // Note: WebSocket doesn't support custom headers in browser, so we use query param
        const separator = url.includes('?') ? '&' : '?';
        const wsUrl = `${url}${separator}token=${encodeURIComponent(token)}`;
        
        // Create WebSocket connection
        const websocket = new WebSocket(wsUrl);
        
        // Mark that onopen handler is set to prevent double rejection
        let opened = false;
        
        websocket.onopen = (event) => {
          opened = true;
          console.log('✅ Authenticated WebSocket connection established');
          if (onOpen) {
            onOpen(event);
          }
          resolve(websocket);
        };
        
        websocket.onmessage = (event) => {
          if (onMessage) {
            onMessage(event);
          }
        };
        
        websocket.onerror = (event) => {
          console.error('❌ WebSocket error:', event);
          if (onError) {
            onError(event);
          }
          // Only reject if connection hasn't opened yet
          if (websocket.readyState === WebSocket.CONNECTING) {
            reject(new Error('WebSocket connection failed'));
          }
        };
        
        websocket.onclose = (event) => {
          console.log('🔌 WebSocket connection closed:', event.code, event.reason);
          
          // If closed before opening (connection rejected), reject the promise
          if (!opened && (event.code === 1008 || event.code === 1011)) {
            const reason = event.reason || `Connection rejected: ${event.code}`;
            console.error('❌ WebSocket connection rejected:', reason);
            reject(new Error(reason));
            return;
          }
          
          if (onClose) {
            onClose(event);
          }
        };
        
        // Set timeout for connection
        setTimeout(() => {
          if (websocket.readyState === WebSocket.CONNECTING) {
            websocket.close();
            reject(new Error('WebSocket connection timeout'));
          }
        }, 10000); // 10 second timeout
      })
      .catch((error) => {
        reject(error);
      });
  });
}

/**
 * WebSocket Service wrapper
 */
export const websocketService = {
  /**
   * Create authenticated WebSocket connection
   */
  createConnection: createAuthenticatedWebSocket,
};

