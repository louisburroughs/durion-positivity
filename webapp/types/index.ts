/**
 * API Request/Response types for durion-positivity API gateway
 * All backend API communication routes through this centralized interface
 */

/**
 * Represents a backend microservice request
 */
export interface ApiRequest {
  /** Backend service name (e.g., 'pos-customer', 'pos-inventory') */
  service: string;
  /** API endpoint path (e.g., '/list', '/{id}') */
  endpoint: string;
  /** HTTP method */
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  /** Request body data */
  data?: Record<string, unknown>;
  /** Custom headers to merge with defaults */
  headers?: Record<string, string>;
  /** Optional request timeout in milliseconds */
  timeoutMs?: number;
  /** Optional idempotency key for safe retries */
  idempotencyKey?: string;
}

/**
 * Represents a successful API response
 */
export interface ApiResponse<T> {
  data: T;
  status: number;
  headers: Record<string, string>;
  timestamp: string;
  correlationId: string;
}

/**
 * Represents an API error
 */
export interface ApiError {
  message: string;
  code: string;
  status: number;
  service: string;
  endpoint: string;
  correlationId: string;
  timestamp: string;
  details?: Record<string, unknown>;
}

/**
 * Request configuration used internally
 */
export interface ApiRequestConfig {
  url: string;
  method: ApiRequest['method'];
  headers: Record<string, string>;
  body?: string;
  timeout?: number;
}

/**
 * Auth token information
 */
export interface AuthToken {
  token: string;
  expiresAt: number;
  refreshToken?: string;
}
