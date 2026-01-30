/**
 * Central API gateway for all backend microservice communication
 * ⚠️ MANDATORY: ALL backend calls must route through this client
 * 
 * This composable provides:
 * - Unified authentication token management
 * - Automatic correlation ID injection for observability
 * - Centralized error handling and logging
 * - Request/response transformation
 * - Retry logic for transient failures
 */

import { ref, computed } from 'vue';
import type { ApiRequest, ApiResponse, ApiError } from '../types';
import { PositivityApiError, parseApiError, isRetriableError, getErrorMessage } from './errors';

/**
 * Generate a unique request ID for tracing
 */
function generateRequestId(): string {
  return `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Get auth token from store (from auth store if available)
 * Fallback to localStorage for backward compatibility
 */
function getAuthToken(): string {
  // Try to get from Vue store first (if auth store is initialized)
  try {
    // This will be injected by Vue context - for now use localStorage
    const token = localStorage.getItem('auth_token');
    return token || '';
  } catch {
    return '';
  }
}

/**
 * Build complete request URL
 */
function buildUrl(service: string, endpoint: string, baseURL: string): string {
  // Remove leading slash from endpoint if present
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  return `${baseURL}/${service}${cleanEndpoint}`;
}

/**
 * Build request headers with auth and correlation ID
 */
function buildHeaders(
  customHeaders?: Record<string, string>,
  correlationId?: string
): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Service': 'durion-frontend',
    'X-Request-ID': generateRequestId()
  };

  // Add correlation ID for distributed tracing
  if (correlationId) {
    headers['X-Correlation-ID'] = correlationId;
  }

  // Add auth token if available
  const token = getAuthToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  // Merge custom headers
  if (customHeaders) {
    Object.assign(headers, customHeaders);
  }

  return headers;
}

/**
 * Central API client composable
 * ⚠️ USAGE: Only import and use from durion-positivity
 * DO NOT make direct fetch/axios calls from other components
 */
export function usePositivityApiClient() {
  const baseURL = ref('/rest/api/v1');
  const requestTimeout = ref(30000); // 30 seconds
  const maxRetries = ref(3);

  /**
   * Make a request to a backend microservice
   * ✅ This is the ONLY way to call backend APIs from Vue components
   */
  async function request<T>(req: ApiRequest): Promise<T> {
    const correlationId = generateRequestId();
    const headers = buildHeaders(req.headers, correlationId);
    const url = buildUrl(req.service, req.endpoint, baseURL.value);

    // Add idempotency key if provided
    if (req.idempotencyKey) {
      headers['Idempotency-Key'] = req.idempotencyKey;
    }

    let lastError: PositivityApiError | null = null;

    // Retry logic for transient failures
    for (let attempt = 0; attempt <= maxRetries.value; attempt++) {
      try {
        const timeout = req.timeoutMs || requestTimeout.value;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        try {
          const response = await fetch(url, {
            method: req.method,
            headers,
            body: req.method !== 'GET' && req.method !== 'HEAD' ? JSON.stringify(req.data) : undefined,
            signal: controller.signal
          });

          clearTimeout(timeoutId);

          // Log response for observability
          logApiCall(
            req.service,
            req.endpoint,
            req.method,
            response.status,
            correlationId,
            attempt
          );

          if (!response.ok) {
            const errorData = await parseResponse(response);
            const apiError = parseApiError(
              response.status,
              errorData,
              req.service,
              req.endpoint,
              correlationId
            );

            const error = new PositivityApiError(apiError);

            // Check if error is retriable and we have retries left
            if (isRetriableError(apiError) && attempt < maxRetries.value) {
              lastError = error;
              // Exponential backoff: 100ms * 2^attempt
              await new Promise(resolve => setTimeout(resolve, 100 * Math.pow(2, attempt)));
              continue;
            }

            throw error;
          }

          const responseData = await parseResponse(response);
          return responseData as T;
        } finally {
          clearTimeout(timeoutId);
        }
      } catch (error) {
        if (error instanceof PositivityApiError) {
          throw error;
        }

        if (error instanceof TypeError && error.message === 'Failed to fetch') {
          // Network error
          lastError = new PositivityApiError({
            message: 'Network error - unable to reach backend',
            code: 'NETWORK_ERROR',
            status: 0,
            service: req.service,
            endpoint: req.endpoint,
            correlationId,
            timestamp: new Date().toISOString()
          });

          if (attempt < maxRetries.value) {
            await new Promise(resolve => setTimeout(resolve, 100 * Math.pow(2, attempt)));
            continue;
          }
        } else if (error instanceof DOMException && error.name === 'AbortError') {
          // Timeout
          lastError = new PositivityApiError({
            message: 'Request timeout - backend service did not respond in time',
            code: 'TIMEOUT',
            status: 408,
            service: req.service,
            endpoint: req.endpoint,
            correlationId,
            timestamp: new Date().toISOString()
          });

          if (attempt < maxRetries.value) {
            await new Promise(resolve => setTimeout(resolve, 100 * Math.pow(2, attempt)));
            continue;
          }
        }

        // Unrecoverable error
        throw lastError || new PositivityApiError({
          message: 'Unknown error',
          code: 'UNKNOWN',
          status: 0,
          service: req.service,
          endpoint: req.endpoint,
          correlationId,
          timestamp: new Date().toISOString()
        });
      }
    }

    // All retries exhausted
    throw lastError || new PositivityApiError({
      message: 'Request failed after retries',
      code: 'MAX_RETRIES',
      status: 0,
      service: req.service,
      endpoint: req.endpoint,
      correlationId,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Parse response body as JSON
   */
  async function parseResponse(response: Response): Promise<unknown> {
    const contentType = response.headers.get('content-type');

    if (contentType?.includes('application/json')) {
      try {
        return await response.json();
      } catch {
        return null;
      }
    }

    try {
      return await response.text();
    } catch {
      return null;
    }
  }

  /**
   * Log API call for observability
   */
  function logApiCall(
    service: string,
    endpoint: string,
    method: string,
    status: number,
    correlationId: string,
    attempt: number
  ): void {
    const isError = status >= 400;
    const level = isError ? 'error' : 'info';
    const retryNote = attempt > 0 ? ` (attempt ${attempt + 1})` : '';

    console.log(
      `[durion-positivity] ${level.toUpperCase()} ${method} /${service}${endpoint} -> ${status}${retryNote} [${correlationId}]`
    );
  }

  return {
    request,
    baseURL: computed(() => baseURL.value),
    requestTimeout: computed(() => requestTimeout.value),
    maxRetries: computed(() => maxRetries.value),
    setBaseURL: (url: string) => {
      baseURL.value = url;
    },
    setRequestTimeout: (ms: number) => {
      requestTimeout.value = ms;
    },
    setMaxRetries: (count: number) => {
      maxRetries.value = count;
    }
  };
}

// Export error utilities for use in other components
export { PositivityApiError, parseApiError, isRetriableError, getErrorMessage } from './errors';
export type { ApiError } from '../types';
