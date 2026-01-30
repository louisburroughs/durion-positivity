/**
 * Error handling utilities for centralized API gateway
 */

import type { ApiError } from '../types';

/**
 * Custom error class for API errors
 */
export class PositivityApiError extends Error implements ApiError {
  message: string;
  code: string;
  status: number;
  service: string;
  endpoint: string;
  correlationId: string;
  timestamp: string;
  details?: Record<string, unknown>;

  constructor(error: ApiError) {
    super(error.message);
    this.name = 'PositivityApiError';
    this.message = error.message;
    this.code = error.code;
    this.status = error.status;
    this.service = error.service;
    this.endpoint = error.endpoint;
    this.correlationId = error.correlationId;
    this.timestamp = error.timestamp;
    this.details = error.details;

    // Maintain proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, PositivityApiError.prototype);
  }

  toJSON(): ApiError {
    return {
      message: this.message,
      code: this.code,
      status: this.status,
      service: this.service,
      endpoint: this.endpoint,
      correlationId: this.correlationId,
      timestamp: this.timestamp,
      details: this.details
    };
  }
}

/**
 * Parse error response from backend API
 */
export function parseApiError(
  status: number,
  responseData: unknown,
  service: string,
  endpoint: string,
  correlationId: string
): ApiError {
  const isObject = (val: unknown): val is Record<string, unknown> =>
    typeof val === 'object' && val !== null;

  const data = isObject(responseData) ? responseData : {};

  return {
    message: typeof data.message === 'string' ? data.message : `API error from ${service}`,
    code: typeof data.code === 'string' ? data.code : `HTTP_${status}`,
    status,
    service,
    endpoint,
    correlationId,
    timestamp: typeof data.timestamp === 'string' ? data.timestamp : new Date().toISOString(),
    details: data
  };
}

/**
 * Determine if error is retriable
 */
export function isRetriableError(error: ApiError): boolean {
  // Retriable status codes
  const retriableCodes = [408, 429, 500, 502, 503, 504];
  return retriableCodes.includes(error.status);
}

/**
 * Get user-friendly error message
 */
export function getErrorMessage(error: ApiError): string {
  const statusMessages: Record<number, string> = {
    400: 'Bad request - check your input',
    401: 'Unauthorized - please login again',
    403: 'Forbidden - you do not have permission',
    404: 'Resource not found',
    408: 'Request timeout - please try again',
    409: 'Conflict - the resource may have been modified',
    429: 'Too many requests - please try again later',
    500: 'Server error - please try again later',
    502: 'Bad gateway - service unavailable',
    503: 'Service unavailable - please try again later',
    504: 'Gateway timeout - please try again'
  };

  return statusMessages[error.status] || error.message || 'An error occurred';
}
