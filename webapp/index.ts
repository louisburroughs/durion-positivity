/**
 * durion-positivity main exports
 * 
 * ✅ Other components MUST import API client from here:
 * import { usePositivityApiClient, PositivityApiError } from 'durion-positivity';
 */

// API Gateway
export { usePositivityApiClient, PositivityApiError, parseApiError, isRetriableError, getErrorMessage } from './api';
export type { ApiRequest, ApiResponse, ApiError, ApiRequestConfig, AuthToken } from './types';
