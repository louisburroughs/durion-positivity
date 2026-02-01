/**
 * durion-positivity main exports
 *
 * ✅ Other components MUST import API client from here:
 * import { usePositivityApiClient, PositivityApiError } from 'durion-positivity';
 *
 * ✅ For security service:
 * import { useSecurityService } from 'durion-positivity';
 */

// API Gateway
export {
  usePositivityApiClient,
  PositivityApiError,
  parseApiError,
  isRetriableError,
  getErrorMessage
} from './api';

// Composables
export { useSecurityService } from './composables';

// Types
export type { ApiRequest, ApiResponse, ApiError, ApiRequestConfig, AuthToken } from './types';
export type {
  LoginRequest,
  TokenResponse,
  TokenPairRequest,
  TokenPairResponse,
  RefreshTokenRequest,
  TokenValidationResponse,
  User,
  CreateUserRequest,
  UpdateUserRequest,
  Role,
  CreateRoleRequest,
  RolePermissionsRequest,
  RoleAssignment,
  RoleAssignmentRequest,
  Permission,
  PermissionDefinition,
  PermissionRegistrationRequest,
  PermissionRegistrationResponse,
  SecurityErrorResponse
} from './types/security';

// Type Guards
export {
  isTokenPairResponse,
  isTokenResponse,
  isSecurityErrorResponse
} from './types/security';
