/**
 * Security & Authentication Types (CAP-275)
 *
 * TypeScript types matching the Security Service backend contract.
 * See: domains/security/.business-rules/BACKEND_CONTRACT_GUIDE.md
 *
 * @since 1.0
 */

// ============================================================================
// Authentication Types
// ============================================================================

/**
 * Login request payload
 */
export interface LoginRequest {
  /** Username/subject for the token */
  username: string;
  /** Set of roles to include in the token */
  roles: string[];
}

/**
 * Token response from login endpoint
 */
export interface TokenResponse {
  /** JWT access token */
  token: string;
}

/**
 * Token pair request payload
 */
export interface TokenPairRequest {
  /** Username/subject for the tokens */
  username: string;
  /** Set of roles to include in the access token */
  roles: string[];
}

/**
 * Token pair response containing access and refresh tokens
 */
export interface TokenPairResponse {
  /** JWT access token (1 hour lifetime) */
  accessToken: string;
  /** JWT refresh token (7 days lifetime) */
  refreshToken: string;
}

/**
 * Refresh token request payload
 */
export interface RefreshTokenRequest {
  /** Refresh token to exchange for new token pair */
  refreshToken: string;
}

/**
 * Token validation response
 */
export interface TokenValidationResponse {
  /** Whether the token is valid */
  valid: boolean;
}

// ============================================================================
// User Types
// ============================================================================

/**
 * User entity
 */
export interface User {
  /** Unique identifier */
  id?: number;
  /** Username */
  username: string;
  /** Password (only for create/update requests) */
  password?: string;
  /** Assigned roles */
  roles?: string[];
}

/**
 * Create user request payload
 */
export interface CreateUserRequest {
  /** Username */
  username: string;
  /** Password */
  password: string;
  /** Initial roles */
  roles?: string[];
}

/**
 * Update user request payload
 */
export interface UpdateUserRequest {
  /** Username */
  username?: string;
  /** Password */
  password?: string;
  /** Roles */
  roles?: string[];
}

// ============================================================================
// Role Types
// ============================================================================

/**
 * Role entity
 */
export interface Role {
  /** Unique identifier */
  id?: number;
  /** Role name */
  name: string;
  /** Role description */
  description?: string;
  /** Assigned permissions */
  permissions?: Permission[];
  /** Creation timestamp */
  createdAt?: string;
  /** Creator identifier */
  createdBy?: string;
  /** Last modification timestamp */
  lastModifiedAt?: string;
  /** Last modifier identifier */
  lastModifiedBy?: string;
}

/**
 * Create role request payload
 */
export interface CreateRoleRequest {
  /** Role name */
  name: string;
  /** Role description */
  description?: string;
}

/**
 * Role permissions update request
 */
export interface RolePermissionsRequest {
  /** Role ID to update */
  roleId: number;
  /** Permission names to assign */
  permissionNames: string[];
}

// ============================================================================
// Role Assignment Types
// ============================================================================

/**
 * Role assignment entity
 */
export interface RoleAssignment {
  /** Unique identifier */
  id?: number;
  /** Assigned role name */
  role: string;
  /** Assigned user identifier */
  user: string;
  /** Scope type (e.g., 'GLOBAL', 'LOCATION') */
  scopeType?: string;
  /** Location IDs for scoped assignments */
  scopeLocationIds?: string[];
  /** Effective start date (ISO 8601) */
  effectiveStartDate?: string;
  /** Effective end date (ISO 8601) */
  effectiveEndDate?: string;
  /** Whether assignment is currently effective */
  effective?: boolean;
  /** Creation timestamp */
  createdAt?: string;
  /** Creator identifier */
  createdBy?: string;
  /** Last modification timestamp */
  lastModifiedAt?: string;
  /** Last modifier identifier */
  lastModifiedBy?: string;
}

/**
 * Create role assignment request
 */
export interface RoleAssignmentRequest {
  /** User ID to assign role to */
  userId: number;
  /** Role ID to assign */
  roleId: number;
  /** Scope type */
  scopeType?: string;
  /** Location IDs for scoped assignments */
  scopeLocationIds?: string[];
  /** Effective start date */
  effectiveStartDate?: string;
  /** Effective end date */
  effectiveEndDate?: string;
}

// ============================================================================
// Permission Types
// ============================================================================

/**
 * Permission entity
 */
export interface Permission {
  /** Unique identifier */
  id?: number;
  /** Permission name (format: domain:resource:action) */
  name: string;
  /** Permission description */
  description?: string;
  /** Domain/service that owns this permission */
  domain?: string;
  /** Resource the permission applies to */
  resource?: string;
  /** Action allowed on the resource */
  action?: string;
  /** Service that registered this permission */
  registeredByService?: string;
  /** Registration timestamp */
  registeredAt?: string;
  /** Permission version */
  version?: string;
}

/**
 * Permission definition for registration
 */
export interface PermissionDefinition {
  /** Permission name */
  name: string;
  /** Permission description */
  description?: string;
}

/**
 * Permission registration request
 */
export interface PermissionRegistrationRequest {
  /** Service name registering permissions */
  serviceName: string;
  /** Domain for the permissions */
  domain: string;
  /** List of permissions to register */
  permissions: PermissionDefinition[];
  /** Version of the permissions */
  version?: string;
}

/**
 * Permission registration response
 */
export interface PermissionRegistrationResponse {
  /** Whether registration was successful */
  success: boolean;
  /** Response message */
  message?: string;
  /** Total permissions in request */
  totalPermissions?: number;
  /** Number of newly registered permissions */
  registeredPermissions?: number;
  /** Number of updated permissions */
  updatedPermissions?: number;
  /** Number of skipped permissions */
  skippedPermissions?: number;
  /** Error messages if any */
  errors?: string[];
}

// ============================================================================
// Error Types
// ============================================================================

/**
 * Security service error response
 */
export interface SecurityErrorResponse {
  /** Error code */
  error: string;
  /** Error message */
  message: string;
  /** Correlation ID for tracing */
  correlationId: string;
  /** Error timestamp */
  timestamp?: string;
}

// ============================================================================
// Type Guards
// ============================================================================

/**
 * Type guard for TokenPairResponse
 */
export function isTokenPairResponse(obj: unknown): obj is TokenPairResponse {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    'accessToken' in obj &&
    'refreshToken' in obj &&
    typeof (obj as TokenPairResponse).accessToken === 'string' &&
    typeof (obj as TokenPairResponse).refreshToken === 'string'
  );
}

/**
 * Type guard for TokenResponse
 */
export function isTokenResponse(obj: unknown): obj is TokenResponse {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    'token' in obj &&
    typeof (obj as TokenResponse).token === 'string'
  );
}

/**
 * Type guard for SecurityErrorResponse
 */
export function isSecurityErrorResponse(obj: unknown): obj is SecurityErrorResponse {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    'error' in obj &&
    'message' in obj &&
    typeof (obj as SecurityErrorResponse).error === 'string' &&
    typeof (obj as SecurityErrorResponse).message === 'string'
  );
}
