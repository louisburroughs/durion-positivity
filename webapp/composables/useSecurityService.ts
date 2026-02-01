/**
 * Security Service Composable (CAP-275)
 *
 * Provides typed API methods for Security Service endpoints.
 * ⚠️ ALL security API calls MUST route through this composable.
 *
 * Endpoints covered:
 * - Authentication: login, token-pair, refresh, validate, revoke
 * - Users: CRUD operations
 * - Roles: CRUD operations, assignments, permissions
 * - Permissions: registration, validation, lookup
 *
 * @see domains/security/.business-rules/BACKEND_CONTRACT_GUIDE.md
 * @since 1.0
 */

import { ref, computed } from 'vue';
import { usePositivityApiClient } from '../api';
import type {
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
  PermissionRegistrationRequest,
  PermissionRegistrationResponse
} from '../types/security';

/** Service name for API routing */
const SERVICE_NAME = 'pos-security-service';

/**
 * Security service composable
 *
 * @example
 * ```typescript
 * const { login, isAuthenticated, currentUser } = useSecurityService();
 *
 * // Login and get token pair
 * const tokens = await login({ username: 'john', roles: ['SHOP_MGR'] });
 *
 * // Validate token
 * const isValid = await validateToken(tokens.accessToken);
 * ```
 */
export function useSecurityService() {
  const { request } = usePositivityApiClient();

  // Reactive state
  const isLoading = ref(false);
  const error = ref<Error | null>(null);
  const currentUser = ref<User | null>(null);
  const accessToken = ref<string | null>(null);
  const refreshToken = ref<string | null>(null);

  // Computed
  const isAuthenticated = computed(() => !!accessToken.value);

  // ============================================================================
  // Authentication Methods
  // ============================================================================

  /**
   * Authenticate user and issue JWT token
   *
   * @param loginRequest - Login credentials
   * @returns Token response with JWT
   * @throws PositivityApiError on authentication failure
   */
  async function login(loginRequest: LoginRequest): Promise<TokenResponse> {
    isLoading.value = true;
    error.value = null;

    try {
      const response = await request<TokenResponse>({
        service: SERVICE_NAME,
        endpoint: `/v1/auth/login?subject=${encodeURIComponent(loginRequest.username)}&roles=${loginRequest.roles.join(',')}`,
        method: 'POST'
      });

      accessToken.value = response.token;
      localStorage.setItem('auth_token', response.token);

      return response;
    } catch (err) {
      error.value = err instanceof Error ? err : new Error('Login failed');
      throw err;
    } finally {
      isLoading.value = false;
    }
  }

  /**
   * Generate access and refresh token pair
   *
   * @param tokenPairRequest - Token pair request
   * @returns Token pair with access and refresh tokens
   */
  async function generateTokenPair(tokenPairRequest: TokenPairRequest): Promise<TokenPairResponse> {
    isLoading.value = true;
    error.value = null;

    try {
      const response = await request<TokenPairResponse>({
        service: SERVICE_NAME,
        endpoint: `/v1/auth/token-pair?subject=${encodeURIComponent(tokenPairRequest.username)}&roles=${tokenPairRequest.roles.join(',')}`,
        method: 'POST'
      });

      accessToken.value = response.accessToken;
      refreshToken.value = response.refreshToken;
      localStorage.setItem('auth_token', response.accessToken);
      localStorage.setItem('refresh_token', response.refreshToken);

      return response;
    } catch (err) {
      error.value = err instanceof Error ? err : new Error('Token pair generation failed');
      throw err;
    } finally {
      isLoading.value = false;
    }
  }

  /**
   * Refresh access token using refresh token
   *
   * @param refreshTokenRequest - Refresh token request
   * @returns New token pair
   */
  async function refreshAccessToken(refreshTokenRequest: RefreshTokenRequest): Promise<TokenPairResponse> {
    isLoading.value = true;
    error.value = null;

    try {
      const response = await request<TokenPairResponse>({
        service: SERVICE_NAME,
        endpoint: `/v1/auth/refresh?refreshToken=${encodeURIComponent(refreshTokenRequest.refreshToken)}`,
        method: 'POST'
      });

      accessToken.value = response.accessToken;
      refreshToken.value = response.refreshToken;
      localStorage.setItem('auth_token', response.accessToken);
      localStorage.setItem('refresh_token', response.refreshToken);

      return response;
    } catch (err) {
      error.value = err instanceof Error ? err : new Error('Token refresh failed');
      throw err;
    } finally {
      isLoading.value = false;
    }
  }

  /**
   * Validate JWT token
   *
   * @param token - JWT token to validate
   * @returns Validation response
   */
  async function validateToken(token: string): Promise<TokenValidationResponse> {
    try {
      return await request<TokenValidationResponse>({
        service: SERVICE_NAME,
        endpoint: `/v1/auth/validate?token=${encodeURIComponent(token)}`,
        method: 'GET'
      });
    } catch {
      return { valid: false };
    }
  }

  /**
   * Revoke/delete a token
   *
   * @param token - Token to revoke
   */
  async function revokeToken(token: string): Promise<void> {
    await request<void>({
      service: SERVICE_NAME,
      endpoint: `/v1/auth/delete?token=${encodeURIComponent(token)}`,
      method: 'DELETE'
    });
  }

  /**
   * Get roles from token
   *
   * @param token - JWT token
   * @returns Array of role names
   */
  async function getRolesFromToken(token: string): Promise<string[]> {
    return await request<string[]>({
      service: SERVICE_NAME,
      endpoint: `/v1/auth/roles?token=${encodeURIComponent(token)}`,
      method: 'GET'
    });
  }

  /**
   * Get authorities from token
   *
   * @param token - JWT token
   * @returns Array of authority names
   */
  async function getAuthoritiesFromToken(token: string): Promise<string[]> {
    return await request<string[]>({
      service: SERVICE_NAME,
      endpoint: `/v1/auth/authorities?token=${encodeURIComponent(token)}`,
      method: 'GET'
    });
  }

  /**
   * Get subject (username) from token
   *
   * @param token - JWT token
   * @returns Subject/username
   */
  async function getSubjectFromToken(token: string): Promise<string> {
    return await request<string>({
      service: SERVICE_NAME,
      endpoint: `/v1/auth/subject?token=${encodeURIComponent(token)}`,
      method: 'GET'
    });
  }

  /**
   * Logout - clear tokens and revoke
   */
  async function logout(): Promise<void> {
    const token = accessToken.value;
    const refresh = refreshToken.value;

    // Clear local state first
    accessToken.value = null;
    refreshToken.value = null;
    currentUser.value = null;
    localStorage.removeItem('auth_token');
    localStorage.removeItem('refresh_token');

    // Revoke tokens on server (best-effort)
    try {
      if (token) {
        await revokeToken(token);
      }
      if (refresh) {
        await revokeToken(refresh);
      }
    } catch {
      // Ignore errors during logout - tokens are already cleared locally
    }
  }

  // ============================================================================
  // User Management Methods
  // ============================================================================

  /**
   * Get all users
   *
   * @returns Array of users
   */
  async function getAllUsers(): Promise<User[]> {
    return await request<User[]>({
      service: SERVICE_NAME,
      endpoint: '/v1/users',
      method: 'GET'
    });
  }

  /**
   * Get user by ID
   *
   * @param id - User ID
   * @returns User or null if not found
   */
  async function getUserById(id: number): Promise<User> {
    return await request<User>({
      service: SERVICE_NAME,
      endpoint: `/v1/users/${id}`,
      method: 'GET'
    });
  }

  /**
   * Create a new user
   *
   * @param user - User creation request
   * @returns Created user
   */
  async function createUser(user: CreateUserRequest): Promise<User> {
    return await request<User>({
      service: SERVICE_NAME,
      endpoint: '/v1/users',
      method: 'POST',
      data: user as unknown as Record<string, unknown>
    });
  }

  /**
   * Update an existing user
   *
   * @param id - User ID
   * @param user - User update request
   * @returns Updated user
   */
  async function updateUser(id: number, user: UpdateUserRequest): Promise<User> {
    return await request<User>({
      service: SERVICE_NAME,
      endpoint: `/v1/users/${id}`,
      method: 'PUT',
      data: user as unknown as Record<string, unknown>
    });
  }

  /**
   * Delete a user
   *
   * @param id - User ID
   */
  async function deleteUser(id: number): Promise<void> {
    await request<void>({
      service: SERVICE_NAME,
      endpoint: `/v1/users/${id}`,
      method: 'DELETE'
    });
  }

  /**
   * Assign roles to user
   *
   * @param username - Username
   * @param roles - Roles to assign
   */
  async function assignRolesToUser(username: string, roles: string[]): Promise<void> {
    await request<void>({
      service: SERVICE_NAME,
      endpoint: `/v1/users/${encodeURIComponent(username)}/roles`,
      method: 'PUT',
      data: { roles }
    });
  }

  // ============================================================================
  // Role Management Methods
  // ============================================================================

  /**
   * Get all roles
   *
   * @returns Array of roles
   */
  async function getAllRoles(): Promise<Role[]> {
    return await request<Role[]>({
      service: SERVICE_NAME,
      endpoint: '/v1/roles',
      method: 'GET'
    });
  }

  /**
   * Get role by name
   *
   * @param name - Role name
   * @returns Role
   */
  async function getRoleByName(name: string): Promise<Role> {
    return await request<Role>({
      service: SERVICE_NAME,
      endpoint: `/v1/roles/${encodeURIComponent(name)}`,
      method: 'GET'
    });
  }

  /**
   * Create a new role
   *
   * @param role - Role creation request
   * @returns Created role
   */
  async function createRole(role: CreateRoleRequest): Promise<Role> {
    return await request<Role>({
      service: SERVICE_NAME,
      endpoint: '/v1/roles',
      method: 'POST',
      data: role as unknown as Record<string, unknown>
    });
  }

  /**
   * Update role permissions
   *
   * @param rolePermissions - Role permissions request
   */
  async function updateRolePermissions(rolePermissions: RolePermissionsRequest): Promise<void> {
    await request<void>({
      service: SERVICE_NAME,
      endpoint: '/v1/roles/permissions',
      method: 'PUT',
      data: rolePermissions as unknown as Record<string, unknown>
    });
  }

  /**
   * Get user permissions
   *
   * @param userId - User ID
   * @returns Array of permissions
   */
  async function getUserPermissions(userId: number): Promise<Permission[]> {
    return await request<Permission[]>({
      service: SERVICE_NAME,
      endpoint: `/v1/roles/permissions/user/${userId}`,
      method: 'GET'
    });
  }

  /**
   * Check if user has permission
   *
   * @param userId - User ID
   * @param permission - Permission name
   * @param locationId - Optional location ID for scoped check
   * @returns Whether user has permission
   */
  async function checkUserPermission(
    userId: number,
    permission: string,
    locationId?: string
  ): Promise<boolean> {
    let endpoint = `/v1/roles/check-permission?userId=${userId}&permission=${encodeURIComponent(permission)}`;
    if (locationId) {
      endpoint += `&locationId=${encodeURIComponent(locationId)}`;
    }

    return await request<boolean>({
      service: SERVICE_NAME,
      endpoint,
      method: 'GET'
    });
  }

  // ============================================================================
  // Role Assignment Methods
  // ============================================================================

  /**
   * Create role assignment
   *
   * @param assignment - Role assignment request
   * @returns Created assignment
   */
  async function createRoleAssignment(assignment: RoleAssignmentRequest): Promise<RoleAssignment> {
    return await request<RoleAssignment>({
      service: SERVICE_NAME,
      endpoint: '/v1/roles/assignments',
      method: 'POST',
      data: assignment as unknown as Record<string, unknown>
    });
  }

  /**
   * Get user role assignments
   *
   * @param userId - User ID
   * @returns Array of role assignments
   */
  async function getUserRoleAssignments(userId: number): Promise<RoleAssignment[]> {
    return await request<RoleAssignment[]>({
      service: SERVICE_NAME,
      endpoint: `/v1/roles/assignments/user/${userId}`,
      method: 'GET'
    });
  }

  /**
   * Revoke role assignment
   *
   * @param assignmentId - Assignment ID
   */
  async function revokeRoleAssignment(assignmentId: number): Promise<void> {
    await request<void>({
      service: SERVICE_NAME,
      endpoint: `/v1/roles/assignments/${assignmentId}`,
      method: 'DELETE'
    });
  }

  // ============================================================================
  // Permission Management Methods
  // ============================================================================

  /**
   * Get all registered permissions
   *
   * @returns Array of permissions
   */
  async function getAllPermissions(): Promise<Permission[]> {
    return await request<Permission[]>({
      service: SERVICE_NAME,
      endpoint: '/v1/permissions',
      method: 'GET'
    });
  }

  /**
   * Get permissions by domain
   *
   * @param domain - Domain name
   * @returns Array of permissions for domain
   */
  async function getPermissionsByDomain(domain: string): Promise<Permission[]> {
    return await request<Permission[]>({
      service: SERVICE_NAME,
      endpoint: `/v1/permissions/domain/${encodeURIComponent(domain)}`,
      method: 'GET'
    });
  }

  /**
   * Check if permission exists
   *
   * @param permissionName - Permission name
   * @returns Whether permission exists
   */
  async function permissionExists(permissionName: string): Promise<boolean> {
    return await request<boolean>({
      service: SERVICE_NAME,
      endpoint: `/v1/permissions/exists/${encodeURIComponent(permissionName)}`,
      method: 'GET'
    });
  }

  /**
   * Validate permission name format
   *
   * @param permissionName - Permission name to validate
   * @returns Whether name is valid
   */
  async function validatePermissionName(permissionName: string): Promise<boolean> {
    return await request<boolean>({
      service: SERVICE_NAME,
      endpoint: `/v1/permissions/validate/${encodeURIComponent(permissionName)}`,
      method: 'GET'
    });
  }

  /**
   * Register permissions from a service
   *
   * @param registrationRequest - Permission registration request
   * @returns Registration response
   */
  async function registerPermissions(
    registrationRequest: PermissionRegistrationRequest
  ): Promise<PermissionRegistrationResponse> {
    return await request<PermissionRegistrationResponse>({
      service: SERVICE_NAME,
      endpoint: '/v1/permissions/register',
      method: 'POST',
      data: registrationRequest as unknown as Record<string, unknown>
    });
  }

  // ============================================================================
  // Initialization
  // ============================================================================

  /**
   * Initialize from stored tokens
   */
  function initializeFromStorage(): void {
    const storedToken = localStorage.getItem('auth_token');
    const storedRefresh = localStorage.getItem('refresh_token');

    if (storedToken) {
      accessToken.value = storedToken;
    }
    if (storedRefresh) {
      refreshToken.value = storedRefresh;
    }
  }

  // Initialize on composable creation
  initializeFromStorage();

  return {
    // State
    isLoading,
    error,
    currentUser,
    accessToken,
    refreshToken,
    isAuthenticated,

    // Authentication
    login,
    generateTokenPair,
    refreshAccessToken,
    validateToken,
    revokeToken,
    getRolesFromToken,
    getAuthoritiesFromToken,
    getSubjectFromToken,
    logout,

    // Users
    getAllUsers,
    getUserById,
    createUser,
    updateUser,
    deleteUser,
    assignRolesToUser,

    // Roles
    getAllRoles,
    getRoleByName,
    createRole,
    updateRolePermissions,
    getUserPermissions,
    checkUserPermission,

    // Role Assignments
    createRoleAssignment,
    getUserRoleAssignments,
    revokeRoleAssignment,

    // Permissions
    getAllPermissions,
    getPermissionsByDomain,
    permissionExists,
    validatePermissionName,
    registerPermissions
  };
}
