/**
 * Security Service Composable Tests (CAP-275)
 *
 * Unit tests for useSecurityService composable.
 * Tests authentication flows, token management, and API integration.
 *
 * @jest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { useSecurityService } from '../webapp/composables/useSecurityService';
import type {
  TokenResponse,
  TokenPairResponse,
  TokenValidationResponse,
  User,
  Role,
  Permission
} from '../webapp/types/security';

// Mock the API client
const mockRequest = vi.fn();
vi.mock('../webapp/api', () => ({
  usePositivityApiClient: () => ({
    request: mockRequest
  })
}));

// Mock localStorage
const localStorageMock = {
  store: {} as Record<string, string>,
  getItem: vi.fn((key: string) => localStorageMock.store[key] || null),
  setItem: vi.fn((key: string, value: string) => {
    localStorageMock.store[key] = value;
  }),
  removeItem: vi.fn((key: string) => {
    delete localStorageMock.store[key];
  }),
  clear: vi.fn(() => {
    localStorageMock.store = {};
  })
};

Object.defineProperty(window, 'localStorage', { value: localStorageMock });

describe('useSecurityService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorageMock.clear();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('Authentication', () => {
    it('should login and store token', async () => {
      const mockResponse: TokenResponse = { token: 'jwt-token-123' };
      mockRequest.mockResolvedValueOnce(mockResponse);

      const { login, accessToken, isAuthenticated } = useSecurityService();

      const result = await login({ username: 'testuser', roles: ['SHOP_MGR'] });

      expect(result).toEqual(mockResponse);
      expect(accessToken.value).toBe('jwt-token-123');
      expect(isAuthenticated.value).toBe(true);
      expect(localStorageMock.setItem).toHaveBeenCalledWith('auth_token', 'jwt-token-123');
      expect(mockRequest).toHaveBeenCalledWith({
        service: 'pos-security-service',
        endpoint: '/v1/auth/login?subject=testuser&roles=SHOP_MGR',
        method: 'POST'
      });
    });

    it('should generate token pair and store both tokens', async () => {
      const mockResponse: TokenPairResponse = {
        accessToken: 'access-token-123',
        refreshToken: 'refresh-token-456'
      };
      mockRequest.mockResolvedValueOnce(mockResponse);

      const { generateTokenPair, accessToken, refreshToken } = useSecurityService();

      const result = await generateTokenPair({ username: 'testuser', roles: ['ADMIN'] });

      expect(result).toEqual(mockResponse);
      expect(accessToken.value).toBe('access-token-123');
      expect(refreshToken.value).toBe('refresh-token-456');
      expect(localStorageMock.setItem).toHaveBeenCalledWith('auth_token', 'access-token-123');
      expect(localStorageMock.setItem).toHaveBeenCalledWith('refresh_token', 'refresh-token-456');
    });

    it('should refresh access token', async () => {
      const mockResponse: TokenPairResponse = {
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token'
      };
      mockRequest.mockResolvedValueOnce(mockResponse);

      const { refreshAccessToken, accessToken, refreshToken } = useSecurityService();

      const result = await refreshAccessToken({ refreshToken: 'old-refresh-token' });

      expect(result).toEqual(mockResponse);
      expect(accessToken.value).toBe('new-access-token');
      expect(refreshToken.value).toBe('new-refresh-token');
    });

    it('should validate token', async () => {
      const mockResponse: TokenValidationResponse = { valid: true };
      mockRequest.mockResolvedValueOnce(mockResponse);

      const { validateToken } = useSecurityService();

      const result = await validateToken('test-token');

      expect(result).toEqual({ valid: true });
      expect(mockRequest).toHaveBeenCalledWith({
        service: 'pos-security-service',
        endpoint: '/v1/auth/validate?token=test-token',
        method: 'GET'
      });
    });

    it('should return invalid for validation errors', async () => {
      mockRequest.mockRejectedValueOnce(new Error('Unauthorized'));

      const { validateToken } = useSecurityService();

      const result = await validateToken('invalid-token');

      expect(result).toEqual({ valid: false });
    });

    it('should revoke token', async () => {
      mockRequest.mockResolvedValueOnce(undefined);

      const { revokeToken } = useSecurityService();

      await revokeToken('token-to-revoke');

      expect(mockRequest).toHaveBeenCalledWith({
        service: 'pos-security-service',
        endpoint: '/v1/auth/delete?token=token-to-revoke',
        method: 'DELETE'
      });
    });

    it('should logout and clear tokens', async () => {
      // Setup initial state
      localStorageMock.store['auth_token'] = 'access-token';
      localStorageMock.store['refresh_token'] = 'refresh-token';

      mockRequest.mockResolvedValue(undefined);

      const { logout, accessToken, refreshToken, isAuthenticated } = useSecurityService();

      // Set initial values
      accessToken.value = 'access-token';
      refreshToken.value = 'refresh-token';

      await logout();

      expect(accessToken.value).toBeNull();
      expect(refreshToken.value).toBeNull();
      expect(isAuthenticated.value).toBe(false);
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('auth_token');
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('refresh_token');
    });

    it('should get roles from token', async () => {
      mockRequest.mockResolvedValueOnce(['SHOP_MGR', 'INVENTORY_MGR']);

      const { getRolesFromToken } = useSecurityService();

      const roles = await getRolesFromToken('test-token');

      expect(roles).toEqual(['SHOP_MGR', 'INVENTORY_MGR']);
    });

    it('should get subject from token', async () => {
      mockRequest.mockResolvedValueOnce('john.doe');

      const { getSubjectFromToken } = useSecurityService();

      const subject = await getSubjectFromToken('test-token');

      expect(subject).toBe('john.doe');
    });
  });

  describe('User Management', () => {
    it('should get all users', async () => {
      const mockUsers: User[] = [
        { id: 1, username: 'user1' },
        { id: 2, username: 'user2' }
      ];
      mockRequest.mockResolvedValueOnce(mockUsers);

      const { getAllUsers } = useSecurityService();

      const users = await getAllUsers();

      expect(users).toEqual(mockUsers);
      expect(mockRequest).toHaveBeenCalledWith({
        service: 'pos-security-service',
        endpoint: '/v1/users',
        method: 'GET'
      });
    });

    it('should get user by ID', async () => {
      const mockUser: User = { id: 1, username: 'testuser', roles: ['ADMIN'] };
      mockRequest.mockResolvedValueOnce(mockUser);

      const { getUserById } = useSecurityService();

      const user = await getUserById(1);

      expect(user).toEqual(mockUser);
      expect(mockRequest).toHaveBeenCalledWith({
        service: 'pos-security-service',
        endpoint: '/v1/users/1',
        method: 'GET'
      });
    });

    it('should create user', async () => {
      const newUser: User = { id: 1, username: 'newuser' };
      mockRequest.mockResolvedValueOnce(newUser);

      const { createUser } = useSecurityService();

      const user = await createUser({
        username: 'newuser',
        password: 'password123',
        roles: ['USER']
      });

      expect(user).toEqual(newUser);
      expect(mockRequest).toHaveBeenCalledWith({
        service: 'pos-security-service',
        endpoint: '/v1/users',
        method: 'POST',
        data: {
          username: 'newuser',
          password: 'password123',
          roles: ['USER']
        }
      });
    });

    it('should update user', async () => {
      const updatedUser: User = { id: 1, username: 'updateduser' };
      mockRequest.mockResolvedValueOnce(updatedUser);

      const { updateUser } = useSecurityService();

      const user = await updateUser(1, { username: 'updateduser' });

      expect(user).toEqual(updatedUser);
    });

    it('should delete user', async () => {
      mockRequest.mockResolvedValueOnce(undefined);

      const { deleteUser } = useSecurityService();

      await deleteUser(1);

      expect(mockRequest).toHaveBeenCalledWith({
        service: 'pos-security-service',
        endpoint: '/v1/users/1',
        method: 'DELETE'
      });
    });
  });

  describe('Role Management', () => {
    it('should get all roles', async () => {
      const mockRoles: Role[] = [
        { id: 1, name: 'ADMIN' },
        { id: 2, name: 'USER' }
      ];
      mockRequest.mockResolvedValueOnce(mockRoles);

      const { getAllRoles } = useSecurityService();

      const roles = await getAllRoles();

      expect(roles).toEqual(mockRoles);
    });

    it('should get role by name', async () => {
      const mockRole: Role = { id: 1, name: 'ADMIN', description: 'Administrator' };
      mockRequest.mockResolvedValueOnce(mockRole);

      const { getRoleByName } = useSecurityService();

      const role = await getRoleByName('ADMIN');

      expect(role).toEqual(mockRole);
      expect(mockRequest).toHaveBeenCalledWith({
        service: 'pos-security-service',
        endpoint: '/v1/roles/ADMIN',
        method: 'GET'
      });
    });

    it('should create role', async () => {
      const mockRole: Role = { id: 1, name: 'NEW_ROLE' };
      mockRequest.mockResolvedValueOnce(mockRole);

      const { createRole } = useSecurityService();

      const role = await createRole({ name: 'NEW_ROLE', description: 'A new role' });

      expect(role).toEqual(mockRole);
    });

    it('should check user permission', async () => {
      mockRequest.mockResolvedValueOnce(true);

      const { checkUserPermission } = useSecurityService();

      const hasPermission = await checkUserPermission(1, 'inventory:read', 'LOC-001');

      expect(hasPermission).toBe(true);
      expect(mockRequest).toHaveBeenCalledWith({
        service: 'pos-security-service',
        endpoint: '/v1/roles/check-permission?userId=1&permission=inventory%3Aread&locationId=LOC-001',
        method: 'GET'
      });
    });
  });

  describe('Permission Management', () => {
    it('should get all permissions', async () => {
      const mockPermissions: Permission[] = [
        { id: 1, name: 'inventory:item:read' },
        { id: 2, name: 'inventory:item:write' }
      ];
      mockRequest.mockResolvedValueOnce(mockPermissions);

      const { getAllPermissions } = useSecurityService();

      const permissions = await getAllPermissions();

      expect(permissions).toEqual(mockPermissions);
    });

    it('should get permissions by domain', async () => {
      const mockPermissions: Permission[] = [
        { id: 1, name: 'inventory:item:read', domain: 'inventory' }
      ];
      mockRequest.mockResolvedValueOnce(mockPermissions);

      const { getPermissionsByDomain } = useSecurityService();

      const permissions = await getPermissionsByDomain('inventory');

      expect(permissions).toEqual(mockPermissions);
      expect(mockRequest).toHaveBeenCalledWith({
        service: 'pos-security-service',
        endpoint: '/v1/permissions/domain/inventory',
        method: 'GET'
      });
    });

    it('should check if permission exists', async () => {
      mockRequest.mockResolvedValueOnce(true);

      const { permissionExists } = useSecurityService();

      const exists = await permissionExists('inventory:item:read');

      expect(exists).toBe(true);
    });

    it('should validate permission name', async () => {
      mockRequest.mockResolvedValueOnce(true);

      const { validatePermissionName } = useSecurityService();

      const isValid = await validatePermissionName('inventory:item:read');

      expect(isValid).toBe(true);
    });

    it('should register permissions', async () => {
      const mockResponse = {
        success: true,
        registeredPermissions: 2,
        totalPermissions: 2
      };
      mockRequest.mockResolvedValueOnce(mockResponse);

      const { registerPermissions } = useSecurityService();

      const response = await registerPermissions({
        serviceName: 'inventory-service',
        domain: 'inventory',
        permissions: [
          { name: 'inventory:item:read', description: 'Read items' },
          { name: 'inventory:item:write', description: 'Write items' }
        ]
      });

      expect(response).toEqual(mockResponse);
    });
  });

  describe('Error Handling', () => {
    it('should set error state on login failure', async () => {
      const mockError = new Error('Invalid credentials');
      mockRequest.mockRejectedValueOnce(mockError);

      const { login, error, isLoading } = useSecurityService();

      await expect(login({ username: 'bad', roles: [] })).rejects.toThrow('Invalid credentials');

      expect(error.value).toEqual(mockError);
      expect(isLoading.value).toBe(false);
    });

    it('should handle loading state correctly', async () => {
      let resolvePromise: (value: TokenResponse) => void;
      const pendingPromise = new Promise<TokenResponse>((resolve) => {
        resolvePromise = resolve;
      });
      mockRequest.mockReturnValueOnce(pendingPromise);

      const { login, isLoading } = useSecurityService();

      const loginPromise = login({ username: 'test', roles: ['USER'] });

      // isLoading should be true while waiting
      expect(isLoading.value).toBe(true);

      // Resolve the promise
      resolvePromise!({ token: 'test-token' });
      await loginPromise;

      // isLoading should be false after completion
      expect(isLoading.value).toBe(false);
    });
  });

  describe('Storage Initialization', () => {
    it('should initialize from localStorage', () => {
      localStorageMock.store['auth_token'] = 'stored-access-token';
      localStorageMock.store['refresh_token'] = 'stored-refresh-token';

      const { accessToken, refreshToken, isAuthenticated } = useSecurityService();

      expect(accessToken.value).toBe('stored-access-token');
      expect(refreshToken.value).toBe('stored-refresh-token');
      expect(isAuthenticated.value).toBe(true);
    });
  });
});
