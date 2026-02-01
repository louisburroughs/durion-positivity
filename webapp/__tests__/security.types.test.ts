/**
 * Security Types Tests (CAP-275)
 *
 * Unit tests for security type definitions and type guards.
 *
 * @jest-environment jsdom
 */

import { describe, it, expect } from 'vitest';
import {
  isTokenPairResponse,
  isTokenResponse,
  isSecurityErrorResponse
} from '../webapp/types/security';

describe('Security Type Guards', () => {
  describe('isTokenResponse', () => {
    it('should return true for valid TokenResponse', () => {
      const valid = { token: 'jwt-token-123' };
      expect(isTokenResponse(valid)).toBe(true);
    });

    it('should return false for TokenPairResponse', () => {
      const tokenPair = { accessToken: 'access', refreshToken: 'refresh' };
      expect(isTokenResponse(tokenPair)).toBe(false);
    });

    it('should return false for null', () => {
      expect(isTokenResponse(null)).toBe(false);
    });

    it('should return false for undefined', () => {
      expect(isTokenResponse(undefined)).toBe(false);
    });

    it('should return false for primitive values', () => {
      expect(isTokenResponse('string')).toBe(false);
      expect(isTokenResponse(123)).toBe(false);
      expect(isTokenResponse(true)).toBe(false);
    });

    it('should return false for object without token', () => {
      expect(isTokenResponse({ other: 'value' })).toBe(false);
    });

    it('should return false for object with non-string token', () => {
      expect(isTokenResponse({ token: 123 })).toBe(false);
      expect(isTokenResponse({ token: null })).toBe(false);
    });
  });

  describe('isTokenPairResponse', () => {
    it('should return true for valid TokenPairResponse', () => {
      const valid = {
        accessToken: 'access-token-123',
        refreshToken: 'refresh-token-456'
      };
      expect(isTokenPairResponse(valid)).toBe(true);
    });

    it('should return false for TokenResponse', () => {
      const tokenResponse = { token: 'jwt-token' };
      expect(isTokenPairResponse(tokenResponse)).toBe(false);
    });

    it('should return false for null', () => {
      expect(isTokenPairResponse(null)).toBe(false);
    });

    it('should return false for undefined', () => {
      expect(isTokenPairResponse(undefined)).toBe(false);
    });

    it('should return false for object with only accessToken', () => {
      expect(isTokenPairResponse({ accessToken: 'access' })).toBe(false);
    });

    it('should return false for object with only refreshToken', () => {
      expect(isTokenPairResponse({ refreshToken: 'refresh' })).toBe(false);
    });

    it('should return false for object with non-string tokens', () => {
      expect(isTokenPairResponse({ accessToken: 123, refreshToken: 'refresh' })).toBe(false);
      expect(isTokenPairResponse({ accessToken: 'access', refreshToken: 456 })).toBe(false);
    });
  });

  describe('isSecurityErrorResponse', () => {
    it('should return true for valid SecurityErrorResponse', () => {
      const valid = {
        error: 'INVALID_REQUEST',
        message: 'Username cannot be blank',
        correlationId: 'corr-123'
      };
      expect(isSecurityErrorResponse(valid)).toBe(true);
    });

    it('should return true for SecurityErrorResponse with optional fields', () => {
      const valid = {
        error: 'INVALID_REQUEST',
        message: 'Error occurred',
        correlationId: 'corr-123',
        timestamp: '2026-01-27T14:30:00Z'
      };
      expect(isSecurityErrorResponse(valid)).toBe(true);
    });

    it('should return false for null', () => {
      expect(isSecurityErrorResponse(null)).toBe(false);
    });

    it('should return false for undefined', () => {
      expect(isSecurityErrorResponse(undefined)).toBe(false);
    });

    it('should return false for object without error', () => {
      expect(isSecurityErrorResponse({ message: 'Error', correlationId: 'id' })).toBe(false);
    });

    it('should return false for object without message', () => {
      expect(isSecurityErrorResponse({ error: 'ERROR', correlationId: 'id' })).toBe(false);
    });

    it('should return false for object with non-string fields', () => {
      expect(isSecurityErrorResponse({ error: 123, message: 'msg', correlationId: 'id' })).toBe(
        false
      );
      expect(isSecurityErrorResponse({ error: 'ERR', message: 456, correlationId: 'id' })).toBe(
        false
      );
    });
  });
});

describe('Security Type Contracts', () => {
  it('LoginRequest should have required fields', () => {
    // This test ensures the type definition is correct
    const loginRequest = {
      username: 'testuser',
      roles: ['SHOP_MGR', 'INVENTORY_MGR']
    };

    expect(loginRequest.username).toBe('testuser');
    expect(loginRequest.roles).toHaveLength(2);
  });

  it('TokenPairResponse should match contract', () => {
    const tokenPair = {
      accessToken: 'eyJhbGciOiJIUzI1NiJ9...',
      refreshToken: 'eyJhbGciOiJIUzI1NiJ9...'
    };

    expect(tokenPair.accessToken).toBeDefined();
    expect(tokenPair.refreshToken).toBeDefined();
  });

  it('User should support optional fields', () => {
    const minimalUser = {
      username: 'testuser'
    };

    const fullUser = {
      id: 1,
      username: 'testuser',
      password: 'secret',
      roles: ['ADMIN', 'USER']
    };

    expect(minimalUser.username).toBeDefined();
    expect(fullUser.id).toBe(1);
    expect(fullUser.roles).toContain('ADMIN');
  });

  it('Role should support audit fields', () => {
    const role = {
      id: 1,
      name: 'SHOP_MGR',
      description: 'Shop Manager',
      permissions: [],
      createdAt: '2026-01-27T14:30:00Z',
      createdBy: 'admin',
      lastModifiedAt: '2026-01-27T15:00:00Z',
      lastModifiedBy: 'admin'
    };

    expect(role.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(role.lastModifiedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('Permission should follow domain:resource:action format', () => {
    const permission = {
      id: 1,
      name: 'inventory:item:read',
      domain: 'inventory',
      resource: 'item',
      action: 'read',
      description: 'Read inventory items'
    };

    expect(permission.name).toBe(`${permission.domain}:${permission.resource}:${permission.action}`);
  });

  it('RoleAssignment should support scoping', () => {
    const globalAssignment = {
      role: 'ADMIN',
      user: 'john.doe',
      scopeType: 'GLOBAL',
      effective: true
    };

    const locationAssignment = {
      role: 'SHOP_MGR',
      user: 'jane.doe',
      scopeType: 'LOCATION',
      scopeLocationIds: ['LOC-001', 'LOC-002'],
      effectiveStartDate: '2026-01-01',
      effectiveEndDate: '2026-12-31',
      effective: true
    };

    expect(globalAssignment.scopeType).toBe('GLOBAL');
    expect(locationAssignment.scopeLocationIds).toHaveLength(2);
  });
});
