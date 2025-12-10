/**
 * Tests for permission utilities
 */

import { describe, test, expect } from 'bun:test';
import {
  matchPermission,
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  expandRolesToPermissions,
  mergePermissions,
  validatePermissionFormat,
} from '../../src/utils/permission-utils.js';

describe('Permission matching', () => {
  test('should match exact permission', () => {
    expect(matchPermission('posts:read', 'posts:read')).toBe(true);
    expect(matchPermission('posts:read', 'posts:write')).toBe(false);
  });

  test('should match wildcard permission', () => {
    expect(matchPermission('posts:read', 'posts:*')).toBe(true);
    expect(matchPermission('posts:write', 'posts:*')).toBe(true);
    expect(matchPermission('users:read', 'posts:*')).toBe(false);
  });

  test('should match super admin wildcard', () => {
    expect(matchPermission('posts:read', '*')).toBe(true);
    expect(matchPermission('users:delete', '*')).toBe(true);
    expect(matchPermission('anything:anything', '*')).toBe(true);
  });
});

describe('hasPermission', () => {
  test('should check if permission list includes permission', () => {
    const permissions = ['posts:read', 'posts:write'];
    
    expect(hasPermission(permissions, 'posts:read')).toBe(true);
    expect(hasPermission(permissions, 'posts:write')).toBe(true);
    expect(hasPermission(permissions, 'posts:delete')).toBe(false);
  });

  test('should check with wildcard permissions', () => {
    const permissions = ['posts:*', 'users:read'];
    
    expect(hasPermission(permissions, 'posts:read')).toBe(true);
    expect(hasPermission(permissions, 'posts:write')).toBe(true);
    expect(hasPermission(permissions, 'users:read')).toBe(true);
    expect(hasPermission(permissions, 'users:write')).toBe(false);
  });
});

describe('hasAnyPermission', () => {
  test('should check if has any of the permissions', () => {
    const permissions = ['posts:read'];
    
    expect(hasAnyPermission(permissions, ['posts:read', 'posts:write'])).toBe(true);
    expect(hasAnyPermission(permissions, ['posts:write', 'posts:delete'])).toBe(false);
  });
});

describe('hasAllPermissions', () => {
  test('should check if has all of the permissions', () => {
    const permissions = ['posts:read', 'posts:write'];
    
    expect(hasAllPermissions(permissions, ['posts:read', 'posts:write'])).toBe(true);
    expect(hasAllPermissions(permissions, ['posts:read'])).toBe(true);
    expect(hasAllPermissions(permissions, ['posts:read', 'posts:delete'])).toBe(false);
  });
});

describe('expandRolesToPermissions', () => {
  test('should expand roles to permissions', () => {
    const rolePermissions = {
      'user': ['posts:read', 'posts:write'],
      'moderator': ['posts:delete', 'users:read'],
      'admin': ['*'],
    };

    const userPerms = expandRolesToPermissions(['user'], rolePermissions);
    expect(userPerms).toEqual(['posts:read', 'posts:write']);

    const modPerms = expandRolesToPermissions(['user', 'moderator'], rolePermissions);
    expect(modPerms).toContain('posts:read');
    expect(modPerms).toContain('posts:write');
    expect(modPerms).toContain('posts:delete');
    expect(modPerms).toContain('users:read');
  });

  test('should handle unknown roles', () => {
    const rolePermissions = {
      'user': ['posts:read'],
    };

    const perms = expandRolesToPermissions(['unknown'], rolePermissions);
    expect(perms).toEqual([]);
  });
});

describe('mergePermissions', () => {
  test('should merge role and explicit permissions', () => {
    const rolePermissions = {
      'user': ['posts:read', 'posts:write'],
    };

    const merged = mergePermissions(['user'], ['users:read'], rolePermissions);
    expect(merged).toContain('posts:read');
    expect(merged).toContain('posts:write');
    expect(merged).toContain('users:read');
  });

  test('should deduplicate permissions', () => {
    const rolePermissions = {
      'user': ['posts:read'],
    };

    const merged = mergePermissions(['user'], ['posts:read'], rolePermissions);
    expect(merged.filter(p => p === 'posts:read').length).toBe(1);
  });
});

describe('validatePermissionFormat', () => {
  test('should validate correct permission formats', () => {
    expect(validatePermissionFormat('posts:read')).toBe(true);
    expect(validatePermissionFormat('users:write')).toBe(true);
    expect(validatePermissionFormat('admin:manage')).toBe(true);
    expect(validatePermissionFormat('posts:*')).toBe(true);
    expect(validatePermissionFormat('*')).toBe(true);
  });

  test('should reject invalid permission formats', () => {
    expect(validatePermissionFormat('invalid')).toBe(false);
    expect(validatePermissionFormat('too:many:parts')).toBe(false);
    expect(validatePermissionFormat(':read')).toBe(false);
    expect(validatePermissionFormat('posts:')).toBe(false);
    expect(validatePermissionFormat('')).toBe(false);
  });
});
