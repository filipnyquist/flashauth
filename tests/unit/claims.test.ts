/**
 * Tests for Claims validation and permission checking
 */

import { describe, test, expect } from 'bun:test';
import { Claims, validateClaims } from '../../src/core/claims.js';
import type { StandardClaims } from '../../src/core/claims.js';

describe('Claims', () => {
  test('should create claims from standard claims', () => {
    const standardClaims: StandardClaims = {
      sub: 'user:123',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      roles: ['user'],
      perms: ['posts:read', 'posts:write'],
    };

    const claims = new Claims(standardClaims);
    expect(claims.sub).toBe(standardClaims.sub);
    expect(claims.roles).toEqual(standardClaims.roles);
    expect(claims.perms).toEqual(standardClaims.perms);
  });

  test('should check exact permission match', () => {
    const claims = new Claims({
      sub: 'user:123',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      perms: ['posts:read', 'posts:write'],
    });

    expect(claims.hasPermission('posts:read')).toBe(true);
    expect(claims.hasPermission('posts:write')).toBe(true);
    expect(claims.hasPermission('posts:delete')).toBe(false);
  });

  test('should check wildcard permission match', () => {
    const claims = new Claims({
      sub: 'user:123',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      perms: ['posts:*'],
    });

    expect(claims.hasPermission('posts:read')).toBe(true);
    expect(claims.hasPermission('posts:write')).toBe(true);
    expect(claims.hasPermission('posts:delete')).toBe(true);
    expect(claims.hasPermission('users:read')).toBe(false);
  });

  test('should check super admin wildcard', () => {
    const claims = new Claims({
      sub: 'user:123',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      perms: ['*'],
    });

    expect(claims.hasPermission('posts:read')).toBe(true);
    expect(claims.hasPermission('users:delete')).toBe(true);
    expect(claims.hasPermission('anything:anything')).toBe(true);
  });

  test('should check any permission', () => {
    const claims = new Claims({
      sub: 'user:123',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      perms: ['posts:read'],
    });

    expect(claims.hasAnyPermission(['posts:read', 'posts:write'])).toBe(true);
    expect(claims.hasAnyPermission(['posts:write', 'posts:delete'])).toBe(false);
  });

  test('should check all permissions', () => {
    const claims = new Claims({
      sub: 'user:123',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      perms: ['posts:read', 'posts:write'],
    });

    expect(claims.hasAllPermissions(['posts:read', 'posts:write'])).toBe(true);
    expect(claims.hasAllPermissions(['posts:read', 'posts:delete'])).toBe(false);
  });

  test('should check role', () => {
    const claims = new Claims({
      sub: 'user:123',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      roles: ['user', 'moderator'],
    });

    expect(claims.hasRole('user')).toBe(true);
    expect(claims.hasRole('moderator')).toBe(true);
    expect(claims.hasRole('admin')).toBe(false);
  });

  test('should check any role', () => {
    const claims = new Claims({
      sub: 'user:123',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      roles: ['user'],
    });

    expect(claims.hasAnyRole(['user', 'admin'])).toBe(true);
    expect(claims.hasAnyRole(['admin', 'moderator'])).toBe(false);
  });

  test('should detect expired token', () => {
    const claims = new Claims({
      sub: 'user:123',
      exp: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
      iat: Math.floor(Date.now() / 1000) - 7200,
    });

    expect(claims.isExpired()).toBe(true);
  });

  test('should detect not expired token', () => {
    const claims = new Claims({
      sub: 'user:123',
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
      iat: Math.floor(Date.now() / 1000),
    });

    expect(claims.isExpired()).toBe(false);
  });

  test('should validate claims successfully', () => {
    const claims = new Claims({
      sub: 'user:123',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    });

    expect(() => validateClaims(claims)).not.toThrow();
  });

  test('should throw on expired token validation', () => {
    const claims = new Claims({
      sub: 'user:123',
      exp: Math.floor(Date.now() / 1000) - 3600,
      iat: Math.floor(Date.now() / 1000) - 7200,
    });

    expect(() => validateClaims(claims)).toThrow('expired');
  });

  test('should respect clock skew', () => {
    const claims = new Claims({
      sub: 'user:123',
      exp: Math.floor(Date.now() / 1000) - 30, // 30 seconds ago
      iat: Math.floor(Date.now() / 1000) - 3630,
    });

    expect(() => validateClaims(claims, { clockSkew: 60 })).not.toThrow();
    expect(() => validateClaims(claims, { clockSkew: 10 })).toThrow();
  });
});
