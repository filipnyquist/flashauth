/**
 * FlashAuth Elysia Plugin
 * Native integration with Elysia.js
 */

import { Elysia } from 'elysia';
import type { FlashAuth } from '../flashauth.js';
import type { Claims } from '../core/claims.js';
import { TokenError, PermissionError } from '../core/errors.js';

/**
 * Plugin configuration
 */
export interface FlashAuthPluginConfig {
  /** Token location: 'bearer' for Authorization header, 'cookie' for cookies */
  tokenLocation?: 'bearer' | 'cookie';
  /** Cookie name (when tokenLocation is 'cookie') */
  cookieName?: string;
  /** Cookie options */
  cookieSecure?: boolean;
  cookieHttpOnly?: boolean;
  cookieSameSite?: 'strict' | 'lax' | 'none';
}

/**
 * FlashAuth context injected into Elysia routes
 */
export interface FlashAuthContext {
  flashAuth: {
    /** Parsed token claims (null if not authenticated) */
    claims: Claims | null;
    /** Raw token string (null if not authenticated) */
    token: string | null;
    /** Check if user has a specific permission */
    hasPermission(permission: string): boolean;
    /** Check if user has any of the specified permissions */
    hasAnyPermission(permissions: string[]): boolean;
    /** Check if user has all of the specified permissions */
    hasAllPermissions(permissions: string[]): boolean;
    /** Check if user has a specific role */
    hasRole(role: string): boolean;
    /** Check if user has any of the specified roles */
    hasAnyRole(roles: string[]): boolean;
    /** Revoke the current token */
    revokeToken(): Promise<void>;
  };
}

/**
 * Create FlashAuth Elysia plugin
 */
export function flashAuth(
  auth: FlashAuth,
  config: FlashAuthPluginConfig = {}
) {
  const {
    tokenLocation = 'bearer',
    cookieName = 'auth_token',
  } = config;

  return new Elysia({ name: 'flashauth' })
    .derive(async ({ headers, cookie }) => {
      let token: string | null = null;
      let claims: Claims | null = null;

      try {
        // Extract token from request
        if (tokenLocation === 'bearer') {
          const authHeader = headers['authorization'];
          if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.slice(7);
          }
        } else if (tokenLocation === 'cookie') {
          const cookieValue = cookie[cookieName];
          if (cookieValue && typeof cookieValue.value === 'string') {
            token = cookieValue.value;
          }
        }

        // Validate token if present
        if (token) {
          claims = await auth.validateToken(token);
        }
      } catch (error) {
        // Token validation failed - leave claims as null
        // Don't throw here, let guards handle authentication
      }

      return {
        flashAuth: {
          claims,
          token,
          hasPermission(permission: string): boolean {
            return claims?.hasPermission(permission) ?? false;
          },
          hasAnyPermission(permissions: string[]): boolean {
            return claims?.hasAnyPermission(permissions) ?? false;
          },
          hasAllPermissions(permissions: string[]): boolean {
            return claims?.hasAllPermissions(permissions) ?? false;
          },
          hasRole(role: string): boolean {
            return claims?.hasRole(role) ?? false;
          },
          hasAnyRole(roles: string[]): boolean {
            return claims?.hasAnyRole(roles) ?? false;
          },
          async revokeToken(): Promise<void> {
            if (claims?.jti) {
              await auth.revokeToken(claims.jti, claims.exp);
            }
          },
        },
      };
    });
}

/**
 * Guard: Require authentication
 */
export const requireAuth = () =>
  new Elysia({ name: 'require-auth' })
    .derive((context: FlashAuthContext) => {
      if (!context.flashAuth || !context.flashAuth.claims) {
        throw new TokenError('Authentication required');
      }
      return {};
    });

/**
 * Guard: Require specific permission
 */
export const requirePermission = (permission: string) =>
  new Elysia({ name: `require-permission:${permission}` })
    .use(requireAuth())
    .derive((context: FlashAuthContext) => {
      if (!context.flashAuth.hasPermission(permission)) {
        throw new PermissionError(`Requires '${permission}' permission`);
      }
      return {};
    });

/**
 * Guard: Require any of multiple permissions
 */
export const requireAnyPermission = (permissions: string[]) =>
  new Elysia({ name: `require-any-permission:${permissions.join(',')}` })
    .use(requireAuth())
    .derive((context: FlashAuthContext) => {
      if (!context.flashAuth.hasAnyPermission(permissions)) {
        throw new PermissionError(
          `Requires one of: ${permissions.join(', ')}`
        );
      }
      return {};
    });

/**
 * Guard: Require all of multiple permissions
 */
export const requireAllPermissions = (permissions: string[]) =>
  new Elysia({ name: `require-all-permissions:${permissions.join(',')}` })
    .use(requireAuth())
    .derive((context: FlashAuthContext) => {
      if (!context.flashAuth.hasAllPermissions(permissions)) {
        throw new PermissionError(
          `Requires all of: ${permissions.join(', ')}`
        );
      }
      return {};
    });

/**
 * Guard: Require specific role
 */
export const requireRole = (role: string) =>
  new Elysia({ name: `require-role:${role}` })
    .use(requireAuth())
    .derive((context: FlashAuthContext) => {
      if (!context.flashAuth.hasRole(role)) {
        throw new PermissionError(`Requires '${role}' role`);
      }
      return {};
    });

/**
 * Guard: Require any of multiple roles
 */
export const requireAnyRole = (roles: string[]) =>
  new Elysia({ name: `require-any-role:${roles.join(',')}` })
    .use(requireAuth())
    .derive((context: FlashAuthContext) => {
      if (!context.flashAuth.hasAnyRole(roles)) {
        throw new PermissionError(
          `Requires one of: ${roles.join(', ')}`
        );
      }
      return {};
    });

