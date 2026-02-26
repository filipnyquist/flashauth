/**
 * FlashAuth authentication plugin for Elysia
 * Provides complete user authentication with email/password, 2FA, passkeys,
 * invite links, API keys, and permission management
 */

import { Elysia } from 'elysia';
import type { AuthPluginConfig } from './config.js';
import { DEFAULT_CONFIG } from './config.js';
import { createAuthRoutes } from './routes.js';
import type { Claims } from '../../core/claims.js';
import type { FlashAuth } from '../../flashauth.js';
import { TokenError, PermissionError } from '../../core/errors.js';

export { type AuthPluginConfig } from './config.js';
export { type User, type UserPublic, type CreateUserInput } from './models/user.model.js';
export { type EmailVerificationToken } from './models/verification.model.js';
export { type PasswordResetToken } from './models/reset.model.js';
export { type TOTPSecret } from './models/totp.model.js';
export { type PasskeyCredential } from './models/passkey.model.js';

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
 * Configuration for the core auth plugin (context & macros only)
 */
export interface FlashAuthCoreConfig {
  /** FlashAuth instance for token validation */
  flashAuth: FlashAuth;
  /** Token location: 'bearer' for Authorization header, 'cookie' for cookies, 'both' for both */
  tokenLocation?: 'bearer' | 'cookie' | 'both';
  /** Cookie name (when tokenLocation includes cookie) */
  cookieName?: string;
}

/**
 * Create core FlashAuth plugin (context & macros only, no /auth routes)
 * Use this in sub-routes to get access to flashAuth context and authentication macros.
 */
export function flashAuthCore(config: FlashAuthCoreConfig) {
  const {
    flashAuth: auth,
    tokenLocation = 'both',
    cookieName = 'auth_token',
  } = config;

  return new Elysia({
    name: 'flashauth-core',
  })
    // Add token validation and flashAuth context
    .derive(async ({ headers, cookie }) => {
      let token: string | null = null;
      let claims: Claims | null = null;

      try {
        // Extract token from bearer header
        if (tokenLocation === 'bearer' || tokenLocation === 'both') {
          const authHeader = headers['authorization'];
          if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.slice(7);
          }
        }

        // Extract token from cookie (fallback when using 'both')
        if (!token && (tokenLocation === 'cookie' || tokenLocation === 'both')) {
          const cookieValue = cookie[cookieName];
          if (cookieValue && typeof cookieValue.value === 'string') {
            token = cookieValue.value;
          }
        }

        // Validate token if present
        if (token) {
          claims = await auth.validateToken(token);
        }
      } catch {
        // Token validation failed - leave claims as null
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
              await auth.revokeToken(claims.jti, claims.exp ?? 0);
            }
          },
        },
      };
    })
    // Add macros for route-level authentication
    .macro({
      isAuth(enabled: boolean) {
        if (!enabled) return;

        return {
          beforeHandle({ flashAuth }: any) {
            if (!flashAuth || !flashAuth.claims) {
              throw new TokenError('Authentication required');
            }
          }
        };
      },

      requirePermission(permission: string | false) {
        if (!permission) return;

        return {
          beforeHandle({ flashAuth }: any) {
            if (!flashAuth || !flashAuth.claims) {
              throw new TokenError('Authentication required');
            }
            if (!flashAuth.hasPermission(permission)) {
              throw new PermissionError(`Requires '${permission}' permission`);
            }
          }
        };
      },

      requireAnyPermission(permissions: string[] | false) {
        if (!permissions) return;

        return {
          beforeHandle({ flashAuth }: any) {
            if (!flashAuth || !flashAuth.claims) {
              throw new TokenError('Authentication required');
            }
            if (!flashAuth.hasAnyPermission(permissions)) {
              throw new PermissionError(
                `Requires one of: ${permissions.join(', ')}`
              );
            }
          }
        };
      },

      requireAllPermissions(permissions: string[] | false) {
        if (!permissions) return;

        return {
          beforeHandle({ flashAuth }: any) {
            if (!flashAuth || !flashAuth.claims) {
              throw new TokenError('Authentication required');
            }
            if (!flashAuth.hasAllPermissions(permissions)) {
              throw new PermissionError(
                `Requires all of: ${permissions.join(', ')}`
              );
            }
          }
        };
      },

      requireRole(role: string | false) {
        if (!role) return;

        return {
          beforeHandle({ flashAuth }: any) {
            if (!flashAuth || !flashAuth.claims) {
              throw new TokenError('Authentication required');
            }
            if (!flashAuth.hasRole(role)) {
              throw new PermissionError(`Requires '${role}' role`);
            }
          }
        };
      },

      requireAnyRole(roles: string[] | false) {
        if (!roles) return;

        return {
          beforeHandle({ flashAuth }: any) {
            if (!flashAuth || !flashAuth.claims) {
              throw new TokenError('Authentication required');
            }
            if (!flashAuth.hasAnyRole(roles)) {
              throw new PermissionError(
                `Requires one of: ${roles.join(', ')}`
              );
            }
          }
        };
      },
    })
    .as('plugin' as any);
}

/**
 * Create FlashAuth routes plugin (provides /auth/* endpoints only)
 * Use this once in the main app to add authentication routes.
 */
export function flashAuthRoutes(config: AuthPluginConfig) {
  // Merge with default config
  const fullConfig: AuthPluginConfig = {
    ...config,
    tokenExpiration: {
      ...DEFAULT_CONFIG.tokenExpiration,
      ...config.tokenExpiration,
    },
    security: {
      ...DEFAULT_CONFIG.security,
      ...config.security,
    },
  };

  const plugin = new Elysia({
    name: 'flashauth-routes',
  });

  const authRoutes = createAuthRoutes(fullConfig.db, fullConfig);
  plugin.use(authRoutes);

  return plugin;
}
