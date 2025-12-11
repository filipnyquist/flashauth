/**
 * FlashAuth authentication plugin for Elysia
 * Provides complete user authentication with email/password, 2FA, and passkeys
 */

import { Elysia } from 'elysia';
import type { AuthPluginConfig } from './config.js';
import { DEFAULT_CONFIG } from './config.js';
import { createDatabaseConnection } from './utils/db.js';
import { createAuthRoutes } from './routes.js';
import type { Claims } from '../../core/claims.js';
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
 * Create FlashAuth authentication plugin for Elysia
 * 
 * @example
 * ```typescript
 * import { Elysia } from 'elysia';
 * import { FlashAuth, flashAuthPlugin } from 'flashauth';
 * 
 * const auth = new FlashAuth({ secret: process.env.AUTH_SECRET! });
 * 
 * const app = new Elysia()
 *   .use(flashAuthPlugin({
 *     databaseUrl: process.env.DATABASE_URL!,
 *     flashAuth: auth,
 *     webauthn: {
 *       rpName: 'My App',
 *       rpID: 'example.com',
 *       origin: 'https://example.com',
 *     },
 *   }))
 *   .listen(3000);
 * ```
 */
export function flashAuthPlugin(config: AuthPluginConfig) {
  // Merge with default config
  const fullConfig: AuthPluginConfig = {
    ...config,
    tokenLocation: config.tokenLocation || 'bearer',
    cookieName: config.cookieName || 'auth_token',
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
    name: 'flashauth-plugin',
  })
    // Add token validation and flashAuth context
    .derive(async ({ headers, cookie }) => {
      let token: string | null = null;
      let claims: Claims | null = null;

      try {
        // Extract token from request
        if (fullConfig.tokenLocation === 'bearer') {
          const authHeader = headers['authorization'];
          if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.slice(7);
          }
        } else if (fullConfig.tokenLocation === 'cookie') {
          const cookieValue = cookie[fullConfig.cookieName!];
          if (cookieValue && typeof cookieValue.value === 'string') {
            token = cookieValue.value;
          }
        }

        // Validate token if present
        if (token) {
          claims = await fullConfig.flashAuth.validateToken(token);
        }
      } catch (error) {
        // Token validation failed - leave claims as null
        // Don't throw here, let macros handle authentication
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
              await fullConfig.flashAuth.revokeToken(claims.jti, claims.exp);
            }
          },
        },
      };
    })
    // Add macros for route-level authentication
    .macro(({ onBeforeHandle }) => ({
      /**
       * Require authentication for this route
       * @example
       * .get('/profile', ({ flashAuth }) => flashAuth.claims, {
       *   isAuth: true
       * })
       */
      isAuth(enabled: boolean) {
        if (!enabled) return;
        
        onBeforeHandle(({ flashAuth }: any) => {
          if (!flashAuth || !flashAuth.claims) {
            throw new TokenError('Authentication required');
          }
        });
      },
      
      /**
       * Require specific permission for this route
       * @example
       * .get('/posts', () => getPosts(), {
       *   requirePermission: 'posts:read'
       * })
       */
      requirePermission(permission: string | false) {
        if (!permission) return;
        
        onBeforeHandle(({ flashAuth }: any) => {
          if (!flashAuth || !flashAuth.claims) {
            throw new TokenError('Authentication required');
          }
          if (!flashAuth.hasPermission(permission)) {
            throw new PermissionError(`Requires '${permission}' permission`);
          }
        });
      },
      
      /**
       * Require any of multiple permissions for this route
       * @example
       * .delete('/posts/:id', () => deletePost(), {
       *   requireAnyPermission: ['posts:delete', 'admin:*']
       * })
       */
      requireAnyPermission(permissions: string[] | false) {
        if (!permissions) return;
        
        onBeforeHandle(({ flashAuth }: any) => {
          if (!flashAuth || !flashAuth.claims) {
            throw new TokenError('Authentication required');
          }
          if (!flashAuth.hasAnyPermission(permissions)) {
            throw new PermissionError(
              `Requires one of: ${permissions.join(', ')}`
            );
          }
        });
      },
      
      /**
       * Require all of multiple permissions for this route
       * @example
       * .get('/dashboard', () => getDashboard(), {
       *   requireAllPermissions: ['users:read', 'posts:write']
       * })
       */
      requireAllPermissions(permissions: string[] | false) {
        if (!permissions) return;
        
        onBeforeHandle(({ flashAuth }: any) => {
          if (!flashAuth || !flashAuth.claims) {
            throw new TokenError('Authentication required');
          }
          if (!flashAuth.hasAllPermissions(permissions)) {
            throw new PermissionError(
              `Requires all of: ${permissions.join(', ')}`
            );
          }
        });
      },
      
      /**
       * Require specific role for this route
       * @example
       * .get('/admin', () => getAdminPanel(), {
       *   requireRole: 'admin'
       * })
       */
      requireRole(role: string | false) {
        if (!role) return;
        
        onBeforeHandle(({ flashAuth }: any) => {
          if (!flashAuth || !flashAuth.claims) {
            throw new TokenError('Authentication required');
          }
          if (!flashAuth.hasRole(role)) {
            throw new PermissionError(`Requires '${role}' role`);
          }
        });
      },
      
      /**
       * Require any of multiple roles for this route
       * @example
       * .get('/moderation', () => getModerationPanel(), {
       *   requireAnyRole: ['admin', 'moderator']
       * })
       */
      requireAnyRole(roles: string[] | false) {
        if (!roles) return;
        
        onBeforeHandle(({ flashAuth }: any) => {
          if (!flashAuth || !flashAuth.claims) {
            throw new TokenError('Authentication required');
          }
          if (!flashAuth.hasAnyRole(roles)) {
            throw new PermissionError(
              `Requires one of: ${roles.join(', ')}`
            );
          }
        });
      },
    }));

  // Only add auth routes if database is configured
  if (fullConfig.databaseUrl) {
    const db = createDatabaseConnection(fullConfig.databaseUrl);
    const authRoutes = createAuthRoutes(db, fullConfig);
    plugin.use(authRoutes);
  }

  return plugin;
}

/**
 * Run database migrations
 * 
 * @example
 * ```typescript
 * import { runMigrations } from 'flashauth/plugins/auth';
 * import { readFileSync } from 'fs';
 * 
 * const migrationSql = readFileSync('./migrations/001_initial.sql', 'utf-8');
 * await runMigrations(process.env.DATABASE_URL!, migrationSql);
 * ```
 */
export async function runMigrations(databaseUrl: string, migrationSql: string): Promise<void> {
  const db = createDatabaseConnection(databaseUrl);
  await db.runMigrations(migrationSql);
  await db.close();
}
