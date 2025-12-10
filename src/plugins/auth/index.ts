/**
 * FlashAuth authentication plugin for Elysia
 * Provides complete user authentication with email/password, 2FA, and passkeys
 */

import { Elysia } from 'elysia';
import type { AuthPluginConfig } from './config.js';
import { DEFAULT_CONFIG } from './config.js';
import { createDatabaseConnection } from './utils/db.js';
import { createAuthRoutes } from './routes.js';

export { type AuthPluginConfig } from './config.js';
export { type User, type UserPublic, type CreateUserInput } from './models/user.model.js';
export { type EmailVerificationToken } from './models/verification.model.js';
export { type PasswordResetToken } from './models/reset.model.js';
export { type TOTPSecret } from './models/totp.model.js';
export { type PasskeyCredential } from './models/passkey.model.js';

/**
 * Create FlashAuth authentication plugin for Elysia
 * 
 * @example
 * ```typescript
 * import { Elysia } from 'elysia';
 * import { FlashAuth } from 'flashauth';
 * import { flashAuthPlugin } from 'flashauth/plugins/auth';
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
    tokenExpiration: {
      ...DEFAULT_CONFIG.tokenExpiration,
      ...config.tokenExpiration,
    },
    security: {
      ...DEFAULT_CONFIG.security,
      ...config.security,
    },
  };

  // Create database connection
  const db = createDatabaseConnection(fullConfig.databaseUrl);

  // Create auth routes
  const authRoutes = createAuthRoutes(db, fullConfig);

  return new Elysia({
    name: 'flashauth-plugin',
  })
    .use(authRoutes);
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
