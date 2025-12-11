/**
 * FlashAuth - Ultra-Fast PASETO v4 Local Authentication Framework
 * @module flashauth
 */

// Main class
export { FlashAuth } from './flashauth.js';
export type { FlashAuthConfig } from './flashauth.js';

// Core types
export { Claims } from './core/claims.js';
export type { StandardClaims, ValidationOptions } from './core/claims.js';

// Token builder
export { TokenBuilder } from './tokens/token-builder.js';

// Token store
export { InMemoryRevocationStore, TokenCache } from './tokens/token-store.js';
export type { RevocationStore } from './tokens/token-store.js';

// Elysia plugins
// flashAuth: lightweight plugin with context & macros only (from elysia-plugin.ts)
// flashAuthCore & flashAuthRoutes: split plugins for better modularity (from auth/index.ts)
export {
  flashAuth,
  type FlashAuthPluginConfig,
  type FlashAuthContext as FlashAuthElysiaContext,
} from './plugins/elysia-plugin.js';

// Guard functions (deprecated in favor of macros, but still available)
export {
  requireAuth,
  requirePermission,
  requireAnyPermission,
  requireAllPermissions,
  requireRole,
  requireAnyRole,
} from './plugins/elysia-plugin.js';

// Permission utilities
export type { RolePermissions } from './utils/permission-utils.js';
export {
  matchPermission,
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  expandRolesToPermissions,
  mergePermissions,
  validatePermissionFormat,
} from './utils/permission-utils.js';

// Errors
export {
  FlashAuthError,
  TokenError,
  TokenExpiredError,
  TokenInvalidError,
  TokenRevokedError,
  PermissionError,
  SessionError,
  CryptographyError,
  KeyError,
  ValidationError,
} from './core/errors.js';

// Cryptography (for advanced usage)
export { generateSecret } from './core/cryptography.js';

// PASETO utilities (for advanced usage)
export { base64urlEncode, base64urlDecode } from './core/paseto.js';

// Authentication plugins
// flashAuthCore: lightweight plugin with context & macros only (use in sub-routes)
// flashAuthRoutes: plugin with /auth routes only (use once in main app)
export {
  flashAuthCore,
  flashAuthRoutes,
  runMigrations,
  type FlashAuthCoreConfig,
  type AuthPluginConfig,
  type FlashAuthContext,
  type User,
  type UserPublic,
  type CreateUserInput,
  type EmailVerificationToken,
  type PasswordResetToken,
  type TOTPSecret,
  type PasskeyCredential,
} from './plugins/auth/index.js';
