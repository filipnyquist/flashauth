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

// Elysia plugin (removed - use flashAuthPlugin instead)
// Guard functions are still available but deprecated in favor of macros
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

// Authentication plugin (user management with email/password, 2FA, passkeys)
export {
  flashAuthPlugin,
  runMigrations,
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
