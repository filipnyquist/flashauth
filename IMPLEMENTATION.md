# FlashAuth Implementation Details

## Architecture Overview

FlashAuth is a JWT authentication framework for Bun.js and Elysia.js, built around the `jose` library for HS256 token signing. The codebase is organized into core modules, token management, Elysia plugins, and database schema.

```
src/
├── core/
│   ├── jwt.ts              # JWT creation/verification via jose (HS256)
│   ├── claims.ts           # Claims class with permission/role helpers
│   ├── cryptography.ts     # Secret key generation (32-byte random)
│   └── errors.ts           # Error hierarchy (TokenError, PermissionError, etc.)
├── tokens/
│   ├── token-builder.ts    # Fluent API for token construction
│   ├── token-parser.ts     # Token validation and claims extraction
│   └── token-store.ts      # Revocation store + LRU cache
├── plugins/
│   ├── elysia-plugin.ts    # Lightweight plugin (context + macros)
│   └── auth/
│       ├── index.ts         # flashAuthCore + flashAuthRoutes exports
│       ├── config.ts        # AuthPluginConfig interface + defaults
│       ├── routes.ts        # All /auth/* route handlers
│       ├── models/          # TypeScript types (User, TOTP, Passkey, etc.)
│       ├── services/        # Business logic per feature
│       └── utils/           # Helpers (password validation, etc.)
├── schema/
│   ├── index.ts             # Drizzle ORM schema (PostgreSQL)
│   └── generate.ts          # CLI for schema generation (TS + SQL output)
├── utils/
│   └── permission-utils.ts  # Permission matching, role expansion, wildcards
├── flashauth.ts             # Main FlashAuth class
└── index.ts                 # Public API exports
```

## Core: JWT Implementation

- **Library**: `jose` v6 — a well-audited, zero-dependency JWT library.
- **Algorithm**: HS256 (HMAC-SHA256) symmetric signing.
- **Secret**: 32-byte random key, generated via `crypto.getRandomValues()`. Accepted as `string` (base64url or raw) or `Uint8Array`.
- **Token format**: Standard JWT (`header.payload.signature`).
- **Expiration handling**: `jose`'s built-in expiration check is bypassed (large clock tolerance); expiration is validated in `Claims` for consistent error types and API key support (no `exp` required).

### Token Creation Flow

1. `FlashAuth.createToken()` → returns a `TokenBuilder` instance
2. Builder methods set claims (subject, roles, permissions, custom claims, etc.)
3. `.build()` merges role permissions into the `perms` claim, validates required fields, and calls `jose.SignJWT.sign()`

### Token Validation Flow

1. `FlashAuth.validateToken(token)` checks LRU cache first
2. Cache miss → `jose.jwtVerify()` verifies signature and returns payload
3. Claims are constructed and validated (expiration, nbf, audience, issuer)
4. Revocation store is checked (per-token JTI and per-user)
5. Valid claims are cached in the LRU store

## Permission System

- **Format**: `resource:action` (e.g., `posts:read`, `users:write`)
- **Wildcards**: `resource:*` matches all actions on a resource; `*` matches everything
- **Role expansion**: When a token is built with `.roles(['user'])`, the builder looks up `rolePermissions` and merges all resolved permissions into the `perms` claim
- **Runtime checks**: `Claims.hasPermission()`, `hasAnyPermission()`, `hasAllPermissions()` perform matching at validation time
- **Database-backed RBAC**: The auth routes plugin provides CRUD endpoints for roles, permissions, user-role assignments, and role-permission assignments stored in PostgreSQL via Drizzle

## Token Store & Caching

### Revocation Store

Interface with two implementations:

- **InMemoryRevocationStore** (default): `Map`-based storage with periodic cleanup of expired entries
- **Custom**: Implement the `RevocationStore` interface for Redis, database-backed stores, etc.

Operations:
- `revoke(jti, expiresAt)` — revoke a single token
- `revokeUser(userId)` — revoke all tokens for a user
- `isRevoked(jti)` / `isUserRevoked(userId)` — check revocation status

### LRU Cache

- Enabled by default; configurable `maxSize` (default: 10,000) and `ttl` (default: 5 minutes)
- Caches parsed `Claims` objects keyed by raw token string
- Revocation checks always hit the store (never served from cache alone)
- Invalidated on revocation

## Elysia Plugins

### `flashAuth(auth, config?)` — Lightweight

- Registers a `.derive()` that extracts tokens from bearer header or cookie
- Validates token and exposes `flashAuth` context (claims, token, permission helpers, revoke)
- Registers `.macro()` for `isAuth`, `requirePermission`, `requireAnyPermission`, `requireAllPermissions`, `requireRole`, `requireAnyRole`

### `flashAuthCore(config)` — Core

- Same as `flashAuth` but supports `tokenLocation: 'both'` (bearer first, cookie fallback)
- Designed for use alongside `flashAuthRoutes` in apps that need both custom routes and auth endpoints

### `flashAuthRoutes(config)` — Full Auth

- Merges provided config with `DEFAULT_CONFIG`
- Instantiates services: `UserService`, `VerificationService`, `PasswordResetService`, `TOTPService`, `PasskeyService`, `InviteService`, `PermissionService`, `ApiKeyService`
- Mounts all `/auth/*` routes (see README for full list)

## Database Schema (Drizzle ORM)

PostgreSQL schema with 10 tables:

| Table | Purpose |
|-------|---------|
| `users` | User accounts (email, password hash, email verified) |
| `roles` | Named roles |
| `permissions` | Named permissions (`resource:action`) |
| `user_roles` | Join table: user ↔ role |
| `role_permissions` | Join table: role ↔ permission |
| `user_permissions` | Direct user ↔ permission assignments |
| `invite_links` | Invite tokens with optional email, role, max uses, expiry |
| `passkey_credentials` | WebAuthn credentials (credential ID, public key, counter) |
| `api_keys` | Named API keys (hashed key, last used, optional expiry) |
| `totp_secrets` | TOTP secrets and backup codes |

All tables use UUID primary keys with `defaultRandom()`. Relations are defined for Drizzle's relational query API.

### Schema Generation

`src/schema/generate.ts` is a CLI that outputs:
- **TypeScript**: Complete Drizzle schema file (default)
- **SQL**: Raw `CREATE TABLE` statements (`--sql` flag)
- **File output**: `--output <path>` writes to disk instead of stdout

## Auth Services

### UserService

- `createUser(email, password)` — hashes password with `Bun.password.hash()` (bcrypt), inserts into `users` table
- `authenticate(email, password)` — looks up user, verifies with `Bun.password.verify()`
- `markEmailVerified(userId)` — sets `emailVerified = true`
- `updatePassword(userId, newPassword)` — re-hashes and updates

### VerificationService / PasswordResetService

- Creates time-limited JWT tokens (24h for email verification, 1h for password reset)
- Tokens are signed with the same FlashAuth secret
- Verification: decodes token, checks expiration, extracts `userId`

### TOTPService

- Uses `otplib` for TOTP secret generation and verification
- Generates QR code URL for authenticator apps
- Manages backup codes (stored as JSON in `totp_secrets.backup_codes`)
- `enableTOTP(userId, code)` verifies a code before enabling

### PasskeyService

- Uses `@simplewebauthn/server` for WebAuthn registration and authentication
- Stores credentials in `passkey_credentials` table
- Challenge storage is in-memory (`Map`) — in production, use Redis or similar

### InviteService

- Creates invite tokens with optional: target email, role assignment, max uses, expiry
- `useInvite(token)` validates and increments use count
- Used by `POST /auth/signup/invite`

### ApiKeyService

- Creates long-lived JWT tokens with `type: 'api_key'`
- Stores key hash in `api_keys` table for management (list, delete)
- Returns raw key only once at creation time

### PermissionService

- CRUD for roles and permissions in the database
- Assign/remove roles to/from users
- Assign/remove permissions to/from users (direct) and roles
- `getUserPermissions(userId)` returns all permissions (via roles + direct assignments)

## Error Handling

Custom error hierarchy rooted at `FlashAuthError`:

- `TokenError` — general token issues
  - `TokenExpiredError` — token past expiration
  - `TokenInvalidError` — signature/format invalid
  - `TokenRevokedError` — token or user revoked
- `PermissionError` — insufficient permissions or role
- `SessionError` — session-related issues
- `CryptographyError` — crypto operation failures
- `KeyError` — invalid key
- `ValidationError` — claim validation failures

All errors have a `name` property matching the class name, for use in Elysia error handlers.

## Testing

44+ unit tests covering:
- JWT creation and verification
- Claims validation and permission checks
- Token builder (fluent API, role expansion, api_key type)
- Token revocation and caching
- Error cases (expired, invalid, revoked tokens)
- Permission utilities (matching, wildcards, merging)

Run tests: `bun test`
