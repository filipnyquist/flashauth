# FlashAuth

**JWT Authentication Framework for Bun.js & Elysia.js**

FlashAuth is a batteries-included authentication framework built for the Bun + Elysia ecosystem. It handles JWT tokens, RBAC permissions, API keys, TOTP 2FA, passkeys, invite links, and full user management — all backed by Drizzle ORM and PostgreSQL.

## Features

- **JWT Tokens** — HS256 signing via the `jose` library, with access, refresh, and API key token types
- **Elysia Plugin** — native plugin with route macros (`isAuth`, `requirePermission`, `requireRole`, etc.)
- **Permission System** — `resource:action` format with wildcard support and role-based expansion
- **Drizzle ORM** — accepts any Drizzle PostgreSQL instance; includes schema generation CLI
- **Full Auth Routes** — signup, login, email verification, password reset, 2FA, passkeys
- **API Keys** — long-lived JWT tokens without expiration
- **Invite Links** — invite-only signups with optional role assignment
- **TOTP 2FA** — time-based one-time passwords with backup codes (via `otplib`)
- **Passkey/WebAuthn** — passwordless authentication (via `@simplewebauthn/server`)
- **Token Revocation** — per-token and per-user revocation with optional LRU cache
- **Type-Safe** — full TypeScript with strict mode

## Installation

```bash
bun add flashauth
```

**Peer dependencies:**

```bash
bun add elysia drizzle-orm
```

**Optional (for full auth plugin features):**

```bash
bun add otplib @simplewebauthn/server
```

**Requirements:** Bun 1.1+

## Quick Start

A minimal example with no database — just token creation, validation, and permission checks:

```typescript
import { Elysia, t } from 'elysia';
import { FlashAuth, flashAuth } from 'flashauth';

const auth = new FlashAuth({
  secret: process.env.AUTH_SECRET ?? FlashAuth.generateSecret(),
  rolePermissions: {
    user: ['posts:read', 'posts:write'],
    admin: ['*'],
  },
});

const app = new Elysia()
  .use(flashAuth(auth))

  .post('/login', async ({ body }) => {
    const token = await auth
      .createToken()
      .subject('user:123')
      .claim('email', body.email)
      .roles(['user'])
      .expiresIn('1h')
      .build();
    return { token };
  }, {
    body: t.Object({
      email: t.String({ format: 'email' }),
      password: t.String({ minLength: 8 }),
    }),
  })

  .get('/profile', ({ flashAuth }) => ({
    userId: flashAuth.claims?.sub,
    roles: flashAuth.claims?.roles,
    permissions: flashAuth.claims?.perms,
  }), { isAuth: true })

  .get('/posts', () => ({ posts: [] }), {
    requirePermission: 'posts:read',
  })

  .listen(3000);
```

See [`examples/basic-app.ts`](examples/basic-app.ts) for a complete runnable version.

## Core Concepts

### JWT Tokens

FlashAuth uses **HS256** symmetric signing via the [`jose`](https://github.com/panva/jose) library. Tokens are standard JWTs and can be inspected with any JWT tool.

```typescript
// Generate a cryptographically secure secret
const secret = FlashAuth.generateSecret(); // base64url-encoded 32-byte key

const auth = new FlashAuth({ secret });
```

### Token Types

| Type | Description | Expiration |
|------|-------------|------------|
| `access` | Short-lived session token | Required |
| `refresh` | Used to obtain new access tokens | Required |
| `api_key` | Long-lived machine-to-machine token | Optional |

### Permission System

Permissions use a `resource:action` format with wildcard support:

```typescript
'posts:read'    // exact match
'posts:*'       // all post operations
'*'             // super admin — matches everything
```

Roles map to permissions and are auto-expanded when creating tokens:

```typescript
const auth = new FlashAuth({
  secret,
  rolePermissions: {
    user: ['posts:read', 'posts:write'],
    moderator: ['posts:read', 'posts:write', 'posts:delete', 'users:read'],
    admin: ['*'],
  },
});

// Permissions are expanded from roles automatically
const token = await auth
  .createToken()
  .subject('user:123')
  .roles(['user'])    // → perms: ['posts:read', 'posts:write']
  .expiresIn('1h')
  .build();
```

## API Reference

### FlashAuth Class

```typescript
import { FlashAuth } from 'flashauth';

const auth = new FlashAuth({
  secret: string | Uint8Array,       // signing key
  rolePermissions?: RolePermissions, // role → permissions mapping
  revocationStore?: RevocationStore, // custom store (default: in-memory)
  enableCache?: boolean,             // default: true
  cache?: { maxSize?: number; ttl?: number },
});

// Create tokens
auth.createToken(claims?)                    // → TokenBuilder

// Validate tokens
await auth.validateToken(token, options?)    // → Claims
await auth.isTokenValid(token)              // → boolean

// Revoke tokens
await auth.revokeToken(jti, expiresAt)
await auth.revokeUser(userId)

// Role permissions
auth.getRolePermissions()
auth.setRolePermissions(rolePermissions)

// Static utilities
FlashAuth.generateSecret()      // base64url string
FlashAuth.generateSecretHex()   // hex string
```

### TokenBuilder (Fluent API)

```typescript
const token = await auth
  .createToken()
  .subject('user:123')              // required
  .issuer('my-app')                 // optional
  .audience('api')                  // optional (string or string[])
  .expiresIn('1h')                  // "1h", "30m", "7d", "1w"
  .expiration(1700000000)           // or absolute Unix timestamp
  .notBefore(1699999000)            // optional
  .tokenId('jti-123')              // for revocation
  .type('access')                   // 'access' | 'refresh' | 'api_key'
  .apiKey()                         // shorthand for type('api_key')
  .roles(['user', 'moderator'])     // auto-expands to permissions
  .permissions(['custom:perm'])     // explicit permissions (merged with role perms)
  .claim('email', 'user@example.com') // custom claims
  .build();                         // → Promise<string>
```

### Claims Class

Returned by `auth.validateToken()`. Includes permission/role helper methods:

```typescript
const claims = await auth.validateToken(token);

claims.sub        // subject (user ID)
claims.exp        // expiration (Unix timestamp)
claims.iat        // issued at
claims.roles      // string[]
claims.perms      // string[] (expanded from roles)
claims.type       // 'access' | 'refresh' | 'api_key'

// Permission checks
claims.hasPermission('posts:write')              // boolean
claims.hasAnyPermission(['posts:read', 'admin:*'])
claims.hasAllPermissions(['posts:read', 'posts:write'])

// Role checks
claims.hasRole('admin')                          // boolean
claims.hasAnyRole(['admin', 'moderator'])

// Time checks
claims.isExpired(clockSkew?)
claims.isNotYetValid(clockSkew?)

// Custom claims
claims.email  // any custom claim set via .claim()
```

## Elysia Plugin

FlashAuth provides three plugins at different levels of functionality:

### `flashAuth` — Lightweight Plugin

Adds token validation context and route macros. No database required.

```typescript
import { FlashAuth, flashAuth } from 'flashauth';

const auth = new FlashAuth({ secret });

const app = new Elysia()
  .use(flashAuth(auth, {
    tokenLocation: 'bearer',  // 'bearer' | 'cookie' (default: 'bearer')
    cookieName: 'auth_token', // cookie name when using cookie mode
  }));
```

### `flashAuthCore` — Core Plugin (for sub-routes)

Same context and macros as `flashAuth`, but supports `'both'` token location (bearer + cookie). Use in sub-routes alongside `flashAuthRoutes`.

```typescript
import { flashAuthCore } from 'flashauth';

app.use(flashAuthCore({
  flashAuth: auth,
  tokenLocation: 'both',   // 'bearer' | 'cookie' | 'both' (default: 'both')
  cookieName: 'auth_token',
}));
```

### `flashAuthRoutes` — Full Auth Routes

Adds complete `/auth/*` endpoints for signup, login, 2FA, passkeys, invites, API keys, and permission management. Requires a Drizzle database.

```typescript
import { flashAuthCore, flashAuthRoutes } from 'flashauth';

app
  .use(flashAuthCore({ flashAuth: auth }))
  .use(flashAuthRoutes({
    db,                        // Drizzle ORM instance
    flashAuth: auth,
    tokenLocation: 'both',
    cookieName: 'auth_token',
    email: {
      sendVerification: async (email, token) => { /* send email */ },
      sendPasswordReset: async (email, token) => { /* send email */ },
    },
    tokenExpiration: {
      emailVerification: 86400,  // 24h (default)
      passwordReset: 3600,       // 1h (default)
      session: 604800,           // 7d (default)
    },
    security: {
      minPasswordLength: 8,
    },
    totpEnabled: true,          // default: true
    passkeysEnabled: false,     // default: false
    inviteOnly: false,          // default: false
    webauthn: {                 // required when passkeysEnabled is true
      rpName: 'My App',
      rpID: 'example.com',
      origin: 'https://example.com',
    },
  }));
```

### Token Extraction

When `tokenLocation` is `'both'` (default for core/routes plugins), tokens are extracted in order:

1. `Authorization: Bearer <token>` header
2. Cookie (default name: `auth_token`)

### Route Macros

All plugins provide these Elysia macros:

```typescript
// Require authentication
.get('/profile', handler, { isAuth: true })

// Require specific permission
.get('/posts', handler, { requirePermission: 'posts:read' })

// Require any of multiple permissions
.delete('/posts/:id', handler, {
  requireAnyPermission: ['posts:delete', 'admin:*'],
})

// Require all permissions
.get('/dashboard', handler, {
  requireAllPermissions: ['users:read', 'posts:read'],
})

// Require specific role
.get('/admin', handler, { requireRole: 'admin' })

// Require any of multiple roles
.get('/mod', handler, { requireAnyRole: ['admin', 'moderator'] })
```

### FlashAuth Context

Every route gets a `flashAuth` context object:

```typescript
.get('/example', ({ flashAuth }) => {
  flashAuth.claims           // Claims | null
  flashAuth.token            // string | null
  flashAuth.hasPermission('posts:read')
  flashAuth.hasAnyPermission(['a', 'b'])
  flashAuth.hasAllPermissions(['a', 'b'])
  flashAuth.hasRole('admin')
  flashAuth.hasAnyRole(['admin', 'mod'])
  await flashAuth.revokeToken()  // revoke current token
})
```

## Database Setup

### Drizzle ORM Schema

FlashAuth provides a complete Drizzle ORM schema for PostgreSQL. Tables: `users`, `roles`, `permissions`, `user_roles`, `role_permissions`, `user_permissions`, `invite_links`, `passkey_credentials`, `api_keys`, `totp_secrets`.

```typescript
import { drizzle } from 'drizzle-orm/node-postgres';
import * as schema from 'flashauth/schema'; // or generate your own

const db = drizzle(process.env.DATABASE_URL!, { schema });
```

### Schema Generation CLI

Generate the schema file for your project:

```bash
# Print TypeScript schema to stdout
bun run generate-schema

# Write to a file
bun run generate-schema --output src/db/schema.ts

# Generate raw SQL CREATE TABLE statements
bun run generate-schema --sql
```

### Migration with drizzle-kit

After generating or importing the schema:

```bash
bunx drizzle-kit push    # apply schema to database
bunx drizzle-kit generate  # generate migration files
```

## Auth Routes

When using `flashAuthRoutes`, these endpoints are added automatically:

### User Management

| Method | Endpoint | Body | Auth | Description |
|--------|----------|------|------|-------------|
| POST | `/auth/signup` | `{ email, password }` | No | Register (blocked when `inviteOnly`) |
| POST | `/auth/signup/invite` | `{ email, password, inviteToken }` | No | Register with invite |
| POST | `/auth/verify-email` | `{ token }` | No | Verify email address |
| POST | `/auth/login` | `{ email, password }` | No | Login (returns `requiresTOTP` if 2FA enabled) |
| POST | `/auth/login/2fa` | `{ userId, code }` | No | Complete login with TOTP/backup code |
| POST | `/auth/password-reset/request` | `{ email }` | No | Request password reset |
| POST | `/auth/password-reset/confirm` | `{ token, newPassword }` | No | Confirm password reset |

### Two-Factor Authentication

| Method | Endpoint | Body | Auth | Description |
|--------|----------|------|------|-------------|
| POST | `/auth/2fa/setup` | — | Yes | Generate TOTP secret + QR code |
| POST | `/auth/2fa/verify` | `{ code }` | Yes | Enable 2FA by verifying a TOTP code |
| POST | `/auth/2fa/disable` | — | Yes | Disable 2FA |

### Passkey/WebAuthn

| Method | Endpoint | Body | Auth | Description |
|--------|----------|------|------|-------------|
| POST | `/auth/passkey/register/start` | — | Yes | Start passkey registration |
| POST | `/auth/passkey/register/finish` | `{ response }` | Yes | Finish passkey registration |
| POST | `/auth/passkey/login/start` | — | No | Start passkey login |
| POST | `/auth/passkey/login/finish` | `{ sessionId, response }` | No | Finish passkey login |

### Invite Links

| Method | Endpoint | Body | Auth | Description |
|--------|----------|------|------|-------------|
| POST | `/auth/invite` | `{ email?, roleId?, maxUses?, expiresAt? }` | Yes | Create invite |
| GET | `/auth/invites` | — | Yes | List your invites |
| DELETE | `/auth/invite/:id` | — | Yes | Delete an invite |

### API Keys

| Method | Endpoint | Body | Auth | Description |
|--------|----------|------|------|-------------|
| POST | `/auth/api-keys` | `{ name }` | Yes | Create API key |
| GET | `/auth/api-keys` | — | Yes | List your API keys |
| DELETE | `/auth/api-keys/:id` | — | Yes | Delete an API key |

### Roles & Permissions

| Method | Endpoint | Body | Auth | Description |
|--------|----------|------|------|-------------|
| POST | `/auth/roles` | `{ name, description? }` | Yes | Create role |
| GET | `/auth/roles` | — | No | List roles |
| DELETE | `/auth/roles/:id` | — | Yes | Delete role |
| POST | `/auth/permissions` | `{ name, description? }` | Yes | Create permission |
| GET | `/auth/permissions` | — | No | List permissions |
| DELETE | `/auth/permissions/:id` | — | Yes | Delete permission |
| POST | `/auth/users/:userId/roles` | `{ roleId }` | Yes | Assign role to user |
| DELETE | `/auth/users/:userId/roles/:roleId` | — | Yes | Remove role from user |
| POST | `/auth/users/:userId/permissions` | `{ permissionId }` | Yes | Assign permission to user |
| DELETE | `/auth/users/:userId/permissions/:permissionId` | — | Yes | Remove permission from user |
| GET | `/auth/users/:userId/permissions` | — | Yes | Get user permissions |
| POST | `/auth/roles/:roleId/permissions` | `{ permissionId }` | Yes | Assign permission to role |
| DELETE | `/auth/roles/:roleId/permissions/:permissionId` | — | Yes | Remove permission from role |

## Invite Links

Use invite links for invite-only signups or to assign roles on registration:

```typescript
const app = new Elysia()
  .use(flashAuthCore({ flashAuth: auth }))
  .use(flashAuthRoutes({
    db,
    flashAuth: auth,
    inviteOnly: true,  // block POST /auth/signup
  }));
```

**Creating invites** (authenticated):

```bash
curl -X POST http://localhost:3000/auth/invite \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"email": "new@example.com", "roleId": "role-uuid", "maxUses": 1}'
```

**Signing up with an invite:**

```bash
curl -X POST http://localhost:3000/auth/signup/invite \
  -H "Content-Type: application/json" \
  -d '{"email": "new@example.com", "password": "securepass", "inviteToken": "<token>"}'
```

## API Keys

API keys are long-lived JWT tokens with `type: 'api_key'` and no expiration. They work anywhere a regular token is accepted.

**Without database** (lightweight plugin):

```typescript
const apiKey = await auth
  .createToken()
  .subject('user:123')
  .apiKey()
  .roles(['user'])
  .claim('name', 'my-api-key')
  .build();
```

**With database** (auth routes plugin):

```bash
# Create
curl -X POST http://localhost:3000/auth/api-keys \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "CI Pipeline"}'

# List
curl http://localhost:3000/auth/api-keys \
  -H "Authorization: Bearer <token>"

# Delete
curl -X DELETE http://localhost:3000/auth/api-keys/<id> \
  -H "Authorization: Bearer <token>"
```

## Permission Management

FlashAuth supports database-backed RBAC via the auth routes plugin:

```bash
# Create a role
curl -X POST http://localhost:3000/auth/roles \
  -H "Authorization: Bearer <token>" \
  -d '{"name": "editor", "description": "Can edit content"}'

# Create a permission
curl -X POST http://localhost:3000/auth/permissions \
  -H "Authorization: Bearer <token>" \
  -d '{"name": "posts:write"}'

# Assign permission to role
curl -X POST http://localhost:3000/auth/roles/<roleId>/permissions \
  -H "Authorization: Bearer <token>" \
  -d '{"permissionId": "<permId>"}'

# Assign role to user
curl -X POST http://localhost:3000/auth/users/<userId>/roles \
  -H "Authorization: Bearer <token>" \
  -d '{"roleId": "<roleId>"}'

# Check user permissions
curl http://localhost:3000/auth/users/<userId>/permissions \
  -H "Authorization: Bearer <token>"
```

## Passkey/WebAuthn

Enable passkey authentication for passwordless login:

```typescript
.use(flashAuthRoutes({
  db,
  flashAuth: auth,
  passkeysEnabled: true,
  webauthn: {
    rpName: 'My Application',
    rpID: 'example.com',
    origin: 'https://example.com',
  },
}))
```

**Registration flow** (authenticated user):

1. `POST /auth/passkey/register/start` → returns WebAuthn `options`
2. Pass options to browser `navigator.credentials.create()`
3. `POST /auth/passkey/register/finish` with the browser response

**Login flow:**

1. `POST /auth/passkey/login/start` → returns `sessionId` and `options`
2. Pass options to browser `navigator.credentials.get()`
3. `POST /auth/passkey/login/finish` with `{ sessionId, response }` → returns JWT

## TOTP 2FA

TOTP is enabled by default. The flow:

**Setup** (authenticated user):

1. `POST /auth/2fa/setup` → returns `secret`, `qrCodeUrl`, and `backupCodes`
2. User scans QR code with authenticator app
3. `POST /auth/2fa/verify` with `{ code }` from authenticator → enables 2FA

**Login with 2FA:**

1. `POST /auth/login` → response includes `{ requiresTOTP: true, userId }`
2. `POST /auth/login/2fa` with `{ userId, code }` → returns JWT

Backup codes can be used in place of TOTP codes during login.

## Examples

| File | Description |
|------|-------------|
| [`examples/basic-app.ts`](examples/basic-app.ts) | Minimal example — no database, bearer auth, permission macros, API keys |
| [`examples/auth-app.ts`](examples/auth-app.ts) | Full auth plugin — all config options, invite-only mode, all endpoints |
| [`examples/full-app.ts`](examples/full-app.ts) | Comprehensive feature showcase |
| [`examples/subroutes-app.ts`](examples/subroutes-app.ts) | Multi-route organization with shared auth context |

Run any example:

```bash
bun run examples/basic-app.ts
```

## Security

See [SECURITY.md](SECURITY.md) for security policy and vulnerability reporting.

**Key security properties:**

- HS256 JWT signing via the audited `jose` library
- Password hashing with `Bun.password` (bcrypt)
- Constant-time token comparison
- Token revocation with per-token and per-user support
- Email enumeration prevention on password reset
- Configurable password policies

## License

MIT
