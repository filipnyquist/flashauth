# FlashAuth Authentication Plugin

Complete user authentication plugin for Elysia.js with email/password signup, email verification, password reset, TOTP 2FA, passkey/WebAuthn, invite links, API keys, and permission management — all backed by Drizzle ORM and PostgreSQL.

## Features

- **Email/Password Authentication** — signup and login with `Bun.password` (bcrypt) hashing
- **Email Verification** — time-limited verification tokens (24h default)
- **Password Reset** — time-limited reset tokens (1h default)
- **TOTP 2FA** — two-factor authentication via `otplib` with backup codes
- **Passkey/WebAuthn** — passwordless authentication via `@simplewebauthn/server`
- **Invite Links** — invite-only signups with optional role assignment
- **API Keys** — long-lived JWT tokens for machine-to-machine auth
- **Permission Management** — database-backed RBAC (roles, permissions, assignments)
- **Drizzle ORM** — PostgreSQL storage with full relational schema

## Two Plugins

The auth module exports two plugins that are used together:

### `flashAuthCore(config)`

Provides the `flashAuth` context and authentication macros to your routes. Use this when you need auth context in custom routes.

```typescript
import { flashAuthCore } from 'flashauth';

app.use(flashAuthCore({
  flashAuth: auth,              // FlashAuth instance
  tokenLocation: 'both',        // 'bearer' | 'cookie' | 'both'
  cookieName: 'auth_token',
}));
```

### `flashAuthRoutes(config)`

Adds all `/auth/*` endpoints. Use once in your main app.

```typescript
import { flashAuthRoutes } from 'flashauth';

app.use(flashAuthRoutes(config));
```

## Configuration

```typescript
import type { AuthPluginConfig } from 'flashauth';

const config: AuthPluginConfig = {
  // Required
  db: drizzleInstance,        // Drizzle ORM PostgreSQL instance
  flashAuth: authInstance,    // FlashAuth instance

  // Token extraction (default: 'both')
  tokenLocation: 'both',     // 'bearer' | 'cookie' | 'both'
  cookieName: 'auth_token',
  cookieSecure: true,
  cookieHttpOnly: true,
  cookieSameSite: 'lax',

  // Email service (optional — if omitted, tokens returned in response)
  email: {
    sendVerification: async (email, token) => { /* ... */ },
    sendPasswordReset: async (email, token) => { /* ... */ },
  },

  // Token expiration (seconds)
  tokenExpiration: {
    emailVerification: 86400,   // 24 hours
    passwordReset: 3600,        // 1 hour
    session: 604800,            // 7 days
  },

  // Password policy
  security: {
    minPasswordLength: 8,
    requireUppercase: false,
    requireLowercase: false,
    requireNumber: false,
    requireSpecialChar: false,
  },

  // Feature toggles
  totpEnabled: true,           // Enable TOTP 2FA (default: true)
  passkeysEnabled: false,      // Enable WebAuthn (default: false)
  disableSignup: false,        // Block all signups (default: false)
  inviteOnly: false,           // Require invite for signup (default: false)

  // WebAuthn config (required when passkeysEnabled is true)
  webauthn: {
    rpName: 'My App',
    rpID: 'example.com',
    origin: 'https://example.com',
  },
};
```

## Routes

All routes are mounted under `/auth`. See the tables below for the full list.

### User Management

| Method | Endpoint | Body | Auth | Description |
|--------|----------|------|------|-------------|
| POST | `/auth/signup` | `{ email, password }` | No | Register (blocked when `inviteOnly` or `disableSignup`) |
| POST | `/auth/signup/invite` | `{ email, password, inviteToken }` | No | Register with invite token |
| POST | `/auth/verify-email` | `{ token }` | No | Verify email address |
| POST | `/auth/login` | `{ email, password }` | No | Login |
| POST | `/auth/login/2fa` | `{ userId, code }` | No | Complete 2FA login |
| POST | `/auth/password-reset/request` | `{ email }` | No | Request password reset |
| POST | `/auth/password-reset/confirm` | `{ token, newPassword }` | No | Confirm password reset |

### TOTP 2FA

| Method | Endpoint | Body | Auth |
|--------|----------|------|------|
| POST | `/auth/2fa/setup` | — | Yes |
| POST | `/auth/2fa/verify` | `{ code }` | Yes |
| POST | `/auth/2fa/disable` | — | Yes |

### Passkey/WebAuthn

| Method | Endpoint | Body | Auth |
|--------|----------|------|------|
| POST | `/auth/passkey/register/start` | — | Yes |
| POST | `/auth/passkey/register/finish` | `{ response }` | Yes |
| POST | `/auth/passkey/login/start` | — | No |
| POST | `/auth/passkey/login/finish` | `{ sessionId, response }` | No |

### Invite Links

| Method | Endpoint | Body | Auth |
|--------|----------|------|------|
| POST | `/auth/invite` | `{ email?, roleId?, maxUses?, expiresAt? }` | Yes |
| GET | `/auth/invites` | — | Yes |
| DELETE | `/auth/invite/:id` | — | Yes |

### API Keys

| Method | Endpoint | Body | Auth |
|--------|----------|------|------|
| POST | `/auth/api-keys` | `{ name }` | Yes |
| GET | `/auth/api-keys` | — | Yes |
| DELETE | `/auth/api-keys/:id` | — | Yes |

### Roles & Permissions

| Method | Endpoint | Body | Auth |
|--------|----------|------|------|
| POST | `/auth/roles` | `{ name, description? }` | Yes |
| GET | `/auth/roles` | — | No |
| DELETE | `/auth/roles/:id` | — | Yes |
| POST | `/auth/permissions` | `{ name, description? }` | Yes |
| GET | `/auth/permissions` | — | No |
| DELETE | `/auth/permissions/:id` | — | Yes |
| POST | `/auth/users/:userId/roles` | `{ roleId }` | Yes |
| DELETE | `/auth/users/:userId/roles/:roleId` | — | Yes |
| POST | `/auth/users/:userId/permissions` | `{ permissionId }` | Yes |
| DELETE | `/auth/users/:userId/permissions/:permissionId` | — | Yes |
| GET | `/auth/users/:userId/permissions` | — | Yes |
| POST | `/auth/roles/:roleId/permissions` | `{ permissionId }` | Yes |
| DELETE | `/auth/roles/:roleId/permissions/:permissionId` | — | Yes |

## Complete Example

```typescript
import { Elysia } from 'elysia';
import { drizzle } from 'drizzle-orm/node-postgres';
import {
  FlashAuth,
  flashAuthCore,
  flashAuthRoutes,
} from 'flashauth';

const db = drizzle(process.env.DATABASE_URL!);
const auth = new FlashAuth({
  secret: process.env.AUTH_SECRET!,
  rolePermissions: {
    user: ['posts:read', 'posts:write'],
    admin: ['*'],
  },
});

const app = new Elysia()
  .use(flashAuthCore({ flashAuth: auth }))
  .use(flashAuthRoutes({
    db,
    flashAuth: auth,
    inviteOnly: true,
    passkeysEnabled: true,
    webauthn: {
      rpName: 'My App',
      rpID: 'localhost',
      origin: 'http://localhost:3000',
    },
  }))

  // Custom protected route using macros from flashAuthCore
  .get('/dashboard', ({ flashAuth }) => ({
    user: flashAuth.claims?.sub,
  }), { isAuth: true })

  .listen(3000);
```

See [`examples/auth-app.ts`](../../examples/auth-app.ts) for a complete runnable example with all configuration options documented.

## Database Schema

The plugin requires these PostgreSQL tables (managed via Drizzle ORM):

- `users` — email, password hash, email verified flag
- `roles` — named roles
- `permissions` — named permissions
- `user_roles` — user ↔ role assignments
- `role_permissions` — role ↔ permission assignments
- `user_permissions` — direct user ↔ permission assignments
- `invite_links` — invite tokens with optional email/role/max uses/expiry
- `passkey_credentials` — WebAuthn credentials
- `api_keys` — named API keys (hashed)
- `totp_secrets` — TOTP secrets and backup codes

Generate the schema:

```bash
bun run generate-schema --output src/db/schema.ts
```

Apply to your database:

```bash
bunx drizzle-kit push
```
