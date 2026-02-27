/**
 * FlashAuth Authentication Plugin Example
 *
 * A comprehensive example showing the full auth plugin with:
 * - Drizzle ORM setup (mock pattern — no real DB connection)
 * - flashAuthCore + flashAuthRoutes usage
 * - All available configuration options documented
 * - Invite-only signup mode
 * - API key management
 *
 * The `flashAuthRoutes` plugin adds a full set of /auth/* endpoints
 * automatically. See the endpoint list printed at startup.
 *
 * Run: bun run examples/auth-app.ts
 */

import { Elysia } from 'elysia';
import {
  FlashAuth,
  flashAuthCore,
  flashAuthRoutes,
  type AuthPluginConfig,
} from '../src/index.js';

// Schema is exported separately — useful for drizzle-kit migrations
// import * as schema from '../src/schema/index.js';

// ── 1. Drizzle ORM setup (mock) ─────────────────────────────────────────────
// In production you would do:
//
//   import { drizzle } from 'drizzle-orm/node-postgres';
//   import * as schema from '../src/schema/index.js';
//   const db = drizzle(process.env.DATABASE_URL!, { schema });
//
// For this example we create a placeholder so the types are satisfied.
const db = {} as any; // Replace with a real Drizzle instance

// ── 2. Initialize FlashAuth ─────────────────────────────────────────────────
const secret = Bun.env.AUTH_SECRET ?? FlashAuth.generateSecret();

const auth = new FlashAuth({
  secret,
  rolePermissions: {
    user: ['posts:read', 'posts:write', 'profile:read', 'profile:write'],
    admin: ['*'],
  },
});

// ── 3. Full plugin configuration ────────────────────────────────────────────
// Every option is shown here with its default value (or a sensible example).
const authConfig: AuthPluginConfig = {
  // Required: Drizzle ORM database instance
  db,

  // Required: FlashAuth instance for token management
  flashAuth: auth,

  // Token location: 'bearer' | 'cookie' | 'both' (default: 'both')
  // When 'both', tokens are read from Authorization header first, then cookie.
  tokenLocation: 'both',

  // Cookie settings (used when tokenLocation includes 'cookie')
  cookieName: 'auth_token',   // default
  cookieSecure: true,          // set false for local dev over HTTP
  cookieHttpOnly: true,        // prevents JS access to the cookie
  cookieSameSite: 'lax',       // 'strict' | 'lax' | 'none'

  // Email service — optional. If omitted, verification/reset tokens are
  // returned in the response body instead of being emailed.
  email: {
    sendVerification: async (email: string, token: string) => {
      console.log(`📧 Verification email to ${email}: token=${token}`);
    },
    sendPasswordReset: async (email: string, token: string) => {
      console.log(`📧 Password reset email to ${email}: token=${token}`);
    },
  },

  // Token expiration times (seconds)
  tokenExpiration: {
    emailVerification: 24 * 60 * 60, // 24 hours (default)
    passwordReset: 60 * 60,          // 1 hour (default)
    session: 7 * 24 * 60 * 60,       // 7 days (default)
  },

  // Password policy
  security: {
    minPasswordLength: 8,        // default
    requireUppercase: false,     // default
    requireLowercase: false,     // default
    requireNumber: false,        // default
    requireSpecialChar: false,   // default
  },

  // Two-factor authentication (TOTP) — enabled by default
  totpEnabled: true,

  // Passkey / WebAuthn — disabled by default
  passkeysEnabled: true,

  // When true, POST /auth/signup is blocked; users must use /auth/signup/invite
  inviteOnly: true,

  // WebAuthn relying-party config (required when passkeysEnabled is true)
  webauthn: {
    rpName: 'FlashAuth Example',
    rpID: 'localhost',
    origin: 'http://localhost:3000',
  },
};

// ── 4. Build the Elysia app ─────────────────────────────────────────────────
const app = new Elysia()
  // flashAuthCore: adds flashAuth context + macros (isAuth, requireRole, etc.)
  // Use this when you need auth context in custom routes.
  .use(flashAuthCore({
    flashAuth: auth,
    tokenLocation: 'both',
    cookieName: 'auth_token',
  }))

  // flashAuthRoutes: adds all /auth/* endpoints automatically
  .use(flashAuthRoutes(authConfig))

  // ── Public route listing all available endpoints ────────────────────────
  .get('/', () => ({
    message: 'FlashAuth Authentication Example',
    note: 'inviteOnly mode is ON — use /auth/signup/invite with a valid invite token',
    endpoints: {
      // ── User management (provided by flashAuthRoutes) ──────────────
      signup: 'POST /auth/signup (blocked when inviteOnly=true)',
      signupWithInvite: 'POST /auth/signup/invite { email, password, inviteToken }',
      verifyEmail: 'POST /auth/verify-email { token }',
      login: 'POST /auth/login { email, password }',
      login2fa: 'POST /auth/login/2fa { userId, code }',
      passwordResetRequest: 'POST /auth/password-reset/request { email }',
      passwordResetConfirm: 'POST /auth/password-reset/confirm { token, newPassword }',

      // ── Two-Factor Authentication (requires auth) ──────────────────
      '2fa_setup': 'POST /auth/2fa/setup',
      '2fa_verify': 'POST /auth/2fa/verify { code }',
      '2fa_disable': 'POST /auth/2fa/disable',

      // ── Passkey / WebAuthn ─────────────────────────────────────────
      passkeyRegisterStart: 'POST /auth/passkey/register/start (requires auth)',
      passkeyRegisterFinish: 'POST /auth/passkey/register/finish (requires auth)',
      passkeyLoginStart: 'POST /auth/passkey/login/start',
      passkeyLoginFinish: 'POST /auth/passkey/login/finish',

      // ── Invite links (requires auth) ───────────────────────────────
      createInvite: 'POST /auth/invite { email?, roleId?, maxUses?, expiresAt? }',
      listInvites: 'GET /auth/invites',
      deleteInvite: 'DELETE /auth/invite/:id',

      // ── API keys (requires auth) ───────────────────────────────────
      createApiKey: 'POST /auth/api-keys { name }',
      listApiKeys: 'GET /auth/api-keys',
      deleteApiKey: 'DELETE /auth/api-keys/:id',

      // ── Roles & permissions (requires auth) ────────────────────────
      createRole: 'POST /auth/roles { name, description? }',
      listRoles: 'GET /auth/roles',
      deleteRole: 'DELETE /auth/roles/:id',
      createPermission: 'POST /auth/permissions { name, description? }',
      listPermissions: 'GET /auth/permissions',
      deletePermission: 'DELETE /auth/permissions/:id',
      assignRoleToUser: 'POST /auth/users/:userId/roles { roleId }',
      removeRoleFromUser: 'DELETE /auth/users/:userId/roles/:roleId',
      assignPermToUser: 'POST /auth/users/:userId/permissions { permissionId }',
      removePermFromUser: 'DELETE /auth/users/:userId/permissions/:permissionId',
      getUserPerms: 'GET /auth/users/:userId/permissions',
      assignPermToRole: 'POST /auth/roles/:roleId/permissions { permissionId }',
      removePermFromRole: 'DELETE /auth/roles/:roleId/permissions/:permissionId',
    },
  }))

  // ── Custom protected route ──────────────────────────────────────────────
  .get('/dashboard', ({ flashAuth }) => ({
    user: flashAuth.claims?.sub,
    message: 'Welcome to the dashboard',
  }), {
    isAuth: true,
  })

  // ── Error handler ───────────────────────────────────────────────────────
  .onError(({ code, error, set }) => {
    console.error(`[${code}]`, error);

    if (code === 'VALIDATION') {
      set.status = 400;
      return { error: 'Validation Error', message: error.message };
    }
    if (error.name === 'TokenError') {
      set.status = 401;
      return { error: 'Unauthorized', message: error.message };
    }
    if (error.name === 'PermissionError') {
      set.status = 403;
      return { error: 'Forbidden', message: error.message };
    }
    set.status = 500;
    return { error: 'Internal Server Error', message: error.message };
  })

  .listen(3000);

console.log(`🚀 FlashAuth Auth Example running at http://${app.server?.hostname}:${app.server?.port}`);
console.log('\n📚 Available Authentication Flows:');
console.log('\n1. Invite-Only Sign Up:');
console.log('   POST /auth/invite        — create invite (requires auth)');
console.log('   POST /auth/signup/invite  — sign up with invite token');
console.log('   POST /auth/verify-email   — verify email address');
console.log('\n2. Login:');
console.log('   POST /auth/login');
console.log('\n3. Password Reset:');
console.log('   POST /auth/password-reset/request');
console.log('   POST /auth/password-reset/confirm');
console.log('\n4. Two-Factor Authentication (2FA):');
console.log('   POST /auth/2fa/setup   (requires auth)');
console.log('   POST /auth/2fa/verify  (requires auth)');
console.log('   POST /auth/login/2fa   (for login with 2FA)');
console.log('\n5. Passkey / WebAuthn:');
console.log('   POST /auth/passkey/register/start  (requires auth)');
console.log('   POST /auth/passkey/register/finish (requires auth)');
console.log('   POST /auth/passkey/login/start');
console.log('   POST /auth/passkey/login/finish');
console.log('\n6. API Keys:');
console.log('   POST   /auth/api-keys   — create a named API key (requires auth)');
console.log('   GET    /auth/api-keys   — list your API keys (requires auth)');
console.log('   DELETE /auth/api-keys/:id');
console.log('\n⚠️  This example uses a mock database. For production:');
console.log('   1. Set up PostgreSQL and configure DATABASE_URL');
console.log('   2. Run `bunx drizzle-kit push` to apply the schema');
console.log('   3. Replace the mock `db` with a real Drizzle instance');
