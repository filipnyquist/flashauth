/**
 * FlashAuth Full Example
 *
 * The definitive reference example demonstrating ALL FlashAuth features:
 *
 *  ✅ FlashAuth + Elysia setup
 *  ✅ JWT tokens in both cookies and Authorization header
 *  ✅ API key generation (long-lived tokens)
 *  ✅ Role and permission management
 *  ✅ Invite link creation and acceptance
 *  ✅ Passkey / WebAuthn configuration
 *  ✅ TOTP 2FA setup
 *  ✅ Error handling middleware
 *  ✅ Cookie configuration for secure sessions
 *
 * Architecture:
 *   - `flashAuthCore`  → token context & macros for all routes
 *   - `flashAuthRoutes` → /auth/* endpoints (signup, login, 2FA, passkeys, etc.)
 *   - Custom routes     → your application logic with macro-based protection
 *
 * Run: bun run examples/full-app.ts
 */

import { Elysia, t } from 'elysia';
import {
  FlashAuth,
  flashAuthCore,
  flashAuthRoutes,
  generateSecret,
  FlashAuthError,
  TokenError,
  PermissionError,
  type AuthPluginConfig,
  type FlashAuthContext,
} from '../src/index.js';

// The Drizzle schema is exported separately — use it with drizzle-kit for
// migrations:
//
//   import * as schema from '../src/schema/index.js';
//   // In drizzle.config.ts:  schema: './node_modules/flashauth/dist/schema/index.js'

// ─────────────────────────────────────────────────────────────────────────────
// 1. DATABASE SETUP (mock)
// ─────────────────────────────────────────────────────────────────────────────
// In production:
//
//   import { drizzle } from 'drizzle-orm/node-postgres';
//   import * as schema from '../src/schema/index.js';
//   const db = drizzle(process.env.DATABASE_URL!, { schema });
//
// Apply the schema with:
//   bunx drizzle-kit push          (development)
//   bunx drizzle-kit migrate       (production)

const db = {} as any; // ← Replace with real Drizzle instance

// ─────────────────────────────────────────────────────────────────────────────
// 2. FLASHAUTH INSTANCE
// ─────────────────────────────────────────────────────────────────────────────
// The secret MUST be stable across restarts so that existing tokens stay valid.
// In production, store it in an environment variable (AUTH_SECRET).
const secret = Bun.env.AUTH_SECRET ?? FlashAuth.generateSecret();

const auth = new FlashAuth({
  secret,

  // Static role → permission mapping.
  // When a token is created with `.roles(['editor'])`, its `perms` claim is
  // automatically expanded using this map.
  rolePermissions: {
    viewer:    ['posts:read', 'comments:read'],
    editor:    ['posts:read', 'posts:write', 'comments:read', 'comments:write'],
    moderator: ['posts:read', 'posts:write', 'posts:delete',
                'comments:read', 'comments:write', 'comments:delete',
                'users:read'],
    admin:     ['*'], // wildcard — matches every permission check
  },

  // Optional: enable token caching for faster repeated validations
  enableCache: true,
  cache: { maxSize: 10_000, ttl: 300 }, // 5 min TTL, 10 k entries
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. AUTH PLUGIN CONFIGURATION
// ─────────────────────────────────────────────────────────────────────────────
const authPluginConfig: AuthPluginConfig = {
  db,
  flashAuth: auth,

  // ── Token delivery ─────────────────────────────────────────────────────
  // 'both' (default): the server reads the Bearer header first, then falls
  // back to the cookie. When the auth plugin issues a token it can set both.
  tokenLocation: 'both',

  // ── Cookie settings ────────────────────────────────────────────────────
  // Applied when tokenLocation includes 'cookie'.
  cookieName: 'auth_token',
  cookieSecure: true,          // Requires HTTPS — set false for local dev
  cookieHttpOnly: true,        // JS cannot read the cookie (XSS protection)
  cookieSameSite: 'lax',       // 'strict' | 'lax' | 'none'

  // ── Email service ──────────────────────────────────────────────────────
  // If omitted, tokens are returned in the JSON response body.
  email: {
    sendVerification: async (email, token) => {
      console.log(`📧 [Verify] ${email} → ${token}`);
    },
    sendPasswordReset: async (email, token) => {
      console.log(`📧 [Reset]  ${email} → ${token}`);
    },
  },

  // ── Token lifetimes ────────────────────────────────────────────────────
  tokenExpiration: {
    emailVerification: 24 * 60 * 60,   // 24 h
    passwordReset: 60 * 60,            // 1 h
    session: 7 * 24 * 60 * 60,         // 7 d
  },

  // ── Password policy ────────────────────────────────────────────────────
  security: {
    minPasswordLength: 10,
    requireUppercase: true,
    requireLowercase: true,
    requireNumber: true,
    requireSpecialChar: false,
  },

  // ── Feature toggles ───────────────────────────────────────────────────
  totpEnabled: true,            // TOTP 2FA
  passkeysEnabled: true,        // WebAuthn / Passkeys
  inviteOnly: false,            // Set true to require invite link for signup
  disableSignup: false,         // Set true to block all signups

  // ── WebAuthn relying-party config ──────────────────────────────────────
  // Required when passkeysEnabled is true.
  webauthn: {
    rpName: 'FlashAuth Full Example',
    rpID: 'localhost',
    origin: 'http://localhost:3000',
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// 4. BUILD THE ELYSIA APP
// ─────────────────────────────────────────────────────────────────────────────
const app = new Elysia()

  // ── Core plugin (context + macros) ─────────────────────────────────────
  // Injects `flashAuth` into every request context. Also registers macros:
  //   isAuth, requirePermission, requireAnyPermission, requireAllPermissions,
  //   requireRole, requireAnyRole
  .use(flashAuthCore({
    flashAuth: auth,
    tokenLocation: 'both',
    cookieName: 'auth_token',
  }))

  // ── Auth routes plugin ─────────────────────────────────────────────────
  // Adds all /auth/* endpoints (signup, login, 2FA, passkeys, invites,
  // API keys, roles, permissions).
  .use(flashAuthRoutes(authPluginConfig))

  // ─────────────────────────────────────────────────────────────────────
  // PUBLIC ROUTES
  // ─────────────────────────────────────────────────────────────────────

  .get('/', () => ({
    app: 'FlashAuth Full Example',
    docs: 'GET / for this listing',
    sections: {
      auth: '/auth/*  (provided by flashAuthRoutes)',
      custom: 'Custom app routes below',
    },
    customEndpoints: {
      login: 'POST /login (simple test login)',
      profile: 'GET /profile (requires auth)',
      posts: 'GET /posts (requires posts:read)',
      createPost: 'POST /posts (requires posts:write)',
      deletePost: 'DELETE /posts/:id (requires posts:delete)',
      admin: 'GET /admin (requires admin role)',
      moderation: 'GET /moderation (requires moderator or admin)',
      dashboard: 'GET /dashboard (requires posts:read + comments:read)',
      createApiKey: 'POST /create-api-key (requires auth)',
      health: 'GET /health (public)',
    },
    authEndpoints: {
      signup: 'POST /auth/signup',
      signupInvite: 'POST /auth/signup/invite',
      login: 'POST /auth/login',
      login2fa: 'POST /auth/login/2fa',
      verifyEmail: 'POST /auth/verify-email',
      passwordReset: 'POST /auth/password-reset/request & /confirm',
      '2fa': 'POST /auth/2fa/setup | /verify | /disable',
      passkey: 'POST /auth/passkey/register/* | /login/*',
      invite: 'POST /auth/invite | GET /auth/invites | DELETE /auth/invite/:id',
      apiKeys: 'POST /auth/api-keys | GET /auth/api-keys | DELETE /auth/api-keys/:id',
      roles: 'POST /auth/roles | GET /auth/roles | DELETE /auth/roles/:id',
      permissions: 'POST /auth/permissions | GET /auth/permissions | ...',
      userRoles: 'POST/DELETE /auth/users/:userId/roles',
      userPerms: 'POST/DELETE/GET /auth/users/:userId/permissions',
      rolePerms: 'POST/DELETE /auth/roles/:roleId/permissions',
    },
  }))

  .get('/health', () => ({ status: 'ok', uptime: process.uptime() }))

  // ─────────────────────────────────────────────────────────────────────
  // TEST LOGIN (for manual testing — issues JWT with requested roles)
  // ─────────────────────────────────────────────────────────────────────

  .post('/login', async ({ body }) => {
    // In a real app, validate credentials via the /auth/login endpoint.
    const userId = body.userId ?? 'user:1';
    const email = body.email;
    const roles = body.roles ?? ['viewer'];

    const token = await auth
      .createToken()
      .subject(userId)
      .claim('email', email)
      .roles(roles)
      .expiresIn('1h')
      .build();

    return { token, expiresIn: 3600, user: { id: userId, email, roles } };
  }, {
    body: t.Object({
      email: t.String({ format: 'email' }),
      password: t.String(),
      userId: t.Optional(t.String()),
      roles: t.Optional(t.Array(t.String())),
    }),
  })

  // ─────────────────────────────────────────────────────────────────────
  // PROTECTED ROUTES (demonstrate macro-based protection)
  // ─────────────────────────────────────────────────────────────────────

  // Any authenticated user
  .get('/profile', ({ flashAuth }) => ({
    userId: flashAuth.claims?.sub,
    roles: flashAuth.claims?.roles,
    permissions: flashAuth.claims?.perms,
    tokenType: flashAuth.claims?.type ?? 'session',
  }), {
    isAuth: true,
  })

  // Requires a single permission
  .get('/posts', ({ flashAuth }) => ({
    posts: [
      { id: 1, title: 'Hello World' },
      { id: 2, title: 'Advanced JWT Patterns' },
    ],
    requestedBy: flashAuth.claims?.sub,
  }), {
    requirePermission: 'posts:read',
  })

  .post('/posts', ({ flashAuth, body }) => ({
    post: { id: Date.now(), ...body, author: flashAuth.claims?.sub },
  }), {
    body: t.Object({
      title: t.String({ minLength: 1 }),
      content: t.String({ minLength: 1 }),
    }),
    requirePermission: 'posts:write',
  })

  .delete('/posts/:id', ({ flashAuth, params }) => ({
    deleted: params.id,
    by: flashAuth.claims?.sub,
  }), {
    requirePermission: 'posts:delete',
  })

  // Requires a specific role
  .get('/admin', ({ flashAuth }) => ({
    message: 'Admin panel',
    user: flashAuth.claims?.sub,
  }), {
    requireRole: 'admin',
  })

  // Requires any of multiple roles
  .get('/moderation', ({ flashAuth }) => ({
    message: 'Moderation queue',
    user: flashAuth.claims?.sub,
  }), {
    requireAnyRole: ['moderator', 'admin'],
  })

  // Requires ALL of multiple permissions
  .get('/dashboard', ({ flashAuth }) => ({
    message: 'Dashboard (needs posts:read AND comments:read)',
    user: flashAuth.claims?.sub,
  }), {
    requireAllPermissions: ['posts:read', 'comments:read'],
  })

  // ─────────────────────────────────────────────────────────────────────
  // API KEY CREATION (custom endpoint using the FlashAuth token builder)
  // ─────────────────────────────────────────────────────────────────────
  // The built-in /auth/api-keys endpoint stores API keys in the database.
  // This shows how to create a lightweight API key with the token builder.

  .post('/create-api-key', async ({ flashAuth, body }) => {
    const userId = flashAuth.claims!.sub;

    // API keys have type 'api_key' and no expiry by default
    const apiKeyToken = await auth
      .createToken()
      .subject(userId)
      .apiKey()
      .claim('name', body.name)
      .roles(body.roles ?? ['viewer'])
      .build();

    return {
      apiKey: apiKeyToken,
      note: 'Store this key securely — it cannot be retrieved again.',
    };
  }, {
    body: t.Object({
      name: t.String({ minLength: 1 }),
      roles: t.Optional(t.Array(t.String())),
    }),
    isAuth: true,
  })

  // ─────────────────────────────────────────────────────────────────────
  // INVITE LINK HELPERS (uses built-in /auth/invite under the hood)
  // ─────────────────────────────────────────────────────────────────────
  // The /auth/invite endpoint handles invite CRUD; here we just show
  // that the macro protections work alongside the auth routes.

  .get('/invite-info', ({ flashAuth }) => ({
    message: 'To create invites, POST to /auth/invite',
    yourUserId: flashAuth.claims?.sub,
    tip: 'Set inviteOnly: true in config to require invites for signup',
  }), {
    isAuth: true,
  })

  // ─────────────────────────────────────────────────────────────────────
  // TOKEN REVOCATION
  // ─────────────────────────────────────────────────────────────────────

  .post('/logout', async ({ flashAuth }) => {
    // Revoke the current token so it can't be reused
    await flashAuth.revokeToken();
    return { message: 'Token revoked. You are now logged out.' };
  }, {
    isAuth: true,
  })

  // ─────────────────────────────────────────────────────────────────────
  // ERROR HANDLING
  // ─────────────────────────────────────────────────────────────────────
  // FlashAuth throws typed errors that can be caught here.

  .onError(({ code, error, set }) => {
    // FlashAuth-specific errors
    if (error instanceof TokenError) {
      set.status = 401;
      return { error: 'Unauthorized', message: error.message };
    }
    if (error instanceof PermissionError) {
      set.status = 403;
      return { error: 'Forbidden', message: error.message };
    }
    if (error instanceof FlashAuthError) {
      set.status = 400;
      return { error: 'Auth Error', message: error.message };
    }

    // Elysia validation errors
    if (code === 'VALIDATION') {
      set.status = 422;
      return { error: 'Validation Error', message: error.message };
    }

    // Catch-all
    console.error(`[${code}]`, error);
    set.status = 500;
    return { error: 'Internal Server Error', message: 'Something went wrong' };
  })

  .listen(3000);

// ─────────────────────────────────────────────────────────────────────────────
// STARTUP BANNER
// ─────────────────────────────────────────────────────────────────────────────
console.log(`
🚀 FlashAuth Full Example
   http://${app.server?.hostname}:${app.server?.port}

📋 Quick Start:

   # 1. Login (get a JWT)
   curl -s -X POST http://localhost:3000/login \\
     -H "Content-Type: application/json" \\
     -d '{"email":"admin@example.com","password":"secret","roles":["admin"]}'

   # 2. Use the token
   TOKEN="<paste token here>"
   curl -s http://localhost:3000/profile -H "Authorization: Bearer $TOKEN"

   # 3. Create an API key (long-lived, no expiry)
   curl -s -X POST http://localhost:3000/create-api-key \\
     -H "Authorization: Bearer $TOKEN" \\
     -H "Content-Type: application/json" \\
     -d '{"name":"ci-bot","roles":["viewer"]}'

   # 4. Permission checks
   curl -s http://localhost:3000/posts -H "Authorization: Bearer $TOKEN"
   curl -s http://localhost:3000/admin -H "Authorization: Bearer $TOKEN"

   # 5. Revoke token (logout)
   curl -s -X POST http://localhost:3000/logout -H "Authorization: Bearer $TOKEN"

⚠️  This example uses a mock database. For production:
   1. Set DATABASE_URL and AUTH_SECRET environment variables
   2. Replace the mock \`db\` with a real Drizzle instance
   3. Run \`bunx drizzle-kit push\` to apply the FlashAuth schema
`);
