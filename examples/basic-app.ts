/**
 * FlashAuth Basic Example
 *
 * A minimal Elysia app demonstrating:
 * - FlashAuth initialization with a secret and role-permission mapping
 * - Public routes (no auth required)
 * - Protected routes using bearer / cookie auth via the `flashAuth` plugin
 * - Login endpoint that creates a JWT
 * - Permission-based route protection using Elysia macros
 * - API key creation and usage (long-lived tokens)
 *
 * No database is required — this example uses the lightweight `flashAuth`
 * plugin which only provides token validation context and macros.
 *
 * Run: bun run examples/basic-app.ts
 */

import { Elysia, t } from 'elysia';
import { FlashAuth, flashAuth } from '../src/index.js';

// ── 1. Initialize FlashAuth ─────────────────────────────────────────────────
// Use AUTH_SECRET from env or generate a random one for development.
const secret = Bun.env.AUTH_SECRET ?? FlashAuth.generateSecret();

const auth = new FlashAuth({
  secret,
  // Map roles → permissions. The wildcard '*' grants everything.
  rolePermissions: {
    user: ['posts:read', 'posts:write'],
    moderator: ['posts:read', 'posts:write', 'posts:delete', 'users:read'],
    admin: ['*'],
  },
});

// ── 2. Create Elysia app ────────────────────────────────────────────────────
const app = new Elysia()
  // Register the lightweight FlashAuth plugin.
  // tokenLocation defaults to 'bearer'; set 'cookie' or use the full auth
  // plugin (flashAuthRoutes) for 'both'.
  .use(flashAuth(auth, { tokenLocation: 'bearer' }))

  // ── Public route ────────────────────────────────────────────────────────
  .get('/', () => ({
    message: 'FlashAuth Basic Example',
    endpoints: {
      login: 'POST /login',
      profile: 'GET /profile (requires auth)',
      posts: 'GET /posts (requires posts:read)',
      createPost: 'POST /posts (requires posts:write)',
      createApiKey: 'POST /api-key (requires auth)',
      protectedByApiKey: 'GET /status (works with API key)',
    },
  }))

  // ── Login endpoint ──────────────────────────────────────────────────────
  // In a real app you would validate credentials against a database.
  .post('/login', async ({ body }) => {
    const userId = 'user:123';
    const roles = ['user'];

    // Create a JWT with the fluent TokenBuilder API
    const token = await auth
      .createToken()
      .subject(userId)
      .claim('email', body.email)
      .roles(roles) // permissions are auto-expanded from rolePermissions
      .expiresIn('1h')
      .build();

    return { token, expiresIn: 3600 };
  }, {
    body: t.Object({
      email: t.String({ format: 'email' }),
      password: t.String({ minLength: 8 }),
    }),
  })

  // ── Protected route – requires authentication ───────────────────────────
  .get('/profile', ({ flashAuth }) => ({
    userId: flashAuth.claims?.sub,
    email: flashAuth.claims?.email,
    roles: flashAuth.claims?.roles,
    permissions: flashAuth.claims?.perms,
  }), {
    isAuth: true,
  })

  // ── Protected route – requires posts:read permission ────────────────────
  .get('/posts', ({ flashAuth }) => ({
    posts: [
      { id: 1, title: 'First Post', author: 'user:123' },
      { id: 2, title: 'Second Post', author: 'user:456' },
    ],
    user: flashAuth.claims?.sub,
  }), {
    requirePermission: 'posts:read',
  })

  // ── Protected route – requires posts:write permission ───────────────────
  .post('/posts', ({ flashAuth, body }) => ({
    id: 3,
    title: body.title,
    content: body.content,
    author: flashAuth.claims?.sub,
    created: new Date().toISOString(),
  }), {
    body: t.Object({
      title: t.String({ minLength: 1 }),
      content: t.String({ minLength: 1 }),
    }),
    requirePermission: 'posts:write',
  })

  // ── API key creation ────────────────────────────────────────────────────
  // API keys are long-lived JWT tokens with type 'api_key' (no expiry).
  .post('/api-key', async ({ flashAuth }) => {
    const userId = flashAuth.claims!.sub;

    const apiKeyToken = await auth
      .createToken()
      .subject(userId)
      .apiKey()
      .claim('name', 'my-api-key')
      .roles(['user'])
      .build();

    return { apiKey: apiKeyToken };
  }, {
    isAuth: true,
  })

  // ── Route that accepts API keys or regular tokens ───────────────────────
  .get('/status', ({ flashAuth }) => ({
    authenticated: !!flashAuth.claims,
    userId: flashAuth.claims?.sub,
    tokenType: flashAuth.claims?.type ?? 'session',
  }), {
    isAuth: true,
  })

  // ── Error handler ───────────────────────────────────────────────────────
  .onError(({ code, error }) => {
    console.error(`[${code}]`, error.message);

    if (code === 'VALIDATION') {
      return { error: 'Validation Error', message: error.message };
    }
    if (error.name === 'TokenError') {
      return { error: 'Unauthorized', message: error.message };
    }
    if (error.name === 'PermissionError') {
      return { error: 'Forbidden', message: error.message };
    }
    return { error: 'Internal Server Error', message: error.message };
  })

  .listen(3000);

console.log(`🚀 FlashAuth Basic Example running at http://${app.server?.hostname}:${app.server?.port}`);
console.log('\nTry these commands:');
console.log('# Login');
console.log('curl -X POST http://localhost:3000/login -H "Content-Type: application/json" \\');
console.log('  -d \'{"email":"user@example.com","password":"password123"}\'');
console.log('\n# Get profile (use token from login)');
console.log('curl http://localhost:3000/profile -H "Authorization: Bearer <token>"');
console.log('\n# Get posts (use token from login)');
console.log('curl http://localhost:3000/posts -H "Authorization: Bearer <token>"');
console.log('\n# Create an API key (use token from login)');
console.log('curl -X POST http://localhost:3000/api-key -H "Authorization: Bearer <token>"');
console.log('\n# Use API key');
console.log('curl http://localhost:3000/status -H "Authorization: Bearer <api-key>"');
