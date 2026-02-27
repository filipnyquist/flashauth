/**
 * FlashAuth Sub-Routes Example
 *
 * Demonstrates modular routing with flashAuthCore:
 * - Using `flashAuthCore` in separate route modules
 * - Different permission requirements per module
 * - Role-based access control across sub-routes
 *
 * Architecture:
 *   Main app ─── flashAuthCore (context & macros)
 *            ├── /api/*    routes (posts, profile, admin)
 *            └── /users/*  routes (user management)
 *
 * Run: bun run examples/subroutes-app.ts
 */

import { Elysia } from 'elysia';
import { FlashAuth, flashAuthCore, type FlashAuthContext } from '../src/index.js';

// ── Initialize FlashAuth ────────────────────────────────────────────────────
const auth = new FlashAuth({
  secret: Bun.env.AUTH_SECRET ?? FlashAuth.generateSecret(),
  rolePermissions: {
    user: ['posts:read', 'posts:write'],
    moderator: ['posts:read', 'posts:write', 'posts:delete', 'users:read'],
    admin: ['*'],
  },
});

// Create a reusable core plugin instance.
// flashAuthCore provides token validation context and macros (isAuth,
// requirePermission, etc.) but does NOT add /auth/* routes.
const authCore = flashAuthCore({
  flashAuth: auth,
  tokenLocation: 'both', // check Authorization header first, then cookie
});

// ═══════════════════════════════════════════════════════════════════════════
// API Routes Module (simulates routes/api.ts)
// ═══════════════════════════════════════════════════════════════════════════
const apiRoutes = new Elysia({ prefix: '/api' })
  .use(authCore)

  // Public — no auth required
  .get('/public', () => ({
    message: 'This is a public API endpoint',
    timestamp: new Date().toISOString(),
  }))

  // Requires authentication (any valid token)
  .get('/profile', ({ flashAuth }: FlashAuthContext) => ({
    message: 'User profile',
    user: {
      id: flashAuth.claims?.sub,
      roles: flashAuth.claims?.roles,
      permissions: flashAuth.claims?.perms,
    },
  }), {
    isAuth: true,
  })

  // Requires the 'admin' role
  .get('/admin/dashboard', ({ flashAuth }: FlashAuthContext) => ({
    message: 'Admin dashboard',
    adminUser: flashAuth.claims?.sub,
    stats: { totalUsers: 42, activeSessions: 12 },
  }), {
    requireRole: 'admin',
  })

  // Requires posts:read permission
  .get('/posts', ({ flashAuth }: FlashAuthContext) => ({
    posts: [
      { id: 1, title: 'Getting Started with FlashAuth', author: 'user:123' },
      { id: 2, title: 'Building Secure APIs', author: 'user:456' },
    ],
    requestedBy: flashAuth.claims?.sub,
  }), {
    requirePermission: 'posts:read',
  })

  // Requires posts:write permission
  .post('/posts', ({ flashAuth, body }: FlashAuthContext & { body: any }) => ({
    post: {
      id: Date.now(),
      title: body.title,
      content: body.content,
      author: flashAuth.claims?.sub,
      created: new Date().toISOString(),
    },
  }), {
    requirePermission: 'posts:write',
  })

  // Requires posts:delete permission (only moderator & admin have this)
  .delete('/posts/:id', ({ flashAuth, params }: FlashAuthContext & { params: any }) => ({
    message: 'Post deleted',
    postId: params.id,
    deletedBy: flashAuth.claims?.sub,
  }), {
    requirePermission: 'posts:delete',
  });

// ═══════════════════════════════════════════════════════════════════════════
// User Management Routes (simulates routes/users.ts)
// ═══════════════════════════════════════════════════════════════════════════
const userRoutes = new Elysia({ prefix: '/users' })
  .use(authCore)

  // Requires users:read OR admin wildcard
  .get('/', ({ flashAuth }: FlashAuthContext) => ({
    users: [
      { id: 'user:123', email: 'alice@example.com', role: 'user' },
      { id: 'user:456', email: 'bob@example.com', role: 'moderator' },
    ],
    requestedBy: flashAuth.claims?.sub,
  }), {
    requireAnyPermission: ['users:read', 'admin:*'],
  })

  // Requires admin role to manage users
  .delete('/:id', ({ flashAuth, params }: FlashAuthContext & { params: any }) => ({
    message: 'User deleted',
    userId: params.id,
    deletedBy: flashAuth.claims?.sub,
  }), {
    requireRole: 'admin',
  });

// ═══════════════════════════════════════════════════════════════════════════
// Main Application
// ═══════════════════════════════════════════════════════════════════════════
const app = new Elysia()
  .use(authCore)

  // Home / docs route
  .get('/', () => ({
    message: 'FlashAuth Sub-Routes Example',
    architecture: {
      flashAuthCore: 'Provides token context & macros — use in every module',
      flashAuthRoutes: 'Provides /auth/* endpoints — use once in main app (not shown here)',
    },
    endpoints: {
      login: 'POST /login  { email, password, roles? }',
      api: {
        public: 'GET /api/public',
        profile: 'GET /api/profile (requires auth)',
        adminDashboard: 'GET /api/admin/dashboard (requires admin role)',
        posts: 'GET /api/posts (requires posts:read)',
        createPost: 'POST /api/posts (requires posts:write)',
        deletePost: 'DELETE /api/posts/:id (requires posts:delete)',
      },
      users: {
        list: 'GET /users (requires users:read or admin:*)',
        deleteUser: 'DELETE /users/:id (requires admin role)',
      },
    },
  }))

  // Simple login endpoint for testing — issue JWT with requested roles
  .post('/login', async ({ body }: { body: any }) => {
    const userId = body.userId ?? 'user:123';
    const email = body.email ?? 'user@example.com';
    const roles = body.roles ?? ['user'];

    const token = await auth
      .createToken()
      .subject(userId)
      .claim('email', email)
      .roles(roles)
      .expiresIn('1h')
      .build();

    return { token, expiresIn: 3600, user: { id: userId, email, roles } };
  })

  // Mount sub-route modules
  .use(apiRoutes)
  .use(userRoutes)

  // Error handler
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

console.log(`🚀 FlashAuth Sub-Routes Example running at http://${app.server?.hostname}:${app.server?.port}`);
console.log('\n📚 Example Usage:\n');
console.log('# 1. Login as regular user');
console.log('curl -X POST http://localhost:3000/login -H "Content-Type: application/json" \\');
console.log('  -d \'{"email":"user@example.com","roles":["user"]}\'');
console.log('\n# 2. Access protected route (use token from step 1)');
console.log('curl http://localhost:3000/api/profile -H "Authorization: Bearer <TOKEN>"');
console.log('\n# 3. Try admin route with user token (should fail with 403)');
console.log('curl http://localhost:3000/api/admin/dashboard -H "Authorization: Bearer <TOKEN>"');
console.log('\n# 4. Login as admin');
console.log('curl -X POST http://localhost:3000/login -H "Content-Type: application/json" \\');
console.log('  -d \'{"email":"admin@example.com","roles":["admin"]}\'');
console.log('\n# 5. Access admin route with admin token');
console.log('curl http://localhost:3000/api/admin/dashboard -H "Authorization: Bearer <ADMIN_TOKEN>"');
console.log('\n# 6. Public route (no auth)');
console.log('curl http://localhost:3000/api/public');
