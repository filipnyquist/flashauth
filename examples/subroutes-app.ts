/**
 * Example: Sub-routes in separate files
 * 
 * This example demonstrates how to use FlashAuth macros and context
 * in sub-routes defined in separate files/modules.
 */

import { Elysia } from 'elysia';
import { FlashAuth, flashAuthCore, flashAuthRoutes, type FlashAuthContext } from '../src/index.js';

// Initialize FlashAuth
const auth = new FlashAuth({
  secret: FlashAuth.generateSecret(),
  rolePermissions: {
    'user': ['posts:read', 'posts:write'],
    'moderator': ['posts:read', 'posts:write', 'posts:delete', 'users:read'],
    'admin': ['*'],
  },
});

// Create the core auth plugin (context & macros only, NO /auth routes)
// This is what sub-routes should use to get flashAuth context and macros
const authCore = flashAuthCore({
  flashAuth: auth,
  tokenLocation: 'bearer',
});

// ============================================================================
// API Routes Module (simulates routes/api.ts in a real application)
// ============================================================================
const apiRoutes = new Elysia({ prefix: '/api' })
  // Use the core auth plugin to get access to flashAuth context and macros
  .use(authCore)
  // Public route - no authentication required
  .get('/public', () => ({
    message: 'This is a public API endpoint',
    timestamp: new Date().toISOString(),
  }))
  
  // Protected route - requires authentication
  .get('/profile', ({ flashAuth }: FlashAuthContext) => ({
    message: 'User profile',
    user: {
      id: flashAuth.claims?.sub,
      email: flashAuth.claims?.email,
      roles: flashAuth.claims?.roles,
      permissions: flashAuth.claims?.perms,
    },
  }), {
    isAuth: true,
  })
  
  // Admin route - requires admin role
  .get('/admin/dashboard', ({ flashAuth }: FlashAuthContext) => ({
    message: 'Admin dashboard',
    adminUser: flashAuth.claims?.sub,
    stats: {
      totalUsers: 42,
      activeSessions: 12,
    },
  }), {
    requireRole: 'admin',
  })
  
  // Posts route - requires posts:read permission
  .get('/posts', ({ flashAuth }: FlashAuthContext) => ({
    message: 'List of posts',
    requestedBy: flashAuth.claims?.sub,
    posts: [
      { id: 1, title: 'Getting Started with FlashAuth', author: 'user:123' },
      { id: 2, title: 'Building Secure APIs', author: 'user:456' },
    ],
  }), {
    requirePermission: 'posts:read',
  })
  
  // Create post - requires posts:write permission
  .post('/posts', ({ flashAuth, body }: FlashAuthContext & { body: any }) => ({
    message: 'Post created',
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
  
  // Delete post - requires posts:delete permission
  .delete('/posts/:id', ({ flashAuth, params }: FlashAuthContext & { params: any }) => ({
    message: 'Post deleted',
    postId: params.id,
    deletedBy: flashAuth.claims?.sub,
  }), {
    requirePermission: 'posts:delete',
  });

// ============================================================================
// User Management Routes (simulates routes/users.ts in a real application)
// ============================================================================
const userRoutes = new Elysia({ prefix: '/users' })
  // Use the core auth plugin to get access to flashAuth context and macros
  .use(authCore)
  // List users - requires users:read permission
  .get('/', ({ flashAuth }: FlashAuthContext) => ({
    message: 'List of users',
    users: [
      { id: 'user:123', email: 'alice@example.com', role: 'user' },
      { id: 'user:456', email: 'bob@example.com', role: 'moderator' },
    ],
    requestedBy: flashAuth.claims?.sub,
  }), {
    requireAnyPermission: ['users:read', 'admin:*'],
  });

// ============================================================================
// Main Application
// ============================================================================
const app = new Elysia()
  // Use the core auth plugin for the main app (context & macros)
  .use(authCore)
  
  // Optionally add the auth routes plugin for /auth/* endpoints
  // .use(flashAuthRoutes({
  //   flashAuth: auth,
  //   databaseUrl: process.env.DATABASE_URL,
  //   webauthn: { rpName: 'My App', rpID: 'localhost', origin: 'http://localhost:3000' }
  // }))
  
  // Home route
  .get('/', () => ({
    message: 'FlashAuth Sub-Routes Example',
    description: 'Demonstrates how to use FlashAuth with routes in separate files/modules',
    architecture: {
      flashAuthCore: 'Provides context & macros (use in main app and sub-routes)',
      flashAuthRoutes: 'Provides /auth/* endpoints (use once in main app)',
    },
    pattern: {
      mainApp: 'Use flashAuthCore() for context & macros',
      subRoutes: 'Use flashAuthCore() - same plugin instance can be reused',
      authRoutes: 'Optionally use flashAuthRoutes() once for /auth/* endpoints',
    },
    note: 'Sub-routes must call .use(authCore) to access flashAuth context and macros',
    endpoints: {
      login: {
        method: 'POST',
        path: '/login',
        description: 'body: { email: string, password: string, roles?: string[] }',
      },
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
      },
    },
  }))
  
  // Login endpoint
  .post('/login', async ({ body }: { body: any }) => {
    // In a real application, you would validate credentials against a database
    const userId = body.userId || 'user:123';
    const email = body.email || 'user@example.com';
    const roles = body.roles || ['user'];
    
    const token = await auth
      .createToken()
      .subject(userId)
      .claim('email', email)
      .roles(roles)
      .expiresIn('1h')
      .build();
    
    return {
      token,
      expiresIn: 3600,
      user: {
        id: userId,
        email,
        roles,
      },
    };
  })
  
  // Mount sub-routes
  .use(apiRoutes)
  .use(userRoutes)
  
  // Error handler
  .onError(({ code, error }) => {
    console.error(`[${code}]`, error.message);
    
    if (code === 'VALIDATION') {
      return {
        error: 'Validation Error',
        message: error.message,
      };
    }
    
    if (error.name === 'TokenError') {
      return {
        error: 'Unauthorized',
        message: error.message,
      };
    }
    
    if (error.name === 'PermissionError') {
      return {
        error: 'Forbidden',
        message: error.message,
      };
    }
    
    return {
      error: 'Internal Server Error',
      message: error.message,
    };
  })
  
  .listen(3000);

console.log(`🚀 FlashAuth Sub-Routes Example running at http://${app.server?.hostname}:${app.server?.port}`);
console.log('\n📚 Example Usage:\n');
console.log('# 1. Login as regular user');
console.log('curl -X POST http://localhost:3000/login -H "Content-Type: application/json" \\');
console.log('  -d \'{"email":"user@example.com","roles":["user"]}\'');
console.log('\n# 2. Access protected route (use token from step 1)');
console.log('curl http://localhost:3000/api/profile -H "Authorization: Bearer <TOKEN>"');
console.log('\n# 3. Try admin route with user token (should fail)');
console.log('curl http://localhost:3000/api/admin/dashboard -H "Authorization: Bearer <TOKEN>"');
console.log('\n# 4. Login as admin');
console.log('curl -X POST http://localhost:3000/login -H "Content-Type: application/json" \\');
console.log('  -d \'{"email":"admin@example.com","roles":["admin"]}\'');
console.log('\n# 5. Access admin route with admin token (should succeed)');
console.log('curl http://localhost:3000/api/admin/dashboard -H "Authorization: Bearer <ADMIN_TOKEN>"');
console.log('\n# 6. Access public route (no auth needed)');
console.log('curl http://localhost:3000/api/public');
