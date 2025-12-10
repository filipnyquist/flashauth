/**
 * FlashAuth Basic Example
 * Demonstrates basic token creation and validation
 */

import { Elysia, t } from 'elysia';
import { FlashAuth, flashAuth, requireAuth, requirePermission } from '../src/index.js';

// Initialize FlashAuth
const auth = new FlashAuth({
  secret: FlashAuth.generateSecret(),
  rolePermissions: {
    'user': ['posts:read', 'posts:write'],
    'moderator': ['posts:read', 'posts:write', 'posts:delete', 'users:read'],
    'admin': ['*'],
  },
});

// Create Elysia app
const app = new Elysia()
  .use(flashAuth(auth))
  
  // Public route
  .get('/', () => ({
    message: 'FlashAuth Basic Example',
    endpoints: {
      login: 'POST /login',
      profile: 'GET /profile (requires auth)',
      posts: 'GET /posts (requires posts:read)',
      createPost: 'POST /posts (requires posts:write)',
    },
  }))
  
  // Login endpoint
  .post('/login', async ({ body }) => {
    // In real app, validate credentials against database
    const userId = 'user:123';
    const email = body.email;
    const roles = ['user'];
    
    // Create token
    const token = auth
      .createToken()
      .subject(userId)
      .claim('email', email)
      .roles(roles)
      .expiresIn('1h')
      .build();
    
    return {
      token,
      expiresIn: 3600,
    };
  }, {
    body: t.Object({
      email: t.String({ format: 'email' }),
      password: t.String({ minLength: 8 }),
    }),
  })
  
  // Protected route - requires authentication
  .use(requireAuth())
  .get('/profile', ({ flashAuth }) => ({
    userId: flashAuth.claims?.sub,
    email: flashAuth.claims?.email,
    roles: flashAuth.claims?.roles,
    permissions: flashAuth.claims?.perms,
  }))
  
  // Protected route - requires posts:read permission
  .use(requirePermission('posts:read'))
  .get('/posts', ({ flashAuth }) => ({
    posts: [
      { id: 1, title: 'First Post', author: 'user:123' },
      { id: 2, title: 'Second Post', author: 'user:456' },
    ],
    user: flashAuth.claims?.sub,
  }))
  
  // Protected route - requires posts:write permission
  .use(requirePermission('posts:write'))
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
  })
  
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

console.log(`🚀 FlashAuth Basic Example running at http://${app.server?.hostname}:${app.server?.port}`);
console.log('\nTry these commands:');
console.log('# Login');
console.log('curl -X POST http://localhost:3000/login -H "Content-Type: application/json" -d \'{"email":"user@example.com","password":"password123"}\'');
console.log('\n# Get profile (use token from login)');
console.log('curl http://localhost:3000/profile -H "Authorization: Bearer <token>"');
console.log('\n# Get posts (use token from login)');
console.log('curl http://localhost:3000/posts -H "Authorization: Bearer <token>"');
