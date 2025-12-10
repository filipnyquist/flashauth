/**
 * Test to reproduce the TypeScript issue with guards
 */

import { Elysia } from 'elysia';
import { FlashAuth, flashAuth, requireAuth, requirePermission } from './src/index.js';

// Initialize FlashAuth
const auth = new FlashAuth({
  secret: FlashAuth.generateSecret(),
  rolePermissions: {
    'user': ['posts:read', 'posts:write'],
    'admin': ['*'],
  },
});

// Create Elysia app - this should demonstrate the type issue
const app = new Elysia()
  .use(flashAuth(auth))
  
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
    posts: [],
    user: flashAuth.claims?.sub,
  }));

console.log('Type test passed!');
