/**
 * FlashAuth HTTP Benchmark Server
 * 
 * A simple ElysiaJS server for HTTP benchmarking of FlashAuth operations.
 * Includes endpoints for:
 * - Baseline (no auth) endpoints to measure server overhead
 * - Token generation (cached and uncached)
 * - Token verification (cached and uncached)
 * 
 * Run with: bun run benchmark:server
 * 
 * Example benchmarks:
 * - wrk -t4 -c100 -d30s http://localhost:3001/ping
 * - wrk -t4 -c100 -d30s -s post.lua http://localhost:3001/token/generate/uncached
 * - wrk -t4 -c100 -d30s -s post-verify.lua http://localhost:3001/token/verify/cached
 */

import { Elysia, t } from 'elysia';
import { FlashAuth } from '../src/index.js';

// Initialize FlashAuth instances
const sharedSecret = FlashAuth.generateSecret();

// Uncached instance for baseline performance
const uncachedAuth = new FlashAuth({
  secret: sharedSecret,
  enableCache: false,
});

// Cached instance for optimized performance
const cachedAuth = new FlashAuth({
  secret: sharedSecret,
  enableCache: true,
  cache: {
    maxSize: 10000,
    ttl: 300000, // 5 minutes
  },
  rolePermissions: {
    'user': ['posts:read', 'posts:write', 'profile:read', 'profile:write'],
    'moderator': ['posts:read', 'posts:write', 'posts:delete', 'users:read', 'comments:delete'],
    'admin': ['*'],
  },
});

// Create Elysia app
const app = new Elysia()
  
  // ============================================================================
  // BASELINE ENDPOINTS (NO AUTH)
  // ============================================================================
  
  .get('/ping', () => ({ pong: true }))
  
  .get('/health', () => ({
    status: 'healthy',
    timestamp: Date.now(),
    uptime: process.uptime(),
  }))
  
  .get('/', () => ({
    name: 'FlashAuth HTTP Benchmark Server',
    version: '1.0.0',
    endpoints: {
      baseline: {
        ping: 'GET /ping',
        health: 'GET /health',
      },
      tokenGeneration: {
        uncached: {
          simple: 'POST /token/generate/uncached',
          complex: 'POST /token/generate/uncached/complex',
        },
        cached: {
          simple: 'POST /token/generate/cached',
          complex: 'POST /token/generate/cached/complex',
        },
      },
      tokenVerification: {
        uncached: 'POST /token/verify/uncached',
        cached: 'POST /token/verify/cached',
      },
    },
    exampleUsage: {
      wrk: [
        'wrk -t4 -c100 -d30s http://localhost:3001/ping',
        'wrk -t4 -c100 -d30s -H "Content-Type: application/json" -d \'{"userId":"user:123"}\' -s post.lua http://localhost:3001/token/generate/uncached',
      ],
      curl: [
        'curl http://localhost:3001/ping',
        'curl -X POST http://localhost:3001/token/generate/uncached -H "Content-Type: application/json" -d \'{"userId":"user:123"}\'',
      ],
    },
  }))
  
  // ============================================================================
  // TOKEN GENERATION ENDPOINTS (UNCACHED)
  // ============================================================================
  
  .post('/token/generate/uncached', async ({ body }) => {
    const token = await uncachedAuth
      .createToken()
      .subject(body.userId || 'user:123')
      .expiresIn('1h')
      .build();
    
    return { token };
  }, {
    body: t.Object({
      userId: t.Optional(t.String()),
    }),
  })
  
  .post('/token/generate/uncached/complex', async ({ body }) => {
    const token = await uncachedAuth
      .createToken()
      .subject(body.userId || 'user:123')
      .issuer('flashauth-benchmark')
      .audience(['service-a', 'service-b'])
      .claim('email', body.email || 'user@example.com')
      .claim('name', body.name || 'John Doe')
      .claim('metadata', { theme: 'dark', lang: 'en' })
      .expiresIn('1h')
      .build();
    
    return { token };
  }, {
    body: t.Object({
      userId: t.Optional(t.String()),
      email: t.Optional(t.String()),
      name: t.Optional(t.String()),
    }),
  })
  
  // ============================================================================
  // TOKEN GENERATION ENDPOINTS (CACHED)
  // ============================================================================
  
  .post('/token/generate/cached', async ({ body }) => {
    const token = await cachedAuth
      .createToken()
      .subject(body.userId || 'user:123')
      .roles(body.roles || ['user'])
      .expiresIn('1h')
      .build();
    
    return { token };
  }, {
    body: t.Object({
      userId: t.Optional(t.String()),
      roles: t.Optional(t.Array(t.String())),
    }),
  })
  
  .post('/token/generate/cached/complex', async ({ body }) => {
    const token = await cachedAuth
      .createToken()
      .subject(body.userId || 'user:123')
      .issuer('flashauth-benchmark')
      .audience(['service-a', 'service-b'])
      .roles(body.roles || ['user', 'moderator'])
      .claim('email', body.email || 'user@example.com')
      .claim('name', body.name || 'John Doe')
      .claim('metadata', { theme: 'dark', lang: 'en' })
      .expiresIn('1h')
      .build();
    
    return { token };
  }, {
    body: t.Object({
      userId: t.Optional(t.String()),
      email: t.Optional(t.String()),
      name: t.Optional(t.String()),
      roles: t.Optional(t.Array(t.String())),
    }),
  })
  
  // ============================================================================
  // TOKEN VERIFICATION ENDPOINTS (UNCACHED)
  // ============================================================================
  
  .post('/token/verify/uncached', async ({ body }) => {
    try {
      const claims = await uncachedAuth.validateToken(body.token);
      
      return {
        valid: true,
        subject: claims.sub,
        expiresAt: claims.exp,
      };
    } catch (error) {
      return {
        valid: false,
        error: error instanceof Error ? error.message : 'Invalid token',
      };
    }
  }, {
    body: t.Object({
      token: t.String(),
    }),
  })
  
  // ============================================================================
  // TOKEN VERIFICATION ENDPOINTS (CACHED)
  // ============================================================================
  
  .post('/token/verify/cached', async ({ body }) => {
    try {
      const claims = await cachedAuth.validateToken(body.token);
      
      return {
        valid: true,
        subject: claims.sub,
        expiresAt: claims.exp,
        roles: claims.roles,
        permissions: claims.perms,
      };
    } catch (error) {
      return {
        valid: false,
        error: error instanceof Error ? error.message : 'Invalid token',
      };
    }
  }, {
    body: t.Object({
      token: t.String(),
    }),
  })
  
  // Error handler
  .onError(({ code, error }) => {
    console.error(`[${code}]`, error.message);
    
    return {
      error: 'Server Error',
      message: error.message,
      code,
    };
  })
  
  .listen(3001);

console.log('🔥 FlashAuth HTTP Benchmark Server\n');
console.log('='.repeat(70));
console.log(`Server running at http://${app.server?.hostname}:${app.server?.port}`);
console.log('='.repeat(70));
console.log('\n📊 Available Endpoints:\n');
console.log('Baseline (no auth):');
console.log('  GET  /ping                              - Simple ping/pong');
console.log('  GET  /health                            - Health check');
console.log('');
console.log('Token Generation (uncached):');
console.log('  POST /token/generate/uncached           - Simple token');
console.log('  POST /token/generate/uncached/complex   - Complex token');
console.log('');
console.log('Token Generation (cached):');
console.log('  POST /token/generate/cached             - Simple token with roles');
console.log('  POST /token/generate/cached/complex     - Complex token with roles');
console.log('');
console.log('Token Verification:');
console.log('  POST /token/verify/uncached             - Verify without cache');
console.log('  POST /token/verify/cached               - Verify with cache');
console.log('');
console.log('='.repeat(70));
console.log('\n📝 Example Commands:\n');
console.log('# Baseline benchmark (no auth)');
console.log('wrk -t4 -c100 -d30s http://localhost:3001/ping');
console.log('');
console.log('# Token generation benchmark');
console.log('curl -X POST http://localhost:3001/token/generate/uncached \\');
console.log('  -H "Content-Type: application/json" \\');
console.log('  -d \'{"userId":"user:123"}\'');
console.log('');
console.log('# Token verification benchmark');
console.log('# First, generate a token:');
console.log('TOKEN=$(curl -s -X POST http://localhost:3001/token/generate/cached \\');
console.log('  -H "Content-Type: application/json" \\');
console.log('  -d \'{"userId":"user:123"}\' | jq -r \'.token\')');
console.log('');
console.log('# Then verify it:');
console.log('curl -X POST http://localhost:3001/token/verify/cached \\');
console.log('  -H "Content-Type: application/json" \\');
console.log('  -d "{\\\"token\\\":\\\"$TOKEN\\\"}"');
console.log('');
console.log('='.repeat(70));
console.log('\n💡 Tips:');
console.log('  • Use wrk or autocannon for HTTP benchmarking');
console.log('  • Compare /ping vs /token/generate to see auth overhead');
console.log('  • Compare cached vs uncached endpoints to see cache benefit');
console.log('  • Use multiple connections (-c flag) to test concurrency');
console.log('');
