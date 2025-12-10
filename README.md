# FlashAuth

**Ultra-Fast PASETO v4 Local Authentication Framework for Bun.js and Elysia.js**

FlashAuth is a high-performance authentication framework designed specifically for modern Bun.js + Elysia.js ecosystems. It focuses on three core pillars:

1. **Raw Speed** - Optimized for Bun's performance characteristics
2. **Security by Default** - PASETO v4 Local with XChaCha20-Poly1305
3. **Developer Velocity** - Pure TypeScript with end-to-end type safety

## Features

- ✅ **PASETO v4 Local**: Secure authenticated encryption with XChaCha20-Poly1305
- ✅ **Native Elysia Plugin**: First-class integration with Elysia.js
- ✅ **Permission System**: Built-in RBAC with wildcard support
- ✅ **Type-Safe**: Full TypeScript support with strict mode
- ✅ **Zero Dependencies** (runtime): Uses Bun's crypto + [@noble/ciphers](https://github.com/paulmillr/noble-ciphers)
- ✅ **Token Revocation**: Per-token and per-user revocation support
- ✅ **Caching Layer**: Optional LRU cache for validated tokens

## Installation

```bash
bun add flashauth
```

**Requirements:**
- Bun 1.1+
- Elysia 1.0+ (peer dependency)

## Quick Start

```typescript
import { Elysia } from 'elysia';
import { FlashAuth, flashAuth, requirePermission } from 'flashauth';

// Initialize FlashAuth
const auth = new FlashAuth({
  secret: FlashAuth.generateSecret(),
  rolePermissions: {
    'user': ['posts:read', 'posts:write'],
    'admin': ['*'], // All permissions
  },
});

// Create Elysia app
const app = new Elysia()
  .use(flashAuth(auth))
  
  // Public login endpoint
  .post('/login', async ({ body }) => {
    // Validate credentials...
    const token = auth
      .createToken()
      .subject('user:123')
      .claim('email', body.email)
      .roles(['user'])
      .expiresIn('1h')
      .build();
    
    return { token };
  })
  
  // Protected endpoint - requires posts:read permission
  .use(requirePermission('posts:read'))
  .get('/posts', ({ flashAuth }) => {
    return {
      posts: [],
      user: flashAuth.claims?.sub,
    };
  })
  
  .listen(3000);
```

## Core Concepts

### PASETO v4 Local

FlashAuth uses PASETO v4 Local tokens for authentication:
- **Format**: `v4.local.{payload}.{footer}`
- **Encryption**: XChaCha20-Poly1305 (via @noble/ciphers)
- **Random**: Bun's `crypto.getRandomValues`
- **No JWT vulnerabilities**: Algorithm fixed by version, no key confusion

### Token Structure

```typescript
interface StandardClaims {
  sub: string;         // Subject (user ID) - required
  exp: number;         // Expiration timestamp - required
  iat: number;         // Issued at timestamp
  iss?: string;        // Issuer
  aud?: string[];      // Audience
  nbf?: number;        // Not before
  jti?: string;        // Token ID for revocation
  roles?: string[];    // User roles
  perms?: string[];    // Permissions (auto-expanded from roles)
  [key: string]: any;  // Custom claims
}
```

### Permission System

Permissions use dot-notation with wildcard support:

```typescript
// Exact match
'posts:read'   // Can read posts
'posts:write'  // Can write posts

// Wildcard match
'posts:*'      // All post operations
'admin:*'      // All admin operations
'*'            // Super admin (all permissions)
```

**Permission checks:**
```typescript
const claims = await auth.validateToken(token);

claims.hasPermission('posts:write');              // Single permission
claims.hasAnyPermission(['posts:read', 'admin:*']); // Any of multiple
claims.hasAllPermissions(['posts:read', 'posts:write']); // All required
```

## API Reference

### FlashAuth Class

#### Constructor

```typescript
const auth = new FlashAuth({
  secret: Uint8Array | string,     // 32-byte secret key
  rolePermissions?: RolePermissions, // Role-to-permission mapping
  revocationStore?: RevocationStore, // Custom revocation store
  enableCache?: boolean,             // Enable token caching (default: true)
  cache?: {
    maxSize?: number,                // Max cached tokens (default: 10000)
    ttl?: number,                    // Cache TTL in ms (default: 300000)
  },
});
```

#### Token Creation

```typescript
// Fluent API
const token = auth
  .createToken()
  .subject('user:123')
  .issuer('my-app')
  .audience(['service-a', 'service-b'])
  .roles(['user', 'moderator'])
  .permissions(['custom:permission'])
  .claim('email', 'user@example.com')
  .expiresIn('1h')  // or '30m', '7d', '1w'
  .tokenId('unique-id')
  .footer('optional-footer')
  .build();

// Direct
const token = auth.createToken({
  sub: 'user:123',
  exp: Math.floor(Date.now() / 1000) + 3600,
  roles: ['user'],
}).build();
```

#### Token Validation

```typescript
const claims = await auth.validateToken(token, {
  clockSkew: 5,                    // Clock skew tolerance (seconds)
  validateExpiry: true,            // Validate expiration (default: true)
  requiredIssuer: 'my-app',       // Required issuer
  requiredAudience: 'service-a',  // Required audience
});
```

#### Token Revocation

```typescript
// Revoke by token ID
await auth.revokeToken(jti, expiresAt);

// Revoke all user tokens
await auth.revokeUser(userId);

// Check if token is valid
const isValid = await auth.isTokenValid(token);
```

#### Key Generation

```typescript
// Generate 32-byte secret
const secret = FlashAuth.generateSecret();       // Uint8Array
const secretHex = FlashAuth.generateSecretHex(); // Hex string
```

### Elysia Plugin

#### Basic Setup

```typescript
import { flashAuth } from 'flashauth';

app.use(flashAuth(auth, {
  tokenLocation: 'bearer',  // or 'cookie'
  cookieName: 'auth_token', // for cookie mode
  cookieSecure: true,
  cookieHttpOnly: true,
  cookieSameSite: 'strict',
}));
```

#### Permission Guards

```typescript
import {
  requireAuth,
  requirePermission,
  requireAnyPermission,
  requireAllPermissions,
  requireRole,
  requireAnyRole,
} from 'flashauth';

// Require authentication
app.use(requireAuth())
  .get('/profile', ({ flashAuth }) => flashAuth.claims);

// Require specific permission
app.use(requirePermission('posts:write'))
  .post('/posts', ({ body }) => createPost(body));

// Require any of multiple permissions
app.use(requireAnyPermission(['posts:delete', 'admin:*']))
  .delete('/posts/:id', ({ params }) => deletePost(params.id));

// Require all permissions
app.use(requireAllPermissions(['users:read', 'posts:write']))
  .get('/dashboard', () => getDashboard());

// Require specific role
app.use(requireRole('admin'))
  .get('/admin', () => getAdminPanel());

// Require any role
app.use(requireAnyRole(['admin', 'moderator']))
  .get('/moderation', () => getModerationPanel());
```

#### Context Injection

All routes have access to `flashAuth` context:

```typescript
app.get('/protected', ({ flashAuth }) => {
  // Access claims
  const userId = flashAuth.claims?.sub;
  const email = flashAuth.claims?.email;
  
  // Check permissions
  if (flashAuth.hasPermission('admin:*')) {
    // Admin access
  }
  
  // Check roles
  if (flashAuth.hasRole('moderator')) {
    // Moderator access
  }
  
  // Revoke current token
  await flashAuth.revokeToken();
  
  return { userId, email };
});
```

## Advanced Usage

### Role-Based Access Control

```typescript
const auth = new FlashAuth({
  secret: process.env.AUTH_SECRET!,
  rolePermissions: {
    'user': [
      'posts:read',
      'posts:write',
      'profile:read',
      'profile:write',
    ],
    'moderator': [
      'posts:read',
      'posts:write',
      'posts:delete',
      'users:read',
      'comments:delete',
    ],
    'admin': ['*'], // All permissions
  },
});

// Permissions are automatically expanded from roles
const token = auth
  .createToken()
  .subject('user:123')
  .roles(['user', 'moderator'])
  .expiresIn('1h')
  .build();

// Token will have permissions from both user and moderator roles
```

### Custom Claims

```typescript
const token = auth
  .createToken()
  .subject('user:123')
  .claim('email', 'user@example.com')
  .claim('organization', 'org:456')
  .claim('mfaVerified', true)
  .claim('metadata', { theme: 'dark' })
  .expiresIn('1h')
  .build();

const claims = await auth.validateToken(token);
console.log(claims.email);         // 'user@example.com'
console.log(claims.organization);   // 'org:456'
console.log(claims.mfaVerified);    // true
```

### Custom Revocation Store

```typescript
import { RevocationStore } from 'flashauth';

class RedisRevocationStore implements RevocationStore {
  async revoke(jti: string, expiresAt: number): Promise<void> {
    // Store in Redis with TTL
    await redis.setex(`revoked:${jti}`, expiresAt - Date.now() / 1000, '1');
  }
  
  async isRevoked(jti: string): Promise<boolean> {
    return await redis.exists(`revoked:${jti}`) === 1;
  }
  
  async revokeUser(userId: string): Promise<void> {
    await redis.sadd('revoked:users', userId);
  }
  
  async isUserRevoked(userId: string): Promise<boolean> {
    return await redis.sismember('revoked:users', userId) === 1;
  }
  
  async cleanup(): Promise<void> {
    // Redis handles TTL automatically
  }
}

const auth = new FlashAuth({
  secret: process.env.AUTH_SECRET!,
  revocationStore: new RedisRevocationStore(),
});
```

## Security Considerations

### Secret Key Management

```typescript
// ✅ DO: Use environment variables
const auth = new FlashAuth({
  secret: process.env.AUTH_SECRET!, // 32-byte hex string
});

// ✅ DO: Generate secure secrets
const secret = FlashAuth.generateSecretHex();
console.log('Add to .env:', secret);

// ❌ DON'T: Hard-code secrets
const auth = new FlashAuth({
  secret: 'my-secret-key', // INSECURE!
});
```

### Token Expiration

```typescript
// Short-lived access tokens
const accessToken = await auth
  .createToken()
  .subject(userId)
  .expiresIn('15m')
  .build();

// Long-lived refresh tokens (store separately)
const refreshToken = await auth
  .createToken()
  .subject(userId)
  .claim('purpose', 'refresh')
  .expiresIn('30d')
  .build();
// Note: This code must be inside an async function or top-level for-await context.
```

### Permission Validation

```typescript
// Always validate permissions on the server
app.use(requirePermission('posts:delete'))
  .delete('/posts/:id', async ({ params, flashAuth }) => {
    // Additional checks
    const post = await getPost(params.id);
    if (post.authorId !== flashAuth.claims?.sub) {
      // User can only delete their own posts
      throw new Error('Forbidden');
    }
    
    await deletePost(params.id);
    return { success: true };
  });
```

## Performance

FlashAuth is designed for high performance:

- **Token Creation**: Asynchronous, <1ms on modern hardware
- **Token Validation**: Cached tokens return instantly
- **Permission Checks**: O(1) for exact match, O(n) for wildcard
- **Memory**: <5MB for typical deployments with 10k cached tokens

## Testing

```bash
# Run all tests
bun test

# Run specific test file
bun test tests/unit/paseto.test.ts

# Watch mode
bun test --watch
```

## Examples

See the `examples/` directory for complete examples:

- [`basic-app.ts`](examples/basic-app.ts) - Minimal working example
- More examples coming soon!

## License

MIT

## Contributing

Contributions are welcome! Please open an issue or PR.

## Credits

- Uses [@noble/ciphers](https://github.com/paulmillr/noble-ciphers) for XChaCha20-Poly1305
- Implements [PASETO v4 specification](https://github.com/paseto-standard/paseto-spec)
- Built for [Bun](https://bun.sh) and [Elysia.js](https://elysiajs.com)
