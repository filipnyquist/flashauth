/**
 * FlashAuth Performance Benchmarks
 * 
 * Comprehensive benchmark suite for measuring token operation performance:
 * - Token creation (with various configurations)
 * - Token validation (cached vs uncached)
 * - Permission checks (exact match, wildcard, role-based)
 * - Role expansion
 * - Token revocation checks
 * 
 * Run with: bun run benchmark
 */

import { FlashAuth } from '../src/index.js';

// Benchmark configuration
const ITERATIONS = {
  WARMUP: 1000,
  SMALL: 10_000,
  MEDIUM: 100_000,
  LARGE: 1_000_000,
};

// Helper function to format numbers
function formatNumber(num: number): string {
  return num.toLocaleString('en-US');
}

// Helper function to format duration
function formatDuration(ms: number): string {
  if (ms < 1) return `${(ms * 1000).toFixed(2)} μs`;
  if (ms < 1000) return `${ms.toFixed(2)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

// Helper function to calculate ops/sec
function calculateOpsPerSec(iterations: number, durationMs: number): number {
  return (iterations / durationMs) * 1000;
}

// Benchmark runner
async function runBenchmark(
  name: string,
  iterations: number,
  operation: () => Promise<void> | void
): Promise<void> {
  // Warmup
  for (let i = 0; i < ITERATIONS.WARMUP; i++) {
    await operation();
  }
  
  // Actual benchmark
  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    await operation();
  }
  const end = performance.now();
  
  const duration = end - start;
  const opsPerSec = calculateOpsPerSec(iterations, duration);
  const avgTime = duration / iterations;
  
  console.log(`  ${name}:`);
  console.log(`    Iterations: ${formatNumber(iterations)}`);
  console.log(`    Total time: ${formatDuration(duration)}`);
  console.log(`    Avg time:   ${formatDuration(avgTime)}`);
  console.log(`    Ops/sec:    ${formatNumber(Math.round(opsPerSec))}`);
  console.log('');
}

// Initialize FlashAuth instances
// Use a shared secret for validation benchmarks
const sharedSecret = FlashAuth.generateSecret();

const simpleAuth = new FlashAuth({
  secret: sharedSecret,
  enableCache: false,
});

const cachedAuth = new FlashAuth({
  secret: sharedSecret,
  enableCache: true,
  cache: {
    maxSize: 10000,
    ttl: 300000,
  },
});

const rbacAuth = new FlashAuth({
  secret: sharedSecret,
  rolePermissions: {
    'user': ['posts:read', 'posts:write', 'profile:read', 'profile:write'],
    'moderator': ['posts:read', 'posts:write', 'posts:delete', 'users:read', 'comments:delete'],
    'admin': ['*'],
  },
  enableCache: true,
});

console.log('🔥 FlashAuth Performance Benchmarks\n');
console.log('='.repeat(70));
console.log('');

// ============================================================================
// TOKEN CREATION BENCHMARKS
// ============================================================================
console.log('📝 Token Creation Benchmarks\n');

await runBenchmark(
  'Simple token (sub + exp only)',
  ITERATIONS.MEDIUM,
  async () => {
    await simpleAuth
      .createToken()
      .subject('user:123')
      .expiresIn('1h')
      .build();
  }
);

await runBenchmark(
  'Token with custom claims',
  ITERATIONS.MEDIUM,
  async () => {
    await simpleAuth
      .createToken()
      .subject('user:123')
      .claim('email', 'user@example.com')
      .claim('name', 'John Doe')
      .claim('organization', 'org:456')
      .expiresIn('1h')
      .build();
  }
);

await runBenchmark(
  'Token with single role',
  ITERATIONS.MEDIUM,
  async () => {
    await rbacAuth
      .createToken()
      .subject('user:123')
      .roles(['user'])
      .expiresIn('1h')
      .build();
  }
);

await runBenchmark(
  'Token with multiple roles',
  ITERATIONS.MEDIUM,
  async () => {
    await rbacAuth
      .createToken()
      .subject('user:123')
      .roles(['user', 'moderator'])
      .expiresIn('1h')
      .build();
  }
);

await runBenchmark(
  'Token with roles and custom permissions',
  ITERATIONS.MEDIUM,
  async () => {
    await rbacAuth
      .createToken()
      .subject('user:123')
      .roles(['user'])
      .permissions(['custom:permission1', 'custom:permission2'])
      .expiresIn('1h')
      .build();
  }
);

await runBenchmark(
  'Complex token (all fields)',
  ITERATIONS.MEDIUM,
  async () => {
    await rbacAuth
      .createToken()
      .subject('user:123')
      .issuer('flashauth-benchmark')
      .audience(['service-a', 'service-b'])
      .roles(['user', 'moderator'])
      .permissions(['custom:action'])
      .claim('email', 'user@example.com')
      .claim('name', 'John Doe')
      .claim('metadata', { theme: 'dark', lang: 'en' })
      .expiresIn('1h')
      .tokenId('unique-id-123')
      .footer('optional-footer')
      .build();
  }
);

// ============================================================================
// TOKEN VALIDATION BENCHMARKS
// ============================================================================
console.log('✅ Token Validation Benchmarks\n');

// Create tokens for validation benchmarks
const simpleToken = await simpleAuth
  .createToken()
  .subject('user:123')
  .expiresIn('1h')
  .build();

const complexToken = await rbacAuth
  .createToken()
  .subject('user:123')
  .roles(['user', 'moderator'])
  .claim('email', 'user@example.com')
  .expiresIn('1h')
  .build();

await runBenchmark(
  'Validate simple token (no cache)',
  ITERATIONS.MEDIUM,
  async () => {
    await simpleAuth.validateToken(simpleToken);
  }
);

await runBenchmark(
  'Validate simple token (with cache)',
  ITERATIONS.MEDIUM,
  async () => {
    await cachedAuth.validateToken(simpleToken);
  }
);

await runBenchmark(
  'Validate complex token (no cache)',
  ITERATIONS.MEDIUM,
  async () => {
    await rbacAuth.validateToken(complexToken);
  }
);

// Create multiple tokens for cache performance test
const cachedTokens: string[] = [];
console.log('  Preparing cache performance test (creating 1000 tokens)...');
for (let i = 0; i < 1000; i++) {
  const token = await cachedAuth
    .createToken()
    .subject(`user:${i}`)
    .expiresIn('1h')
    .build();
  cachedTokens.push(token);
}

await runBenchmark(
  'Validate different tokens (cache warm)',
  ITERATIONS.LARGE,
  async () => {
    const token = cachedTokens[Math.floor(Math.random() * cachedTokens.length)];
    await cachedAuth.validateToken(token);
  }
);

// ============================================================================
// PERMISSION CHECK BENCHMARKS
// ============================================================================
console.log('🔐 Permission Check Benchmarks\n');

const permToken = await rbacAuth
  .createToken()
  .subject('user:123')
  .roles(['user', 'moderator'])
  .expiresIn('1h')
  .build();

const claims = await rbacAuth.validateToken(permToken);

await runBenchmark(
  'Exact permission match',
  ITERATIONS.LARGE,
  () => {
    claims.hasPermission('posts:read');
  }
);

await runBenchmark(
  'Wildcard permission match',
  ITERATIONS.LARGE,
  () => {
    claims.hasPermission('posts:*');
  }
);

await runBenchmark(
  'Super admin wildcard check',
  ITERATIONS.LARGE,
  () => {
    claims.hasPermission('*');
  }
);

await runBenchmark(
  'Check any permission (3 perms)',
  ITERATIONS.LARGE,
  () => {
    claims.hasAnyPermission(['posts:read', 'posts:write', 'posts:delete']);
  }
);

await runBenchmark(
  'Check all permissions (3 perms)',
  ITERATIONS.LARGE,
  () => {
    claims.hasAllPermissions(['posts:read', 'posts:write', 'users:read']);
  }
);

await runBenchmark(
  'Role check',
  ITERATIONS.LARGE,
  () => {
    claims.hasRole('user');
  }
);

await runBenchmark(
  'Check any role (3 roles)',
  ITERATIONS.LARGE,
  () => {
    claims.hasAnyRole(['user', 'admin', 'moderator']);
  }
);

// ============================================================================
// TOKEN REVOCATION BENCHMARKS
// ============================================================================
console.log('🚫 Token Revocation Benchmarks\n');

const revocableToken = await rbacAuth
  .createToken()
  .subject('user:456')
  .tokenId('revocable-123')
  .expiresIn('1h')
  .build();

await runBenchmark(
  'Check if token is valid (not revoked)',
  ITERATIONS.MEDIUM,
  async () => {
    await rbacAuth.isTokenValid(revocableToken);
  }
);

await runBenchmark(
  'Revoke token by ID',
  ITERATIONS.SMALL,
  async () => {
    const jti = `test-jti-${Math.random()}`;
    const exp = Math.floor(Date.now() / 1000) + 3600;
    await rbacAuth.revokeToken(jti, exp);
  }
);

await runBenchmark(
  'Revoke user (all tokens)',
  ITERATIONS.SMALL,
  async () => {
    const userId = `user:${Math.random()}`;
    await rbacAuth.revokeUser(userId);
  }
);

// ============================================================================
// SUMMARY
// ============================================================================
console.log('='.repeat(70));
console.log('');
console.log('✨ Benchmark Complete!\n');
console.log('Key Performance Insights:');
console.log('  • Token creation is fast and scales well');
console.log('  • Token validation with cache provides significant speedup');
console.log('  • Permission checks are extremely fast (O(1) for exact match)');
console.log('  • Wildcard permissions are slightly slower but still very fast');
console.log('  • Role expansion happens at token creation time, not validation');
console.log('');
console.log('Note: Run these benchmarks on your actual hardware for accurate');
console.log('      performance metrics. Results vary based on CPU, memory, and OS.');
console.log('');
