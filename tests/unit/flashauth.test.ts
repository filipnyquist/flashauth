/**
 * Tests for FlashAuth main class
 */

import { describe, test, expect } from 'bun:test';
import { FlashAuth } from '../../src/flashauth.js';

describe('FlashAuth', () => {
  test('should initialize with secret', () => {
    const secret = FlashAuth.generateSecret();
    const auth = new FlashAuth({ secret });
    
    expect(auth).toBeDefined();
  });

  test('should initialize with hex string secret', () => {
    const secret = FlashAuth.generateSecretHex();
    const auth = new FlashAuth({ secret });
    
    expect(auth).toBeDefined();
  });

  test('should create and validate token', async () => {
    const auth = new FlashAuth({
      secret: FlashAuth.generateSecret(),
    });

    const token = await auth
      .createToken()
      .subject('user:123')
      .claim('email', 'user@example.com')
      .expiresIn('1h')
      .build();

    const claims = await auth.validateToken(token);
    expect(claims.sub).toBe('user:123');
    expect(claims.email).toBe('user@example.com');
  });

  test('should expand roles to permissions', async () => {
    const auth = new FlashAuth({
      secret: FlashAuth.generateSecret(),
      rolePermissions: {
        'user': ['posts:read', 'posts:write'],
        'admin': ['*'],
      },
    });

    const token = await auth
      .createToken()
      .subject('user:123')
      .roles(['user'])
      .expiresIn('1h')
      .build();

    const claims = await auth.validateToken(token);
    expect(claims.perms).toContain('posts:read');
    expect(claims.perms).toContain('posts:write');
  });

  test('should merge role and explicit permissions', async () => {
    const auth = new FlashAuth({
      secret: FlashAuth.generateSecret(),
      rolePermissions: {
        'user': ['posts:read'],
      },
    });

    const token = await auth
      .createToken()
      .subject('user:123')
      .roles(['user'])
      .permissions(['users:read'])
      .expiresIn('1h')
      .build();

    const claims = await auth.validateToken(token);
    expect(claims.perms).toContain('posts:read');
    expect(claims.perms).toContain('users:read');
  });

  test('should validate token with custom options', async () => {
    const auth = new FlashAuth({
      secret: FlashAuth.generateSecret(),
    });

    const token = await auth
      .createToken()
      .subject('user:123')
      .issuer('test-issuer')
      .audience(['test-service'])
      .expiresIn('1h')
      .build();

    const claims = await auth.validateToken(token, {
      requiredIssuer: 'test-issuer',
      requiredAudience: 'test-service',
    });

    expect(claims.sub).toBe('user:123');
  });

  test('should fail validation with wrong issuer', async () => {
    const auth = new FlashAuth({
      secret: FlashAuth.generateSecret(),
    });

    const token = await auth
      .createToken()
      .subject('user:123')
      .issuer('wrong-issuer')
      .expiresIn('1h')
      .build();

    await expect(
      auth.validateToken(token, { requiredIssuer: 'correct-issuer' })
    ).rejects.toThrow('issuer');
  });

  test('should revoke token', async () => {
    const auth = new FlashAuth({
      secret: FlashAuth.generateSecret(),
    });

    const jti = 'token-id-123';
    const exp = Math.floor(Date.now() / 1000) + 3600;

    const token = await auth
      .createToken()
      .subject('user:123')
      .tokenId(jti)
      .expiration(exp)
      .build();

    // Should validate before revocation
    const claims1 = await auth.validateToken(token);
    expect(claims1.sub).toBe('user:123');

    // Revoke token
    await auth.revokeToken(jti, exp);

    // Should fail after revocation
    await expect(auth.validateToken(token)).rejects.toThrow('revoked');
  });

  test('should revoke all user tokens', async () => {
    const auth = new FlashAuth({
      secret: FlashAuth.generateSecret(),
    });

    const token = await auth
      .createToken()
      .subject('user:123')
      .expiresIn('1h')
      .build();

    // Should validate before revocation
    await auth.validateToken(token);

    // Revoke all user tokens
    await auth.revokeUser('user:123');

    // Should fail after revocation
    await expect(auth.validateToken(token)).rejects.toThrow('revoked');
  });

  test('should generate secret', () => {
    const secret = FlashAuth.generateSecret();
    expect(secret).toBeInstanceOf(Uint8Array);
    expect(secret.length).toBe(32);
  });

  test('should generate secret as hex', () => {
    const secret = FlashAuth.generateSecretHex();
    expect(typeof secret).toBe('string');
    expect(secret.length).toBe(64);
    expect(/^[0-9a-f]+$/.test(secret)).toBe(true);
  });
});
