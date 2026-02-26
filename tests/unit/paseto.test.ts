/**
 * Tests for JWT implementation
 */

import { describe, test, expect } from 'bun:test';
import { createToken, parseToken, base64urlEncode, base64urlDecode, generateSecret } from '../../src/core/jwt.js';
import type { StandardClaims } from '../../src/core/claims.js';

describe('JWT', () => {
  test('should create and parse a token', async () => {
    const secret = generateSecret();
    const claims: StandardClaims = {
      sub: 'user:123',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    };

    const token = await createToken(claims, secret);
    // JWT tokens have 3 dot-separated parts
    expect(token.split('.').length).toBe(3);

    const parsed = await parseToken(token, secret);
    expect(parsed.claims.sub).toBe(claims.sub);
    expect(parsed.claims.exp).toBe(claims.exp);
    expect(parsed.claims.iat).toBe(claims.iat);
  });

  test('should create token without expiration (API key)', async () => {
    const secret = generateSecret();
    const claims: StandardClaims = {
      sub: 'user:123',
      iat: Math.floor(Date.now() / 1000),
      type: 'api_key',
    };

    const token = await createToken(claims, secret);
    const parsed = await parseToken(token, secret);
    expect(parsed.claims.sub).toBe(claims.sub);
    expect(parsed.claims.exp).toBeUndefined();
    expect(parsed.claims.type).toBe('api_key');
  });

  test('should fail with wrong key', async () => {
    const secret1 = generateSecret();
    const secret2 = generateSecret();
    const claims: StandardClaims = {
      sub: 'user:123',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    };

    const token = await createToken(claims, secret1);
    
    await expect(parseToken(token, secret2)).rejects.toThrow();
  });

  test('should fail with invalid token format', async () => {
    const secret = generateSecret();
    
    await expect(parseToken('invalid', secret)).rejects.toThrow();
    await expect(parseToken('not.a.valid.jwt', secret)).rejects.toThrow();
  });

  test('should handle custom claims', async () => {
    const secret = generateSecret();
    const claims: StandardClaims = {
      sub: 'user:123',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      email: 'user@example.com',
      roles: ['user', 'admin'],
    };

    const token = await createToken(claims, secret);
    const parsed = await parseToken(token, secret);
    
    expect(parsed.claims.email).toBe(claims.email);
    expect(parsed.claims.roles).toEqual(claims.roles);
  });
});

describe('Base64url encoding', () => {
  test('should encode and decode', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5]);
    const encoded = base64urlEncode(data);
    const decoded = base64urlDecode(encoded);
    
    expect(decoded).toEqual(data);
  });

  test('should not contain +, /, or =', () => {
    const data = new Uint8Array(Array(100).fill(0).map((_, i) => i % 256));
    const encoded = base64urlEncode(data);
    
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
    expect(encoded).not.toContain('=');
  });
});
