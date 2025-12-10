/**
 * Tests for PASETO v4 Local implementation
 */

import { describe, test, expect } from 'bun:test';
import { createToken, parseToken, base64urlEncode, base64urlDecode } from '../../src/core/paseto.js';
import { generateSecret } from '../../src/core/cryptography.js';
import type { StandardClaims } from '../../src/core/claims.js';

describe('PASETO v4 Local', () => {
  test('should create and parse a token', async () => {
    const key = generateSecret();
    const claims: StandardClaims = {
      sub: 'user:123',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    };

    const token = await createToken(claims, key);
    expect(token).toStartWith('v4.local.');

    const parsed = await parseToken(token, key);
    expect(parsed.claims.sub).toBe(claims.sub);
    expect(parsed.claims.exp).toBe(claims.exp);
    expect(parsed.claims.iat).toBe(claims.iat);
  });

  test('should create token with footer', async () => {
    const key = generateSecret();
    const claims: StandardClaims = {
      sub: 'user:123',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    };
    const footer = 'test-footer';

    const token = await createToken(claims, key, footer);
    expect(token).toStartWith('v4.local.');
    expect(token.split('.').length).toBe(4);

    const parsed = await parseToken(token, key);
    expect(parsed.claims.sub).toBe(claims.sub);
    expect(parsed.footer).toBe(footer);
  });

  test('should fail with wrong key', async () => {
    const key1 = generateSecret();
    const key2 = generateSecret();
    const claims: StandardClaims = {
      sub: 'user:123',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    };

    const token = await createToken(claims, key1);
    
    await expect(parseToken(token, key2)).rejects.toThrow();
  });

  test('should fail with invalid token format', async () => {
    const key = generateSecret();
    
    await expect(parseToken('invalid', key)).rejects.toThrow('Invalid token format');
    await expect(parseToken('v4.public.test', key)).rejects.toThrow('Invalid token format');
  });

  test('should handle custom claims', async () => {
    const key = generateSecret();
    const claims: StandardClaims = {
      sub: 'user:123',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      email: 'user@example.com',
      roles: ['user', 'admin'],
    };

    const token = await createToken(claims, key);
    const parsed = await parseToken(token, key);
    
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
