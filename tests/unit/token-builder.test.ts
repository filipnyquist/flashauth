/**
 * Tests for TokenBuilder fluent API
 */

import { describe, test, expect } from 'bun:test';
import { FlashAuth } from '../../src/flashauth.js';
import { TokenBuilder } from '../../src/tokens/token-builder.js';

const secret = FlashAuth.generateSecret();

describe('TokenBuilder', () => {
  describe('building tokens with all options', () => {
    test('should build token with subject, issuer, audience', async () => {
      const auth = new FlashAuth({ secret });

      const token = await auth
        .createToken()
        .subject('user:1')
        .issuer('flashauth-tests')
        .audience(['service-a', 'service-b'])
        .expiresIn('1h')
        .build();

      const claims = await auth.validateToken(token);
      expect(claims.sub).toBe('user:1');
      expect(claims.iss).toBe('flashauth-tests');
      expect(claims.aud).toEqual(['service-a', 'service-b']);
    });

    test('should build token with roles and permissions', async () => {
      const auth = new FlashAuth({
        secret,
        rolePermissions: {
          editor: ['posts:read', 'posts:write'],
        },
      });

      const token = await auth
        .createToken()
        .subject('user:2')
        .roles(['editor'])
        .permissions(['analytics:read'])
        .expiresIn('1h')
        .build();

      const claims = await auth.validateToken(token);
      expect(claims.roles).toEqual(['editor']);
      expect(claims.perms).toContain('posts:read');
      expect(claims.perms).toContain('posts:write');
      expect(claims.perms).toContain('analytics:read');
    });

    test('should build token with custom claims', async () => {
      const auth = new FlashAuth({ secret });

      const token = await auth
        .createToken()
        .subject('user:3')
        .claim('email', 'test@example.com')
        .claim('orgId', 'org:42')
        .expiresIn('1h')
        .build();

      const claims = await auth.validateToken(token);
      expect(claims.sub).toBe('user:3');
      expect(claims.email).toBe('test@example.com');
      expect(claims.orgId).toBe('org:42');
    });
  });

  describe('API key tokens', () => {
    test('should build API key token without expiration', async () => {
      const builder = new TokenBuilder(secret);

      const token = await builder
        .subject('svc:key-1')
        .apiKey()
        .build();

      expect(typeof token).toBe('string');
      expect(token.length).toBeGreaterThan(0);
    });
  });

  describe('token type setting', () => {
    test('should set type to access', async () => {
      const auth = new FlashAuth({ secret });

      const token = await auth
        .createToken()
        .subject('user:10')
        .type('access')
        .expiresIn('1h')
        .build();

      const claims = await auth.validateToken(token);
      expect(claims.type).toBe('access');
    });

    test('should set type to refresh', async () => {
      const auth = new FlashAuth({ secret });

      const token = await auth
        .createToken()
        .subject('user:10')
        .type('refresh')
        .expiresIn('7d')
        .build();

      const claims = await auth.validateToken(token);
      expect(claims.type).toBe('refresh');
    });

    test('should set type to api_key', async () => {
      const auth = new FlashAuth({ secret });

      const token = await auth
        .createToken()
        .subject('user:10')
        .type('api_key')
        .build();

      const claims = await auth.validateToken(token);
      expect(claims.type).toBe('api_key');
    });
  });

  describe('duration parsing', () => {
    test('should parse hours (1h)', async () => {
      const auth = new FlashAuth({ secret });
      const now = Math.floor(Date.now() / 1000);

      const token = await auth
        .createToken()
        .subject('user:20')
        .expiresIn('1h')
        .build();

      const claims = await auth.validateToken(token);
      // exp should be roughly now + 3600
      expect(claims.exp).toBeGreaterThanOrEqual(now + 3600 - 5);
      expect(claims.exp).toBeLessThanOrEqual(now + 3600 + 5);
    });

    test('should parse minutes (30m)', async () => {
      const auth = new FlashAuth({ secret });
      const now = Math.floor(Date.now() / 1000);

      const token = await auth
        .createToken()
        .subject('user:20')
        .expiresIn('30m')
        .build();

      const claims = await auth.validateToken(token);
      expect(claims.exp).toBeGreaterThanOrEqual(now + 1800 - 5);
      expect(claims.exp).toBeLessThanOrEqual(now + 1800 + 5);
    });

    test('should parse days (7d)', async () => {
      const auth = new FlashAuth({ secret });
      const now = Math.floor(Date.now() / 1000);

      const token = await auth
        .createToken()
        .subject('user:20')
        .expiresIn('7d')
        .build();

      const claims = await auth.validateToken(token);
      const sevenDays = 7 * 24 * 60 * 60;
      expect(claims.exp).toBeGreaterThanOrEqual(now + sevenDays - 5);
      expect(claims.exp).toBeLessThanOrEqual(now + sevenDays + 5);
    });

    test('should parse weeks (1w)', async () => {
      const auth = new FlashAuth({ secret });
      const now = Math.floor(Date.now() / 1000);

      const token = await auth
        .createToken()
        .subject('user:20')
        .expiresIn('1w')
        .build();

      const claims = await auth.validateToken(token);
      const oneWeek = 7 * 24 * 60 * 60;
      expect(claims.exp).toBeGreaterThanOrEqual(now + oneWeek - 5);
      expect(claims.exp).toBeLessThanOrEqual(now + oneWeek + 5);
    });
  });

  describe('error cases', () => {
    test('should throw when subject is missing', async () => {
      const builder = new TokenBuilder(secret);

      await expect(
        builder.expiresIn('1h').build()
      ).rejects.toThrow('Subject');
    });

    test('should throw when expiration is missing for non-api_key', async () => {
      const builder = new TokenBuilder(secret);

      await expect(
        builder.subject('user:30').build()
      ).rejects.toThrow('Expiration');
    });

    test('should throw on invalid duration format', () => {
      const auth = new FlashAuth({ secret });

      expect(() => {
        auth.createToken().subject('user:30').expiresIn('invalid');
      }).toThrow('Invalid duration');
    });
  });
});
