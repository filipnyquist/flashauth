/**
 * Tests for API Key token functionality
 */

import { describe, test, expect } from 'bun:test';
import { FlashAuth } from '../../src/flashauth.js';
import { TokenBuilder } from '../../src/tokens/token-builder.js';

const secret = FlashAuth.generateSecret();

describe('API Key Tokens', () => {
  test('should create a token with .apiKey() method (no expiration)', async () => {
    const auth = new FlashAuth({ secret });

    const token = await auth
      .createToken()
      .subject('service:api-consumer')
      .apiKey()
      .build();

    expect(typeof token).toBe('string');
    expect(token.length).toBeGreaterThan(0);
  });

  test('should verify API key tokens without expiration', async () => {
    const auth = new FlashAuth({ secret });

    const token = await auth
      .createToken()
      .subject('service:api-consumer')
      .apiKey()
      .build();

    const claims = await auth.validateToken(token);
    expect(claims.sub).toBe('service:api-consumer');
    expect(claims.exp).toBeUndefined();
  });

  test('should have type api_key on API key tokens', async () => {
    const auth = new FlashAuth({ secret });

    const token = await auth
      .createToken()
      .subject('service:worker')
      .apiKey()
      .build();

    const claims = await auth.validateToken(token);
    expect(claims.type).toBe('api_key');
  });

  test('should set token type via type() method', async () => {
    const auth = new FlashAuth({ secret });

    const token = await auth
      .createToken()
      .subject('user:456')
      .type('api_key')
      .build();

    const claims = await auth.validateToken(token);
    expect(claims.type).toBe('api_key');
  });

  test('should create access tokens with expiration', async () => {
    const auth = new FlashAuth({ secret });

    const token = await auth
      .createToken()
      .subject('user:789')
      .type('access')
      .expiresIn('1h')
      .build();

    const claims = await auth.validateToken(token);
    expect(claims.type).toBe('access');
    expect(claims.exp).toBeDefined();
  });

  test('should fail to create access token without expiration', async () => {
    const builder = new TokenBuilder(secret);

    await expect(
      builder.subject('user:100').type('access').build()
    ).rejects.toThrow('Expiration');
  });

  test('should allow API key tokens to skip expiration', async () => {
    const builder = new TokenBuilder(secret);

    const token = await builder
      .subject('user:200')
      .apiKey()
      .build();

    expect(typeof token).toBe('string');
  });
});
