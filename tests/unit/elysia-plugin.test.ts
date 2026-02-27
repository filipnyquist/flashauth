/**
 * Tests for Elysia plugin configuration
 */

import { describe, test, expect } from 'bun:test';
import type { FlashAuthPluginConfig } from '../../src/plugins/elysia-plugin.js';

describe('FlashAuthPluginConfig', () => {
  test('should default tokenLocation to bearer', () => {
    const config: FlashAuthPluginConfig = {};
    const { tokenLocation = 'bearer' } = config;

    expect(tokenLocation).toBe('bearer');
  });

  test('should accept bearer as tokenLocation', () => {
    const config: FlashAuthPluginConfig = { tokenLocation: 'bearer' };
    expect(config.tokenLocation).toBe('bearer');
  });

  test('should accept cookie as tokenLocation', () => {
    const config: FlashAuthPluginConfig = { tokenLocation: 'cookie' };
    expect(config.tokenLocation).toBe('cookie');
  });

  test('should default cookieName to auth_token', () => {
    const config: FlashAuthPluginConfig = {};
    const { cookieName = 'auth_token' } = config;

    expect(cookieName).toBe('auth_token');
  });

  test('should accept custom cookieName', () => {
    const config: FlashAuthPluginConfig = { cookieName: 'session' };
    expect(config.cookieName).toBe('session');
  });

  test('should accept cookie security options', () => {
    const config: FlashAuthPluginConfig = {
      tokenLocation: 'cookie',
      cookieSecure: true,
      cookieHttpOnly: true,
      cookieSameSite: 'strict',
    };

    expect(config.cookieSecure).toBe(true);
    expect(config.cookieHttpOnly).toBe(true);
    expect(config.cookieSameSite).toBe('strict');
  });
});
