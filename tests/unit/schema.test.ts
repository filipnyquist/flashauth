/**
 * Tests for schema generation
 */

import { describe, test, expect } from 'bun:test';
import { getSchemaSQL } from '../../src/schema/generate.js';
import * as schema from '../../src/schema/index.js';

describe('Schema SQL Generation', () => {
  test('should return a non-empty SQL string', () => {
    const sql = getSchemaSQL();
    expect(typeof sql).toBe('string');
    expect(sql.length).toBeGreaterThan(0);
  });

  const expectedTables = [
    'users',
    'roles',
    'user_roles',
    'invite_links',
    'passkey_credentials',
    'api_keys',
    'totp_secrets',
  ];

  test('should contain all expected table names', () => {
    const sql = getSchemaSQL();

    for (const table of expectedTables) {
      expect(sql).toContain(`CREATE TABLE IF NOT EXISTS "${table}"`);
    }
  });

  test('should contain valid SQL CREATE TABLE statements', () => {
    const sql = getSchemaSQL();
    const createCount = (sql.match(/CREATE TABLE IF NOT EXISTS/g) || []).length;
    expect(createCount).toBe(expectedTables.length);
  });

  test('should contain unique index definitions', () => {
    const sql = getSchemaSQL();
    expect(sql).toContain('CREATE UNIQUE INDEX');
    expect(sql).toContain('user_roles_user_role_idx');
  });
});

describe('Schema Exports', () => {
  test('should export all table objects', () => {
    expect(schema.users).toBeDefined();
    expect(schema.roles).toBeDefined();
    expect(schema.userRoles).toBeDefined();
    expect(schema.inviteLinks).toBeDefined();
    expect(schema.passkeyCredentials).toBeDefined();
    expect(schema.apiKeys).toBeDefined();
    expect(schema.totpSecrets).toBeDefined();
  });

  test('should export relation objects', () => {
    expect(schema.usersRelations).toBeDefined();
    expect(schema.rolesRelations).toBeDefined();
    expect(schema.userRolesRelations).toBeDefined();
    expect(schema.inviteLinksRelations).toBeDefined();
    expect(schema.passkeyCredentialsRelations).toBeDefined();
    expect(schema.apiKeysRelations).toBeDefined();
    expect(schema.totpSecretsRelations).toBeDefined();
  });
});
