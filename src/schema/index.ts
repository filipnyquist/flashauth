/**
 * FlashAuth - Drizzle ORM Schema for PostgreSQL
 * @module flashauth/schema
 */

import {
  pgTable,
  uuid,
  varchar,
  text,
  boolean,
  timestamp,
  integer,
  jsonb,
  uniqueIndex,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

// ─── Users ───────────────────────────────────────────────────────────────────

export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  email: varchar('email', { length: 255 }).notNull().unique(),
  passwordHash: text('password_hash'),
  emailVerified: boolean('email_verified').notNull().default(false),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
});

export const usersRelations = relations(users, ({ many }) => ({
  userRoles: many(userRoles),
  userPermissions: many(userPermissions),
  passkeyCredentials: many(passkeyCredentials),
  apiKeys: many(apiKeys),
  totpSecrets: many(totpSecrets),
  createdInviteLinks: many(inviteLinks),
}));

// ─── Roles ───────────────────────────────────────────────────────────────────

export const roles = pgTable('roles', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 255 }).notNull().unique(),
  description: text('description'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

export const rolesRelations = relations(roles, ({ many }) => ({
  userRoles: many(userRoles),
  rolePermissions: many(rolePermissions),
}));

// ─── Permissions ─────────────────────────────────────────────────────────────

export const permissions = pgTable('permissions', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 255 }).notNull().unique(),
  description: text('description'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

export const permissionsRelations = relations(permissions, ({ many }) => ({
  rolePermissions: many(rolePermissions),
  userPermissions: many(userPermissions),
}));

// ─── User Roles (join table) ────────────────────────────────────────────────

export const userRoles = pgTable(
  'user_roles',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id),
    roleId: uuid('role_id')
      .notNull()
      .references(() => roles.id),
    createdAt: timestamp('created_at').notNull().defaultNow(),
  },
  (table) => [uniqueIndex('user_roles_user_role_idx').on(table.userId, table.roleId)],
);

export const userRolesRelations = relations(userRoles, ({ one }) => ({
  user: one(users, { fields: [userRoles.userId], references: [users.id] }),
  role: one(roles, { fields: [userRoles.roleId], references: [roles.id] }),
}));

// ─── Role Permissions (join table) ──────────────────────────────────────────

export const rolePermissions = pgTable(
  'role_permissions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    roleId: uuid('role_id')
      .notNull()
      .references(() => roles.id),
    permissionId: uuid('permission_id')
      .notNull()
      .references(() => permissions.id),
    createdAt: timestamp('created_at').notNull().defaultNow(),
  },
  (table) => [uniqueIndex('role_permissions_role_perm_idx').on(table.roleId, table.permissionId)],
);

export const rolePermissionsRelations = relations(rolePermissions, ({ one }) => ({
  role: one(roles, { fields: [rolePermissions.roleId], references: [roles.id] }),
  permission: one(permissions, {
    fields: [rolePermissions.permissionId],
    references: [permissions.id],
  }),
}));

// ─── User Permissions (direct, join table) ──────────────────────────────────

export const userPermissions = pgTable(
  'user_permissions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id),
    permissionId: uuid('permission_id')
      .notNull()
      .references(() => permissions.id),
    createdAt: timestamp('created_at').notNull().defaultNow(),
  },
  (table) => [uniqueIndex('user_permissions_user_perm_idx').on(table.userId, table.permissionId)],
);

export const userPermissionsRelations = relations(userPermissions, ({ one }) => ({
  user: one(users, { fields: [userPermissions.userId], references: [users.id] }),
  permission: one(permissions, {
    fields: [userPermissions.permissionId],
    references: [permissions.id],
  }),
}));

// ─── Invite Links ───────────────────────────────────────────────────────────

export const inviteLinks = pgTable('invite_links', {
  id: uuid('id').primaryKey().defaultRandom(),
  token: varchar('token', { length: 255 }).notNull().unique(),
  email: varchar('email', { length: 255 }),
  roleId: uuid('role_id').references(() => roles.id),
  createdById: uuid('created_by_id')
    .notNull()
    .references(() => users.id),
  maxUses: integer('max_uses'),
  useCount: integer('use_count').notNull().default(0),
  expiresAt: timestamp('expires_at'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

export const inviteLinksRelations = relations(inviteLinks, ({ one }) => ({
  role: one(roles, { fields: [inviteLinks.roleId], references: [roles.id] }),
  createdBy: one(users, { fields: [inviteLinks.createdById], references: [users.id] }),
}));

// ─── Passkey Credentials ────────────────────────────────────────────────────

export const passkeyCredentials = pgTable('passkey_credentials', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id')
    .notNull()
    .references(() => users.id),
  credentialId: text('credential_id').notNull().unique(),
  publicKey: text('public_key').notNull(),
  counter: integer('counter').notNull(),
  transports: jsonb('transports'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

export const passkeyCredentialsRelations = relations(passkeyCredentials, ({ one }) => ({
  user: one(users, { fields: [passkeyCredentials.userId], references: [users.id] }),
}));

// ─── API Keys ───────────────────────────────────────────────────────────────

export const apiKeys = pgTable('api_keys', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id')
    .notNull()
    .references(() => users.id),
  name: varchar('name', { length: 255 }).notNull(),
  keyHash: text('key_hash').notNull(),
  lastUsedAt: timestamp('last_used_at'),
  expiresAt: timestamp('expires_at'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

export const apiKeysRelations = relations(apiKeys, ({ one }) => ({
  user: one(users, { fields: [apiKeys.userId], references: [users.id] }),
}));

// ─── TOTP Secrets ───────────────────────────────────────────────────────────

export const totpSecrets = pgTable('totp_secrets', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id')
    .notNull()
    .references(() => users.id)
    .unique(),
  secret: text('secret').notNull(),
  backupCodes: jsonb('backup_codes').notNull(),
  verified: boolean('verified').notNull().default(false),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

export const totpSecretsRelations = relations(totpSecrets, ({ one }) => ({
  user: one(users, { fields: [totpSecrets.userId], references: [users.id] }),
}));

// ─── Type Inference Helpers ─────────────────────────────────────────────────

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;

export type Role = typeof roles.$inferSelect;
export type NewRole = typeof roles.$inferInsert;

export type Permission = typeof permissions.$inferSelect;
export type NewPermission = typeof permissions.$inferInsert;

export type UserRole = typeof userRoles.$inferSelect;
export type NewUserRole = typeof userRoles.$inferInsert;

export type RolePermission = typeof rolePermissions.$inferSelect;
export type NewRolePermission = typeof rolePermissions.$inferInsert;

export type UserPermission = typeof userPermissions.$inferSelect;
export type NewUserPermission = typeof userPermissions.$inferInsert;

export type InviteLink = typeof inviteLinks.$inferSelect;
export type NewInviteLink = typeof inviteLinks.$inferInsert;

export type PasskeyCredential = typeof passkeyCredentials.$inferSelect;
export type NewPasskeyCredential = typeof passkeyCredentials.$inferInsert;

export type ApiKey = typeof apiKeys.$inferSelect;
export type NewApiKey = typeof apiKeys.$inferInsert;

export type TotpSecret = typeof totpSecrets.$inferSelect;
export type NewTotpSecret = typeof totpSecrets.$inferInsert;
