/**
 * Permission and role management service using Drizzle ORM
 */

import { eq, and } from 'drizzle-orm';
import {
  roles,
  permissions,
  userRoles,
  rolePermissions,
  userPermissions,
} from '../../../schema/index.js';
import type { Role, Permission } from '../../../schema/index.js';

export class PermissionService {
  private db: any;

  constructor(db: any) {
    this.db = db;
  }

  // ─── Roles ────────────────────────────────────────────────────────────

  async createRole(name: string, description?: string): Promise<Role> {
    const [role] = await this.db.insert(roles).values({ name, description }).returning();
    if (!role) throw new Error('Failed to create role');
    return role;
  }

  async deleteRole(roleId: string): Promise<void> {
    await this.db.delete(roles).where(eq(roles.id, roleId));
  }

  async listRoles(): Promise<Role[]> {
    return await this.db.select().from(roles);
  }

  // ─── Permissions ──────────────────────────────────────────────────────

  async createPermission(name: string, description?: string): Promise<Permission> {
    const [permission] = await this.db.insert(permissions).values({ name, description }).returning();
    if (!permission) throw new Error('Failed to create permission');
    return permission;
  }

  async deletePermission(permissionId: string): Promise<void> {
    await this.db.delete(permissions).where(eq(permissions.id, permissionId));
  }

  async listPermissions(): Promise<Permission[]> {
    return await this.db.select().from(permissions);
  }

  // ─── User Roles ───────────────────────────────────────────────────────

  async assignRoleToUser(userId: string, roleId: string): Promise<void> {
    await this.db.insert(userRoles).values({ userId, roleId });
  }

  async removeRoleFromUser(userId: string, roleId: string): Promise<void> {
    await this.db.delete(userRoles)
      .where(and(eq(userRoles.userId, userId), eq(userRoles.roleId, roleId)));
  }

  async getUserRoles(userId: string): Promise<Role[]> {
    const results = await this.db
      .select({ role: roles })
      .from(userRoles)
      .innerJoin(roles, eq(userRoles.roleId, roles.id))
      .where(eq(userRoles.userId, userId));
    return results.map((r: { role: Role }) => r.role);
  }

  // ─── Role Permissions ─────────────────────────────────────────────────

  async assignPermissionToRole(roleId: string, permissionId: string): Promise<void> {
    await this.db.insert(rolePermissions).values({ roleId, permissionId });
  }

  async removePermissionFromRole(roleId: string, permissionId: string): Promise<void> {
    await this.db.delete(rolePermissions)
      .where(and(eq(rolePermissions.roleId, roleId), eq(rolePermissions.permissionId, permissionId)));
  }

  async getRolePermissions(roleId: string): Promise<Permission[]> {
    const results = await this.db
      .select({ permission: permissions })
      .from(rolePermissions)
      .innerJoin(permissions, eq(rolePermissions.permissionId, permissions.id))
      .where(eq(rolePermissions.roleId, roleId));
    return results.map((r: { permission: Permission }) => r.permission);
  }

  // ─── User Permissions (direct) ────────────────────────────────────────

  async assignPermissionToUser(userId: string, permissionId: string): Promise<void> {
    await this.db.insert(userPermissions).values({ userId, permissionId });
  }

  async removePermissionFromUser(userId: string, permissionId: string): Promise<void> {
    await this.db.delete(userPermissions)
      .where(and(eq(userPermissions.userId, userId), eq(userPermissions.permissionId, permissionId)));
  }

  /**
   * Get all user permissions (direct + from roles)
   */
  async getUserPermissions(userId: string): Promise<Permission[]> {
    // Direct permissions
    const directResults = await this.db
      .select({ permission: permissions })
      .from(userPermissions)
      .innerJoin(permissions, eq(userPermissions.permissionId, permissions.id))
      .where(eq(userPermissions.userId, userId));
    const directPerms: Permission[] = directResults.map((r: { permission: Permission }) => r.permission);

    // Permissions from roles
    const roleResults = await this.db
      .select({ permission: permissions })
      .from(userRoles)
      .innerJoin(rolePermissions, eq(userRoles.roleId, rolePermissions.roleId))
      .innerJoin(permissions, eq(rolePermissions.permissionId, permissions.id))
      .where(eq(userRoles.userId, userId));
    const rolePerms: Permission[] = roleResults.map((r: { permission: Permission }) => r.permission);

    // Merge and deduplicate
    const seen = new Set<string>();
    const allPerms: Permission[] = [];
    for (const perm of [...directPerms, ...rolePerms]) {
      if (!seen.has(perm.id)) {
        seen.add(perm.id);
        allPerms.push(perm);
      }
    }

    return allPerms;
  }
}
