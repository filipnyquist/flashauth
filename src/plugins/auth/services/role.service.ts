/**
 * Role management service using Drizzle ORM
 */

import { eq, and } from 'drizzle-orm';
import {
  roles,
  userRoles,
} from '../../../schema/index.js';
import type { Role } from '../../../schema/index.js';

export class RoleService {
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
}
