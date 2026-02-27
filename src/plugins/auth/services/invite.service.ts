/**
 * Invite link management service using Drizzle ORM
 */

import { eq } from 'drizzle-orm';
import { inviteLinks } from '../../../schema/index.js';
import type { InviteLink } from '../../../schema/index.js';
import { generateSecureToken } from '../utils/tokens.js';

export class InviteService {
  private db: any;

  constructor(db: any) {
    this.db = db;
  }

  /**
   * Create an invite link with a secure token
   */
  async createInvite(
    createdById: string,
    options?: { email?: string; roleId?: string; maxUses?: number; expiresAt?: Date }
  ): Promise<InviteLink> {
    const token = generateSecureToken(32);

    const [invite] = await this.db.insert(inviteLinks).values({
      token,
      email: options?.email,
      roleId: options?.roleId,
      createdById,
      maxUses: options?.maxUses,
      expiresAt: options?.expiresAt,
    }).returning();

    if (!invite) {
      throw new Error('Failed to create invite');
    }

    return invite;
  }

  /**
   * Get invite by token
   */
  async getInvite(token: string): Promise<InviteLink | null> {
    const results = await this.db.select().from(inviteLinks)
      .where(eq(inviteLinks.token, token))
      .limit(1);
    return results[0] ?? null;
  }

  /**
   * Increment use count and validate (check maxUses, expiry)
   */
  async useInvite(token: string): Promise<InviteLink> {
    const invite = await this.getInvite(token);
    if (!invite) {
      throw new Error('Invalid invite token');
    }

    if (invite.expiresAt && new Date() > invite.expiresAt) {
      throw new Error('Invite has expired');
    }

    if (invite.maxUses && invite.useCount >= invite.maxUses) {
      throw new Error('Invite has reached maximum uses');
    }

    const [updated] = await this.db.update(inviteLinks)
      .set({ useCount: invite.useCount + 1 })
      .where(eq(inviteLinks.id, invite.id))
      .returning();

    if (!updated) {
      throw new Error('Failed to update invite');
    }

    return updated;
  }

  /**
   * Delete an invite
   */
  async deleteInvite(id: string): Promise<void> {
    await this.db.delete(inviteLinks).where(eq(inviteLinks.id, id));
  }

  /**
   * List invites (optionally by creator)
   */
  async listInvites(createdById?: string): Promise<InviteLink[]> {
    if (createdById) {
      return await this.db.select().from(inviteLinks)
        .where(eq(inviteLinks.createdById, createdById));
    }
    return await this.db.select().from(inviteLinks);
  }
}
