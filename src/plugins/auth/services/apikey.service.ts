/**
 * API key management service using Drizzle ORM
 */

import { eq, and } from 'drizzle-orm';
import { apiKeys } from '../../../schema/index.js';
import type { ApiKey } from '../../../schema/index.js';

export class ApiKeyService {
  private db: any;

  constructor(db: any) {
    this.db = db;
  }

  /**
   * Generate a new API key (JWT with type 'api_key'), store hash in DB, return the raw key
   */
  async createApiKey(userId: string, name: string, flashAuth: any): Promise<{ apiKey: ApiKey; rawKey: string }> {
    const rawKey = await flashAuth
      .createToken()
      .subject(userId)
      .apiKey()
      .claim('name', name)
      .build();

    const keyHash = await this.hashKey(rawKey);

    const [apiKey] = await this.db.insert(apiKeys).values({
      userId,
      name,
      keyHash,
    }).returning();

    if (!apiKey) {
      throw new Error('Failed to create API key');
    }

    return { apiKey, rawKey };
  }

  /**
   * List user's API keys (without the actual key)
   */
  async listApiKeys(userId: string): Promise<ApiKey[]> {
    return await this.db.select().from(apiKeys).where(eq(apiKeys.userId, userId));
  }

  /**
   * Delete an API key
   */
  async deleteApiKey(keyId: string, userId: string): Promise<void> {
    await this.db.delete(apiKeys)
      .where(and(eq(apiKeys.id, keyId), eq(apiKeys.userId, userId)));
  }

  /**
   * Update last used timestamp
   */
  async updateLastUsed(keyId: string): Promise<void> {
    await this.db.update(apiKeys)
      .set({ lastUsedAt: new Date() })
      .where(eq(apiKeys.id, keyId));
  }

  private async hashKey(key: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(key);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
}
