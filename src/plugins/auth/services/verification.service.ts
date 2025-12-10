/**
 * Email verification service
 */

import type { DatabaseConnection } from '../utils/db.js';
import type { EmailVerificationToken } from '../models/verification.model.js';
import type { AuthPluginConfig } from '../config.js';
import { generateVerificationToken } from '../utils/tokens.js';

export class VerificationService {
  private db: DatabaseConnection;
  private config: AuthPluginConfig;

  constructor(db: DatabaseConnection, config: AuthPluginConfig) {
    this.db = db;
    this.config = config;
  }

  /**
   * Create a verification token for a user
   */
  async createVerificationToken(userId: string): Promise<string> {
    const token = generateVerificationToken();
    const expirationSeconds = this.config.tokenExpiration?.emailVerification || 24 * 60 * 60;
    const expiresAt = new Date(Date.now() + expirationSeconds * 1000);

    const sql = `
      INSERT INTO email_verification_tokens (user_id, token, expires_at)
      VALUES ($1, $2, $3)
      RETURNING *
    `;

    await this.db.queryOne<EmailVerificationToken>(sql, [userId, token, expiresAt]);
    return token;
  }

  /**
   * Verify an email verification token
   */
  async verifyToken(token: string): Promise<{ valid: boolean; userId?: string; error?: string }> {
    const sql = `
      SELECT * FROM email_verification_tokens
      WHERE token = $1
      ORDER BY created_at DESC
      LIMIT 1
    `;

    const tokenRecord = await this.db.queryOne<EmailVerificationToken>(sql, [token]);

    if (!tokenRecord) {
      return { valid: false, error: 'Invalid verification token' };
    }

    // Check if token has expired
    if (new Date() > new Date(tokenRecord.expires_at)) {
      return { valid: false, error: 'Verification token has expired' };
    }

    return { valid: true, userId: tokenRecord.user_id };
  }

  /**
   * Delete verification token after use
   */
  async deleteToken(token: string): Promise<void> {
    const sql = 'DELETE FROM email_verification_tokens WHERE token = $1';
    await this.db.execute(sql, [token]);
  }

  /**
   * Delete all verification tokens for a user
   */
  async deleteUserTokens(userId: string): Promise<void> {
    const sql = 'DELETE FROM email_verification_tokens WHERE user_id = $1';
    await this.db.execute(sql, [userId]);
  }

  /**
   * Clean up expired tokens
   */
  async cleanupExpiredTokens(): Promise<void> {
    const sql = 'DELETE FROM email_verification_tokens WHERE expires_at < $1';
    await this.db.execute(sql, [new Date()]);
  }
}
