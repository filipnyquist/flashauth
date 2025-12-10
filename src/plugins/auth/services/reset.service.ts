/**
 * Password reset service
 */

import type { DatabaseConnection } from '../utils/db.js';
import type { PasswordResetToken } from '../models/reset.model.js';
import type { AuthPluginConfig } from '../config.js';
import { generatePasswordResetToken } from '../utils/tokens.js';

export class PasswordResetService {
  private db: DatabaseConnection;
  private config: AuthPluginConfig;

  constructor(db: DatabaseConnection, config: AuthPluginConfig) {
    this.db = db;
    this.config = config;
  }

  /**
   * Create a password reset token for a user
   */
  async createResetToken(userId: string): Promise<string> {
    const token = generatePasswordResetToken();
    const expirationSeconds = this.config.tokenExpiration?.passwordReset || 60 * 60;
    const expiresAt = new Date(Date.now() + expirationSeconds * 1000);

    const sql = `
      INSERT INTO password_reset_tokens (user_id, token, expires_at)
      VALUES ($1, $2, $3)
      RETURNING *
    `;

    await this.db.queryOne<PasswordResetToken>(sql, [userId, token, expiresAt]);
    return token;
  }

  /**
   * Verify a password reset token
   */
  async verifyToken(token: string): Promise<{ valid: boolean; userId?: string; error?: string }> {
    const sql = `
      SELECT * FROM password_reset_tokens
      WHERE token = $1
      ORDER BY created_at DESC
      LIMIT 1
    `;

    const tokenRecord = await this.db.queryOne<PasswordResetToken>(sql, [token]);

    if (!tokenRecord) {
      return { valid: false, error: 'Invalid reset token' };
    }

    // Check if token has expired
    if (new Date() > new Date(tokenRecord.expires_at)) {
      return { valid: false, error: 'Reset token has expired' };
    }

    return { valid: true, userId: tokenRecord.user_id };
  }

  /**
   * Delete reset token after use
   */
  async deleteToken(token: string): Promise<void> {
    const sql = 'DELETE FROM password_reset_tokens WHERE token = $1';
    await this.db.execute(sql, [token]);
  }

  /**
   * Delete all reset tokens for a user
   */
  async deleteUserTokens(userId: string): Promise<void> {
    const sql = 'DELETE FROM password_reset_tokens WHERE user_id = $1';
    await this.db.execute(sql, [userId]);
  }

  /**
   * Clean up expired tokens
   */
  async cleanupExpiredTokens(): Promise<void> {
    const sql = 'DELETE FROM password_reset_tokens WHERE expires_at < $1';
    await this.db.execute(sql, [new Date()]);
  }
}
