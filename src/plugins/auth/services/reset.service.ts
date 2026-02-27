/**
 * Password reset service using JWT tokens
 */

import type { AuthPluginConfig } from '../config.js';

export class PasswordResetService {
  private config: AuthPluginConfig;

  constructor(config: AuthPluginConfig) {
    this.config = config;
  }

  /**
   * Create a password reset token for a user (JWT-based)
   */
  async createResetToken(userId: string): Promise<string> {
    const expirationSeconds = this.config.tokenExpiration?.passwordReset || 60 * 60;
    return await this.config.flashAuth
      .createToken()
      .subject(userId)
      .claim('purpose', 'password_reset')
      .expiresIn(`${expirationSeconds}s`)
      .build();
  }

  /**
   * Verify a password reset token
   */
  async verifyToken(token: string): Promise<{ valid: boolean; userId?: string; error?: string }> {
    try {
      const claims = await this.config.flashAuth.validateToken(token);
      if (claims['purpose'] !== 'password_reset') {
        return { valid: false, error: 'Invalid token type' };
      }
      return { valid: true, userId: claims.sub };
    } catch {
      return { valid: false, error: 'Invalid or expired reset token' };
    }
  }

  /**
   * Delete reset token after use (no-op for JWT)
   */
  async deleteToken(_token: string): Promise<void> {
    // No-op: JWT tokens are stateless
  }

  /**
   * Delete all reset tokens for a user (no-op for JWT)
   */
  async deleteUserTokens(_userId: string): Promise<void> {
    // No-op: JWT tokens are stateless
  }
}
