/**
 * Email verification service using JWT tokens
 */

import type { AuthPluginConfig } from '../config.js';

export class VerificationService {
  private config: AuthPluginConfig;

  constructor(config: AuthPluginConfig) {
    this.config = config;
  }

  /**
   * Create a verification token for a user (JWT-based)
   */
  async createVerificationToken(userId: string): Promise<string> {
    const expirationSeconds = this.config.tokenExpiration?.emailVerification || 24 * 60 * 60;
    return await this.config.flashAuth
      .createToken()
      .subject(userId)
      .claim('purpose', 'email_verification')
      .expiresIn(`${expirationSeconds}s`)
      .build();
  }

  /**
   * Verify an email verification token
   */
  async verifyToken(token: string): Promise<{ valid: boolean; userId?: string; error?: string }> {
    try {
      const claims = await this.config.flashAuth.validateToken(token);
      if (claims['purpose'] !== 'email_verification') {
        return { valid: false, error: 'Invalid token type' };
      }
      return { valid: true, userId: claims.sub };
    } catch {
      return { valid: false, error: 'Invalid or expired verification token' };
    }
  }

  /**
   * Delete verification token after use (no-op for JWT)
   */
  async deleteToken(_token: string): Promise<void> {
    // No-op: JWT tokens are stateless
  }

  /**
   * Delete all verification tokens for a user (no-op for JWT)
   */
  async deleteUserTokens(_userId: string): Promise<void> {
    // No-op: JWT tokens are stateless
  }
}
