/**
 * TOTP (2FA) service using otplib
 */

import { authenticator } from 'otplib';
import type { DatabaseConnection } from '../utils/db.js';
import type { TOTPSecret } from '../models/totp.model.js';
import type { AuthPluginConfig } from '../config.js';
import { generateBackupCodes, hashBackupCode, verifyBackupCode } from '../utils/tokens.js';

export class TOTPService {
  private db: DatabaseConnection;
  private config: AuthPluginConfig;

  constructor(db: DatabaseConnection, config: AuthPluginConfig) {
    this.db = db;
    this.config = config;
  }

  /**
   * Generate a new TOTP secret for a user
   */
  async generateSecret(userId: string): Promise<{ secret: string; qrCode: string; backupCodes: string[] }> {
    // Generate secret
    const secret = authenticator.generateSecret();

    // Generate backup codes
    const backupCodes = generateBackupCodes(8);

    // Hash backup codes for storage
    const hashedBackupCodes = await Promise.all(
      backupCodes.map(code => hashBackupCode(code))
    );

    // Check if user already has a TOTP secret
    const existing = await this.getTOTPSecret(userId);
    
    if (existing) {
      // Update existing secret
      const sql = `
        UPDATE totp_secrets
        SET secret = $1, backup_codes = $2, enabled = $3
        WHERE user_id = $4
      `;
      await this.db.execute(sql, [secret, hashedBackupCodes, false, userId]);
    } else {
      // Create new secret
      const sql = `
        INSERT INTO totp_secrets (user_id, secret, backup_codes, enabled)
        VALUES ($1, $2, $3, $4)
      `;
      await this.db.execute(sql, [userId, secret, hashedBackupCodes, false]);
    }

    // Generate QR code URL
    const user = await this.db.queryOne<{ email: string }>(
      'SELECT email FROM users WHERE id = $1',
      [userId]
    );
    const appName = this.config.webauthn.rpName || 'FlashAuth';
    const userEmail = user?.email;
    if (!userEmail) {
      throw new Error('User email not found');
    }
    const qrCode = authenticator.keyuri(userEmail, appName, secret);

    return {
      secret,
      qrCode,
      backupCodes, // Return unhashed codes to show to user
    };
  }

  /**
   * Verify a TOTP token
   */
  async verifyToken(userId: string, token: string): Promise<boolean> {
    const totpSecret = await this.getTOTPSecret(userId);
    if (!totpSecret || !totpSecret.enabled) {
      return false;
    }

    return authenticator.verify({
      token,
      secret: totpSecret.secret,
    });
  }

  /**
   * Verify and enable TOTP for a user
   */
  async enableTOTP(userId: string, token: string): Promise<boolean> {
    const totpSecret = await this.getTOTPSecret(userId);
    if (!totpSecret) {
      return false;
    }

    // Verify the token
    const valid = authenticator.verify({
      token,
      secret: totpSecret.secret,
    });

    if (!valid) {
      return false;
    }

    // Enable TOTP
    const sql = 'UPDATE totp_secrets SET enabled = $1 WHERE user_id = $2';
    await this.db.execute(sql, [true, userId]);

    return true;
  }

  /**
   * Disable TOTP for a user
   */
  async disableTOTP(userId: string): Promise<void> {
    const sql = 'DELETE FROM totp_secrets WHERE user_id = $1';
    await this.db.execute(sql, [userId]);
  }

  /**
   * Check if user has TOTP enabled
   */
  async isTOTPEnabled(userId: string): Promise<boolean> {
    const totpSecret = await this.getTOTPSecret(userId);
    return totpSecret?.enabled || false;
  }

  /**
   * Get TOTP secret for user
   */
  async getTOTPSecret(userId: string): Promise<TOTPSecret | null> {
    const sql = 'SELECT * FROM totp_secrets WHERE user_id = $1';
    return await this.db.queryOne<TOTPSecret>(sql, [userId]);
  }

  /**
   * Verify a backup code
   */
  async verifyBackupCode(userId: string, code: string): Promise<boolean> {
    const totpSecret = await this.getTOTPSecret(userId);
    if (!totpSecret || !totpSecret.enabled) {
      return false;
    }

    // Check each backup code
    for (let i = 0; i < totpSecret.backup_codes.length; i++) {
      const hash = totpSecret.backup_codes[i];
      if (!hash) continue;
      const valid = await verifyBackupCode(code, hash);
      
      if (valid) {
        // Remove used backup code
        const newBackupCodes = totpSecret.backup_codes.filter((_, index) => index !== i);
        const sql = 'UPDATE totp_secrets SET backup_codes = $1 WHERE user_id = $2';
        await this.db.execute(sql, [newBackupCodes, userId]);
        return true;
      }
    }

    return false;
  }

  /**
   * Get remaining backup codes count
   */
  async getRemainingBackupCodesCount(userId: string): Promise<number> {
    const totpSecret = await this.getTOTPSecret(userId);
    return totpSecret?.backup_codes.length || 0;
  }
}
