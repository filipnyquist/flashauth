/**
 * TOTP (2FA) service using otplib and Drizzle ORM
 */

import { authenticator } from 'otplib';
import { eq } from 'drizzle-orm';
import { users, totpSecrets } from '../../../schema/index.js';
import type { TotpSecret } from '../../../schema/index.js';
import type { AuthPluginConfig } from '../config.js';
import { generateBackupCodes, hashBackupCode, verifyBackupCode } from '../utils/tokens.js';

export class TOTPService {
  private db: any;
  private config: AuthPluginConfig;

  constructor(db: any, config: AuthPluginConfig) {
    this.db = db;
    this.config = config;
  }

  /**
   * Generate a new TOTP secret for a user
   */
  async generateSecret(userId: string): Promise<{ secret: string; qrCode: string; backupCodes: string[] }> {
    const secret = authenticator.generateSecret();
    const backupCodes = generateBackupCodes(8);

    const hashedBackupCodes = await Promise.all(
      backupCodes.map(code => hashBackupCode(code))
    );

    const existing = await this.getTOTPSecret(userId);

    if (existing) {
      await this.db.update(totpSecrets)
        .set({ secret, backupCodes: hashedBackupCodes, verified: false })
        .where(eq(totpSecrets.userId, userId));
    } else {
      await this.db.insert(totpSecrets).values({
        userId,
        secret,
        backupCodes: hashedBackupCodes,
        verified: false,
      });
    }

    const userResults = await this.db
      .select({ email: users.email })
      .from(users)
      .where(eq(users.id, userId))
      .limit(1);
    const user = userResults[0] as { email: string } | undefined;
    const appName = this.config.webauthn?.rpName || 'FlashAuth';
    if (!user?.email) {
      throw new Error('User email not found');
    }
    const qrCode = authenticator.keyuri(user.email, appName, secret);

    return { secret, qrCode, backupCodes };
  }

  /**
   * Verify a TOTP token
   */
  async verifyToken(userId: string, token: string): Promise<boolean> {
    const totpSecret = await this.getTOTPSecret(userId);
    if (!totpSecret || !totpSecret.verified) {
      return false;
    }

    return authenticator.verify({ token, secret: totpSecret.secret });
  }

  /**
   * Verify and enable TOTP for a user
   */
  async enableTOTP(userId: string, token: string): Promise<boolean> {
    const totpSecret = await this.getTOTPSecret(userId);
    if (!totpSecret) {
      return false;
    }

    const valid = authenticator.verify({ token, secret: totpSecret.secret });
    if (!valid) {
      return false;
    }

    await this.db.update(totpSecrets)
      .set({ verified: true })
      .where(eq(totpSecrets.userId, userId));

    return true;
  }

  /**
   * Disable TOTP for a user
   */
  async disableTOTP(userId: string): Promise<void> {
    await this.db.delete(totpSecrets).where(eq(totpSecrets.userId, userId));
  }

  /**
   * Check if user has TOTP enabled
   */
  async isTOTPEnabled(userId: string): Promise<boolean> {
    const totpSecret = await this.getTOTPSecret(userId);
    return totpSecret?.verified || false;
  }

  /**
   * Get TOTP secret for user
   */
  async getTOTPSecret(userId: string): Promise<TotpSecret | null> {
    const results = await this.db.select().from(totpSecrets)
      .where(eq(totpSecrets.userId, userId))
      .limit(1);
    return results[0] ?? null;
  }

  /**
   * Verify a backup code
   */
  async verifyBackupCode(userId: string, code: string): Promise<boolean> {
    const totpSecret = await this.getTOTPSecret(userId);
    if (!totpSecret || !totpSecret.verified) {
      return false;
    }

    const codes = totpSecret.backupCodes as string[];
    for (let i = 0; i < codes.length; i++) {
      const hash = codes[i];
      if (!hash) continue;
      const valid = await verifyBackupCode(code, hash);

      if (valid) {
        const newBackupCodes = codes.filter((_, index) => index !== i);
        await this.db.update(totpSecrets)
          .set({ backupCodes: newBackupCodes })
          .where(eq(totpSecrets.userId, userId));
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
    return (totpSecret?.backupCodes as string[] | undefined)?.length || 0;
  }
}
