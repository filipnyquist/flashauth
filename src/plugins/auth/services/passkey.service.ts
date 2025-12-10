/**
 * Passkey/WebAuthn service using @simplewebauthn/server
 */

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type GenerateRegistrationOptionsOpts,
  type GenerateAuthenticationOptionsOpts,
  type VerifyRegistrationResponseOpts,
  type VerifyAuthenticationResponseOpts,
  type VerifiedRegistrationResponse,
  type VerifiedAuthenticationResponse,
} from '@simplewebauthn/server';
import type { DatabaseConnection } from '../utils/db.js';
import type { PasskeyCredential } from '../models/passkey.model.js';
import type { AuthPluginConfig } from '../config.js';

export class PasskeyService {
  private db: DatabaseConnection;
  private config: AuthPluginConfig;

  constructor(db: DatabaseConnection, config: AuthPluginConfig) {
    this.db = db;
    this.config = config;
  }

  /**
   * Generate registration options for a new passkey
   */
  async generateRegistrationOptions(userId: string, userName: string): Promise<any> {
    // Get user's existing credentials to exclude them
    const existingCredentials = await this.getUserCredentials(userId);

    const opts: GenerateRegistrationOptionsOpts = {
      rpName: this.config.webauthn.rpName,
      rpID: this.config.webauthn.rpID,
      userID: new TextEncoder().encode(userId),
      userName: userName,
      attestationType: 'none',
      excludeCredentials: existingCredentials.map(cred => ({
        id: cred.credential_id,
        type: 'public-key' as const,
        transports: cred.transports as any[],
      })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    };

    return await generateRegistrationOptions(opts);
  }

  /**
   * Verify registration response and store credential
   */
  async verifyRegistration(
    userId: string,
    response: any,
    expectedChallenge: string
  ): Promise<{ verified: boolean; error?: string }> {
    try {
      const opts: VerifyRegistrationResponseOpts = {
        response,
        expectedChallenge,
        expectedOrigin: Array.isArray(this.config.webauthn.origin) 
          ? this.config.webauthn.origin 
          : [this.config.webauthn.origin],
        expectedRPID: this.config.webauthn.rpID,
      };

      const verification: VerifiedRegistrationResponse = await verifyRegistrationResponse(opts);

      if (!verification.verified || !verification.registrationInfo) {
        return { verified: false, error: 'Registration verification failed' };
      }

      const { credential } = verification.registrationInfo;

      // Store credential in database
      const sql = `
        INSERT INTO passkey_credentials (user_id, credential_id, public_key, counter, transports)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
      `;

      await this.db.queryOne<PasskeyCredential>(sql, [
        userId,
        Buffer.from(credential.id).toString('base64'),
        Buffer.from(credential.publicKey).toString('base64'),
        credential.counter,
        response.response.transports || [],
      ]);

      return { verified: true };
    } catch (error) {
      return { verified: false, error: (error as Error).message };
    }
  }

  /**
   * Generate authentication options for passkey login
   */
  async generateAuthenticationOptions(userId?: string): Promise<any> {
    let allowCredentials: any[] | undefined;

    if (userId) {
      // Get user's credentials
      const credentials = await this.getUserCredentials(userId);
      allowCredentials = credentials.map(cred => ({
        id: cred.credential_id,
        type: 'public-key' as const,
        transports: cred.transports as any[],
      }));
    }

    const opts: GenerateAuthenticationOptionsOpts = {
      rpID: this.config.webauthn.rpID,
      allowCredentials,
      userVerification: 'preferred',
    };

    return await generateAuthenticationOptions(opts);
  }

  /**
   * Verify authentication response
   */
  async verifyAuthentication(
    response: any,
    expectedChallenge: string
  ): Promise<{ verified: boolean; userId?: string; error?: string }> {
    try {
      // Get credential from database
      const credentialId = Buffer.from(response.id, 'base64url').toString('base64');
      const credential = await this.getCredentialById(credentialId);

      if (!credential) {
        return { verified: false, error: 'Credential not found' };
      }

      const opts: VerifyAuthenticationResponseOpts = {
        response,
        expectedChallenge,
        expectedOrigin: Array.isArray(this.config.webauthn.origin)
          ? this.config.webauthn.origin
          : [this.config.webauthn.origin],
        expectedRPID: this.config.webauthn.rpID,
        credential: {
          id: credential.credential_id,
          publicKey: Buffer.from(credential.public_key, 'base64'),
          counter: credential.counter,
        },
      };

      const verification: VerifiedAuthenticationResponse = await verifyAuthenticationResponse(opts);

      if (!verification.verified) {
        return { verified: false, error: 'Authentication verification failed' };
      }

      // Update counter and last used timestamp
      await this.updateCredentialCounter(credential.id, verification.authenticationInfo.newCounter);

      return { verified: true, userId: credential.user_id };
    } catch (error) {
      return { verified: false, error: (error as Error).message };
    }
  }

  /**
   * Get all credentials for a user
   */
  async getUserCredentials(userId: string): Promise<PasskeyCredential[]> {
    const sql = 'SELECT * FROM passkey_credentials WHERE user_id = $1';
    return await this.db.query<PasskeyCredential>(sql, [userId]);
  }

  /**
   * Get credential by credential ID
   */
  async getCredentialById(credentialId: string): Promise<PasskeyCredential | null> {
    const sql = 'SELECT * FROM passkey_credentials WHERE credential_id = $1';
    return await this.db.queryOne<PasskeyCredential>(sql, [credentialId]);
  }

  /**
   * Delete a credential
   */
  async deleteCredential(credentialId: string): Promise<void> {
    const sql = 'DELETE FROM passkey_credentials WHERE id = $1';
    await this.db.execute(sql, [credentialId]);
  }

  /**
   * Update credential counter
   */
  private async updateCredentialCounter(credentialId: string, newCounter: number): Promise<void> {
    const sql = `
      UPDATE passkey_credentials
      SET counter = $1, last_used_at = $2
      WHERE id = $3
    `;
    await this.db.execute(sql, [newCounter, new Date(), credentialId]);
  }
}
