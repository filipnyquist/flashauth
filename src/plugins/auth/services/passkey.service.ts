/**
 * Passkey/WebAuthn service using @simplewebauthn/server and Drizzle ORM
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
import { eq } from 'drizzle-orm';
import { passkeyCredentials } from '../../../schema/index.js';
import type { PasskeyCredential } from '../../../schema/index.js';
import type { AuthPluginConfig } from '../config.js';

export class PasskeyService {
  private db: any;
  private config: AuthPluginConfig;

  constructor(db: any, config: AuthPluginConfig) {
    this.db = db;
    this.config = config;
  }

  /**
   * Generate registration options for a new passkey
   */
  async generateRegistrationOptions(userId: string, userName: string): Promise<any> {
    if (!this.config.passkeysEnabled) {
      throw new Error('Passkey authentication is not enabled');
    }

    if (!this.config.webauthn) {
      throw new Error('WebAuthn configuration is required when passkeys are enabled');
    }

    const existingCredentials = await this.getUserCredentials(userId);
    const webauthn = this.config.webauthn;

    const opts: GenerateRegistrationOptionsOpts = {
      rpName: webauthn.rpName,
      rpID: webauthn.rpID,
      userID: new TextEncoder().encode(userId),
      userName,
      attestationType: 'none',
      excludeCredentials: existingCredentials.map(cred => ({
        id: cred.credentialId,
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
    if (!this.config.passkeysEnabled) {
      throw new Error('Passkey authentication is not enabled');
    }

    if (!this.config.webauthn) {
      throw new Error('WebAuthn configuration is required when passkeys are enabled');
    }

    try {
      const webauthn = this.config.webauthn;
      const opts: VerifyRegistrationResponseOpts = {
        response,
        expectedChallenge,
        expectedOrigin: Array.isArray(webauthn.origin)
          ? webauthn.origin
          : [webauthn.origin],
        expectedRPID: webauthn.rpID,
      };

      const verification: VerifiedRegistrationResponse = await verifyRegistrationResponse(opts);

      if (!verification.verified || !verification.registrationInfo) {
        return { verified: false, error: 'Registration verification failed' };
      }

      const { credential } = verification.registrationInfo;

      await this.db.insert(passkeyCredentials).values({
        userId,
        credentialId: Buffer.from(credential.id).toString('base64'),
        publicKey: Buffer.from(credential.publicKey).toString('base64'),
        counter: credential.counter,
        transports: response.response.transports || [],
      });

      return { verified: true };
    } catch (error) {
      return { verified: false, error: (error as Error).message };
    }
  }

  /**
   * Generate authentication options for passkey login
   */
  async generateAuthenticationOptions(userId?: string): Promise<any> {
    if (!this.config.passkeysEnabled) {
      throw new Error('Passkey authentication is not enabled');
    }

    if (!this.config.webauthn) {
      throw new Error('WebAuthn configuration is required when passkeys are enabled');
    }

    let allowCredentials: any[] | undefined;

    if (userId) {
      const credentials = await this.getUserCredentials(userId);
      allowCredentials = credentials.map(cred => ({
        id: cred.credentialId,
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
    if (!this.config.passkeysEnabled) {
      throw new Error('Passkey authentication is not enabled');
    }

    if (!this.config.webauthn) {
      throw new Error('WebAuthn configuration is required when passkeys are enabled');
    }

    try {
      const credentialId = Buffer.from(response.id, 'base64url').toString('base64');
      const credential = await this.getCredentialById(credentialId);

      if (!credential) {
        return { verified: false, error: 'Credential not found' };
      }

      const webauthn = this.config.webauthn;
      const opts: VerifyAuthenticationResponseOpts = {
        response,
        expectedChallenge,
        expectedOrigin: Array.isArray(webauthn.origin)
          ? webauthn.origin
          : [webauthn.origin],
        expectedRPID: webauthn.rpID,
        credential: {
          id: credential.credentialId,
          publicKey: Buffer.from(credential.publicKey, 'base64'),
          counter: credential.counter,
        },
      };

      const verification: VerifiedAuthenticationResponse = await verifyAuthenticationResponse(opts);

      if (!verification.verified) {
        return { verified: false, error: 'Authentication verification failed' };
      }

      await this.updateCredentialCounter(credential.id, verification.authenticationInfo.newCounter);

      return { verified: true, userId: credential.userId };
    } catch (error) {
      return { verified: false, error: (error as Error).message };
    }
  }

  /**
   * Get all credentials for a user
   */
  async getUserCredentials(userId: string): Promise<PasskeyCredential[]> {
    return await this.db.select().from(passkeyCredentials)
      .where(eq(passkeyCredentials.userId, userId));
  }

  /**
   * Get credential by credential ID
   */
  async getCredentialById(credentialId: string): Promise<PasskeyCredential | null> {
    const results = await this.db.select().from(passkeyCredentials)
      .where(eq(passkeyCredentials.credentialId, credentialId))
      .limit(1);
    return results[0] ?? null;
  }

  /**
   * Delete a credential
   */
  async deleteCredential(credentialId: string): Promise<void> {
    await this.db.delete(passkeyCredentials)
      .where(eq(passkeyCredentials.id, credentialId));
  }

  /**
   * Update credential counter
   */
  private async updateCredentialCounter(id: string, newCounter: number): Promise<void> {
    await this.db.update(passkeyCredentials)
      .set({ counter: newCounter })
      .where(eq(passkeyCredentials.id, id));
  }
}
