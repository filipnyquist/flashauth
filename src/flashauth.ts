/**
 * FlashAuth Main Class
 * Ultra-Fast PASETO v4 Local Authentication Framework
 */

import { generateSecret } from './core/cryptography.js';
import { TokenBuilder } from './tokens/token-builder.js';
import { TokenParser } from './tokens/token-parser.js';
import { InMemoryRevocationStore, TokenCache } from './tokens/token-store.js';
import { Claims } from './core/claims.js';
import { TokenExpiredError, TokenRevokedError, ValidationError } from './core/errors.js';
import type { ValidationOptions, StandardClaims } from './core/claims.js';
import type { RevocationStore } from './tokens/token-store.js';
import type { RolePermissions } from './utils/permission-utils.js';

/**
 * FlashAuth configuration
 */
export interface FlashAuthConfig {
  /** Secret key for token encryption/decryption (32 bytes) */
  secret: Uint8Array | string;
  /** Role to permissions mapping */
  rolePermissions?: RolePermissions;
  /** Token revocation store */
  revocationStore?: RevocationStore;
  /** Enable token caching */
  enableCache?: boolean;
  /** Cache configuration */
  cache?: {
    maxSize?: number;
    ttl?: number;
  };
}

/**
 * FlashAuth main class
 */
export class FlashAuth {
  private key: Uint8Array;
  private rolePermissions: RolePermissions;
  private revocationStore: RevocationStore;
  private tokenCache?: TokenCache;
  private parser: TokenParser;

  constructor(config: FlashAuthConfig) {
    // Parse secret key
    if (typeof config.secret === 'string') {
      // If string, assume it's base64 or hex encoded
      if (config.secret.length === 64) {
        // Hex encoded
        this.key = new Uint8Array(
          config.secret.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) ?? []
        );
      } else {
        // Base64 encoded or raw string - convert to 32 bytes
        const encoder = new TextEncoder();
        const bytes = encoder.encode(config.secret);
        if (bytes.length < 32) {
          throw new ValidationError('Secret must be at least 32 bytes');
        }
        this.key = bytes.slice(0, 32);
      }
    } else {
      this.key = config.secret;
    }

    if (this.key.length !== 32) {
      throw new ValidationError('Secret key must be exactly 32 bytes');
    }

    this.rolePermissions = config.rolePermissions ?? {};
    this.revocationStore = config.revocationStore ?? new InMemoryRevocationStore();
    
    if (config.enableCache !== false) {
      this.tokenCache = new TokenCache(config.cache);
    }

    this.parser = new TokenParser(this.key);
  }

  /**
   * Create a new token builder
   */
  createToken(claims?: Partial<StandardClaims>): TokenBuilder {
    const builder = new TokenBuilder(this.key, this.rolePermissions);
    
    if (claims) {
      if (claims.sub) builder.subject(claims.sub);
      if (claims.iss) builder.issuer(claims.iss);
      if (claims.aud) builder.audience(claims.aud);
      if (claims.exp) builder.expiration(claims.exp);
      if (claims.nbf) builder.notBefore(claims.nbf);
      if (claims.jti) builder.tokenId(claims.jti);
      if (claims.roles) builder.roles(claims.roles);
      if (claims.perms) builder.permissions(claims.perms);
      
      // Copy custom claims
      for (const [key, value] of Object.entries(claims)) {
        if (!['sub', 'iss', 'aud', 'exp', 'iat', 'nbf', 'jti', 'roles', 'perms'].includes(key)) {
          builder.claim(key, value);
        }
      }
    }
    
    return builder;
  }

  /**
   * Validate and parse a token
   */
  async validateToken(token: string, options: ValidationOptions = {}): Promise<Claims> {
    // Check cache first for faster parsing
    let claims: Claims;
    const cached = this.tokenCache?.get(token);
    
    if (cached) {
      claims = cached as Claims;
    } else {
      // Parse token
      claims = this.parser.parse(token, options);
      
      // Cache validated token (before revocation check for performance)
      if (this.tokenCache) {
        this.tokenCache.set(token, claims);
      }
    }

    // Always check if token is revoked (even for cached tokens)
    if (claims.jti) {
      const isRevoked = await this.revocationStore.isRevoked(claims.jti);
      if (isRevoked) {
        // Invalidate cache for revoked token
        if (this.tokenCache) {
          this.tokenCache.invalidate(token);
        }
        throw new TokenRevokedError('Token has been revoked');
      }
    }

    // Always check if user is revoked (even for cached tokens)
    const isUserRevoked = await this.revocationStore.isUserRevoked(claims.sub);
    if (isUserRevoked) {
      // Invalidate cache for revoked user token
      if (this.tokenCache) {
        this.tokenCache.invalidate(token);
      }
      throw new TokenRevokedError('All user tokens have been revoked');
    }

    return claims;
  }

  /**
   * Revoke a token by its JTI
   */
  async revokeToken(jti: string, expiresAt: number): Promise<void> {
    await this.revocationStore.revoke(jti, expiresAt);
  }

  /**
   * Revoke all tokens for a user
   */
  async revokeUser(userId: string): Promise<void> {
    await this.revocationStore.revokeUser(userId);
  }

  /**
   * Check if a token is valid (not revoked)
   */
  async isTokenValid(token: string): Promise<boolean> {
    try {
      await this.validateToken(token);
      return true;
    } catch (error) {
      if (error instanceof TokenRevokedError) {
        return false;
      }
      if (error instanceof TokenExpiredError) {
        return false;
      }
      throw error;
    }
  }

  /**
   * Generate a new secret key
   */
  static generateSecret(): Uint8Array {
    return generateSecret();
  }

  /**
   * Generate a secret key as hex string
   */
  static generateSecretHex(): string {
    const secret = generateSecret();
    return Array.from(secret)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Get role permissions mapping
   */
  getRolePermissions(): RolePermissions {
    return this.rolePermissions;
  }

  /**
   * Update role permissions mapping
   */
  setRolePermissions(rolePermissions: RolePermissions): void {
    this.rolePermissions = rolePermissions;
  }
}
