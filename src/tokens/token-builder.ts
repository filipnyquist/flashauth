/**
 * FlashAuth Token Builder
 * Fluent API for creating JWT tokens
 */

import { createToken } from '../core/jwt.js';
import { ValidationError } from '../core/errors.js';
import { mergePermissions } from '../utils/permission-utils.js';
import type { StandardClaims, TokenType } from '../core/claims.js';
import type { RolePermissions } from '../utils/permission-utils.js';

/**
 * Token builder with fluent API
 */
export class TokenBuilder {
  private claims: Partial<StandardClaims> = {};
  private secret: string | Uint8Array;
  private rolePermissions: RolePermissions;

  constructor(secret: string | Uint8Array, rolePermissions: RolePermissions = {}) {
    this.secret = secret;
    this.rolePermissions = rolePermissions;
    
    // Set default iat
    this.claims.iat = Math.floor(Date.now() / 1000);
  }

  /**
   * Set subject (user ID)
   */
  subject(sub: string): this {
    this.claims.sub = sub;
    return this;
  }

  /**
   * Set issuer
   */
  issuer(iss: string): this {
    this.claims.iss = iss;
    return this;
  }

  /**
   * Set audience
   */
  audience(aud: string | string[]): this {
    this.claims.aud = Array.isArray(aud) ? aud : [aud];
    return this;
  }

  /**
   * Set expiration time (Unix timestamp in seconds)
   */
  expiration(exp: number): this {
    this.claims.exp = exp;
    return this;
  }

  /**
   * Set expiration time from duration string
   * Examples: "1h", "30m", "7d", "1w"
   */
  expiresIn(duration: string): this {
    const exp = this.parseDuration(duration);
    this.claims.exp = Math.floor(Date.now() / 1000) + exp;
    return this;
  }

  /**
   * Set not before time
   */
  notBefore(nbf: number): this {
    this.claims.nbf = nbf;
    return this;
  }

  /**
   * Set token ID for revocation
   */
  tokenId(jti: string): this {
    this.claims.jti = jti;
    return this;
  }

  /**
   * Set token type
   */
  type(type: TokenType): this {
    this.claims.type = type;
    return this;
  }

  /**
   * Convenience method: set type to 'api_key' (no expiry required)
   */
  apiKey(): this {
    this.claims.type = 'api_key';
    return this;
  }

  /**
   * Set roles
   */
  roles(roles: string[]): this {
    this.claims.roles = roles;
    return this;
  }

  /**
   * Set explicit permissions
   */
  permissions(perms: string[]): this {
    this.claims.perms = perms;
    return this;
  }

  /**
   * Set a custom claim
   */
  claim<T = unknown>(key: string, value: T): this {
    this.claims[key] = value;
    return this;
  }

  /**
   * Build the token (async)
   */
  async build(): Promise<string> {
    // Validate required claims
    if (!this.claims.sub) {
      throw new ValidationError('Subject (sub) is required');
    }
    // Expiration is required unless type is 'api_key'
    if (this.claims.type !== 'api_key' && !this.claims.exp) {
      throw new ValidationError('Expiration (exp) is required');
    }

    // Merge role permissions with explicit permissions
    if (this.claims.roles && this.claims.roles.length > 0) {
      const explicitPerms = this.claims.perms ?? [];
      this.claims.perms = mergePermissions(
        this.claims.roles,
        explicitPerms,
        this.rolePermissions
      );
    }

    // Create JWT token
    return await createToken(this.claims as StandardClaims, this.secret);
  }

  /**
   * Parse duration string to seconds
   */
  private parseDuration(duration: string): number {
    const match = duration.match(/^(\d+)([smhdw])$/);
    if (!match) {
      throw new ValidationError(`Invalid duration format: ${duration}`);
    }

    const [, valueStr, unit] = match;
    const value = parseInt(valueStr ?? '0', 10);

    switch (unit) {
      case 's':
        return value;
      case 'm':
        return value * 60;
      case 'h':
        return value * 60 * 60;
      case 'd':
        return value * 60 * 60 * 24;
      case 'w':
        return value * 60 * 60 * 24 * 7;
      default:
        throw new ValidationError(`Invalid duration unit: ${unit}`);
    }
  }
}
