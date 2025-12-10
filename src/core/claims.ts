/**
 * FlashAuth Claims
 * PASETO standard claims and permission helpers
 */

import { ValidationError } from './errors.js';

/**
 * Standard PASETO claims
 */
export interface StandardClaims {
  /** Issuer */
  iss?: string;
  /** Subject (user ID) - required */
  sub: string;
  /** Audience (services that can use this) */
  aud?: string[];
  /** Expiration (Unix timestamp in seconds) - required */
  exp: number;
  /** Issued at (Unix timestamp in seconds) */
  iat: number;
  /** Not before */
  nbf?: number;
  /** Unique token ID for revocation */
  jti?: string;
  /** User roles */
  roles?: string[];
  /** Explicit permissions (dot-notation) */
  perms?: string[];
  /** Custom claims */
  [key: string]: unknown;
}

/**
 * Claims with permission helper methods
 */
export class Claims implements StandardClaims {
  iss?: string;
  sub: string;
  aud?: string[];
  exp: number;
  iat: number;
  nbf?: number;
  jti?: string;
  roles?: string[];
  perms?: string[];
  [key: string]: unknown;

  constructor(claims: StandardClaims) {
    this.sub = claims.sub;
    this.exp = claims.exp;
    this.iat = claims.iat;
    
    if (claims.iss) this.iss = claims.iss;
    if (claims.aud) this.aud = claims.aud;
    if (claims.nbf) this.nbf = claims.nbf;
    if (claims.jti) this.jti = claims.jti;
    if (claims.roles) this.roles = claims.roles;
    if (claims.perms) this.perms = claims.perms;

    // Copy custom claims
    for (const [key, value] of Object.entries(claims)) {
      if (!['iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'jti', 'roles', 'perms'].includes(key)) {
        this[key] = value;
      }
    }
  }

  /**
   * Check if claims have a specific permission
   */
  hasPermission(permission: string): boolean {
    if (!this.perms || this.perms.length === 0) {
      return false;
    }

    // Check for exact match or wildcard match
    for (const perm of this.perms) {
      if (perm === '*') return true; // Super admin
      if (perm === permission) return true; // Exact match
      
      // Wildcard matching: "users:*" matches "users:read", "users:write", etc.
      if (perm.endsWith(':*')) {
        const prefix = perm.slice(0, -2);
        if (permission.startsWith(prefix + ':')) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Check if claims have any of the specified permissions
   */
  hasAnyPermission(permissions: string[]): boolean {
    return permissions.some(perm => this.hasPermission(perm));
  }

  /**
   * Check if claims have all of the specified permissions
   */
  hasAllPermissions(permissions: string[]): boolean {
    return permissions.every(perm => this.hasPermission(perm));
  }

  /**
   * Check if claims have a specific role
   */
  hasRole(role: string): boolean {
    return this.roles?.includes(role) ?? false;
  }

  /**
   * Check if claims have any of the specified roles
   */
  hasAnyRole(roles: string[]): boolean {
    if (!this.roles || this.roles.length === 0) {
      return false;
    }
    return roles.some(role => this.roles?.includes(role));
  }

  /**
   * Validate required claims
   */
  static validate(claims: Partial<StandardClaims>): void {
    if (!claims.sub) {
      throw new ValidationError('Subject (sub) is required');
    }
    if (!claims.exp) {
      throw new ValidationError('Expiration (exp) is required');
    }
    if (typeof claims.exp !== 'number') {
      throw new ValidationError('Expiration (exp) must be a number');
    }
    if (!claims.iat) {
      throw new ValidationError('Issued at (iat) is required');
    }
    if (typeof claims.iat !== 'number') {
      throw new ValidationError('Issued at (iat) must be a number');
    }
  }

  /**
   * Check if token is expired
   */
  isExpired(clockSkew: number = 0): boolean {
    const now = Math.floor(Date.now() / 1000);
    return this.exp < (now - clockSkew);
  }

  /**
   * Check if token is not yet valid
   */
  isNotYetValid(clockSkew: number = 0): boolean {
    if (!this.nbf) return false;
    const now = Math.floor(Date.now() / 1000);
    return this.nbf > (now + clockSkew);
  }
}

/**
 * Validation options
 */
export interface ValidationOptions {
  /** Clock skew tolerance in seconds (default: 0) */
  clockSkew?: number;
  /** Validate expiration (default: true) */
  validateExpiry?: boolean;
  /** Minimum issued at timestamp */
  minIssuedAt?: number;
  /** Required audience */
  requiredAudience?: string;
  /** Required issuer */
  requiredIssuer?: string;
}

/**
 * Validate claims against options
 */
export function validateClaims(claims: Claims, options: ValidationOptions = {}): void {
  const {
    clockSkew = 0,
    validateExpiry = true,
    minIssuedAt,
    requiredAudience,
    requiredIssuer,
  } = options;

  // Validate expiration
  if (validateExpiry && claims.isExpired(clockSkew)) {
    throw new ValidationError('Token has expired');
  }

  // Validate not before
  if (claims.isNotYetValid(clockSkew)) {
    throw new ValidationError('Token is not yet valid');
  }

  // Validate minimum issued at
  if (minIssuedAt && claims.iat < minIssuedAt) {
    throw new ValidationError('Token issued too long ago');
  }

  // Validate audience
  if (requiredAudience && (!claims.aud || !claims.aud.includes(requiredAudience))) {
    throw new ValidationError(`Token audience does not include ${requiredAudience}`);
  }

  // Validate issuer
  if (requiredIssuer && claims.iss !== requiredIssuer) {
    throw new ValidationError(`Token issuer does not match ${requiredIssuer}`);
  }
}
