/**
 * FlashAuth Token Parser
 * JWT token validation and parsing
 */

import { parseToken } from '../core/jwt.js';
import { Claims, validateClaims } from '../core/claims.js';
import type { ValidationOptions, StandardClaims } from '../core/claims.js';

/**
 * Token parser
 */
export class TokenParser {
  private secret: string | Uint8Array;

  constructor(secret: string | Uint8Array) {
    this.secret = secret;
  }

  /**
   * Parse and validate a token (async)
   */
  async parse(token: string, options: ValidationOptions = {}): Promise<Claims> {
    // Parse JWT token
    const { claims: rawClaims } = await parseToken(token, this.secret);
    
    // Create Claims instance
    const claims = new Claims(rawClaims);
    
    // Validate claims
    validateClaims(claims, options);
    
    return claims;
  }

  /**
   * Parse token without validation (async)
   * Useful for inspecting token contents
   */
  async parseUnsafe(token: string): Promise<StandardClaims> {
    const { claims } = await parseToken(token, this.secret);
    return claims;
  }
}
