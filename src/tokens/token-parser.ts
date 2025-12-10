/**
 * FlashAuth Token Parser
 * Token validation and parsing
 */

import { parseToken } from '../core/paseto.js';
import { Claims, validateClaims } from '../core/claims.js';
import type { ValidationOptions, StandardClaims } from '../core/claims.js';

/**
 * Token parser
 */
export class TokenParser {
  private key: Uint8Array;

  constructor(key: Uint8Array) {
    this.key = key;
  }

  /**
   * Parse and validate a token
   */
  parse(token: string, options: ValidationOptions = {}): Claims {
    // Parse token
    const { claims: rawClaims } = parseToken(token, this.key);
    
    // Create Claims instance
    const claims = new Claims(rawClaims);
    
    // Validate claims
    validateClaims(claims, options);
    
    return claims;
  }

  /**
   * Parse token without validation
   * Useful for inspecting token contents
   */
  parseUnsafe(token: string): StandardClaims {
    const { claims } = parseToken(token, this.key);
    return claims;
  }
}
