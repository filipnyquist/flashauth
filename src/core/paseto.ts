/**
 * FlashAuth PASETO v4 Local Implementation
 * Token creation and validation
 */

import { encryptLocal, decryptLocal } from './cryptography.js';
import { TokenError, TokenInvalidError } from './errors.js';
import type { StandardClaims } from './claims.js';

const PASETO_V4_LOCAL_HEADER = 'v4.local.';

/**
 * Encode data to base64url (RFC 4648)
 */
export function base64urlEncode(data: Uint8Array): string {
  const base64 = Buffer.from(data).toString('base64');
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Decode base64url to Uint8Array
 */
export function base64urlDecode(str: string): Uint8Array {
  // Add padding if needed
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

/**
 * Create a PASETO v4 local token (async)
 * 
 * @param claims - Token claims (must include sub and exp)
 * @param key - 32-byte encryption key
 * @param footer - Optional footer (authenticated but not encrypted)
 * @returns PASETO v4.local token string
 */
export async function createToken(
  claims: StandardClaims,
  key: Uint8Array,
  footer?: string
): Promise<string> {
  // Serialize claims to JSON
  const message = new TextEncoder().encode(JSON.stringify(claims));
  
  // Encode footer if provided
  const footerBytes = footer ? new TextEncoder().encode(footer) : new Uint8Array(0);
  
  // Encrypt message (async)
  const encrypted = await encryptLocal(message, key, footerBytes);
  
  // Encode encrypted data
  const payload = base64urlEncode(encrypted);
  
  // Build token: v4.local.{payload} or v4.local.{payload}.{footer}
  let token = PASETO_V4_LOCAL_HEADER + payload;
  
  if (footer) {
    token += '.' + base64urlEncode(footerBytes);
  }
  
  return token;
}

/**
 * Parse and validate a PASETO v4 local token (async)
 * 
 * @param token - PASETO v4.local token string
 * @param key - 32-byte decryption key
 * @returns Parsed claims and footer (if present)
 * @throws TokenInvalidError if token format is invalid or decryption fails
 */
export async function parseToken(
  token: string,
  key: Uint8Array
): Promise<{ claims: StandardClaims; footer?: string }> {
  // Validate token format
  if (!token.startsWith(PASETO_V4_LOCAL_HEADER)) {
    throw new TokenInvalidError('Invalid token format: must start with v4.local.');
  }

  // Remove header
  const withoutHeader = token.slice(PASETO_V4_LOCAL_HEADER.length);
  
  // Split payload and footer
  const parts = withoutHeader.split('.');
  
  if (parts.length < 1 || parts.length > 2) {
    throw new TokenInvalidError('Invalid token format: incorrect number of parts');
  }

  const payloadStr = parts[0];
  const footerStr = parts[1];
  
  if (!payloadStr) {
    throw new TokenInvalidError('Invalid token format: empty payload');
  }

  try {
    // Decode payload and footer
    const encrypted = base64urlDecode(payloadStr);
    const footerBytes = footerStr ? base64urlDecode(footerStr) : new Uint8Array(0);
    
    // Decrypt message (async)
    const decrypted = await decryptLocal(encrypted, key, footerBytes);
    
    // Parse claims from JSON
    const claimsJson = new TextDecoder().decode(decrypted);
    const claims = JSON.parse(claimsJson) as StandardClaims;
    
    // Decode footer if present
    const footer = footerStr ? new TextDecoder().decode(footerBytes) : undefined;
    
    return { claims, footer };
  } catch (error) {
    if (error instanceof TokenError) {
      throw error;
    }
    throw new TokenInvalidError(
      `Failed to parse token: ${error instanceof Error ? error.message : 'Unknown error'}`
    );
  }
}

/**
 * Extract footer from token without validation
 * Useful for inspecting token metadata without decryption
 */
export function extractFooter(token: string): string | undefined {
  if (!token.startsWith(PASETO_V4_LOCAL_HEADER)) {
    return undefined;
  }

  const withoutHeader = token.slice(PASETO_V4_LOCAL_HEADER.length);
  const parts = withoutHeader.split('.');
  
  if (parts.length !== 2) {
    return undefined;
  }

  try {
    const footerBytes = base64urlDecode(parts[1] ?? '');
    return new TextDecoder().decode(footerBytes);
  } catch {
    return undefined;
  }
}
