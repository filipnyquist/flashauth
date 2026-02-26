/**
 * FlashAuth JWT Implementation
 * Token creation and verification using the jose library
 */

import { SignJWT, jwtVerify } from 'jose';
import { TokenError, TokenInvalidError } from './errors.js';
import type { StandardClaims } from './claims.js';

/**
 * Options for JWT token creation
 */
export interface JWTOptions {
  /** Algorithm (default: HS256) */
  algorithm?: string;
  /** Token expiration in seconds from now (optional for API keys) */
  expiresIn?: number;
}

/**
 * Convert a secret string or Uint8Array to a Uint8Array suitable for HS256
 */
function toSecretKey(secret: string | Uint8Array): Uint8Array {
  if (secret instanceof Uint8Array) return secret;
  return new TextEncoder().encode(secret);
}

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
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

/**
 * Generate a random secret string suitable for HS256 signing
 * Returns a base64url-encoded 32-byte random value
 */
export function generateSecret(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return base64urlEncode(bytes);
}

/**
 * Create a signed JWT token
 *
 * @param claims - Token claims
 * @param secret - Secret key (string or Uint8Array)
 * @param options - JWT options
 * @returns Signed JWT string
 */
export async function createToken(
  claims: StandardClaims,
  secret: string | Uint8Array,
  options?: JWTOptions,
): Promise<string> {
  const key = toSecretKey(secret);
  const alg = options?.algorithm ?? 'HS256';

  // Separate registered claims from custom payload
  const { sub, iss, aud, exp, iat, nbf, jti, ...customClaims } = claims;

  let builder = new SignJWT(customClaims)
    .setProtectedHeader({ alg });

  if (sub) builder = builder.setSubject(sub);
  if (iss) builder = builder.setIssuer(iss);
  if (aud) builder = builder.setAudience(aud);
  if (jti) builder = builder.setJti(jti);

  // Set iat
  if (iat !== undefined) {
    builder = builder.setIssuedAt(iat);
  } else {
    builder = builder.setIssuedAt();
  }

  // Set nbf if present
  if (nbf !== undefined) builder = builder.setNotBefore(nbf);

  // Set expiration if present (omit for API keys)
  if (exp !== undefined) builder = builder.setExpirationTime(exp);

  try {
    return await builder.sign(key);
  } catch (error) {
    throw new TokenError(
      `Failed to create token: ${error instanceof Error ? error.message : 'Unknown error'}`
    );
  }
}

/**
 * Parse and verify a JWT token
 *
 * @param token - JWT string
 * @param secret - Secret key (string or Uint8Array)
 * @returns Parsed claims
 */
export async function parseToken(
  token: string,
  secret: string | Uint8Array,
): Promise<{ claims: StandardClaims }> {
  const key = toSecretKey(secret);

  try {
    const { payload } = await jwtVerify(token, key, {
      // Use large clockTolerance to skip jose's built-in exp check;
      // we validate expiration ourselves in claims.ts
      clockTolerance: Number.MAX_SAFE_INTEGER,
    });

    // Reconstruct StandardClaims from the JWT payload
    const claims: StandardClaims = {
      sub: payload.sub ?? '',
      iat: payload.iat ?? Math.floor(Date.now() / 1000),
      ...payload,
    } as StandardClaims;

    // exp may be undefined for API key tokens
    if (payload.exp !== undefined) {
      claims.exp = payload.exp;
    }

    // aud comes back as string | string[] from jose; normalize to string[]
    if (payload.aud) {
      claims.aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    }

    return { claims };
  } catch (error) {
    if (error instanceof TokenError) {
      throw error;
    }
    throw new TokenInvalidError(
      `Failed to parse token: ${error instanceof Error ? error.message : 'Unknown error'}`
    );
  }
}
