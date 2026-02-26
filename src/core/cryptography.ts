/**
 * FlashAuth Cryptography
 * Utility functions for JWT-based authentication
 */

/**
 * Generate a random 32-byte secret key for HS256 JWT signing
 * Uses crypto.getRandomValues for cryptographically secure randomness
 */
export function generateSecret(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Timing-safe comparison of two buffers
 * Prevents timing attacks by ensuring comparison takes constant time
 *
 * @param a - First buffer
 * @param b - Second buffer
 * @returns true if buffers are equal, false otherwise
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }

  return result === 0;
}
