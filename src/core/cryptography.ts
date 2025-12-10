/**
 * FlashAuth Cryptography
 * PASETO v4 Local implementation with XChaCha20-Poly1305
 * Using @noble/ciphers for XChaCha20-Poly1305 and Bun's crypto for random bytes
 * 
 * PASETO v4.local specification:
 * - PAE(h, n, f, i) where h="v4.local.", n=nonce, f=footer, i="" (implicit assertion)
 * - Encrypt with XChaCha20-Poly1305 using PAE as additional authenticated data
 * - Never reuse nonce with same key (ensured by crypto.getRandomValues)
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { CryptographyError } from './errors.js';

/**
 * Generate a random 32-byte secret key for PASETO v4 local
 * Uses Bun's crypto.getRandomValues for cryptographically secure randomness
 */
export function generateSecret(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Generate a random 24-byte nonce for XChaCha20-Poly1305
 * Uses Bun's crypto.getRandomValues for cryptographically secure randomness
 * Each nonce MUST be unique for the same key to maintain security
 */
export function generateNonce(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(24));
}

/**
 * PASETO v4 local encrypt (async for async-first architecture)
 * Uses XChaCha20-Poly1305 for authenticated encryption
 * 
 * @param message - Plaintext message to encrypt
 * @param key - 32-byte encryption key
 * @param footer - Optional footer (authenticated but not encrypted)
 * @returns Encrypted data: nonce (24 bytes) || ciphertext || tag (16 bytes)
 */
export async function encryptLocal(
  message: Uint8Array,
  key: Uint8Array,
  footer: Uint8Array = new Uint8Array(0)
): Promise<Uint8Array> {
  if (key.length !== 32) {
    throw new CryptographyError('Key must be 32 bytes');
  }

  // Step 1: Generate random nonce (never reuse with same key)
  const nonce = generateNonce();

  // Step 2: Calculate PAE according to PASETO v4 spec
  // PAE(header, nonce, footer, implicit_assertion)
  // For v4.local, implicit_assertion is empty
  const pae = preAuthEncode([
    new TextEncoder().encode('v4.local.'),
    nonce,
    footer,
    new Uint8Array(0), // Empty implicit assertion for v4.local
  ]);

  try {
    // Step 3: Encrypt with XChaCha20-Poly1305 using PAE as AAD
    // Wrapping in promise for async-first API, though noble-ciphers is synchronous
    const cipher = xchacha20poly1305(key, nonce, pae);
    const sealed = cipher.encrypt(message);

    // Step 4: Concatenate nonce + sealed (ciphertext + 16-byte auth tag)
    const result = new Uint8Array(nonce.length + sealed.length);
    result.set(nonce, 0);
    result.set(sealed, nonce.length);

    return result;
  } catch (error) {
    throw new CryptographyError(`Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * PASETO v4 local decrypt (async for async-first architecture)
 * Uses XChaCha20-Poly1305 for authenticated decryption
 * 
 * @param encrypted - Encrypted data: nonce || ciphertext || tag
 * @param key - 32-byte decryption key
 * @param footer - Optional footer (must match encryption footer)
 * @returns Decrypted plaintext message
 * @throws CryptographyError if decryption fails (wrong key, tampered data, wrong footer)
 */
export async function decryptLocal(
  encrypted: Uint8Array,
  key: Uint8Array,
  footer: Uint8Array = new Uint8Array(0)
): Promise<Uint8Array> {
  if (key.length !== 32) {
    throw new CryptographyError('Key must be 32 bytes');
  }

  // Minimum: 24 bytes nonce + 16 bytes auth tag
  if (encrypted.length < 40) {
    throw new CryptographyError('Invalid encrypted data: too short');
  }

  // Step 1: Extract nonce (first 24 bytes) and sealed data (rest)
  const nonce = encrypted.slice(0, 24);
  const sealed = encrypted.slice(24); // ciphertext + auth tag

  // Step 2: Calculate PAE (must match encryption PAE)
  // PAE(header, nonce, footer, implicit_assertion)
  const pae = preAuthEncode([
    new TextEncoder().encode('v4.local.'),
    nonce,
    footer,
    new Uint8Array(0), // Empty implicit assertion for v4.local
  ]);

  try {
    // Step 3: Decrypt and verify with XChaCha20-Poly1305
    // Wrapping in promise for async-first API
    const cipher = xchacha20poly1305(key, nonce, pae);
    const decrypted = cipher.decrypt(sealed);

    return decrypted;
  } catch (error) {
    // Decryption failure indicates tampering, wrong key, or wrong footer
    throw new CryptographyError(`Decryption failed: ${error instanceof Error ? error.message : 'Invalid token or key'}`);
  }
}

/**
 * Pre-Authentication Encoding (PAE)
 * PASETO specification requirement for authenticated data
 * 
 * Encodes an array of byte arrays into a single byte array with length prefixes
 * Format: LE64(count) || LE64(len1) || data1 || LE64(len2) || data2 || ...
 * 
 * @param pieces - Array of byte arrays to encode
 * @returns PAE-encoded byte array
 */
function preAuthEncode(pieces: Uint8Array[]): Uint8Array {
  // Count of pieces as LE64
  const count = le64(pieces.length);
  
  // Each piece prefixed with its length as LE64
  const encoded: Uint8Array[] = [count];
  
  for (const piece of pieces) {
    encoded.push(le64(piece.length));
    encoded.push(piece);
  }

  // Concatenate all parts
  const totalLength = encoded.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  
  for (const arr of encoded) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
}

/**
 * Encode number as little-endian 64-bit unsigned integer
 * 
 * @param n - Number to encode (must be safe integer)
 * @returns 8-byte little-endian representation
 */
function le64(n: number): Uint8Array {
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  // Use BigInt for safe 64-bit operations
  view.setBigUint64(0, BigInt(n), true); // true = little endian
  return new Uint8Array(buffer);
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
