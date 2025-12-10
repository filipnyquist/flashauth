/**
 * FlashAuth Cryptography
 * PASETO v4 Local implementation with XChaCha20-Poly1305
 * Using @noble/ciphers for XChaCha20-Poly1305 and Bun's crypto for random bytes
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { CryptographyError } from './errors.js';

/**
 * Generate a random 32-byte secret key for PASETO v4 local
 * Uses Bun's crypto.getRandomValues
 */
export function generateSecret(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Generate a random 24-byte nonce for XChaCha20-Poly1305
 * Uses Bun's crypto.getRandomValues
 */
export function generateNonce(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(24));
}

/**
 * PASETO v4 local encrypt
 * Uses XChaCha20-Poly1305 for authenticated encryption
 */
export function encryptLocal(
  message: Uint8Array,
  key: Uint8Array,
  footer: Uint8Array = new Uint8Array(0)
): Uint8Array {
  if (key.length !== 32) {
    throw new CryptographyError('Key must be 32 bytes');
  }

  // Generate random nonce
  const nonce = generateNonce();

  try {
    // Step 1: Encrypt with empty AAD to get ciphertext
    const cipher = xchacha20poly1305(key, nonce);
    const sealed = cipher.encrypt(message);
    
    // sealed = ciphertext + tag (16 bytes)
    // Extract just the ciphertext (without tag) for PAE
    const ciphertext = sealed.slice(0, -16);
    
    // Step 2: Now create PAE with the ciphertext
    const pae = preAuthEncode([
      new TextEncoder().encode('v4.local.'),
      nonce,
      ciphertext,
      footer
    ]);
    
    // Step 3: Re-encrypt with proper PAE as AAD
    const cipher2 = xchacha20poly1305(key, nonce, pae);
    const finalSealed = cipher2.encrypt(message);

    // Concatenate nonce + sealed (ciphertext + tag)
    const result = new Uint8Array(nonce.length + finalSealed.length);
    result.set(nonce, 0);
    result.set(finalSealed, nonce.length);

    return result;
  } catch (error) {
    throw new CryptographyError(`Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * PASETO v4 local decrypt
 * Uses XChaCha20-Poly1305 for authenticated decryption
 */
export function decryptLocal(
  encrypted: Uint8Array,
  key: Uint8Array,
  footer: Uint8Array = new Uint8Array(0)
): Uint8Array {
  if (key.length !== 32) {
    throw new CryptographyError('Key must be 32 bytes');
  }

  if (encrypted.length < 40) { // 24 bytes nonce + 16 bytes tag minimum
    throw new CryptographyError('Invalid encrypted data: too short');
  }

  // Extract nonce (24 bytes) and sealed data (ciphertext + tag)
  const nonce = encrypted.slice(0, 24);
  const sealed = encrypted.slice(24);
  
  // Extract ciphertext (without tag) for PAE
  const ciphertext = sealed.slice(0, -16);

  // Pre-authentication encoding (PAE)
  // Note: For PASETO v4, PAE uses ciphertext not plaintext during decryption
  const pae = preAuthEncode([
    new TextEncoder().encode('v4.local.'),
    nonce,
    ciphertext,
    footer
  ]);

  try {
    // Create cipher instance
    const cipher = xchacha20poly1305(key, nonce, pae);
    
    // Decrypt with XChaCha20-Poly1305
    const decrypted = cipher.decrypt(sealed);

    return decrypted;
  } catch (error) {
    throw new CryptographyError(`Decryption failed: ${error instanceof Error ? error.message : 'Invalid token or key'}`);
  }
}

/**
 * Pre-Authentication Encoding (PAE)
 * PASETO specification requirement for authenticated data
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
 * Prevents timing attacks
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
