/**
 * Token generation utilities for verification and reset tokens
 */

/**
 * Generate a secure random token
 * Uses Bun's crypto.getRandomValues for cryptographically secure randomness
 */
export function generateSecureToken(length: number = 32): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Generate a verification token (64 characters)
 */
export function generateVerificationToken(): string {
  return generateSecureToken(32); // 32 bytes = 64 hex characters
}

/**
 * Generate a password reset token (64 characters)
 */
export function generatePasswordResetToken(): string {
  return generateSecureToken(32); // 32 bytes = 64 hex characters
}

/**
 * Generate TOTP backup codes (8 codes, each 8 characters)
 */
export function generateBackupCodes(count: number = 8): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    // Generate 4 bytes (8 hex chars) for each code
    const code = generateSecureToken(4);
    codes.push(code);
  }
  return codes;
}

/**
 * Hash a backup code for storage
 * Uses Bun's password hashing
 */
export async function hashBackupCode(code: string): Promise<string> {
  return await Bun.password.hash(code, {
    algorithm: 'bcrypt',
    cost: 10,
  });
}

/**
 * Verify a backup code
 */
export async function verifyBackupCode(code: string, hash: string): Promise<boolean> {
  return await Bun.password.verify(code, hash);
}
