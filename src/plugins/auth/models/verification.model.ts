/**
 * Email verification token model
 * Now JWT-based, no database table needed
 */

export interface EmailVerificationToken {
  userId: string;
  purpose: 'email_verification';
}
