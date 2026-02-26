/**
 * Password reset token model
 * Now JWT-based, no database table needed
 */

export interface PasswordResetToken {
  userId: string;
  purpose: 'password_reset';
}
