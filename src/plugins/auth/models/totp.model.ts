/**
 * TOTP (2FA) secret model
 */

export interface TOTPSecret {
  id: string;
  user_id: string;
  secret: string;
  backup_codes: string[];
  enabled: boolean;
  created_at: Date;
  updated_at: Date;
}
