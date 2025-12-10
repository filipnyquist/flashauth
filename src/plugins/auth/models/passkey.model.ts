/**
 * Passkey/WebAuthn credential model
 */

export interface PasskeyCredential {
  id: string;
  user_id: string;
  credential_id: string;
  public_key: string;
  counter: number;
  transports: string[];
  created_at: Date;
  last_used_at: Date | null;
}
