/**
 * FlashAuth authentication plugin configuration
 */

export interface AuthPluginConfig {
  /**
   * Drizzle ORM database instance
   */
  db: any;

  /**
   * FlashAuth instance for token management
   */
  flashAuth: any;

  /**
   * Token location: 'bearer' for Authorization header, 'cookie' for cookies, 'both' for both
   * Default: 'both'
   */
  tokenLocation?: 'bearer' | 'cookie' | 'both';

  /**
   * Cookie name (when tokenLocation includes cookie)
   * Default: 'auth_token'
   */
  cookieName?: string;

  /**
   * Cookie options
   */
  cookieSecure?: boolean;
  cookieHttpOnly?: boolean;
  cookieSameSite?: 'strict' | 'lax' | 'none';

  /**
   * Email service for sending verification and reset emails
   * Optional - if not provided, tokens will be returned but emails won't be sent
   */
  email?: {
    sendVerification?: (email: string, token: string) => Promise<void>;
    sendPasswordReset?: (email: string, token: string) => Promise<void>;
  };

  /**
   * Token expiration times (in seconds)
   */
  tokenExpiration?: {
    emailVerification?: number;
    passwordReset?: number;
    session?: number;
  };

  /**
   * Security settings
   */
  security?: {
    minPasswordLength?: number;
    requireUppercase?: boolean;
    requireLowercase?: boolean;
    requireNumber?: boolean;
    requireSpecialChar?: boolean;
  };

  /**
   * Enable/disable two-factor authentication (TOTP) (default: true)
   */
  totpEnabled?: boolean;

  /**
   * Enable/disable passkey authentication (default: false)
   */
  passkeysEnabled?: boolean;

  /**
   * Disable user signups (default: false)
   */
  disableSignup?: boolean;

  /**
   * Require invite link for signup (default: false)
   */
  inviteOnly?: boolean;

  /**
   * Relying Party (RP) configuration for WebAuthn/Passkey
   * Required when passkeysEnabled is true
   */
  webauthn?: {
    rpName: string;
    rpID: string;
    origin: string | string[];
  };
}

/**
 * Default configuration values
 */
export const DEFAULT_CONFIG: Partial<AuthPluginConfig> = {
  tokenLocation: 'both',
  cookieName: 'auth_token',
  totpEnabled: true,
  passkeysEnabled: false,
  disableSignup: false,
  inviteOnly: false,
  tokenExpiration: {
    emailVerification: 24 * 60 * 60, // 24 hours
    passwordReset: 60 * 60, // 1 hour
    session: 7 * 24 * 60 * 60, // 7 days
  },
  security: {
    minPasswordLength: 8,
    requireUppercase: false,
    requireLowercase: false,
    requireNumber: false,
    requireSpecialChar: false,
  },
};
