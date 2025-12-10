/**
 * FlashAuth authentication plugin configuration
 */

export interface AuthPluginConfig {
  /**
   * PostgreSQL database connection string
   * Example: "postgres://user:password@localhost:5432/database"
   */
  databaseUrl: string;

  /**
   * FlashAuth instance for token management
   */
  flashAuth: any; // Will be the FlashAuth instance

  /**
   * Relying Party (RP) configuration for WebAuthn/Passkey
   */
  webauthn: {
    /**
     * Human-readable name of the relying party (your app name)
     */
    rpName: string;

    /**
     * Relying Party ID - typically your domain
     * Example: "example.com"
     */
    rpID: string;

    /**
     * Expected origin(s) for WebAuthn operations
     * Example: "https://example.com" or ["https://example.com", "https://www.example.com"]
     */
    origin: string | string[];
  };

  /**
   * Email service for sending verification and reset emails
   * Optional - if not provided, tokens will be returned but emails won't be sent
   */
  email?: {
    /**
     * Send email verification email
     */
    sendVerification?: (email: string, token: string) => Promise<void>;

    /**
     * Send password reset email
     */
    sendPasswordReset?: (email: string, token: string) => Promise<void>;
  };

  /**
   * Token expiration times (in seconds)
   */
  tokenExpiration?: {
    /**
     * Email verification token expiration (default: 24 hours)
     */
    emailVerification?: number;

    /**
     * Password reset token expiration (default: 1 hour)
     */
    passwordReset?: number;

    /**
     * Session token expiration (default: 7 days)
     */
    session?: number;
  };

  /**
   * Security settings
   */
  security?: {
    /**
     * Minimum password length (default: 8)
     */
    minPasswordLength?: number;

    /**
     * Require uppercase letter in password (default: false)
     */
    requireUppercase?: boolean;

    /**
     * Require lowercase letter in password (default: false)
     */
    requireLowercase?: boolean;

    /**
     * Require number in password (default: false)
     */
    requireNumber?: boolean;

    /**
     * Require special character in password (default: false)
     */
    requireSpecialChar?: boolean;
  };
}

/**
 * Default configuration values
 */
export const DEFAULT_CONFIG: Partial<AuthPluginConfig> = {
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
