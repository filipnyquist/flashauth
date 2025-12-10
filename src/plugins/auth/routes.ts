/**
 * Authentication routes for Elysia
 */

import { Elysia, t } from 'elysia';
import type { AuthPluginConfig } from './config.js';
import type { DatabaseConnection } from './utils/db.js';
import { UserService } from './services/user.service.js';
import { VerificationService } from './services/verification.service.js';
import { PasswordResetService } from './services/reset.service.js';
import { TOTPService } from './services/totp.service.js';
import { PasskeyService } from './services/passkey.service.js';
import { toPublicUser } from './models/user.model.js';

export function createAuthRoutes(db: DatabaseConnection, config: AuthPluginConfig) {
  const userService = new UserService(db, config);
  const verificationService = new VerificationService(db, config);
  const resetService = new PasswordResetService(db, config);
  const totpService = new TOTPService(db, config);
  const passkeyService = new PasskeyService(db, config);

  // Store challenges temporarily (in production, use Redis or similar)
  const challenges = new Map<string, string>();

  return new Elysia({ prefix: '/auth' })
    // Signup
    .post('/signup', async ({ body }) => {
      const user = await userService.createUser({
        email: body.email,
        password: body.password,
      });

      // Generate verification token
      const token = await verificationService.createVerificationToken(user.id);

      // Send verification email if configured
      if (config.email?.sendVerification) {
        await config.email.sendVerification(user.email, token);
      }

      return {
        user: toPublicUser(user),
        verificationToken: config.email?.sendVerification ? undefined : token,
        message: config.email?.sendVerification 
          ? 'Verification email sent' 
          : 'Please verify your email with the provided token',
      };
    }, {
      body: t.Object({
        email: t.String({ format: 'email' }),
        password: t.String({ minLength: 8 }),
      }),
    })

    // Verify email
    .post('/verify-email', async ({ body }) => {
      const verification = await verificationService.verifyToken(body.token);

      if (!verification.valid) {
        return {
          success: false,
          error: verification.error,
        };
      }

      // Mark email as verified
      await userService.markEmailVerified(verification.userId!);

      // Delete the token
      await verificationService.deleteToken(body.token);

      return {
        success: true,
        message: 'Email verified successfully',
      };
    }, {
      body: t.Object({
        token: t.String(),
      }),
    })

    // Login with email/password
    .post('/login', async ({ body }) => {
      const user = await userService.authenticate(body.email, body.password);

      if (!user) {
        return {
          success: false,
          error: 'Invalid email or password',
        };
      }

      if (!user.email_verified) {
        return {
          success: false,
          error: 'Email not verified',
        };
      }

      // Check if TOTP is enabled
      const totpEnabled = await totpService.isTOTPEnabled(user.id);

      if (totpEnabled) {
        // Return a temporary token that requires 2FA completion
        return {
          success: true,
          requiresTOTP: true,
          userId: user.id,
          message: 'Please provide TOTP code',
        };
      }

      // Create session token
      const sessionToken = await config.flashAuth
        .createToken()
        .subject(user.id)
        .claim('email', user.email)
        .expiresIn(`${config.tokenExpiration?.session || 7 * 24 * 60 * 60}s`)
        .build();

      return {
        success: true,
        token: sessionToken,
        user: toPublicUser(user),
      };
    }, {
      body: t.Object({
        email: t.String({ format: 'email' }),
        password: t.String(),
      }),
    })

    // Complete login with TOTP
    .post('/login/2fa', async ({ body }) => {
      const user = await userService.findById(body.userId);

      if (!user) {
        return {
          success: false,
          error: 'Invalid user',
        };
      }

      // Verify TOTP token or backup code
      let valid = await totpService.verifyToken(user.id, body.code);

      if (!valid) {
        // Try backup code
        valid = await totpService.verifyBackupCode(user.id, body.code);
      }

      if (!valid) {
        return {
          success: false,
          error: 'Invalid TOTP code or backup code',
        };
      }

      // Create session token
      const sessionToken = await config.flashAuth
        .createToken()
        .subject(user.id)
        .claim('email', user.email)
        .claim('mfaVerified', true)
        .expiresIn(`${config.tokenExpiration?.session || 7 * 24 * 60 * 60}s`)
        .build();

      return {
        success: true,
        token: sessionToken,
        user: toPublicUser(user),
      };
    }, {
      body: t.Object({
        userId: t.String(),
        code: t.String(),
      }),
    })

    // Password reset request
    .post('/password-reset/request', async ({ body }) => {
      const user = await userService.findByEmail(body.email);

      // Always return success to prevent email enumeration
      if (!user) {
        return {
          success: true,
          message: 'If the email exists, a password reset link has been sent',
        };
      }

      // Generate reset token
      const token = await resetService.createResetToken(user.id);

      // Send reset email if configured
      if (config.email?.sendPasswordReset) {
        await config.email.sendPasswordReset(user.email, token);
      }

      return {
        success: true,
        resetToken: config.email?.sendPasswordReset ? undefined : token,
        message: config.email?.sendPasswordReset
          ? 'Password reset email sent'
          : 'Use the provided token to reset your password',
      };
    }, {
      body: t.Object({
        email: t.String({ format: 'email' }),
      }),
    })

    // Password reset confirmation
    .post('/password-reset/confirm', async ({ body }) => {
      const verification = await resetService.verifyToken(body.token);

      if (!verification.valid) {
        return {
          success: false,
          error: verification.error,
        };
      }

      // Update password
      await userService.updatePassword(verification.userId!, body.newPassword);

      // Delete the token
      await resetService.deleteToken(body.token);

      // Delete all other reset tokens for this user
      await resetService.deleteUserTokens(verification.userId!);

      return {
        success: true,
        message: 'Password reset successfully',
      };
    }, {
      body: t.Object({
        token: t.String(),
        newPassword: t.String({ minLength: 8 }),
      }),
    })

    // Setup TOTP 2FA
    .post('/2fa/setup', async ({ headers }) => {
      // This endpoint requires authentication
      const authHeader = headers.authorization;
      if (!authHeader) {
        return {
          success: false,
          error: 'Unauthorized',
        };
      }

      const token = authHeader.replace('Bearer ', '');
      const claims = await config.flashAuth.validateToken(token);
      const userId = claims.sub;

      const user = await userService.findById(userId);
      if (!user) {
        return {
          success: false,
          error: 'User not found',
        };
      }

      // Generate TOTP secret
      const { secret, qrCode, backupCodes } = await totpService.generateSecret(userId);

      return {
        success: true,
        secret,
        qrCodeUrl: qrCode,
        backupCodes,
        message: 'Scan the QR code with your authenticator app and verify with a code',
      };
    })

    // Verify and enable TOTP
    .post('/2fa/verify', async ({ body, headers }) => {
      const authHeader = headers.authorization;
      if (!authHeader) {
        return {
          success: false,
          error: 'Unauthorized',
        };
      }

      const token = authHeader.replace('Bearer ', '');
      const claims = await config.flashAuth.validateToken(token);
      const userId = claims.sub;

      const enabled = await totpService.enableTOTP(userId, body.code);

      if (!enabled) {
        return {
          success: false,
          error: 'Invalid TOTP code',
        };
      }

      return {
        success: true,
        message: '2FA enabled successfully',
      };
    }, {
      body: t.Object({
        code: t.String(),
      }),
    })

    // Disable TOTP
    .post('/2fa/disable', async ({ headers }) => {
      const authHeader = headers.authorization;
      if (!authHeader) {
        return {
          success: false,
          error: 'Unauthorized',
        };
      }

      const token = authHeader.replace('Bearer ', '');
      const claims = await config.flashAuth.validateToken(token);
      const userId = claims.sub;

      await totpService.disableTOTP(userId);

      return {
        success: true,
        message: '2FA disabled successfully',
      };
    })

    // Passkey registration start
    .post('/passkey/register/start', async ({ headers }) => {
      const authHeader = headers.authorization;
      if (!authHeader) {
        return {
          success: false,
          error: 'Unauthorized',
        };
      }

      const token = authHeader.replace('Bearer ', '');
      const claims = await config.flashAuth.validateToken(token);
      const userId = claims.sub;

      const user = await userService.findById(userId);
      if (!user) {
        return {
          success: false,
          error: 'User not found',
        };
      }

      const options = await passkeyService.generateRegistrationOptions(userId, user.email);

      // Store challenge temporarily
      challenges.set(userId, options.challenge);

      return {
        success: true,
        options,
      };
    })

    // Passkey registration finish
    .post('/passkey/register/finish', async ({ body, headers }) => {
      const authHeader = headers.authorization;
      if (!authHeader) {
        return {
          success: false,
          error: 'Unauthorized',
        };
      }

      const token = authHeader.replace('Bearer ', '');
      const claims = await config.flashAuth.validateToken(token);
      const userId = claims.sub;

      const expectedChallenge = challenges.get(userId);
      if (!expectedChallenge) {
        return {
          success: false,
          error: 'No challenge found',
        };
      }

      const result = await passkeyService.verifyRegistration(userId, body.response, expectedChallenge);

      // Clean up challenge
      challenges.delete(userId);

      if (!result.verified) {
        return {
          success: false,
          error: result.error,
        };
      }

      return {
        success: true,
        message: 'Passkey registered successfully',
      };
    }, {
      body: t.Object({
        response: t.Any(),
      }),
    })

    // Passkey authentication start
    .post('/passkey/login/start', async () => {
      const options = await passkeyService.generateAuthenticationOptions();

      // Store challenge with a random session ID
      const sessionId = crypto.randomUUID();
      challenges.set(sessionId, options.challenge);

      return {
        success: true,
        sessionId,
        options,
      };
    })

    // Passkey authentication finish
    .post('/passkey/login/finish', async ({ body }) => {
      const expectedChallenge = challenges.get(body.sessionId);
      if (!expectedChallenge) {
        return {
          success: false,
          error: 'No challenge found',
        };
      }

      const result = await passkeyService.verifyAuthentication(body.response, expectedChallenge);

      // Clean up challenge
      challenges.delete(body.sessionId);

      if (!result.verified || !result.userId) {
        return {
          success: false,
          error: result.error,
        };
      }

      const user = await userService.findById(result.userId);
      if (!user) {
        return {
          success: false,
          error: 'User not found',
        };
      }

      // Create session token
      const sessionToken = await config.flashAuth
        .createToken()
        .subject(user.id)
        .claim('email', user.email)
        .claim('passkeyAuth', true)
        .expiresIn(`${config.tokenExpiration?.session || 7 * 24 * 60 * 60}s`)
        .build();

      return {
        success: true,
        token: sessionToken,
        user: toPublicUser(user),
      };
    }, {
      body: t.Object({
        sessionId: t.String(),
        response: t.Any(),
      }),
    });
}
