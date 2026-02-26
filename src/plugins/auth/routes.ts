/**
 * Authentication routes for Elysia
 */

import { Elysia, t } from 'elysia';
import type { AuthPluginConfig } from './config.js';
import { UserService } from './services/user.service.js';
import { VerificationService } from './services/verification.service.js';
import { PasswordResetService } from './services/reset.service.js';
import { TOTPService } from './services/totp.service.js';
import { PasskeyService } from './services/passkey.service.js';
import { InviteService } from './services/invite.service.js';
import { PermissionService } from './services/permission.service.js';
import { ApiKeyService } from './services/apikey.service.js';
import { toPublicUser } from './models/user.model.js';

function extractToken(headers: any, cookie: any, config: AuthPluginConfig): string | null {
  const tokenLocation = config.tokenLocation || 'both';
  const cookieName = config.cookieName || 'auth_token';
  let token: string | null = null;

  if (tokenLocation === 'bearer' || tokenLocation === 'both') {
    const authHeader = headers['authorization'] || headers['Authorization'];
    if (authHeader && typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
      token = authHeader.slice(7);
    }
  }

  if (!token && (tokenLocation === 'cookie' || tokenLocation === 'both')) {
    const cookieValue = cookie?.[cookieName];
    if (cookieValue && typeof cookieValue.value === 'string') {
      token = cookieValue.value;
    }
  }

  return token;
}

async function requireAuthClaims(headers: any, cookie: any, config: AuthPluginConfig): Promise<any> {
  const token = extractToken(headers, cookie, config);
  if (!token) {
    throw new Error('Unauthorized');
  }
  return await config.flashAuth.validateToken(token);
}

export function createAuthRoutes(db: any, config: AuthPluginConfig) {
  const userService = new UserService(db, config);
  const verificationService = new VerificationService(config);
  const resetService = new PasswordResetService(config);
  const totpService = new TOTPService(db, config);
  const passkeyService = new PasskeyService(db, config);
  const inviteService = new InviteService(db);
  const permissionService = new PermissionService(db);
  const apiKeyService = new ApiKeyService(db);

  // Store challenges temporarily (in production, use Redis or similar)
  const challenges = new Map<string, string>();

  return new Elysia({ prefix: '/auth' })
    // ─── Signup ──────────────────────────────────────────────────────────
    .post('/signup', async ({ body }) => {
      if (config.disableSignup) {
        return { success: false, error: 'Signups are currently disabled' };
      }

      if (config.inviteOnly) {
        return { success: false, error: 'Signup requires an invite link' };
      }

      const user = await userService.createUser({
        email: body.email,
        password: body.password,
      });

      const token = await verificationService.createVerificationToken(user.id);

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

    // ─── Signup with Invite ──────────────────────────────────────────────
    .post('/signup/invite', async ({ body }) => {
      if (config.disableSignup) {
        return { success: false, error: 'Signups are currently disabled' };
      }

      const invite = await inviteService.useInvite(body.inviteToken);

      if (invite.email && invite.email !== body.email) {
        return { success: false, error: 'Email does not match invite' };
      }

      const user = await userService.createUser({
        email: body.email,
        password: body.password,
      });

      // If invite has a role, assign it
      if (invite.roleId) {
        await permissionService.assignRoleToUser(user.id, invite.roleId);
      }

      const token = await verificationService.createVerificationToken(user.id);

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
        inviteToken: t.String(),
      }),
    })

    // ─── Verify Email ────────────────────────────────────────────────────
    .post('/verify-email', async ({ body }) => {
      const verification = await verificationService.verifyToken(body.token);

      if (!verification.valid) {
        return { success: false, error: verification.error };
      }

      await userService.markEmailVerified(verification.userId!);

      return { success: true, message: 'Email verified successfully' };
    }, {
      body: t.Object({
        token: t.String(),
      }),
    })

    // ─── Login ───────────────────────────────────────────────────────────
    .post('/login', async ({ body }) => {
      const user = await userService.authenticate(body.email, body.password);

      if (!user) {
        return { success: false, error: 'Invalid email or password' };
      }

      if (!user.emailVerified) {
        return { success: false, error: 'Email not verified' };
      }

      const totpEnabled = await totpService.isTOTPEnabled(user.id);

      if (totpEnabled) {
        return {
          success: true,
          requiresTOTP: true,
          userId: user.id,
          message: 'Please provide TOTP code',
        };
      }

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

    // ─── Login 2FA ───────────────────────────────────────────────────────
    .post('/login/2fa', async ({ body }) => {
      const user = await userService.findById(body.userId);

      if (!user) {
        return { success: false, error: 'Invalid user' };
      }

      let valid = await totpService.verifyToken(user.id, body.code);

      if (!valid) {
        valid = await totpService.verifyBackupCode(user.id, body.code);
      }

      if (!valid) {
        return { success: false, error: 'Invalid TOTP code or backup code' };
      }

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

    // ─── Password Reset Request ──────────────────────────────────────────
    .post('/password-reset/request', async ({ body }) => {
      const user = await userService.findByEmail(body.email);

      // Always return success to prevent email enumeration
      if (!user) {
        return {
          success: true,
          message: 'If the email exists, a password reset link has been sent',
        };
      }

      const token = await resetService.createResetToken(user.id);

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

    // ─── Password Reset Confirm ──────────────────────────────────────────
    .post('/password-reset/confirm', async ({ body }) => {
      const verification = await resetService.verifyToken(body.token);

      if (!verification.valid) {
        return { success: false, error: verification.error };
      }

      await userService.updatePassword(verification.userId!, body.newPassword);

      return { success: true, message: 'Password reset successfully' };
    }, {
      body: t.Object({
        token: t.String(),
        newPassword: t.String({ minLength: 8 }),
      }),
    })

    // ─── 2FA Setup ───────────────────────────────────────────────────────
    .post('/2fa/setup', async ({ headers, cookie }) => {
      if (!config.totpEnabled) {
        return { success: false, error: 'Two-factor authentication is not enabled' };
      }

      const claims = await requireAuthClaims(headers, cookie, config);
      const userId = claims.sub;

      const user = await userService.findById(userId);
      if (!user) {
        return { success: false, error: 'User not found' };
      }

      const { secret, qrCode, backupCodes } = await totpService.generateSecret(userId);

      return {
        success: true,
        secret,
        qrCodeUrl: qrCode,
        backupCodes,
        message: 'Scan the QR code with your authenticator app and verify with a code',
      };
    })

    // ─── 2FA Verify ──────────────────────────────────────────────────────
    .post('/2fa/verify', async ({ body, headers, cookie }) => {
      if (!config.totpEnabled) {
        return { success: false, error: 'Two-factor authentication is not enabled' };
      }

      const claims = await requireAuthClaims(headers, cookie, config);
      const userId = claims.sub;

      const enabled = await totpService.enableTOTP(userId, body.code);

      if (!enabled) {
        return { success: false, error: 'Invalid TOTP code' };
      }

      return { success: true, message: '2FA enabled successfully' };
    }, {
      body: t.Object({
        code: t.String(),
      }),
    })

    // ─── 2FA Disable ─────────────────────────────────────────────────────
    .post('/2fa/disable', async ({ headers, cookie }) => {
      if (!config.totpEnabled) {
        return { success: false, error: 'Two-factor authentication is not enabled' };
      }

      const claims = await requireAuthClaims(headers, cookie, config);
      await totpService.disableTOTP(claims.sub);

      return { success: true, message: '2FA disabled successfully' };
    })

    // ─── Passkey Register Start ──────────────────────────────────────────
    .post('/passkey/register/start', async ({ headers, cookie }) => {
      if (!config.passkeysEnabled) {
        return { success: false, error: 'Passkey authentication is not enabled' };
      }

      const claims = await requireAuthClaims(headers, cookie, config);
      const userId = claims.sub;

      const user = await userService.findById(userId);
      if (!user) {
        return { success: false, error: 'User not found' };
      }

      const options = await passkeyService.generateRegistrationOptions(userId, user.email);
      challenges.set(userId, options.challenge);

      return { success: true, options };
    })

    // ─── Passkey Register Finish ─────────────────────────────────────────
    .post('/passkey/register/finish', async ({ body, headers, cookie }) => {
      if (!config.passkeysEnabled) {
        return { success: false, error: 'Passkey authentication is not enabled' };
      }

      const claims = await requireAuthClaims(headers, cookie, config);
      const userId = claims.sub;

      const expectedChallenge = challenges.get(userId);
      if (!expectedChallenge) {
        return { success: false, error: 'No challenge found' };
      }

      const result = await passkeyService.verifyRegistration(userId, body.response, expectedChallenge);
      challenges.delete(userId);

      if (!result.verified) {
        return { success: false, error: result.error };
      }

      return { success: true, message: 'Passkey registered successfully' };
    }, {
      body: t.Object({
        response: t.Any(),
      }),
    })

    // ─── Passkey Login Start ─────────────────────────────────────────────
    .post('/passkey/login/start', async () => {
      if (!config.passkeysEnabled) {
        return { success: false, error: 'Passkey authentication is not enabled' };
      }

      const options = await passkeyService.generateAuthenticationOptions();
      const sessionId = crypto.randomUUID();
      challenges.set(sessionId, options.challenge);

      return { success: true, sessionId, options };
    })

    // ─── Passkey Login Finish ────────────────────────────────────────────
    .post('/passkey/login/finish', async ({ body }) => {
      if (!config.passkeysEnabled) {
        return { success: false, error: 'Passkey authentication is not enabled' };
      }

      const expectedChallenge = challenges.get(body.sessionId);
      if (!expectedChallenge) {
        return { success: false, error: 'No challenge found' };
      }

      const result = await passkeyService.verifyAuthentication(body.response, expectedChallenge);
      challenges.delete(body.sessionId);

      if (!result.verified || !result.userId) {
        return { success: false, error: result.error };
      }

      const user = await userService.findById(result.userId);
      if (!user) {
        return { success: false, error: 'User not found' };
      }

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
    })

    // ─── Invite Links ────────────────────────────────────────────────────
    .post('/invite', async ({ body, headers, cookie }) => {
      const claims = await requireAuthClaims(headers, cookie, config);

      const invite = await inviteService.createInvite(claims.sub, {
        email: body.email,
        roleId: body.roleId,
        maxUses: body.maxUses,
        expiresAt: body.expiresAt ? new Date(body.expiresAt) : undefined,
      });

      return { success: true, invite };
    }, {
      body: t.Object({
        email: t.Optional(t.String({ format: 'email' })),
        roleId: t.Optional(t.String()),
        maxUses: t.Optional(t.Number()),
        expiresAt: t.Optional(t.String()),
      }),
    })

    .get('/invites', async ({ headers, cookie }) => {
      const claims = await requireAuthClaims(headers, cookie, config);
      const invites = await inviteService.listInvites(claims.sub);
      return { success: true, invites };
    })

    .delete('/invite/:id', async ({ params, headers, cookie }) => {
      await requireAuthClaims(headers, cookie, config);
      await inviteService.deleteInvite(params.id);
      return { success: true, message: 'Invite deleted' };
    })

    // ─── API Keys ────────────────────────────────────────────────────────
    .post('/api-keys', async ({ body, headers, cookie }) => {
      const claims = await requireAuthClaims(headers, cookie, config);
      const { apiKey, rawKey } = await apiKeyService.createApiKey(claims.sub, body.name, config.flashAuth);
      return { success: true, apiKey, rawKey };
    }, {
      body: t.Object({
        name: t.String(),
      }),
    })

    .get('/api-keys', async ({ headers, cookie }) => {
      const claims = await requireAuthClaims(headers, cookie, config);
      const keys = await apiKeyService.listApiKeys(claims.sub);
      return { success: true, apiKeys: keys };
    })

    .delete('/api-keys/:id', async ({ params, headers, cookie }) => {
      const claims = await requireAuthClaims(headers, cookie, config);
      await apiKeyService.deleteApiKey(params.id, claims.sub);
      return { success: true, message: 'API key deleted' };
    })

    // ─── Roles ───────────────────────────────────────────────────────────
    .post('/roles', async ({ body, headers, cookie }) => {
      await requireAuthClaims(headers, cookie, config);
      const role = await permissionService.createRole(body.name, body.description);
      return { success: true, role };
    }, {
      body: t.Object({
        name: t.String(),
        description: t.Optional(t.String()),
      }),
    })

    .get('/roles', async () => {
      const rolesList = await permissionService.listRoles();
      return { success: true, roles: rolesList };
    })

    .delete('/roles/:id', async ({ params, headers, cookie }) => {
      await requireAuthClaims(headers, cookie, config);
      await permissionService.deleteRole(params.id);
      return { success: true, message: 'Role deleted' };
    })

    // ─── Permissions ─────────────────────────────────────────────────────
    .post('/permissions', async ({ body, headers, cookie }) => {
      await requireAuthClaims(headers, cookie, config);
      const permission = await permissionService.createPermission(body.name, body.description);
      return { success: true, permission };
    }, {
      body: t.Object({
        name: t.String(),
        description: t.Optional(t.String()),
      }),
    })

    .get('/permissions', async () => {
      const permissionsList = await permissionService.listPermissions();
      return { success: true, permissions: permissionsList };
    })

    .delete('/permissions/:id', async ({ params, headers, cookie }) => {
      await requireAuthClaims(headers, cookie, config);
      await permissionService.deletePermission(params.id);
      return { success: true, message: 'Permission deleted' };
    })

    // ─── User Roles ──────────────────────────────────────────────────────
    .post('/users/:userId/roles', async ({ params, body, headers, cookie }) => {
      await requireAuthClaims(headers, cookie, config);
      await permissionService.assignRoleToUser(params.userId, body.roleId);
      return { success: true, message: 'Role assigned to user' };
    }, {
      body: t.Object({
        roleId: t.String(),
      }),
    })

    .delete('/users/:userId/roles/:roleId', async ({ params, headers, cookie }) => {
      await requireAuthClaims(headers, cookie, config);
      await permissionService.removeRoleFromUser(params.userId, params.roleId);
      return { success: true, message: 'Role removed from user' };
    })

    // ─── User Permissions ────────────────────────────────────────────────
    .post('/users/:userId/permissions', async ({ params, body, headers, cookie }) => {
      await requireAuthClaims(headers, cookie, config);
      await permissionService.assignPermissionToUser(params.userId, body.permissionId);
      return { success: true, message: 'Permission assigned to user' };
    }, {
      body: t.Object({
        permissionId: t.String(),
      }),
    })

    .delete('/users/:userId/permissions/:permissionId', async ({ params, headers, cookie }) => {
      await requireAuthClaims(headers, cookie, config);
      await permissionService.removePermissionFromUser(params.userId, params.permissionId);
      return { success: true, message: 'Permission removed from user' };
    })

    .get('/users/:userId/permissions', async ({ params, headers, cookie }) => {
      await requireAuthClaims(headers, cookie, config);
      const perms = await permissionService.getUserPermissions(params.userId);
      return { success: true, permissions: perms };
    })

    // ─── Role Permissions ────────────────────────────────────────────────
    .post('/roles/:roleId/permissions', async ({ params, body, headers, cookie }) => {
      await requireAuthClaims(headers, cookie, config);
      await permissionService.assignPermissionToRole(params.roleId, body.permissionId);
      return { success: true, message: 'Permission assigned to role' };
    }, {
      body: t.Object({
        permissionId: t.String(),
      }),
    })

    .delete('/roles/:roleId/permissions/:permissionId', async ({ params, headers, cookie }) => {
      await requireAuthClaims(headers, cookie, config);
      await permissionService.removePermissionFromRole(params.roleId, params.permissionId);
      return { success: true, message: 'Permission removed from role' };
    });
}
