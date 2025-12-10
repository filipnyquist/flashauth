/**
 * FlashAuth Authentication Plugin Example
 * Demonstrates user signup, login, 2FA, and passkeys
 */

import { Elysia } from 'elysia';
import { FlashAuth, flashAuth, flashAuthPlugin } from '../src/index.js';

// Initialize FlashAuth
const auth = new FlashAuth({
  secret: FlashAuth.generateSecret(),
  rolePermissions: {
    'user': ['posts:read', 'posts:write', 'profile:read', 'profile:write'],
    'admin': ['*'],
  },
});

// Create Elysia app with authentication plugin
const app = new Elysia()
  // Add FlashAuth token plugin
  .use(flashAuth(auth))
  
  // Add authentication plugin with user management
  .use(flashAuthPlugin({
    // Database connection (using in-memory for example)
    databaseUrl: process.env.DATABASE_URL || 'postgres://localhost:5432/flashauth',
    
    // FlashAuth instance for token management
    flashAuth: auth,
    
    // WebAuthn/Passkey configuration
    webauthn: {
      rpName: 'FlashAuth Example',
      rpID: 'localhost',
      origin: 'http://localhost:3000',
    },
    
    // Optional: Email service configuration
    email: {
      sendVerification: async (email: string, token: string) => {
        console.log(`📧 Verification email to ${email}:`);
        console.log(`   Token: ${token}`);
        console.log(`   Verify at: http://localhost:3000/verify?token=${token}`);
      },
      sendPasswordReset: async (email: string, token: string) => {
        console.log(`📧 Password reset email to ${email}:`);
        console.log(`   Token: ${token}`);
        console.log(`   Reset at: http://localhost:3000/reset?token=${token}`);
      },
    },
    
    // Token expiration times
    tokenExpiration: {
      emailVerification: 24 * 60 * 60, // 24 hours
      passwordReset: 60 * 60, // 1 hour
      session: 7 * 24 * 60 * 60, // 7 days
    },
    
    // Security settings
    security: {
      minPasswordLength: 8,
      requireUppercase: false,
      requireLowercase: false,
      requireNumber: false,
      requireSpecialChar: false,
    },
  }))
  
  // Public routes
  .get('/', () => ({
    message: 'FlashAuth Authentication Example',
    endpoints: {
      auth: {
        signup: 'POST /auth/signup',
        verifyEmail: 'POST /auth/verify-email',
        login: 'POST /auth/login',
        login2fa: 'POST /auth/login/2fa',
        passwordResetRequest: 'POST /auth/password-reset/request',
        passwordResetConfirm: 'POST /auth/password-reset/confirm',
      },
      twoFactor: {
        setup: 'POST /auth/2fa/setup (requires auth)',
        verify: 'POST /auth/2fa/verify (requires auth)',
        disable: 'POST /auth/2fa/disable (requires auth)',
      },
      passkey: {
        registerStart: 'POST /auth/passkey/register/start (requires auth)',
        registerFinish: 'POST /auth/passkey/register/finish (requires auth)',
        loginStart: 'POST /auth/passkey/login/start',
        loginFinish: 'POST /auth/passkey/login/finish',
      },
    },
  }))
  
  // Error handler
  .onError(({ code, error, set }) => {
    console.error(`[${code}]`, error);
    
    if (code === 'VALIDATION') {
      set.status = 400;
      return {
        error: 'Validation Error',
        message: error.message,
      };
    }
    
    if (error.name === 'TokenError') {
      set.status = 401;
      return {
        error: 'Unauthorized',
        message: error.message,
      };
    }
    
    if (error.name === 'PermissionError') {
      set.status = 403;
      return {
        error: 'Forbidden',
        message: error.message,
      };
    }
    
    set.status = 500;
    return {
      error: 'Internal Server Error',
      message: error.message,
    };
  })
  
  .listen(3000);

console.log(`🚀 FlashAuth Authentication Example running at http://${app.server?.hostname}:${app.server?.port}`);
console.log('\n📚 Available Authentication Flows:');
console.log('\n1. Sign Up & Email Verification:');
console.log('   POST /auth/signup');
console.log('   POST /auth/verify-email');
console.log('\n2. Login:');
console.log('   POST /auth/login');
console.log('\n3. Password Reset:');
console.log('   POST /auth/password-reset/request');
console.log('   POST /auth/password-reset/confirm');
console.log('\n4. Two-Factor Authentication (2FA):');
console.log('   POST /auth/2fa/setup (requires auth token)');
console.log('   POST /auth/2fa/verify (requires auth token)');
console.log('   POST /auth/login/2fa (for login with 2FA)');
console.log('\n5. Passkey/WebAuthn:');
console.log('   POST /auth/passkey/register/start (requires auth token)');
console.log('   POST /auth/passkey/register/finish (requires auth token)');
console.log('   POST /auth/passkey/login/start');
console.log('   POST /auth/passkey/login/finish');
console.log('\n⚠️  Note: This example uses an in-memory database. For production, configure a PostgreSQL connection.');
console.log('⚠️  Run migrations before starting: node -e "require(\'./migrations/001_initial.sql\')"');
