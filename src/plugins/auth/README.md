# FlashAuth Authentication Plugin

Complete user authentication plugin for FlashAuth with email/password signup, email verification, password reset, TOTP 2FA, and passkey support.

## Features

- ✅ **Email/Password Authentication** - User signup and login with Bun's native password hashing
- ✅ **Email Verification** - Secure email verification flow with time-limited tokens
- ✅ **Password Reset** - Secure password reset flow with time-limited tokens
- ✅ **TOTP 2FA** - Time-based One-Time Password two-factor authentication using otplib
- ✅ **Passkey/WebAuthn** - Passwordless authentication using @simplewebauthn/server
- ✅ **PostgreSQL Storage** - Database schema for users, tokens, and credentials
- ✅ **Type-Safe** - Full TypeScript support
- ✅ **Elysia Plugin** - First-class integration with Elysia.js

## Installation

```bash
bun add flashauth otplib @simplewebauthn/server
```

## Quick Start

```typescript
import { Elysia } from 'elysia';
import { FlashAuth, flashAuth, flashAuthPlugin } from 'flashauth';

const auth = new FlashAuth({
  secret: process.env.AUTH_SECRET!,
});

const app = new Elysia()
  .use(flashAuth(auth))
  .use(flashAuthPlugin({
    databaseUrl: process.env.DATABASE_URL!,
    flashAuth: auth,
    webauthn: {
      rpName: 'My App',
      rpID: 'example.com',
      origin: 'https://example.com',
    },
  }))
  .listen(3000);
```

## Database Setup

### 1. Create PostgreSQL Database

```bash
createdb flashauth
```

### 2. Run Migrations

Use the provided SQL migration file:

```sql
-- Run src/plugins/auth/migrations/001_initial.sql
psql flashauth < src/plugins/auth/migrations/001_initial.sql
```

Or programmatically:

```typescript
import { runMigrations } from 'flashauth';
import { readFileSync } from 'fs';

const migrationSql = readFileSync('./migrations/001_initial.sql', 'utf-8');
await runMigrations(process.env.DATABASE_URL!, migrationSql);
```

## API Routes

The plugin automatically creates the following routes:

### Authentication

- `POST /auth/signup` - Register new user
- `POST /auth/verify-email` - Verify email with token
- `POST /auth/login` - Login with email/password
- `POST /auth/login/2fa` - Complete login with TOTP code

### Password Reset

- `POST /auth/password-reset/request` - Request password reset
- `POST /auth/password-reset/confirm` - Confirm password reset with token

### Two-Factor Authentication

- `POST /auth/2fa/setup` - Setup TOTP 2FA (requires auth)
- `POST /auth/2fa/verify` - Verify and enable 2FA (requires auth)
- `POST /auth/2fa/disable` - Disable 2FA (requires auth)

### Passkey/WebAuthn

- `POST /auth/passkey/register/start` - Start passkey registration (requires auth)
- `POST /auth/passkey/register/finish` - Finish passkey registration (requires auth)
- `POST /auth/passkey/login/start` - Start passkey login
- `POST /auth/passkey/login/finish` - Finish passkey login

## Configuration

```typescript
interface AuthPluginConfig {
  // Database connection string
  databaseUrl: string;

  // FlashAuth instance
  flashAuth: FlashAuth;

  // WebAuthn configuration
  webauthn: {
    rpName: string;      // App name
    rpID: string;        // Domain (e.g., 'example.com')
    origin: string | string[]; // Expected origin(s)
  };

  // Optional: Email service
  email?: {
    sendVerification?: (email: string, token: string) => Promise<void>;
    sendPasswordReset?: (email: string, token: string) => Promise<void>;
  };

  // Optional: Token expiration times (in seconds)
  tokenExpiration?: {
    emailVerification?: number; // Default: 24 hours
    passwordReset?: number;     // Default: 1 hour
    session?: number;           // Default: 7 days
  };

  // Optional: Security settings
  security?: {
    minPasswordLength?: number;    // Default: 8
    requireUppercase?: boolean;    // Default: false
    requireLowercase?: boolean;    // Default: false
    requireNumber?: boolean;       // Default: false
    requireSpecialChar?: boolean;  // Default: false
  };
}
```

## Usage Examples

### User Signup

```bash
curl -X POST http://localhost:3000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'
```

### Email Verification

```bash
curl -X POST http://localhost:3000/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "token": "verification-token-here"
  }'
```

### Login

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'
```

### Setup 2FA

```bash
curl -X POST http://localhost:3000/auth/2fa/setup \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Passkey Registration

```typescript
// Client-side JavaScript
// 1. Start registration
const startResponse = await fetch('/auth/passkey/register/start', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
  },
});
const { options } = await startResponse.json();

// 2. Create credential using WebAuthn API
const credential = await navigator.credentials.create({
  publicKey: options,
});

// 3. Finish registration
const finishResponse = await fetch('/auth/passkey/register/finish', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ response: credential }),
});
```

## Database Schema

The plugin creates the following tables:

- `users` - User accounts
- `email_verification_tokens` - Email verification tokens
- `password_reset_tokens` - Password reset tokens
- `totp_secrets` - TOTP 2FA secrets and backup codes
- `passkey_credentials` - WebAuthn/Passkey credentials

See `migrations/001_initial.sql` for the complete schema.

## Security Considerations

- **Password Hashing**: Uses Bun's native bcrypt implementation
- **Token Generation**: Uses cryptographically secure random generation
- **TOTP**: Standard TOTP implementation with backup codes
- **WebAuthn**: Follows WebAuthn specification using SimpleWebAuthn
- **Email Enumeration**: Password reset doesn't reveal if email exists

## License

MIT
