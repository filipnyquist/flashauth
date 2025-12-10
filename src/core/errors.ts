/**
 * FlashAuth Error Hierarchy
 * Custom error classes for precise error handling
 */

export class FlashAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FlashAuthError';
    Object.setPrototypeOf(this, FlashAuthError.prototype);
  }
}

export class TokenError extends FlashAuthError {
  constructor(message: string) {
    super(message);
    this.name = 'TokenError';
    Object.setPrototypeOf(this, TokenError.prototype);
  }
}

export class TokenExpiredError extends TokenError {
  constructor(message: string = 'Token has expired') {
    super(message);
    this.name = 'TokenExpiredError';
    Object.setPrototypeOf(this, TokenExpiredError.prototype);
  }
}

export class TokenInvalidError extends TokenError {
  constructor(message: string = 'Token is invalid') {
    super(message);
    this.name = 'TokenInvalidError';
    Object.setPrototypeOf(this, TokenInvalidError.prototype);
  }
}

export class TokenRevokedError extends TokenError {
  constructor(message: string = 'Token has been revoked') {
    super(message);
    this.name = 'TokenRevokedError';
    Object.setPrototypeOf(this, TokenRevokedError.prototype);
  }
}

export class PermissionError extends FlashAuthError {
  constructor(message: string) {
    super(message);
    this.name = 'PermissionError';
    Object.setPrototypeOf(this, PermissionError.prototype);
  }
}

export class SessionError extends FlashAuthError {
  constructor(message: string) {
    super(message);
    this.name = 'SessionError';
    Object.setPrototypeOf(this, SessionError.prototype);
  }
}

export class CryptographyError extends FlashAuthError {
  constructor(message: string) {
    super(message);
    this.name = 'CryptographyError';
    Object.setPrototypeOf(this, CryptographyError.prototype);
  }
}

export class KeyError extends FlashAuthError {
  constructor(message: string) {
    super(message);
    this.name = 'KeyError';
    Object.setPrototypeOf(this, KeyError.prototype);
  }
}

export class ValidationError extends FlashAuthError {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}
