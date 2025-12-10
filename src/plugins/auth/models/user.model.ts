/**
 * User model
 */

export interface User {
  id: string;
  email: string;
  password_hash: string;
  email_verified: boolean;
  created_at: Date;
  updated_at: Date;
}

export interface CreateUserInput {
  email: string;
  password: string;
}

export interface UserPublic {
  id: string;
  email: string;
  email_verified: boolean;
  created_at: Date;
}

/**
 * Convert User to public-facing UserPublic
 */
export function toPublicUser(user: User): UserPublic {
  return {
    id: user.id,
    email: user.email,
    email_verified: user.email_verified,
    created_at: user.created_at,
  };
}
