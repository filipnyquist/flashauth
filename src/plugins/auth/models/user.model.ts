/**
 * User model - re-exports from Drizzle schema
 */

export type { User, NewUser } from '../../../schema/index.js';
import type { User } from '../../../schema/index.js';

export interface CreateUserInput {
  email: string;
  password: string;
}

export interface UserPublic {
  id: string;
  email: string;
  emailVerified: boolean;
  createdAt: Date;
}

/**
 * Convert User to public-facing UserPublic
 */
export function toPublicUser(user: User): UserPublic {
  return {
    id: user.id,
    email: user.email,
    emailVerified: user.emailVerified,
    createdAt: user.createdAt,
  };
}
