/**
 * User service using Drizzle ORM
 */

import { eq } from 'drizzle-orm';
import { users } from '../../../schema/index.js';
import type { User } from '../../../schema/index.js';
import type { CreateUserInput } from '../models/user.model.js';
import type { AuthPluginConfig } from '../config.js';
import { PasswordService } from './password.service.js';

export class UserService {
  private db: any;
  private passwordService: PasswordService;

  constructor(db: any, config: AuthPluginConfig) {
    this.db = db;
    this.passwordService = new PasswordService(config);
  }

  /**
   * Create a new user
   */
  async createUser(input: CreateUserInput): Promise<User> {
    if (!this.isValidEmail(input.email)) {
      throw new Error('Invalid email format');
    }

    const passwordValidation = this.passwordService.validatePasswordStrength(input.password);
    if (!passwordValidation.valid) {
      throw new Error(passwordValidation.errors.join(', '));
    }

    const existing = await this.findByEmail(input.email);
    if (existing) {
      throw new Error('User with this email already exists');
    }

    const passwordHash = await this.passwordService.hashPassword(input.password);

    const [newUser] = await this.db.insert(users).values({
      email: input.email,
      passwordHash,
      emailVerified: false,
    }).returning();

    if (!newUser) {
      throw new Error('Failed to create user');
    }

    return newUser;
  }

  /**
   * Find user by ID
   */
  async findById(id: string): Promise<User | null> {
    const results = await this.db.select().from(users).where(eq(users.id, id)).limit(1);
    return results[0] ?? null;
  }

  /**
   * Find user by email
   */
  async findByEmail(email: string): Promise<User | null> {
    const results = await this.db.select().from(users).where(eq(users.email, email)).limit(1);
    return results[0] ?? null;
  }

  /**
   * Update user's email verification status
   */
  async markEmailVerified(userId: string): Promise<void> {
    await this.db.update(users).set({ emailVerified: true }).where(eq(users.id, userId));
  }

  /**
   * Update user's password
   */
  async updatePassword(userId: string, newPassword: string): Promise<void> {
    const passwordValidation = this.passwordService.validatePasswordStrength(newPassword);
    if (!passwordValidation.valid) {
      throw new Error(passwordValidation.errors.join(', '));
    }

    const passwordHash = await this.passwordService.hashPassword(newPassword);
    await this.db.update(users).set({ passwordHash }).where(eq(users.id, userId));
  }

  /**
   * Verify user password
   */
  async verifyPassword(userId: string, password: string): Promise<boolean> {
    const user = await this.findById(userId);
    if (!user || !user.passwordHash) {
      return false;
    }

    return await this.passwordService.verifyPassword(password, user.passwordHash);
  }

  /**
   * Authenticate user with email and password
   */
  async authenticate(email: string, password: string): Promise<User | null> {
    const user = await this.findByEmail(email);
    if (!user || !user.passwordHash) {
      return null;
    }

    const valid = await this.passwordService.verifyPassword(password, user.passwordHash);
    if (!valid) {
      return null;
    }

    return user;
  }

  /**
   * Delete user
   */
  async deleteUser(userId: string): Promise<void> {
    await this.db.delete(users).where(eq(users.id, userId));
  }

  /**
   * Validate email format
   */
  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }
}
