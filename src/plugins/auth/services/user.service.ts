/**
 * User service for user CRUD operations
 */

import type { DatabaseConnection } from '../utils/db.js';
import type { User, CreateUserInput } from '../models/user.model.js';
import type { AuthPluginConfig } from '../config.js';
import { PasswordService } from './password.service.js';

export class UserService {
  private db: DatabaseConnection;
  private passwordService: PasswordService;

  constructor(db: DatabaseConnection, config: AuthPluginConfig) {
    this.db = db;
    this.passwordService = new PasswordService(config);
  }

  /**
   * Create a new user
   */
  async createUser(input: CreateUserInput): Promise<User> {
    // Validate email format
    if (!this.isValidEmail(input.email)) {
      throw new Error('Invalid email format');
    }

    // Validate password strength
    const passwordValidation = this.passwordService.validatePasswordStrength(input.password);
    if (!passwordValidation.valid) {
      throw new Error(passwordValidation.errors.join(', '));
    }

    // Check if user already exists
    const existing = await this.findByEmail(input.email);
    if (existing) {
      throw new Error('User with this email already exists');
    }

    // Hash password
    const password_hash = await this.passwordService.hashPassword(input.password);

    // Insert user
    const sql = `
      INSERT INTO users (email, password_hash, email_verified)
      VALUES ($1, $2, $3)
      RETURNING *
    `;

    const user = await this.db.queryOne<User>(sql, [input.email, password_hash, false]);
    if (!user) {
      throw new Error('Failed to create user');
    }

    return user;
  }

  /**
   * Find user by ID
   */
  async findById(id: string): Promise<User | null> {
    const sql = 'SELECT * FROM users WHERE id = $1';
    return await this.db.queryOne<User>(sql, [id]);
  }

  /**
   * Find user by email
   */
  async findByEmail(email: string): Promise<User | null> {
    const sql = 'SELECT * FROM users WHERE email = $1';
    return await this.db.queryOne<User>(sql, [email]);
  }

  /**
   * Update user's email verification status
   */
  async markEmailVerified(userId: string): Promise<void> {
    const sql = 'UPDATE users SET email_verified = $1 WHERE id = $2';
    await this.db.execute(sql, [true, userId]);
  }

  /**
   * Update user's password
   */
  async updatePassword(userId: string, newPassword: string): Promise<void> {
    // Validate password strength
    const passwordValidation = this.passwordService.validatePasswordStrength(newPassword);
    if (!passwordValidation.valid) {
      throw new Error(passwordValidation.errors.join(', '));
    }

    // Hash new password
    const password_hash = await this.passwordService.hashPassword(newPassword);

    // Update password
    const sql = 'UPDATE users SET password_hash = $1 WHERE id = $2';
    await this.db.execute(sql, [password_hash, userId]);
  }

  /**
   * Verify user password
   */
  async verifyPassword(userId: string, password: string): Promise<boolean> {
    const user = await this.findById(userId);
    if (!user) {
      return false;
    }

    return await this.passwordService.verifyPassword(password, user.password_hash);
  }

  /**
   * Authenticate user with email and password
   */
  async authenticate(email: string, password: string): Promise<User | null> {
    const user = await this.findByEmail(email);
    if (!user) {
      return null;
    }

    const valid = await this.passwordService.verifyPassword(password, user.password_hash);
    if (!valid) {
      return null;
    }

    return user;
  }

  /**
   * Delete user
   */
  async deleteUser(userId: string): Promise<void> {
    const sql = 'DELETE FROM users WHERE id = $1';
    await this.db.execute(sql, [userId]);
  }

  /**
   * Validate email format
   */
  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }
}
