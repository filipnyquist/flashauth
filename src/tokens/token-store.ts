/**
 * FlashAuth Token Store
 * Token revocation and caching
 */

/**
 * Token revocation store interface
 */
export interface RevocationStore {
  /**
   * Add a token ID to the revocation list
   */
  revoke(jti: string, expiresAt: number): Promise<void>;

  /**
   * Check if a token ID is revoked
   */
  isRevoked(jti: string): Promise<boolean>;

  /**
   * Revoke all tokens for a user
   */
  revokeUser(userId: string): Promise<void>;

  /**
   * Check if any user tokens are revoked
   */
  isUserRevoked(userId: string): Promise<boolean>;

  /**
   * Clean up expired revocations
   */
  cleanup(): Promise<void>;
}

/**
 * In-memory revocation store
 */
export class InMemoryRevocationStore implements RevocationStore {
  private revokedTokens: Map<string, number> = new Map();
  private revokedUsers: Set<string> = new Set();
  private cleanupInterval: Timer | null = null;

  constructor() {
    // Auto-cleanup every 5 minutes
    this.cleanupInterval = setInterval(() => {
      this.cleanup().catch((err) => {
        console.error('Cleanup failed:', err);
      });
    }, 5 * 60 * 1000);
  }

  async revoke(jti: string, expiresAt: number): Promise<void> {
    this.revokedTokens.set(jti, expiresAt);
  }

  async isRevoked(jti: string): Promise<boolean> {
    return this.revokedTokens.has(jti);
  }

  async revokeUser(userId: string): Promise<void> {
    this.revokedUsers.add(userId);
  }

  async isUserRevoked(userId: string): Promise<boolean> {
    return this.revokedUsers.has(userId);
  }

  async cleanup(): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    for (const [jti, expiresAt] of this.revokedTokens.entries()) {
      if (expiresAt < now) {
        this.revokedTokens.delete(jti);
      }
    }
  }

  /**
   * Stop cleanup interval
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  /**
   * Get revocation stats
   */
  getStats(): { revokedTokens: number; revokedUsers: number } {
    return {
      revokedTokens: this.revokedTokens.size,
      revokedUsers: this.revokedUsers.size,
    };
  }
}

/**
 * LRU cache for validated tokens
 */
export class TokenCache {
  private cache: Map<string, { claims: unknown; expiresAt: number }> = new Map();
  private maxSize: number;
  private ttl: number;

  constructor(options: { maxSize?: number; ttl?: number } = {}) {
    this.maxSize = options.maxSize ?? 10000;
    this.ttl = options.ttl ?? 5 * 60 * 1000; // 5 minutes default
  }

  /**
   * Get cached token claims
   */
  get(token: string): unknown | null {
    const cached = this.cache.get(token);
    if (!cached) {
      return null;
    }

    // Check if expired
    if (Date.now() > cached.expiresAt) {
      this.cache.delete(token);
      return null;
    }

    return cached.claims;
  }

  /**
   * Cache token claims
   */
  set(token: string, claims: unknown): void {
    // Evict oldest entry if cache is full
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey !== undefined) {
        this.cache.delete(firstKey);
      }
    }

    this.cache.set(token, {
      claims,
      expiresAt: Date.now() + this.ttl,
    });
  }

  /**
   * Invalidate cached token
   */
  invalidate(token: string): void {
    this.cache.delete(token);
  }

  /**
   * Clear all cached tokens
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Get cache stats
   */
  getStats(): { size: number; maxSize: number } {
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
    };
  }
}
