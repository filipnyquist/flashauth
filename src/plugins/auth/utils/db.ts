/**
 * Database utilities using PostgreSQL client compatible with Bun
 * Uses postgres.js which is optimized for Bun runtime
 */

/**
 * PostgreSQL database connection wrapper
 * 
 * @example
 * ```typescript
 * const db = new DatabaseConnection(process.env.DATABASE_URL!);
 * const users = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
 * ```
 */
export class DatabaseConnection {
  private connectionUrl: string;
  private postgresClient: any = null;

  constructor(connectionString: string) {
    this.connectionUrl = connectionString;
  }

  /**
   * Get or create PostgreSQL client
   * Uses dynamic import to load postgres package
   */
  private async getClient() {
    if (!this.postgresClient) {
      try {
        // Import postgres package (postgres.js compatible with Bun)
        const postgres = (await import('postgres')).default;
        this.postgresClient = postgres(this.connectionUrl);
      } catch (error) {
        throw new Error(
          'PostgreSQL client not found. Please install: bun add postgres\n' +
          'Error: ' + (error as Error).message
        );
      }
    }
    return this.postgresClient;
  }

  /**
   * Execute a query and return all rows
   */
  async query<T = any>(sqlQuery: string, params?: any[]): Promise<T[]> {
    try {
      const sql = await this.getClient();
      
      // postgres.js uses $1, $2 syntax natively
      const result = await sql.unsafe(sqlQuery, params || []);
      return result as T[];
    } catch (error) {
      throw new Error(`Database query failed: ${(error as Error).message}`);
    }
  }

  /**
   * Execute a query and return a single row
   */
  async queryOne<T = any>(sqlQuery: string, params?: any[]): Promise<T | null> {
    const results = await this.query<T>(sqlQuery, params);
    return results[0] || null;
  }

  /**
   * Execute a query that doesn't return rows (INSERT, UPDATE, DELETE)
   */
  async execute(sqlQuery: string, params?: any[]): Promise<void> {
    try {
      const sql = await this.getClient();
      await sql.unsafe(sqlQuery, params || []);
    } catch (error) {
      throw new Error(`Database execute failed: ${(error as Error).message}`);
    }
  }

  /**
   * Run migrations from SQL file
   */
  async runMigrations(migrationSql: string): Promise<void> {
    // Split by semicolon and execute each statement
    const statements = migrationSql
      .split(';')
      .map(s => s.trim())
      .filter(s => s.length > 0);

    for (const statement of statements) {
      await this.execute(statement);
    }
  }

  /**
   * Close the connection
   */
  async close(): Promise<void> {
    if (this.postgresClient) {
      await this.postgresClient.end();
    }
  }
}

/**
 * Create a database connection
 */
export function createDatabaseConnection(connectionString: string): DatabaseConnection {
  return new DatabaseConnection(connectionString);
}
