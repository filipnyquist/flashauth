/**
 * Database utilities using Bun's built-in SQL client for PostgreSQL
 * https://bun.com/docs/runtime/sql
 */

/**
 * PostgreSQL database connection wrapper using Bun.SQL
 * 
 * @example
 * ```typescript
 * const db = new DatabaseConnection(process.env.DATABASE_URL!);
 * const users = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
 * ```
 */
export class DatabaseConnection {
  private sql: any;

  constructor(connectionString: string) {
    // Use Bun's built-in SQL client for PostgreSQL
    // new SQL(url) creates a connection with the specified PostgreSQL URL
    this.sql = new Bun.SQL(connectionString);
  }

  /**
   * Execute a query and return all rows
   * Uses Bun.SQL with parameterized queries
   */
  async query<T = any>(sqlQuery: string, params?: any[]): Promise<T[]> {
    try {
      // Use sql.unsafe() for parameterized queries with $1, $2, etc.
      // Bun.SQL automatically handles parameterized queries safely
      const result = await this.sql.unsafe(sqlQuery, params || []);
      // Ensure we always return an array
      return Array.isArray(result) ? result : (result ? [result] : []);
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
      await this.sql.unsafe(sqlQuery, params || []);
    } catch (error) {
      throw new Error(`Database execute failed: ${(error as Error).message}`);
    }
  }

  /**
   * Run migrations from SQL file
   * Uses sql.file() if available, otherwise falls back to splitting statements
   */
  async runMigrations(migrationSql: string): Promise<void> {
    // For multiple statements, we need to use simple() or split them
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
    if (this.sql) {
      await this.sql.close();
    }
  }
}

/**
 * Create a database connection using Bun's built-in SQL client
 */
export function createDatabaseConnection(connectionString: string): DatabaseConnection {
  return new DatabaseConnection(connectionString);
}
