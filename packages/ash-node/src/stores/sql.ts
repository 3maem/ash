/**
 * SQL context store.
 *
 * Production-ready store for SQL databases.
 * Supports PostgreSQL, MySQL, and SQLite through a generic interface.
 */

import type { AshContext, AshContextOptions, AshContextStore } from '../index';
import { randomBytes } from 'crypto';

/**
 * SQL store configuration options.
 */
export interface AshSqlStoreOptions {
  /** SQL query executor */
  query: SqlQueryExecutor;
  /** Table name for contexts */
  tableName?: string;
}

/**
 * Generic SQL query executor interface.
 * Implement this for your specific database driver.
 */
export interface SqlQueryExecutor {
  /**
   * Execute a SQL query with parameters.
   * Parameters use $1, $2, etc. placeholders (PostgreSQL style).
   */
  execute<T = unknown>(sql: string, params?: unknown[]): Promise<T[]>;
}

/**
 * SQL row representation of a context.
 */
interface ContextRow {
  id: string;
  binding: string;
  expires_at: number;
  mode: string;
  used: boolean | number;
  nonce: string | null;
  metadata: string | null;
}

/**
 * SQL implementation of AshContextStore.
 *
 * @example
 * ```typescript
 * import { Pool } from 'pg';
 *
 * const pool = new Pool();
 * const store = new AshSqlStore({
 *   query: {
 *     execute: async (sql, params) => {
 *       const result = await pool.query(sql, params);
 *       return result.rows;
 *     },
 *   },
 * });
 *
 * // Create table (run once)
 * await store.createTable();
 *
 * const ctx = await store.create({
 *   binding: 'POST /api/update',
 *   ttlMs: 30000,
 * });
 * ```
 */
export class AshSqlStore implements AshContextStore {
  private query: SqlQueryExecutor;
  private tableName: string;

  constructor(options: AshSqlStoreOptions) {
    this.query = options.query;
    this.tableName = options.tableName ?? 'ash_contexts';
  }

  /**
   * Create the contexts table.
   * Run this once during setup.
   */
  async createTable(): Promise<void> {
    const sql = `
      CREATE TABLE IF NOT EXISTS ${this.tableName} (
        id VARCHAR(64) PRIMARY KEY,
        binding VARCHAR(255) NOT NULL,
        expires_at BIGINT NOT NULL,
        mode VARCHAR(16) NOT NULL,
        used BOOLEAN NOT NULL DEFAULT FALSE,
        nonce VARCHAR(64),
        metadata TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    await this.query.execute(sql);

    // Create index for cleanup
    await this.query.execute(
      `CREATE INDEX IF NOT EXISTS idx_${this.tableName}_expires ON ${this.tableName} (expires_at)`
    );
  }

  /**
   * Create a new context.
   */
  async create(options: AshContextOptions): Promise<AshContext> {
    const id = `ctx_${randomBytes(16).toString('hex')}`;
    const nonce = options.mode === 'strict' ? randomBytes(16).toString('hex') : undefined;

    const context: AshContext = {
      id,
      binding: options.binding,
      expiresAt: Date.now() + options.ttlMs,
      mode: options.mode ?? 'balanced',
      used: false,
      nonce,
      metadata: options.metadata,
    };

    const sql = `
      INSERT INTO ${this.tableName} (id, binding, expires_at, mode, used, nonce, metadata)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
    `;

    await this.query.execute(sql, [
      context.id,
      context.binding,
      context.expiresAt,
      context.mode,
      false,
      context.nonce ?? null,
      context.metadata ? JSON.stringify(context.metadata) : null,
    ]);

    return context;
  }

  /**
   * Get a context by ID.
   */
  async get(id: string): Promise<AshContext | null> {
    const sql = `
      SELECT id, binding, expires_at, mode, used, nonce, metadata
      FROM ${this.tableName}
      WHERE id = $1 AND expires_at > $2
    `;

    const rows = await this.query.execute<ContextRow>(sql, [id, Date.now()]);

    if (rows.length === 0) {
      return null;
    }

    const row = rows[0];
    return this.rowToContext(row);
  }

  /**
   * Consume a context atomically.
   */
  async consume(id: string): Promise<boolean> {
    // Use UPDATE with WHERE to ensure atomicity
    const sql = `
      UPDATE ${this.tableName}
      SET used = TRUE
      WHERE id = $1 AND used = FALSE AND expires_at > $2
    `;

    const result = await this.query.execute<{ rowCount?: number }>(sql, [id, Date.now()]);

    // Check if any row was updated
    // Different drivers return this differently
    if (Array.isArray(result) && result.length > 0) {
      return true;
    }

    return false;
  }

  /**
   * Remove expired contexts.
   */
  async cleanup(): Promise<number> {
    const sql = `
      DELETE FROM ${this.tableName}
      WHERE expires_at < $1
    `;

    const result = await this.query.execute<{ rowCount?: number }>(sql, [Date.now()]);

    // Return count of deleted rows if available
    return result.rowCount ?? 0;
  }

  private rowToContext(row: ContextRow): AshContext {
    return {
      id: row.id,
      binding: row.binding,
      expiresAt: Number(row.expires_at),
      mode: row.mode as AshContext['mode'],
      used: Boolean(row.used),
      nonce: row.nonce ?? undefined,
      metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
    };
  }
}
