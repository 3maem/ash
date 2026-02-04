/**
 * SQL context store.
 *
 * Production-ready store for SQL databases.
 * Supports PostgreSQL, MySQL, and SQLite through a generic interface.
 *
 * INFO-001 SECURITY NOTE: Nonces are stored in plaintext in the database.
 * This is necessary for the ASH protocol but means database compromise
 * exposes all nonces. Consider:
 * 1. Encrypting the nonce column at rest using database-level encryption
 * 2. Using a separate encryption key that's not stored in the database
 * 3. Implementing short TTLs to limit exposure window
 *
 * INFO-002 SECURITY NOTE: Key rotation is not built into this implementation.
 * For key rotation:
 * 1. Generate new nonces for all new contexts after rotation
 * 2. Allow old contexts to expire naturally (do not invalidate immediately)
 * 3. Monitor for any contexts that fail verification after rotation
 */

import type { AshContext, AshContextOptions, AshContextStore } from '../index';
import { randomBytes, createHmac } from 'crypto';

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
 * Result of an UPDATE/DELETE query with affected row count.
 */
export interface SqlMutationResult {
  /** Number of rows affected by the mutation */
  affectedRows?: number;
  /** Alternative property name used by some drivers */
  rowCount?: number;
  /** Alternative property name used by some drivers (mysql2) */
  changedRows?: number;
}

/**
 * Generic SQL query executor interface.
 * Implement this for your specific database driver.
 */
export interface SqlQueryExecutor {
  /**
   * Execute a SQL query with parameters.
   * Parameters use $1, $2, etc. placeholders (PostgreSQL style).
   *
   * For SELECT queries, returns array of rows.
   * For UPDATE/DELETE queries, should return SqlMutationResult or
   * an object with affectedRows/rowCount/changedRows property.
   */
  execute<T = unknown>(sql: string, params?: unknown[]): Promise<T[] | SqlMutationResult>;
}

/**
 * SQL row representation of a context.
 */
interface ContextRow {
  id: string;
  binding: string;
  expires_at: number;
  mode: string;
  // BUG-LOGIC-110: SQL drivers return booleans differently:
  // - PostgreSQL: boolean
  // - MySQL/SQLite: number (0 or 1)
  // - Some drivers: string ("true"/"false" or "0"/"1")
  used: boolean | number | string;
  nonce: string | null;
  client_secret: string | null;
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
/**
 * BUG-33 FIX: Common SQL reserved words that should not be used as table names.
 */
const SQL_RESERVED_WORDS = new Set([
  'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter', 'table',
  'index', 'view', 'database', 'schema', 'user', 'group', 'order', 'by',
  'where', 'from', 'join', 'on', 'and', 'or', 'not', 'null', 'true', 'false',
  'primary', 'key', 'foreign', 'references', 'constraint', 'unique', 'check',
  'default', 'values', 'into', 'set', 'grant', 'revoke', 'commit', 'rollback',
  'transaction', 'begin', 'end', 'case', 'when', 'then', 'else', 'if', 'exists',
  'in', 'like', 'between', 'is', 'as', 'distinct', 'all', 'any', 'some',
  'limit', 'offset', 'having', 'union', 'intersect', 'except', 'cross', 'inner',
  'outer', 'left', 'right', 'full', 'natural', 'using', 'column', 'row', 'rows',
]);

/**
 * Validates a SQL identifier (table name) to prevent SQL injection.
 * Only allows alphanumeric characters and underscores.
 * BUG-33 FIX: Also rejects SQL reserved words.
 */
function validateSqlIdentifier(name: string): string {
  // Only allow alphanumeric characters and underscores
  const validPattern = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
  if (!validPattern.test(name)) {
    throw new Error(
      `Invalid SQL identifier: "${name}". ` +
      'Table names must start with a letter or underscore and contain only alphanumeric characters and underscores.'
    );
  }
  // Limit length to prevent buffer overflow attacks
  if (name.length > 64) {
    throw new Error('SQL identifier too long (max 64 characters)');
  }
  // BUG-33 FIX: Check for SQL reserved words
  if (SQL_RESERVED_WORDS.has(name.toLowerCase())) {
    throw new Error(
      `Invalid SQL identifier: "${name}" is a SQL reserved word. ` +
      'Please choose a different table name.'
    );
  }
  return name;
}

export class AshSqlStore implements AshContextStore {
  private query: SqlQueryExecutor;
  private tableName: string;

  constructor(options: AshSqlStoreOptions) {
    this.query = options.query;
    // Validate table name to prevent SQL injection
    this.tableName = validateSqlIdentifier(options.tableName ?? 'ash_contexts');
  }

  /**
   * Create the contexts table.
   * Run this once during setup.
   *
   * BUG-24 FIX: binding column increased to TEXT to support MAX_BINDING_LENGTH (8192).
   * BUG-25 NOTE: This SQL uses PostgreSQL syntax. For MySQL/SQLite, you may need
   * to adjust the SQL syntax (e.g., BOOLEAN handling differs).
   */
  async createTable(): Promise<void> {
    const sql = `
      CREATE TABLE IF NOT EXISTS ${this.tableName} (
        id VARCHAR(64) PRIMARY KEY,
        binding TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        mode VARCHAR(16) NOT NULL,
        used BOOLEAN NOT NULL DEFAULT FALSE,
        nonce VARCHAR(128),
        client_secret VARCHAR(64),
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
   * Always generates a nonce for v2.1+ proof verification.
   * @throws Error if ttlMs is not a positive finite number
   */
  async create(options: AshContextOptions): Promise<AshContext> {
    // BUG-LOGIC-060 FIX: Validate ttlMs before creating context
    if (typeof options.ttlMs !== 'number' || !Number.isFinite(options.ttlMs) || options.ttlMs <= 0) {
      throw new Error('ttlMs must be a positive finite number');
    }

    // BUG-LOGIC-123 FIX: Validate TTL won't cause precision loss or overflow
    // Max safe TTL is ~10 years in ms to ensure Date.now() + ttlMs is safe
    const MAX_TTL_MS = 315360000000; // ~10 years in milliseconds
    if (options.ttlMs > MAX_TTL_MS) {
      throw new Error(`ttlMs exceeds maximum value of ${MAX_TTL_MS} milliseconds (~10 years)`);
    }
    const expiresAt = Date.now() + options.ttlMs;
    if (!Number.isSafeInteger(expiresAt)) {
      throw new Error('TTL calculation resulted in unsafe integer value');
    }

    // BUG-LOGIC-079 FIX: Validate metadata if provided
    if (options.metadata !== undefined && options.metadata !== null) {
      if (typeof options.metadata !== 'object' || Array.isArray(options.metadata)) {
        throw new Error('metadata must be a plain object');
      }
      // BUG-LOGIC-127 FIX: Check for dangerous keys using hasOwnProperty
      // Object.keys() doesn't enumerate __proto__ so we must check it explicitly
      const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
      for (const key of dangerousKeys) {
        if (Object.prototype.hasOwnProperty.call(options.metadata, key)) {
          throw new Error(`metadata cannot contain dangerous key: ${key}`);
        }
      }
      // Also check enumerable keys in case of other dangerous patterns
      for (const key of Object.keys(options.metadata)) {
        if (dangerousKeys.includes(key)) {
          throw new Error(`metadata cannot contain dangerous key: ${key}`);
        }
      }
      // Check size limit (64KB)
      const metadataJson = JSON.stringify(options.metadata);
      if (metadataJson.length > 65536) {
        throw new Error('metadata exceeds maximum size of 64KB');
      }
    }

    const id = `ctx_${randomBytes(16).toString('hex')}`;
    // Always generate nonce - required for v2.1+ HMAC-SHA256 proof verification
    // Use 32 bytes (256 bits) for security, output as 64 hex chars
    const nonce = randomBytes(32).toString('hex');

    // BUG-32 FIX: Use imported crypto instead of dynamic require
    // Derive client secret for v2.1+ (client needs this to build proofs)
    const clientSecret = createHmac('sha256', nonce)
      .update(`${id}|${options.binding}`)
      .digest('hex');

    const context: AshContext = {
      id,
      binding: options.binding,
      expiresAt, // BUG-LOGIC-123 FIX: Use pre-validated expiresAt
      mode: options.mode ?? 'balanced',
      used: false,
      nonce,
      clientSecret,
      metadata: options.metadata,
    };

    const sql = `
      INSERT INTO ${this.tableName} (id, binding, expires_at, mode, used, nonce, client_secret, metadata)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `;

    await this.query.execute(sql, [
      context.id,
      context.binding,
      context.expiresAt,
      context.mode,
      false,
      context.nonce,
      context.clientSecret,
      context.metadata ? JSON.stringify(context.metadata) : null,
    ]);

    return context;
  }

  /**
   * Get a context by ID.
   */
  async get(id: string): Promise<AshContext | null> {
    const sql = `
      SELECT id, binding, expires_at, mode, used, nonce, client_secret, metadata
      FROM ${this.tableName}
      WHERE id = $1 AND expires_at > $2
    `;

    const result = await this.query.execute<ContextRow>(sql, [id, Date.now()]);
    const rows = Array.isArray(result) ? result : [];

    if (rows.length === 0) {
      return null;
    }

    const row = rows[0];
    return this.rowToContext(row);
  }

  /**
   * Consume a context atomically.
   * The UPDATE query with WHERE clause ensures atomicity -
   * only one request can successfully update from used=FALSE to used=TRUE.
   */
  async consume(id: string): Promise<boolean> {
    // Use UPDATE with WHERE to ensure atomicity
    const sql = `
      UPDATE ${this.tableName}
      SET used = TRUE
      WHERE id = $1 AND used = FALSE AND expires_at > $2
    `;

    const result = await this.query.execute(sql, [id, Date.now()]);

    // Check if any row was updated
    // Different drivers return this differently:
    // - PostgreSQL (pg): result.rowCount
    // - MySQL (mysql2): result.affectedRows or result.changedRows
    // - SQLite (better-sqlite3): result.changes
    // - Some drivers return the result directly as an object with these properties

    // Handle array result (some drivers wrap result in array)
    const resultObj = Array.isArray(result) ? result[0] : result;

    if (resultObj && typeof resultObj === 'object') {
      const obj = resultObj as Record<string, unknown>;
      // Check various property names used by different drivers
      const affected =
        obj.affectedRows ??
        obj.rowCount ??
        obj.changedRows ??
        obj.changes ??
        0;
      // BUG-LOGIC-072 FIX: Handle BigInt values from some SQL drivers
      if (typeof affected === 'bigint') {
        return affected > 0n;
      }
      return Number(affected) > 0;
    }

    // If result is a number directly (some drivers)
    if (typeof result === 'number') {
      return result > 0;
    }

    // BUG-LOGIC-072 FIX: Handle BigInt result
    if (typeof result === 'bigint') {
      return result > 0n;
    }

    return false;
  }

  /**
   * Remove expired contexts.
   * BUG-LOGIC-012 FIX: Attempts to return actual deleted count from driver.
   */
  async cleanup(): Promise<number> {
    const sql = `
      DELETE FROM ${this.tableName}
      WHERE expires_at < $1
    `;

    const result = await this.query.execute(sql, [Date.now()]);

    // BUG-LOGIC-012 FIX: Try to extract row count from result
    // Different drivers return this differently
    const resultObj = Array.isArray(result) ? result[0] : result;

    if (resultObj && typeof resultObj === 'object') {
      const obj = resultObj as Record<string, unknown>;
      const affected =
        obj.affectedRows ??
        obj.rowCount ??
        obj.changedRows ??
        obj.changes ??
        0;
      // BUG-LOGIC-072 FIX: Handle BigInt values from some SQL drivers
      if (typeof affected === 'bigint') {
        return Number(affected);
      }
      // BUG-LOGIC-107 FIX: Validate result is a valid number, not NaN
      const numAffected = Number(affected);
      return isNaN(numAffected) ? 0 : numAffected;
    }

    // If result is a number directly (some drivers)
    if (typeof result === 'number') {
      return isNaN(result) ? 0 : result;
    }

    // BUG-LOGIC-072 FIX: Handle BigInt result
    if (typeof result === 'bigint') {
      return Number(result);
    }

    return 0;
  }

  private rowToContext(row: ContextRow): AshContext {
    // BUG-45 FIX: Validate mode value from database
    // VULN-011 FIX: Log warning for invalid mode values instead of silently correcting
    // BUG-LOGIC-003 FIX: Must match AshMode type definition
    const validModes = ['strict', 'balanced', 'minimal'];
    let mode: AshContext['mode'];
    if (validModes.includes(row.mode)) {
      mode = row.mode as AshContext['mode'];
    } else {
      // Log warning in non-production environments
      if (process.env.NODE_ENV !== 'production') {
        console.warn(
          `[ASH] Invalid mode value "${row.mode}" in context ${row.id}. ` +
          'Defaulting to "balanced". This may indicate database corruption.'
        );
      }
      mode = 'balanced';
    }

    // VULN-002 FIX: Safely parse metadata JSON with validation
    let metadata: Record<string, unknown> | undefined;
    if (row.metadata) {
      try {
        const parsed = JSON.parse(row.metadata);
        // Validate it's a plain object, not an array or primitive
        if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
          // VULN-002 FIX: Create a clean object to prevent prototype pollution
          metadata = Object.create(null);
          for (const [key, value] of Object.entries(parsed)) {
            // Skip dangerous keys
            if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
              continue;
            }
            (metadata as Record<string, unknown>)[key] = value;
          }
        }
      } catch {
        // Invalid JSON - log warning and skip metadata
        if (process.env.NODE_ENV !== 'production') {
          console.warn(
            `[ASH] Invalid metadata JSON in context ${row.id}. Metadata will be undefined.`
          );
        }
      }
    }

    // BUG-LOGIC-110 FIX: Proper boolean coercion handling
    // Different SQL drivers return booleans differently:
    // - PostgreSQL: actual boolean
    // - MySQL/SQLite: 0 or 1 (number)
    // - Some drivers: "true"/"false" (string) - Boolean("false") === true!
    let used: boolean;
    if (typeof row.used === 'boolean') {
      used = row.used;
    } else if (typeof row.used === 'number') {
      used = row.used !== 0;
    } else if (typeof row.used === 'string') {
      used = row.used.toLowerCase() === 'true' || row.used === '1';
    } else {
      used = Boolean(row.used);
    }

    // BUG-LOGIC-124 FIX: Validate expiresAt conversion
    const expiresAt = Number(row.expires_at);
    if (!Number.isFinite(expiresAt)) {
      // Log warning and use 0 (will be treated as expired)
      if (process.env.NODE_ENV !== 'production') {
        console.warn(
          `[ASH] Invalid expires_at value in context ${row.id}. Context will be treated as expired.`
        );
      }
    }

    return {
      id: row.id,
      binding: row.binding,
      expiresAt: Number.isFinite(expiresAt) ? expiresAt : 0,
      mode,
      used,
      nonce: row.nonce ?? undefined,
      clientSecret: row.client_secret ?? undefined,
      metadata,
    };
  }
}
