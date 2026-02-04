/**
 * In-memory context store.
 *
 * Suitable for development and single-instance deployments.
 * For production with multiple instances, use Redis or SQL store.
 */

import type { AshContext, AshContextOptions, AshContextStore } from '../index';
import { randomBytes, createHmac } from 'crypto';

/**
 * In-memory implementation of AshContextStore.
 *
 * @example
 * ```typescript
 * const store = new AshMemoryStore();
 *
 * // Create a context
 * const ctx = await store.create({
 *   binding: 'POST /api/update',
 *   ttlMs: 30000,
 *   mode: 'balanced',
 * });
 *
 * console.log(ctx.id); // 'ctx_abc123...'
 * ```
 */
export class AshMemoryStore implements AshContextStore {
  private contexts = new Map<string, AshContext>();
  private cleanupInterval: NodeJS.Timeout | null = null;
  /**
   * BUG-LOGIC-001 FIX: Use a Set for synchronous lock checking.
   * JavaScript is single-threaded for synchronous code, so checking and setting
   * a Set in the same synchronous block is atomic (no await between check and set).
   */
  private consumeLocks = new Set<string>();

  /**
   * Create a new in-memory store.
   *
   * @param autoCleanupMs - Interval for automatic cleanup (0 to disable)
   * @throws Error if autoCleanupMs is negative
   */
  constructor(autoCleanupMs = 60000) {
    // BUG-LOGIC-055 FIX: Validate autoCleanupMs is non-negative
    if (autoCleanupMs < 0) {
      throw new Error('autoCleanupMs must be non-negative (use 0 to disable auto-cleanup)');
    }
    if (autoCleanupMs > 0) {
      this.cleanupInterval = setInterval(() => {
        this.cleanup().catch(console.error);
      }, autoCleanupMs);

      // Don't prevent process exit
      this.cleanupInterval.unref();
    }
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

    // BUG-LOGIC-119 FIX: Validate TTL won't cause precision loss or overflow
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
      expiresAt, // BUG-LOGIC-119 FIX: Use pre-validated expiresAt
      mode: options.mode ?? 'balanced',
      used: false,
      nonce,
      clientSecret,
      metadata: options.metadata,
    };

    this.contexts.set(id, context);
    return context;
  }

  /**
   * Get a context by ID.
   * Returns null if not found or expired.
   */
  async get(id: string): Promise<AshContext | null> {
    const context = this.contexts.get(id);

    if (!context) {
      return null;
    }

    // Check expiration
    if (Date.now() > context.expiresAt) {
      this.contexts.delete(id);
      return null;
    }

    // BUG-LOGIC-059 FIX: Return a copy to prevent mutation attacks
    // Without this, a caller could do: ctx.used = false; to bypass anti-replay protection
    // BUG-LOGIC-081 FIX: Use deep copy for metadata to prevent nested object mutation
    // BUG-LOGIC-099 FIX: Validate mode like Redis/SQL stores do
    const validModes = ['strict', 'balanced', 'minimal'];
    let mode: AshContext['mode'] = context.mode;
    if (!validModes.includes(context.mode)) {
      if (process.env.NODE_ENV !== 'production') {
        console.warn(
          `[ASH] Invalid mode value "${context.mode}" in context ${context.id}. ` +
          'Defaulting to "balanced". This may indicate data corruption.'
        );
      }
      mode = 'balanced';
    }

    // BUG-LOGIC-081 FIX: Deep copy metadata to prevent nested mutation attacks
    // BUG-LOGIC-121 FIX: Use null prototype object to prevent prototype pollution
    let metadataCopy: Record<string, unknown> | undefined;
    if (context.metadata) {
      metadataCopy = Object.create(null);
      const parsed = JSON.parse(JSON.stringify(context.metadata));
      for (const [key, value] of Object.entries(parsed)) {
        // Skip dangerous keys (defense in depth)
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
          continue;
        }
        (metadataCopy as Record<string, unknown>)[key] = value;
      }
    }

    return {
      ...context,
      mode,
      metadata: metadataCopy,
    };
  }

  /**
   * Consume a context (mark as used) atomically.
   * Returns false if context not found, expired, already used, or being consumed.
   * BUG-LOGIC-001 FIX: Uses synchronous lock acquisition to prevent race conditions.
   * JavaScript is single-threaded for synchronous code, so the check-and-set
   * operation on consumeLocks is atomic when no await is between them.
   */
  async consume(id: string): Promise<boolean> {
    // BUG-LOGIC-001 FIX: Synchronous lock acquisition - no await between check and set
    // This is atomic in single-threaded JavaScript
    if (this.consumeLocks.has(id)) {
      // Another operation is in progress
      return false;
    }

    // Acquire lock synchronously (atomic with the check above)
    this.consumeLocks.add(id);

    try {
      const context = this.contexts.get(id);

      if (!context) {
        return false;
      }

      // Check expiration
      if (Date.now() > context.expiresAt) {
        this.contexts.delete(id);
        return false;
      }

      if (context.used) {
        return false;
      }

      // Mark as used
      context.used = true;
      return true;
    } finally {
      // Release lock
      this.consumeLocks.delete(id);
    }
  }

  /**
   * Remove expired contexts.
   * Returns the number of contexts removed.
   */
  async cleanup(): Promise<number> {
    const now = Date.now();
    let removed = 0;

    for (const [id, context] of this.contexts) {
      // BUG-LOGIC-118 FIX: Skip contexts being consumed to avoid race condition
      if (this.consumeLocks.has(id)) {
        continue;
      }
      if (now > context.expiresAt) {
        this.contexts.delete(id);
        removed++;
      }
    }

    return removed;
  }

  /**
   * Get the number of active contexts.
   */
  size(): number {
    return this.contexts.size;
  }

  /**
   * Clear all contexts and stop cleanup timer.
   * BUG-LOGIC-011 FIX: Also clears consumeLocks.
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.contexts.clear();
    // BUG-LOGIC-011 FIX: Clear consume locks
    this.consumeLocks.clear();
  }
}
