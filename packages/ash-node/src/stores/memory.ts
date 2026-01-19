/**
 * In-memory context store.
 *
 * Suitable for development and single-instance deployments.
 * For production with multiple instances, use Redis or SQL store.
 */

import type { AshContext, AshContextOptions, AshContextStore } from '../index';
import { randomBytes } from 'crypto';

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
   * Create a new in-memory store.
   *
   * @param autoCleanupMs - Interval for automatic cleanup (0 to disable)
   */
  constructor(autoCleanupMs = 60000) {
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

    return context;
  }

  /**
   * Consume a context (mark as used).
   * Returns false if context not found, expired, or already used.
   */
  async consume(id: string): Promise<boolean> {
    const context = await this.get(id);

    if (!context) {
      return false;
    }

    if (context.used) {
      return false;
    }

    context.used = true;
    return true;
  }

  /**
   * Remove expired contexts.
   * Returns the number of contexts removed.
   */
  async cleanup(): Promise<number> {
    const now = Date.now();
    let removed = 0;

    for (const [id, context] of this.contexts) {
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
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.contexts.clear();
  }
}
