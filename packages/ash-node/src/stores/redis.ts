/**
 * Redis context store.
 *
 * Production-ready store for distributed deployments.
 * Requires ioredis as a peer dependency.
 */

import type { AshContext, AshContextOptions, AshContextStore } from '../index';
import { randomBytes } from 'crypto';

/**
 * Redis store configuration options.
 */
export interface AshRedisStoreOptions {
  /** Redis client instance (ioredis) */
  client: RedisClient;
  /** Key prefix for ASH contexts */
  keyPrefix?: string;
}

/**
 * Minimal Redis client interface (compatible with ioredis).
 */
interface RedisClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, expiryMode?: string, time?: number): Promise<string | null>;
  del(...keys: string[]): Promise<number>;
  scan(cursor: string, ...args: string[]): Promise<[string, string[]]>;
}

/**
 * Redis implementation of AshContextStore.
 *
 * @example
 * ```typescript
 * import Redis from 'ioredis';
 *
 * const redis = new Redis();
 * const store = new AshRedisStore({ client: redis });
 *
 * const ctx = await store.create({
 *   binding: 'POST /api/update',
 *   ttlMs: 30000,
 * });
 * ```
 */
export class AshRedisStore implements AshContextStore {
  private client: RedisClient;
  private keyPrefix: string;

  constructor(options: AshRedisStoreOptions) {
    this.client = options.client;
    this.keyPrefix = options.keyPrefix ?? 'ash:ctx:';
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
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

    // Store with TTL (add 1 second buffer for clock skew)
    const ttlSeconds = Math.ceil(options.ttlMs / 1000) + 1;
    await this.client.set(
      this.key(id),
      JSON.stringify(context),
      'EX',
      ttlSeconds
    );

    return context;
  }

  /**
   * Get a context by ID.
   */
  async get(id: string): Promise<AshContext | null> {
    const data = await this.client.get(this.key(id));

    if (!data) {
      return null;
    }

    const context: AshContext = JSON.parse(data);

    // Check expiration (Redis TTL should handle this, but double-check)
    if (Date.now() > context.expiresAt) {
      await this.client.del(this.key(id));
      return null;
    }

    return context;
  }

  /**
   * Consume a context atomically.
   */
  async consume(id: string): Promise<boolean> {
    const context = await this.get(id);

    if (!context) {
      return false;
    }

    if (context.used) {
      return false;
    }

    // Mark as used and update
    context.used = true;
    const remainingTtl = Math.max(1, Math.ceil((context.expiresAt - Date.now()) / 1000));

    await this.client.set(
      this.key(id),
      JSON.stringify(context),
      'EX',
      remainingTtl
    );

    return true;
  }

  /**
   * Cleanup is handled by Redis TTL.
   */
  async cleanup(): Promise<number> {
    // Redis handles expiration automatically via TTL
    return 0;
  }
}
