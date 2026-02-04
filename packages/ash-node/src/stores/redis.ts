/**
 * Redis context store.
 *
 * Production-ready store for distributed deployments.
 * Requires ioredis as a peer dependency.
 */

import type { AshContext, AshContextOptions, AshContextStore, AshMode } from '../index';
import { randomBytes, createHmac } from 'crypto';

/**
 * BUG-LOGIC-003 FIX: Valid mode values for validation.
 * Must match AshMode type definition.
 */
const VALID_MODES: AshMode[] = ['strict', 'balanced', 'minimal'];

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
  /**
   * Evaluate a Lua script atomically.
   * Required for atomic consume operation.
   */
  eval(script: string, numKeys: number, ...args: (string | number)[]): Promise<unknown>;
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

    // Store with TTL (add 1 second buffer for clock skew)
    // BUG-LOGIC-109 FIX: Cap TTL at reasonable maximum to prevent Redis issues
    // BUG-LOGIC-114 FIX: Validate TTL is a safe integer to prevent precision loss
    const MAX_TTL_SECONDS = 315360000; // ~10 years
    const ttlSeconds = Math.min(Math.ceil(options.ttlMs / 1000) + 1, MAX_TTL_SECONDS);
    if (!Number.isSafeInteger(ttlSeconds)) {
      throw new Error('TTL calculation resulted in unsafe integer value');
    }
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
   * BUG-LOGIC-003 FIX: Safely parse JSON with validation to prevent prototype pollution.
   */
  async get(id: string): Promise<AshContext | null> {
    const data = await this.client.get(this.key(id));

    if (!data) {
      return null;
    }

    // BUG-LOGIC-003 FIX: Safely parse and validate JSON
    const context = this.safeParseContext(data);
    if (!context) {
      // BUG-LOGIC-054 FIX: Log corruption instead of deleting on read
      // Read operations should be idempotent - let TTL handle cleanup
      if (process.env.NODE_ENV !== 'production') {
        console.warn(`[ASH] Corrupted context data detected for key ${id}, returning null`);
      }
      return null;
    }

    // Check expiration (Redis TTL should handle this, but double-check)
    if (Date.now() > context.expiresAt) {
      await this.client.del(this.key(id));
      return null;
    }

    return context;
  }

  /**
   * Safely parse context JSON with prototype pollution protection.
   * BUG-LOGIC-003 FIX: Validates and sanitizes parsed data.
   * @internal
   */
  private safeParseContext(data: string): AshContext | null {
    try {
      const parsed = JSON.parse(data);

      // Validate it's an object
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return null;
      }

      // Validate required fields exist and have correct types
      if (typeof parsed.id !== 'string' ||
          typeof parsed.binding !== 'string' ||
          typeof parsed.expiresAt !== 'number' ||
          typeof parsed.mode !== 'string' ||
          typeof parsed.used !== 'boolean') {
        return null;
      }

      // Validate mode value
      let mode: AshMode;
      if (VALID_MODES.includes(parsed.mode as AshMode)) {
        mode = parsed.mode as AshMode;
      } else {
        // Log warning in non-production environments
        if (process.env.NODE_ENV !== 'production') {
          console.warn(
            `[ASH] Invalid mode value "${parsed.mode}" in context ${parsed.id}. ` +
            'Defaulting to "balanced". This may indicate data corruption.'
          );
        }
        mode = 'balanced';
      }

      // Safely extract metadata with prototype pollution protection
      let metadata: Record<string, unknown> | undefined;
      if (parsed.metadata !== undefined && parsed.metadata !== null) {
        if (typeof parsed.metadata === 'object' && !Array.isArray(parsed.metadata)) {
          metadata = Object.create(null);
          for (const [key, value] of Object.entries(parsed.metadata)) {
            // Skip dangerous keys
            if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
              continue;
            }
            (metadata as Record<string, unknown>)[key] = value;
          }
        }
      }

      // Build validated context object
      const context: AshContext = {
        id: parsed.id,
        binding: parsed.binding,
        expiresAt: parsed.expiresAt,
        mode,
        used: parsed.used,
        nonce: typeof parsed.nonce === 'string' ? parsed.nonce : undefined,
        clientSecret: typeof parsed.clientSecret === 'string' ? parsed.clientSecret : undefined,
        metadata,
      };

      return context;
    } catch {
      // JSON parse failed
      return null;
    }
  }

  /**
   * Lua script for atomic consume operation.
   * Returns 1 if consumed, 0 if not found/expired/already used.
   */
  private static readonly CONSUME_SCRIPT = `
    local key = KEYS[1]
    local now = tonumber(ARGV[1])

    local data = redis.call('GET', key)
    if not data then
      return 0
    end

    -- BUG-LOGIC-113 FIX: Use pcall to safely decode JSON and handle corruption
    local ok, context = pcall(cjson.decode, data)
    if not ok or not context or type(context) ~= 'table' then
      redis.call('DEL', key)
      return 0
    end

    -- BUG-LOGIC-102 FIX: Validate expiresAt is a number to prevent type confusion
    if type(context.expiresAt) ~= 'number' then
      redis.call('DEL', key)
      return 0
    end

    -- Check if already used
    if context.used then
      return 0
    end

    -- Check if expired
    if context.expiresAt <= now then
      redis.call('DEL', key)
      return 0
    end

    -- Mark as used
    context.used = true

    -- Calculate remaining TTL
    local remainingTtl = math.max(1, math.ceil((context.expiresAt - now) / 1000))

    -- Update atomically
    redis.call('SET', key, cjson.encode(context), 'EX', remainingTtl)

    return 1
  `;

  /**
   * Consume a context atomically using Lua script.
   * This prevents TOCTOU race conditions where two requests
   * could both see used=false and consume the same context.
   */
  async consume(id: string): Promise<boolean> {
    const result = await this.client.eval(
      AshRedisStore.CONSUME_SCRIPT,
      1,
      this.key(id),
      Date.now()
    );

    // BUG-LOGIC-125 FIX: Handle different types returned by various Redis clients
    // - ioredis returns numbers
    // - Some clients may return strings ("1") or BigInt (1n)
    if (typeof result === 'number') {
      return result === 1;
    }
    if (typeof result === 'bigint') {
      return result === 1n;
    }
    if (typeof result === 'string') {
      return result === '1';
    }
    return result === 1;
  }

  /**
   * Cleanup is handled by Redis TTL.
   */
  async cleanup(): Promise<number> {
    // Redis handles expiration automatically via TTL
    return 0;
  }
}
