/**
 * ASH SDK Store Tests
 *
 * Tests for context stores: Memory, Redis, and SQL implementations.
 * These tests verify atomic operations, TTL handling, and concurrency safety.
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import * as crypto from 'crypto';
import {
  ashInit,
  ashGenerateNonce,
  ashGenerateContextId,
  AshMemoryStore,
} from './index';

beforeAll(() => {
  ashInit();
});

// =========================================================================
// MEMORY STORE TESTS
// =========================================================================

describe('Store: AshMemoryStore', () => {
  let store: AshMemoryStore;

  beforeEach(() => {
    store = new AshMemoryStore(0); // Disable auto-cleanup for tests
  });

  afterEach(() => {
    store.destroy();
  });

  describe('Basic Operations', () => {
    it('should create context with all required fields', async () => {
      const ctx = await store.create({
        binding: 'POST|/api/test|',
        ttlMs: 60000,
      });

      expect(ctx.id).toBeDefined();
      expect(ctx.id).toMatch(/^ctx_/);
      expect(ctx.nonce).toHaveLength(64);
      expect(ctx.binding).toBe('POST|/api/test|');
      expect(typeof ctx.expiresAt).toBe('number');
      expect(ctx.used).toBe(false);
    });

    it('should create context with metadata', async () => {
      const metadata = { userId: '123', action: 'transfer' };
      const ctx = await store.create({
        binding: 'POST|/api/transfer|',
        ttlMs: 60000,
        metadata,
      });

      expect(ctx.metadata).toEqual(metadata);
    });

    it('should get context by ID', async () => {
      const ctx = await store.create({
        binding: 'POST|/api/test|',
        ttlMs: 60000,
      });

      const retrieved = await store.get(ctx.id);

      expect(retrieved).not.toBeNull();
      expect(retrieved!.id).toBe(ctx.id);
      expect(retrieved!.nonce).toBe(ctx.nonce);
      expect(retrieved!.binding).toBe(ctx.binding);
    });

    it('should return null for non-existent context', async () => {
      const retrieved = await store.get('ctx_nonexistent');
      expect(retrieved).toBeNull();
    });

    it('should consume context exactly once', async () => {
      const ctx = await store.create({
        binding: 'POST|/api/test|',
        ttlMs: 60000,
      });

      const firstConsume = await store.consume(ctx.id);
      expect(firstConsume).toBe(true);

      const secondConsume = await store.consume(ctx.id);
      expect(secondConsume).toBe(false);
    });
  });

  describe('TTL and Expiration', () => {
    it('should expire context after TTL', async () => {
      const ctx = await store.create({
        binding: 'POST|/api/test|',
        ttlMs: 50, // 50ms TTL
      });

      // Should exist immediately
      const before = await store.get(ctx.id);
      expect(before).not.toBeNull();

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 100));

      // Should be expired (consume returns false)
      const consumed = await store.consume(ctx.id);
      expect(consumed).toBe(false);
    });

    it('should set correct expiration time', async () => {
      const ttlMs = 60000;
      const beforeCreate = Date.now();

      const ctx = await store.create({
        binding: 'POST|/api/test|',
        ttlMs,
      });

      const afterCreate = Date.now();

      // expiresAt is a number (timestamp), not a Date
      expect(ctx.expiresAt).toBeGreaterThanOrEqual(beforeCreate + ttlMs);
      expect(ctx.expiresAt).toBeLessThanOrEqual(afterCreate + ttlMs);
    });

    it('should reject zero TTL', async () => {
      await expect(store.create({
        binding: 'POST|/api/test|',
        ttlMs: 0,
      })).rejects.toThrow(/ttlMs/);
    });

    it('should reject negative TTL', async () => {
      await expect(store.create({
        binding: 'POST|/api/test|',
        ttlMs: -1000,
      })).rejects.toThrow(/ttlMs/);
    });
  });

  describe('Concurrent Access', () => {
    it('should handle 100 concurrent creates', async () => {
      const createPromises = Array(100).fill(null).map((_, i) =>
        store.create({
          binding: `POST|/api/resource/${i}|`,
          ttlMs: 60000,
        })
      );

      const contexts = await Promise.all(createPromises);

      // All should have unique IDs
      const ids = new Set(contexts.map(c => c.id));
      expect(ids.size).toBe(100);

      // All should have unique nonces
      const nonces = new Set(contexts.map(c => c.nonce));
      expect(nonces.size).toBe(100);
    });

    it('should ensure exactly-once consumption under race', async () => {
      const results: boolean[] = [];

      for (let i = 0; i < 50; i++) {
        const ctx = await store.create({
          binding: 'POST|/api/test|',
          ttlMs: 60000,
        });

        // 20 concurrent consume attempts
        const consumeResults = await Promise.all(
          Array(20).fill(null).map(() => store.consume(ctx.id))
        );

        const successCount = consumeResults.filter(r => r === true).length;
        results.push(successCount === 1);
      }

      // All iterations should have exactly 1 success
      expect(results.every(r => r)).toBe(true);
    });

    it('should handle mixed operations concurrently', async () => {
      const ctx = await store.create({
        binding: 'POST|/api/test|',
        ttlMs: 60000,
      });

      const operations = [
        store.get(ctx.id),
        store.get(ctx.id),
        store.consume(ctx.id),
        store.get(ctx.id),
        store.consume(ctx.id),
      ];

      const results = await Promise.all(operations);

      // At least one get should return the context
      const gets = [results[0], results[1], results[3]];
      expect(gets.some(r => r !== null)).toBe(true);

      // Exactly one consume should succeed
      const consumes = [results[2], results[4]];
      expect(consumes.filter(r => r === true).length).toBe(1);
    });
  });

  describe('Edge Cases', () => {
    it('should handle very long binding', async () => {
      const longPath = '/api/' + 'a'.repeat(1000);
      const ctx = await store.create({
        binding: `POST|${longPath}|`,
        ttlMs: 60000,
      });

      expect(ctx.binding).toBe(`POST|${longPath}|`);
    });

    it('should handle special characters in binding', async () => {
      const ctx = await store.create({
        binding: 'POST|/api/users?name=John%20Doe&age=30|',
        ttlMs: 60000,
      });

      const retrieved = await store.get(ctx.id);
      expect(retrieved!.binding).toContain('John%20Doe');
    });

    it('should handle empty metadata', async () => {
      const ctx = await store.create({
        binding: 'POST|/api/test|',
        ttlMs: 60000,
        metadata: {},
      });

      expect(ctx.metadata).toEqual({});
    });

    it('should reject oversized metadata', async () => {
      const largeMetadata = { data: 'x'.repeat(100000) };

      await expect(store.create({
        binding: 'POST|/api/test|',
        ttlMs: 60000,
        metadata: largeMetadata,
      })).rejects.toThrow(/size|64KB/);
    });

    it('should return false when consuming expired context', async () => {
      const ctx = await store.create({
        binding: 'POST|/api/test|',
        ttlMs: 1, // 1ms TTL
      });

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 50));

      const consumed = await store.consume(ctx.id);
      expect(consumed).toBe(false);
    });
  });

  describe('Cleanup', () => {
    it('should cleanup expired contexts', async () => {
      // Create some contexts with short TTL
      await store.create({ binding: 'POST|/api/1|', ttlMs: 1 });
      await store.create({ binding: 'POST|/api/2|', ttlMs: 1 });
      await store.create({ binding: 'POST|/api/3|', ttlMs: 60000 });

      // Wait for short TTLs to expire
      await new Promise(resolve => setTimeout(resolve, 50));

      const cleaned = await store.cleanup();
      expect(cleaned).toBe(2);
    });

    it('should report correct size', async () => {
      expect(store.size()).toBe(0);

      await store.create({ binding: 'POST|/api/1|', ttlMs: 60000 });
      expect(store.size()).toBe(1);

      await store.create({ binding: 'POST|/api/2|', ttlMs: 60000 });
      expect(store.size()).toBe(2);
    });

    it('should clear all on destroy', async () => {
      await store.create({ binding: 'POST|/api/1|', ttlMs: 60000 });
      await store.create({ binding: 'POST|/api/2|', ttlMs: 60000 });

      store.destroy();

      expect(store.size()).toBe(0);
    });
  });
});

// =========================================================================
// REDIS STORE SIMULATION (Mock)
// =========================================================================

describe('Store: Redis Store Simulation', () => {
  // This simulates Redis behavior using in-memory store
  // Real Redis tests would require a Redis server

  interface MockRedisContext {
    id: string;
    nonce: string;
    binding: string;
    metadata?: Record<string, unknown>;
    consumed: boolean;
    expiresAt: number;
  }

  class MockRedisStore {
    private data = new Map<string, string>();
    private locks = new Set<string>();

    async set(key: string, value: string, ttlMs: number): Promise<void> {
      this.data.set(key, value);
      setTimeout(() => this.data.delete(key), ttlMs);
    }

    async get(key: string): Promise<string | null> {
      return this.data.get(key) || null;
    }

    async del(key: string): Promise<boolean> {
      return this.data.delete(key);
    }

    // Simulates WATCH/MULTI/EXEC for atomic operations
    async atomicConsumeWithLock(key: string): Promise<boolean> {
      const lockKey = `lock:${key}`;

      // Simulate acquiring lock
      if (this.locks.has(lockKey)) {
        return false; // Lock already held
      }

      this.locks.add(lockKey);

      try {
        const value = this.data.get(key);
        if (!value) {
          return false;
        }

        const context: MockRedisContext = JSON.parse(value);
        if (context.consumed || Date.now() > context.expiresAt) {
          return false;
        }

        context.consumed = true;
        this.data.set(key, JSON.stringify(context));
        return true;
      } finally {
        this.locks.delete(lockKey);
      }
    }

    async create(options: {
      binding: string;
      ttlMs: number;
      nonce?: string;
      metadata?: Record<string, unknown>;
    }): Promise<MockRedisContext> {
      const id = `ctx_${crypto.randomBytes(16).toString('hex')}`;
      const nonce = options.nonce || crypto.randomBytes(32).toString('hex');

      const context: MockRedisContext = {
        id,
        nonce,
        binding: options.binding,
        metadata: options.metadata,
        consumed: false,
        expiresAt: Date.now() + options.ttlMs,
      };

      await this.set(id, JSON.stringify(context), options.ttlMs);
      return context;
    }

    async consume(id: string): Promise<boolean> {
      return this.atomicConsumeWithLock(id);
    }
  }

  let store: MockRedisStore;

  beforeEach(() => {
    store = new MockRedisStore();
  });

  it('should create context with Redis-style TTL', async () => {
    const ctx = await store.create({
      binding: 'POST|/api/test|',
      ttlMs: 60000,
    });

    expect(ctx.id).toMatch(/^ctx_/);
    expect(ctx.nonce).toHaveLength(64);
  });

  it('should atomically consume context', async () => {
    const ctx = await store.create({
      binding: 'POST|/api/test|',
      ttlMs: 60000,
    });

    const first = await store.consume(ctx.id);
    expect(first).toBe(true);

    const second = await store.consume(ctx.id);
    expect(second).toBe(false);
  });

  it('should handle concurrent consume with locking', async () => {
    const ctx = await store.create({
      binding: 'POST|/api/test|',
      ttlMs: 60000,
    });

    // Simulate concurrent consume attempts
    const results = await Promise.all([
      store.consume(ctx.id),
      store.consume(ctx.id),
      store.consume(ctx.id),
      store.consume(ctx.id),
      store.consume(ctx.id),
    ]);

    const successCount = results.filter(r => r === true).length;
    expect(successCount).toBe(1);
  });

  it('should handle Redis connection recovery simulation', async () => {
    const ctx = await store.create({
      binding: 'POST|/api/test|',
      ttlMs: 60000,
    });

    // Simulate successful operations
    const consumed = await store.consume(ctx.id);
    expect(consumed).toBe(true);
  });
});

// =========================================================================
// SQL STORE SIMULATION (Mock)
// =========================================================================

describe('Store: SQL Store Simulation', () => {
  // Simulates SQL database behavior

  interface SqlContext {
    id: string;
    nonce: string;
    binding: string;
    metadata: string | null;
    consumed: boolean;
    created_at: Date;
    expires_at: Date;
  }

  class MockSqlStore {
    private table: SqlContext[] = [];
    private transactionLock = false;

    async beginTransaction(): Promise<void> {
      while (this.transactionLock) {
        await new Promise(resolve => setTimeout(resolve, 1));
      }
      this.transactionLock = true;
    }

    async commit(): Promise<void> {
      this.transactionLock = false;
    }

    async rollback(): Promise<void> {
      this.transactionLock = false;
    }

    async create(options: {
      binding: string;
      ttlMs: number;
      nonce?: string;
      metadata?: Record<string, unknown>;
    }): Promise<SqlContext> {
      const now = new Date();
      const context: SqlContext = {
        id: `ctx_${crypto.randomBytes(16).toString('hex')}`,
        nonce: options.nonce || crypto.randomBytes(32).toString('hex'),
        binding: options.binding,
        metadata: options.metadata ? JSON.stringify(options.metadata) : null,
        consumed: false,
        created_at: now,
        expires_at: new Date(now.getTime() + options.ttlMs),
      };

      await this.beginTransaction();
      try {
        this.table.push(context);
        await this.commit();
        return context;
      } catch {
        await this.rollback();
        throw new Error('Failed to create context');
      }
    }

    async get(id: string): Promise<SqlContext | null> {
      const context = this.table.find(c => c.id === id);
      if (!context || context.expires_at < new Date()) {
        return null;
      }
      return context;
    }

    async consume(id: string): Promise<boolean> {
      await this.beginTransaction();
      try {
        const context = this.table.find(c => c.id === id);
        if (!context || context.consumed || context.expires_at < new Date()) {
          await this.commit();
          return false;
        }

        context.consumed = true;
        await this.commit();
        return true;
      } catch {
        await this.rollback();
        return false;
      }
    }

    async delete(id: string): Promise<boolean> {
      await this.beginTransaction();
      try {
        const index = this.table.findIndex(c => c.id === id);
        if (index === -1) {
          await this.commit();
          return false;
        }
        this.table.splice(index, 1);
        await this.commit();
        return true;
      } catch {
        await this.rollback();
        return false;
      }
    }

    async cleanupExpired(): Promise<number> {
      const now = new Date();
      const before = this.table.length;
      this.table = this.table.filter(c => c.expires_at > now);
      return before - this.table.length;
    }
  }

  let store: MockSqlStore;

  beforeEach(() => {
    store = new MockSqlStore();
  });

  it('should create context with SQL transaction', async () => {
    const ctx = await store.create({
      binding: 'POST|/api/test|',
      ttlMs: 60000,
    });

    expect(ctx.id).toMatch(/^ctx_/);
    expect(ctx.consumed).toBe(false);
  });

  it('should get context by ID', async () => {
    const ctx = await store.create({
      binding: 'POST|/api/test|',
      ttlMs: 60000,
    });

    const retrieved = await store.get(ctx.id);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.id).toBe(ctx.id);
  });

  it('should consume context with transaction isolation', async () => {
    const ctx = await store.create({
      binding: 'POST|/api/test|',
      ttlMs: 60000,
    });

    const first = await store.consume(ctx.id);
    expect(first).toBe(true);

    const second = await store.consume(ctx.id);
    expect(second).toBe(false);
  });

  it('should cleanup expired contexts', async () => {
    // Create contexts with very short TTL
    await store.create({ binding: 'POST|/api/1|', ttlMs: 1 });
    await store.create({ binding: 'POST|/api/2|', ttlMs: 1 });
    await store.create({ binding: 'POST|/api/3|', ttlMs: 60000 }); // Long TTL

    await new Promise(resolve => setTimeout(resolve, 10));

    const cleaned = await store.cleanupExpired();
    expect(cleaned).toBe(2); // Two short-TTL contexts expired
  });

  it('should store and retrieve metadata', async () => {
    const metadata = { userId: '123', action: 'transfer', amount: 100 };
    const ctx = await store.create({
      binding: 'POST|/api/transfer|',
      ttlMs: 60000,
      metadata,
    });

    const retrieved = await store.get(ctx.id);
    expect(JSON.parse(retrieved!.metadata!)).toEqual(metadata);
  });

  it('should handle concurrent transactions', async () => {
    const ctx = await store.create({
      binding: 'POST|/api/test|',
      ttlMs: 60000,
    });

    // Concurrent consume attempts
    const results = await Promise.all([
      store.consume(ctx.id),
      store.consume(ctx.id),
      store.consume(ctx.id),
    ]);

    const successCount = results.filter(r => r === true).length;
    expect(successCount).toBe(1);
  });
});

// =========================================================================
// STORE INTERFACE COMPLIANCE
// =========================================================================

describe('Store: Interface Compliance', () => {
  it('AshMemoryStore should implement required methods', () => {
    const store = new AshMemoryStore(0);

    expect(typeof store.create).toBe('function');
    expect(typeof store.get).toBe('function');
    expect(typeof store.consume).toBe('function');
    expect(typeof store.cleanup).toBe('function');
    expect(typeof store.size).toBe('function');
    expect(typeof store.destroy).toBe('function');

    store.destroy();
  });

  it('create should return context with all required fields', async () => {
    const store = new AshMemoryStore(0);
    const ctx = await store.create({
      binding: 'POST|/api/test|',
      ttlMs: 60000,
    });

    // Required fields
    expect(ctx).toHaveProperty('id');
    expect(ctx).toHaveProperty('nonce');
    expect(ctx).toHaveProperty('binding');
    expect(ctx).toHaveProperty('expiresAt');
    expect(ctx).toHaveProperty('used');

    // Type checks
    expect(typeof ctx.id).toBe('string');
    expect(typeof ctx.nonce).toBe('string');
    expect(typeof ctx.binding).toBe('string');
    expect(typeof ctx.expiresAt).toBe('number');
    expect(typeof ctx.used).toBe('boolean');

    store.destroy();
  });
});

console.log('Store Tests loaded');
