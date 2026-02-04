/**
 * Stress and Performance Comprehensive Tests
 *
 * Tests for stress and performance covering:
 * - High volume operations
 * - Concurrent operations
 * - Memory stability
 * - Performance benchmarks
 * - Resource exhaustion prevention
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'crypto';
import {
  ashInit,
  ashHashBody,
  ashBuildProof,
  ashVerifyProof,
  ashBuildProofUnified,
  ashVerifyProofUnified,
  ashCanonicalizeJson,
  ashCanonicalizeJsonNative,
  ashCanonicalizeQuery,
  ashNormalizeBinding,
  ashGenerateNonce,
  ashGenerateContextId,
  ashDeriveClientSecret,
  ashExtractScopedFields,
  AshMemoryStore,
} from './index';

// Initialize WASM
beforeAll(() => {
  try {
    ashInit();
  } catch {
    // WASM not available, tests will use native fallback
  }
});

// Helper to create proof setup
function createProofSetup() {
  const nonce = ashGenerateNonce();
  const contextId = ashGenerateContextId();
  const binding = ashNormalizeBinding('POST', '/api/test');
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const body = JSON.stringify({ action: 'test', data: Math.random() });
  const bodyHash = ashHashBody(body);
  const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
  const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

  return { nonce, contextId, binding, timestamp, bodyHash, clientSecret, proof };
}

describe('Stress and Performance Comprehensive Tests', () => {
  describe('High Volume - Hashing', () => {
    it('performs 10000 hash operations', () => {
      const iterations = 10000;
      const start = Date.now();

      for (let i = 0; i < iterations; i++) {
        ashHashBody(`message${i}`);
      }

      const duration = Date.now() - start;
      const opsPerSecond = (iterations / duration) * 1000;

      console.log(`Hash performance: ${opsPerSecond.toFixed(0)} ops/sec`);
      expect(opsPerSecond).toBeGreaterThan(1000);
    });

    it('handles 1000 unique messages without collision', () => {
      const hashes = new Set<string>();
      for (let i = 0; i < 1000; i++) {
        const hash = ashHashBody(crypto.randomBytes(32).toString('hex'));
        expect(hashes.has(hash)).toBe(false);
        hashes.add(hash);
      }
      expect(hashes.size).toBe(1000);
    });

    it('hashes large payloads efficiently', () => {
      const sizes = [1024, 10240, 102400]; // 1KB, 10KB, 100KB

      for (const size of sizes) {
        const payload = 'x'.repeat(size);
        const start = Date.now();
        for (let i = 0; i < 100; i++) {
          ashHashBody(payload);
        }
        const duration = Date.now() - start;
        console.log(`Hash ${size} bytes: ${(duration / 100).toFixed(2)}ms avg`);
        expect(duration).toBeLessThan(5000); // Should complete in under 5 seconds
      }
    });
  });

  describe('High Volume - JSON Canonicalization', () => {
    it('performs 5000 canonicalization operations', () => {
      const iterations = 5000;
      const json = '{"z":1,"a":2,"nested":{"b":3,"a":4}}';
      const start = Date.now();

      for (let i = 0; i < iterations; i++) {
        ashCanonicalizeJsonNative(json);
      }

      const duration = Date.now() - start;
      const opsPerSecond = (iterations / duration) * 1000;

      console.log(`JSON canonicalization: ${opsPerSecond.toFixed(0)} ops/sec`);
      expect(opsPerSecond).toBeGreaterThan(500);
    });

    it('canonicalizes deeply nested structures', () => {
      let deep: any = { value: 1 };
      for (let i = 0; i < 50; i++) {
        deep = { nested: deep };
      }
      const json = JSON.stringify(deep);

      const start = Date.now();
      for (let i = 0; i < 100; i++) {
        ashCanonicalizeJsonNative(json);
      }
      const duration = Date.now() - start;

      console.log(`Deep nesting (50 levels): ${(duration / 100).toFixed(2)}ms avg`);
      expect(duration).toBeLessThan(5000);
    });

    it('canonicalizes wide objects efficiently', () => {
      const wide: Record<string, number> = {};
      for (let i = 0; i < 1000; i++) {
        wide[`key${i}`] = i;
      }
      const json = JSON.stringify(wide);

      const start = Date.now();
      for (let i = 0; i < 50; i++) {
        ashCanonicalizeJsonNative(json);
      }
      const duration = Date.now() - start;

      console.log(`Wide object (1000 keys): ${(duration / 50).toFixed(2)}ms avg`);
      expect(duration).toBeLessThan(5000);
    });
  });

  describe('High Volume - Proof Operations', () => {
    it('builds 1000 proofs', () => {
      const iterations = 1000;
      const secret = 'testsecret';
      const binding = 'POST|/api/test|';
      const bodyHash = ashHashBody('{}');
      const start = Date.now();

      for (let i = 0; i < iterations; i++) {
        ashBuildProof(secret, (1700000000 + i).toString(), binding, bodyHash);
      }

      const duration = Date.now() - start;
      const opsPerSecond = (iterations / duration) * 1000;

      console.log(`Proof build: ${opsPerSecond.toFixed(0)} ops/sec`);
      expect(opsPerSecond).toBeGreaterThan(100);
    });

    it('verifies 1000 proofs', () => {
      const setup = createProofSetup();
      const iterations = 1000;
      const start = Date.now();

      for (let i = 0; i < iterations; i++) {
        ashVerifyProof(
          setup.nonce,
          setup.contextId,
          setup.binding,
          setup.timestamp,
          setup.bodyHash,
          setup.proof
        );
      }

      const duration = Date.now() - start;
      const opsPerSecond = (iterations / duration) * 1000;

      console.log(`Proof verify: ${opsPerSecond.toFixed(0)} ops/sec`);
      expect(opsPerSecond).toBeGreaterThan(100);
    });

    it('builds 500 unified proofs with scoping', () => {
      const setup = createProofSetup();
      const payload = { a: 1, b: 2, c: 3, d: 4 };
      const scope = ['a', 'b'];
      const iterations = 500;
      const start = Date.now();

      for (let i = 0; i < iterations; i++) {
        ashBuildProofUnified(
          setup.clientSecret,
          (parseInt(setup.timestamp) + i).toString(),
          setup.binding,
          payload,
          scope
        );
      }

      const duration = Date.now() - start;
      const opsPerSecond = (iterations / duration) * 1000;

      console.log(`Unified proof build: ${opsPerSecond.toFixed(0)} ops/sec`);
      expect(opsPerSecond).toBeGreaterThan(50);
    });
  });

  describe('High Volume - Nonce Generation', () => {
    it('generates 10000 nonces without collision', () => {
      const iterations = 10000;
      const nonces = new Set<string>();
      const start = Date.now();

      for (let i = 0; i < iterations; i++) {
        nonces.add(ashGenerateNonce());
      }

      const duration = Date.now() - start;
      const opsPerSecond = (iterations / duration) * 1000;

      console.log(`Nonce generation: ${opsPerSecond.toFixed(0)} ops/sec`);
      expect(nonces.size).toBe(iterations);
      expect(opsPerSecond).toBeGreaterThan(1000);
    });

    it('generates 10000 context IDs without collision', () => {
      const iterations = 10000;
      const ids = new Set<string>();
      const start = Date.now();

      for (let i = 0; i < iterations; i++) {
        ids.add(ashGenerateContextId());
      }

      const duration = Date.now() - start;
      const opsPerSecond = (iterations / duration) * 1000;

      console.log(`Context ID generation: ${opsPerSecond.toFixed(0)} ops/sec`);
      expect(ids.size).toBe(iterations);
      expect(opsPerSecond).toBeGreaterThan(1000);
    });
  });

  describe('Concurrent Operations', () => {
    it('handles 100 concurrent proof verifications', async () => {
      const setup = createProofSetup();
      const start = Date.now();

      const verifications = Array.from({ length: 100 }, () =>
        Promise.resolve(ashVerifyProof(
          setup.nonce,
          setup.contextId,
          setup.binding,
          setup.timestamp,
          setup.bodyHash,
          setup.proof
        ))
      );

      const results = await Promise.all(verifications);
      const duration = Date.now() - start;

      expect(results.every(r => r === true)).toBe(true);
      console.log(`100 concurrent verifications: ${duration}ms`);
    });

    it('handles 50 concurrent proof builds', async () => {
      const setup = createProofSetup();
      const start = Date.now();

      const builds = Array.from({ length: 50 }, (_, i) =>
        Promise.resolve(ashBuildProof(
          setup.clientSecret,
          (parseInt(setup.timestamp) + i).toString(),
          setup.binding,
          setup.bodyHash
        ))
      );

      const results = await Promise.all(builds);
      const duration = Date.now() - start;

      expect(results.length).toBe(50);
      expect(new Set(results).size).toBe(50); // All unique
      console.log(`50 concurrent builds: ${duration}ms`);
    });

    it('handles mixed concurrent operations', async () => {
      const start = Date.now();

      const operations = [];
      for (let i = 0; i < 30; i++) {
        // Mix of different operation types
        operations.push(Promise.resolve(ashHashBody(`msg${i}`)));
        operations.push(Promise.resolve(ashGenerateNonce()));
        operations.push(Promise.resolve(ashCanonicalizeJsonNative(`{"key":${i}}`)));
      }

      const results = await Promise.all(operations);
      const duration = Date.now() - start;

      expect(results.length).toBe(90);
      console.log(`90 mixed concurrent operations: ${duration}ms`);
    });
  });

  describe('Memory Stability', () => {
    it('does not leak memory over 5000 operations', () => {
      const initialMemory = process.memoryUsage().heapUsed;

      for (let i = 0; i < 5000; i++) {
        ashHashBody(crypto.randomBytes(1024).toString('hex'));
      }

      // Force GC if available
      if (global.gc) {
        global.gc();
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const growth = (finalMemory - initialMemory) / 1024 / 1024;

      console.log(`Memory growth: ${growth.toFixed(2)}MB`);
      // Memory should not grow excessively (allow up to 50MB growth)
      expect(growth).toBeLessThan(50);
    });

    it('handles repeated proof operations without memory leak', () => {
      const initialMemory = process.memoryUsage().heapUsed;

      for (let i = 0; i < 2000; i++) {
        const setup = createProofSetup();
        ashVerifyProof(
          setup.nonce,
          setup.contextId,
          setup.binding,
          setup.timestamp,
          setup.bodyHash,
          setup.proof
        );
      }

      if (global.gc) {
        global.gc();
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const growth = (finalMemory - initialMemory) / 1024 / 1024;

      console.log(`Memory growth (proofs): ${growth.toFixed(2)}MB`);
      expect(growth).toBeLessThan(50);
    });
  });

  describe('Memory Store Stress', () => {
    it('handles 1000 context creations', async () => {
      const store = new AshMemoryStore();
      const start = Date.now();

      for (let i = 0; i < 1000; i++) {
        await store.create({
          binding: `GET|/api/test/${i}|`,
          ttlMs: 60000,
        });
      }

      const duration = Date.now() - start;
      console.log(`1000 context creations: ${duration}ms`);
      expect(duration).toBeLessThan(5000);
    });

    it('handles rapid create-consume cycles', async () => {
      const store = new AshMemoryStore();
      const start = Date.now();

      for (let i = 0; i < 500; i++) {
        const ctx = await store.create({
          binding: 'GET|/api/test|',
          ttlMs: 60000,
        });
        await store.consume(ctx.id);
      }

      const duration = Date.now() - start;
      console.log(`500 create-consume cycles: ${duration}ms`);
      expect(duration).toBeLessThan(5000);
    });

    it('handles concurrent context operations', async () => {
      const store = new AshMemoryStore();
      const start = Date.now();

      const creates = Array.from({ length: 100 }, (_, i) =>
        store.create({
          binding: `GET|/api/test/${i}|`,
          ttlMs: 60000,
        })
      );

      const contexts = await Promise.all(creates);

      const consumes = contexts.map(ctx => store.consume(ctx.id));
      const results = await Promise.all(consumes);

      const duration = Date.now() - start;
      expect(results.every(r => r === true)).toBe(true);
      console.log(`100 concurrent context ops: ${duration}ms`);
    });

    it('cleans up expired contexts efficiently', async () => {
      const store = new AshMemoryStore();

      // Create 100 contexts with short TTL
      for (let i = 0; i < 100; i++) {
        await store.create({
          binding: 'GET|/api/test|',
          ttlMs: 10, // 10ms TTL
        });
      }

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 50));

      const start = Date.now();
      const cleaned = await store.cleanup();
      const duration = Date.now() - start;

      expect(cleaned).toBe(100);
      console.log(`Cleanup 100 contexts: ${duration}ms`);
    });
  });

  describe('Scope Extraction Stress', () => {
    it('extracts from 100 scoped fields', () => {
      const payload: Record<string, number> = {};
      for (let i = 0; i < 100; i++) {
        payload[`field${i}`] = i;
      }

      const scope = Object.keys(payload);
      const start = Date.now();

      for (let i = 0; i < 100; i++) {
        ashExtractScopedFields(payload, scope);
      }

      const duration = Date.now() - start;
      console.log(`100 extractions with 100 fields: ${duration}ms`);
      expect(duration).toBeLessThan(5000);
    });

    it('handles deeply nested scope paths', () => {
      const payload = {
        level1: {
          level2: {
            level3: {
              level4: {
                level5: {
                  value: 'deep',
                },
              },
            },
          },
        },
      };

      const scope = ['level1.level2.level3.level4.level5.value'];
      const start = Date.now();

      for (let i = 0; i < 1000; i++) {
        ashExtractScopedFields(payload, scope);
      }

      const duration = Date.now() - start;
      console.log(`1000 deep extractions: ${duration}ms`);
      expect(duration).toBeLessThan(5000);
    });
  });

  describe('Query Canonicalization Stress', () => {
    it('canonicalizes query with 100 parameters', () => {
      const params = Array.from({ length: 100 }, (_, i) => `key${i}=value${i}`).join('&');
      const start = Date.now();

      for (let i = 0; i < 500; i++) {
        ashCanonicalizeQuery(params);
      }

      const duration = Date.now() - start;
      console.log(`500 canonicalizations of 100 params: ${duration}ms`);
      expect(duration).toBeLessThan(5000);
    });
  });

  describe('Full Request Flow Stress', () => {
    it('processes 500 complete request flows', () => {
      const start = Date.now();

      for (let i = 0; i < 500; i++) {
        // Complete request flow
        const nonce = ashGenerateNonce();
        const contextId = ashGenerateContextId();
        const binding = ashNormalizeBinding('POST', '/api/test', `page=${i}`);
        const payload = { action: 'test', iteration: i };
        const bodyHash = ashHashBody(JSON.stringify(payload));
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
        const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);
        const valid = ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof);

        expect(valid).toBe(true);
      }

      const duration = Date.now() - start;
      const opsPerSecond = (500 / duration) * 1000;

      console.log(`Complete request flows: ${opsPerSecond.toFixed(0)} ops/sec`);
      expect(opsPerSecond).toBeGreaterThan(10);
    });

    it('processes 200 chained request flows', () => {
      const setup = createProofSetup();
      const start = Date.now();

      let previousProof: string | undefined;

      for (let i = 0; i < 200; i++) {
        const payload = { step: i };
        const timestamp = (parseInt(setup.timestamp) + i).toString();

        const result = ashBuildProofUnified(
          setup.clientSecret,
          timestamp,
          setup.binding,
          payload,
          [],
          previousProof
        );

        const valid = ashVerifyProofUnified(
          setup.nonce,
          setup.contextId,
          setup.binding,
          timestamp,
          payload,
          result.proof,
          [],
          '',
          previousProof,
          result.chainHash
        );

        expect(valid).toBe(true);
        previousProof = result.proof;
      }

      const duration = Date.now() - start;
      console.log(`200 chained requests: ${duration}ms`);
      expect(duration).toBeLessThan(10000);
    });
  });

  describe('Throughput Benchmarks', () => {
    it('measures overall throughput', () => {
      const operations = 1000;
      const results: Record<string, number> = {};

      // Hash throughput
      let start = Date.now();
      for (let i = 0; i < operations; i++) {
        ashHashBody(`data${i}`);
      }
      results['hash'] = Math.round((operations / (Date.now() - start)) * 1000);

      // JSON canonicalization throughput
      start = Date.now();
      for (let i = 0; i < operations; i++) {
        ashCanonicalizeJsonNative(`{"key":${i}}`);
      }
      results['json_canon'] = Math.round((operations / (Date.now() - start)) * 1000);

      // Nonce generation throughput
      start = Date.now();
      for (let i = 0; i < operations; i++) {
        ashGenerateNonce();
      }
      results['nonce_gen'] = Math.round((operations / (Date.now() - start)) * 1000);

      // Proof build throughput
      const secret = 'testsecret';
      const binding = 'POST|/test|';
      const bodyHash = ashHashBody('{}');
      start = Date.now();
      for (let i = 0; i < operations; i++) {
        ashBuildProof(secret, (1700000000 + i).toString(), binding, bodyHash);
      }
      results['proof_build'] = Math.round((operations / (Date.now() - start)) * 1000);

      console.log('Throughput (ops/sec):', results);

      // Verify minimum throughputs
      expect(results['hash']).toBeGreaterThan(100);
      expect(results['json_canon']).toBeGreaterThan(100);
      expect(results['nonce_gen']).toBeGreaterThan(100);
      expect(results['proof_build']).toBeGreaterThan(100);
    });
  });
});
