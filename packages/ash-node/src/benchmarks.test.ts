/**
 * ASH SDK Performance Benchmarks
 *
 * Tests performance characteristics to ensure the SDK meets production requirements.
 * Note: These are functional tests that verify performance is acceptable, not microbenchmarks.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'crypto';
import {
  ashInit,
  ashBuildProofV21,
  ashVerifyProofV21,
  ashDeriveClientSecret,
  ashCanonicalizeJson,
  ashCanonicalizeQuery,
  ashNormalizeBinding,
  ashHashBody,
  ashGenerateNonce,
  ashGenerateContextId,
  canonicalizeJsonNative,
  canonicalQueryNative,
  ashBuildProofScoped,
  ashVerifyProofScoped,
  AshMemoryStore,
} from './index';

beforeAll(() => {
  ashInit();
});

// =========================================================================
// HELPER FUNCTIONS
// =========================================================================

function measureTime(fn: () => void, iterations: number): { totalMs: number; avgMs: number; opsPerSec: number } {
  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    fn();
  }
  const end = performance.now();
  const totalMs = end - start;
  const avgMs = totalMs / iterations;
  const opsPerSec = (iterations / totalMs) * 1000;

  return { totalMs, avgMs, opsPerSec };
}

async function measureTimeAsync(fn: () => Promise<void>, iterations: number): Promise<{ totalMs: number; avgMs: number; opsPerSec: number }> {
  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    await fn();
  }
  const end = performance.now();
  const totalMs = end - start;
  const avgMs = totalMs / iterations;
  const opsPerSec = (iterations / totalMs) * 1000;

  return { totalMs, avgMs, opsPerSec };
}

// =========================================================================
// PROOF GENERATION BENCHMARKS
// =========================================================================

describe('Benchmark: Proof Generation', () => {
  const nonce = crypto.randomBytes(32).toString('hex');
  const contextId = 'ctx_benchmark';
  const binding = 'POST|/api/test|';
  const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const bodyHash = crypto.randomBytes(32).toString('hex');

  it('should generate at least 5,000 proofs per second', () => {
    const iterations = 5000;
    const result = measureTime(() => {
      ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);
    }, iterations);

    console.log(`Proof generation: ${result.opsPerSec.toFixed(0)} ops/sec (${result.avgMs.toFixed(3)}ms avg)`);

    expect(result.opsPerSec).toBeGreaterThan(5000);
  });

  it('should generate 10,000 proofs in under 2 seconds', () => {
    const iterations = 10000;
    const result = measureTime(() => {
      ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);
    }, iterations);

    console.log(`10,000 proofs in ${result.totalMs.toFixed(0)}ms`);

    expect(result.totalMs).toBeLessThan(2000);
  });
});

// =========================================================================
// PROOF VERIFICATION BENCHMARKS
// =========================================================================

describe('Benchmark: Proof Verification', () => {
  const nonce = crypto.randomBytes(32).toString('hex');
  const contextId = 'ctx_benchmark';
  const binding = 'POST|/api/test|';
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const bodyHash = crypto.randomBytes(32).toString('hex');
  const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
  const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

  it('should verify at least 5,000 proofs per second', () => {
    const iterations = 5000;
    const result = measureTime(() => {
      ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof);
    }, iterations);

    console.log(`Proof verification: ${result.opsPerSec.toFixed(0)} ops/sec (${result.avgMs.toFixed(3)}ms avg)`);

    expect(result.opsPerSec).toBeGreaterThan(5000);
  });

  it('should verify 10,000 proofs in under 2 seconds', () => {
    const iterations = 10000;
    const result = measureTime(() => {
      ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof);
    }, iterations);

    console.log(`10,000 verifications in ${result.totalMs.toFixed(0)}ms`);

    expect(result.totalMs).toBeLessThan(2000);
  });
});

// =========================================================================
// JSON CANONICALIZATION BENCHMARKS
// =========================================================================

describe('Benchmark: JSON Canonicalization', () => {
  const smallJson = '{"b":2,"a":1}';
  const mediumJson = JSON.stringify({
    user: { name: 'John', age: 30, email: 'john@example.com' },
    items: [1, 2, 3, 4, 5],
    metadata: { created: '2024-01-01', updated: '2024-01-02' },
  });
  const largeJson = JSON.stringify({
    users: Array(100).fill(null).map((_, i) => ({
      id: i,
      name: `User ${i}`,
      email: `user${i}@example.com`,
      data: { value: i * 100 },
    })),
  });

  it('should canonicalize at least 10,000 small JSON objects per second', () => {
    const iterations = 10000;
    const result = measureTime(() => {
      canonicalizeJsonNative(smallJson);
    }, iterations);

    console.log(`Small JSON: ${result.opsPerSec.toFixed(0)} ops/sec`);

    expect(result.opsPerSec).toBeGreaterThan(10000);
  });

  it('should canonicalize at least 5,000 medium JSON objects per second', () => {
    const iterations = 5000;
    const result = measureTime(() => {
      canonicalizeJsonNative(mediumJson);
    }, iterations);

    console.log(`Medium JSON: ${result.opsPerSec.toFixed(0)} ops/sec`);

    expect(result.opsPerSec).toBeGreaterThan(5000);
  });

  it('should canonicalize at least 500 large JSON objects per second', () => {
    const iterations = 500;
    const result = measureTime(() => {
      canonicalizeJsonNative(largeJson);
    }, iterations);

    console.log(`Large JSON (100 users): ${result.opsPerSec.toFixed(0)} ops/sec`);

    expect(result.opsPerSec).toBeGreaterThan(500);
  });
});

// =========================================================================
// QUERY STRING CANONICALIZATION BENCHMARKS
// =========================================================================

describe('Benchmark: Query String Canonicalization', () => {
  const simpleQuery = 'a=1&b=2&c=3';
  const complexQuery = Array(20).fill(null)
    .map((_, i) => `param${i}=value${i}`)
    .join('&');

  it('should canonicalize at least 20,000 simple queries per second', () => {
    const iterations = 20000;
    const result = measureTime(() => {
      canonicalQueryNative(simpleQuery);
    }, iterations);

    console.log(`Simple query: ${result.opsPerSec.toFixed(0)} ops/sec`);

    expect(result.opsPerSec).toBeGreaterThan(20000);
  });

  it('should canonicalize at least 5,000 complex queries per second', () => {
    const iterations = 5000;
    const result = measureTime(() => {
      canonicalQueryNative(complexQuery);
    }, iterations);

    console.log(`Complex query (20 params): ${result.opsPerSec.toFixed(0)} ops/sec`);

    expect(result.opsPerSec).toBeGreaterThan(5000);
  });
});

// =========================================================================
// HASHING BENCHMARKS
// =========================================================================

describe('Benchmark: Hashing', () => {
  const smallBody = '{"key":"value"}';
  const largeBody = JSON.stringify({ data: 'x'.repeat(10000) });

  it('should hash at least 50,000 small bodies per second', () => {
    const iterations = 50000;
    const result = measureTime(() => {
      ashHashBody(smallBody);
    }, iterations);

    console.log(`Small body hash: ${result.opsPerSec.toFixed(0)} ops/sec`);

    expect(result.opsPerSec).toBeGreaterThan(50000);
  });

  it('should hash at least 5,000 large bodies (10KB) per second', () => {
    const iterations = 5000;
    const result = measureTime(() => {
      ashHashBody(largeBody);
    }, iterations);

    console.log(`Large body hash (10KB): ${result.opsPerSec.toFixed(0)} ops/sec`);

    expect(result.opsPerSec).toBeGreaterThan(5000);
  });
});

// =========================================================================
// CLIENT SECRET DERIVATION BENCHMARKS
// =========================================================================

describe('Benchmark: Client Secret Derivation', () => {
  const nonce = crypto.randomBytes(32).toString('hex');
  const contextId = 'ctx_benchmark';
  const binding = 'POST|/api/test|';

  it('should derive at least 10,000 secrets per second', () => {
    const iterations = 10000;
    const result = measureTime(() => {
      ashDeriveClientSecret(nonce, contextId, binding);
    }, iterations);

    console.log(`Secret derivation: ${result.opsPerSec.toFixed(0)} ops/sec`);

    expect(result.opsPerSec).toBeGreaterThan(10000);
  });
});

// =========================================================================
// CONTEXT STORE BENCHMARKS
// =========================================================================

describe('Benchmark: Context Store', () => {
  it('should create at least 5,000 contexts per second', async () => {
    const store = new AshMemoryStore();
    const iterations = 5000;

    const result = await measureTimeAsync(async () => {
      await store.create({
        binding: 'POST|/api/test|',
        ttlMs: 60000,
      });
    }, iterations);

    console.log(`Context creation: ${result.opsPerSec.toFixed(0)} ops/sec`);

    expect(result.opsPerSec).toBeGreaterThan(5000);
  });

  it('should consume at least 10,000 contexts per second', async () => {
    const store = new AshMemoryStore();

    // Pre-create contexts
    const contexts = await Promise.all(
      Array(10000).fill(null).map(() =>
        store.create({ binding: 'POST|/api/test|', ttlMs: 60000 })
      )
    );

    let index = 0;
    const result = await measureTimeAsync(async () => {
      await store.consume(contexts[index++].id);
    }, contexts.length);

    console.log(`Context consumption: ${result.opsPerSec.toFixed(0)} ops/sec`);

    expect(result.opsPerSec).toBeGreaterThan(10000);
  });

  it('should handle 1,000 concurrent operations', async () => {
    const store = new AshMemoryStore();

    const start = performance.now();

    await Promise.all([
      // 500 creates
      ...Array(500).fill(null).map(() =>
        store.create({ binding: 'POST|/api/test|', ttlMs: 60000 })
      ),
      // 500 creates followed by consumes
      ...Array(500).fill(null).map(async () => {
        const ctx = await store.create({ binding: 'POST|/api/test|', ttlMs: 60000 });
        return store.consume(ctx.id);
      }),
    ]);

    const elapsed = performance.now() - start;
    console.log(`1,000 concurrent operations in ${elapsed.toFixed(0)}ms`);

    expect(elapsed).toBeLessThan(2000);
  });
});

// =========================================================================
// SCOPED PROOF BENCHMARKS
// =========================================================================

describe('Benchmark: Scoped Proofs', () => {
  const nonce = crypto.randomBytes(32).toString('hex');
  const contextId = 'ctx_scoped_bench';
  const binding = 'POST|/api/transfer|';
  const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const payload = { amount: 100, recipient: 'alice', memo: 'test payment' };
  const scope = ['amount', 'recipient'];

  it('should build at least 3,000 scoped proofs per second', () => {
    const iterations = 3000;
    const result = measureTime(() => {
      ashBuildProofScoped(clientSecret, timestamp, binding, payload, scope);
    }, iterations);

    console.log(`Scoped proof build: ${result.opsPerSec.toFixed(0)} ops/sec`);

    expect(result.opsPerSec).toBeGreaterThan(3000);
  });

  it('should verify at least 3,000 scoped proofs per second', () => {
    const { proof, scopeHash } = ashBuildProofScoped(clientSecret, timestamp, binding, payload, scope);

    const iterations = 3000;
    const result = measureTime(() => {
      ashVerifyProofScoped(nonce, contextId, binding, timestamp, payload, scope, scopeHash, proof);
    }, iterations);

    console.log(`Scoped proof verify: ${result.opsPerSec.toFixed(0)} ops/sec`);

    expect(result.opsPerSec).toBeGreaterThan(3000);
  });
});

// =========================================================================
// END-TO-END WORKFLOW BENCHMARKS
// =========================================================================

describe('Benchmark: End-to-End Workflow', () => {
  it('should complete full request signing workflow 2,000 times per second', () => {
    const iterations = 2000;

    const result = measureTime(() => {
      const nonce = crypto.randomBytes(32).toString('hex');
      const contextId = `ctx_${crypto.randomBytes(8).toString('hex')}`;
      const method = 'POST';
      const path = '/api/transfer';
      const query = 'confirm=true';
      const body = JSON.stringify({ amount: 100, recipient: 'alice' });

      // Full workflow
      const binding = ashNormalizeBinding(method, path, query);
      const canonicalBody = canonicalizeJsonNative(body);
      const bodyHash = ashHashBody(canonicalBody);
      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

      // Verification
      ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof);
    }, iterations);

    console.log(`End-to-end workflow: ${result.opsPerSec.toFixed(0)} ops/sec`);

    expect(result.opsPerSec).toBeGreaterThan(2000);
  });
});

// =========================================================================
// MEMORY STABILITY
// =========================================================================

describe('Benchmark: Memory Stability', () => {
  it('should not show significant memory growth over 100,000 operations', () => {
    const nonce = crypto.randomBytes(32).toString('hex');
    const contextId = 'ctx_memory_test';
    const binding = 'POST|/api/test|';
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const bodyHash = crypto.randomBytes(32).toString('hex');

    // Force GC if available
    if (global.gc) {
      global.gc();
    }

    const initialMemory = process.memoryUsage().heapUsed;

    // Run 100,000 operations
    for (let i = 0; i < 100000; i++) {
      const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);
      ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof);
    }

    // Force GC if available
    if (global.gc) {
      global.gc();
    }

    const finalMemory = process.memoryUsage().heapUsed;
    const memoryGrowthMB = (finalMemory - initialMemory) / (1024 * 1024);

    console.log(`Memory growth after 100,000 ops: ${memoryGrowthMB.toFixed(2)}MB`);

    // Memory growth should be less than 50MB (allowing for normal variation)
    expect(memoryGrowthMB).toBeLessThan(50);
  });
});

// =========================================================================
// NONCE GENERATION BENCHMARKS
// =========================================================================

describe('Benchmark: Nonce Generation', () => {
  it('should generate at least 50,000 nonces per second', () => {
    const iterations = 50000;
    const result = measureTime(() => {
      ashGenerateNonce();
    }, iterations);

    console.log(`Nonce generation: ${result.opsPerSec.toFixed(0)} ops/sec`);

    expect(result.opsPerSec).toBeGreaterThan(50000);
  });

  it('should generate at least 50,000 context IDs per second', () => {
    const iterations = 50000;
    const result = measureTime(() => {
      ashGenerateContextId();
    }, iterations);

    console.log(`Context ID generation: ${result.opsPerSec.toFixed(0)} ops/sec`);

    expect(result.opsPerSec).toBeGreaterThan(50000);
  });
});

console.log('Performance Benchmarks loaded');
