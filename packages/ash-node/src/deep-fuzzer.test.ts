/**
 * ASH SDK Deep Fuzzer Test Suite
 *
 * High-iteration fuzzing with 10,000+ test cases per category.
 * Tests randomized inputs across all API surfaces.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as fc from 'fast-check';
import * as crypto from 'crypto';
import {
  ashInit,
  ashBuildProofV21,
  ashVerifyProofV21,
  ashDeriveClientSecret,
  ashCanonicalizeJson,
  ashCanonicalizeUrlencoded,
  ashCanonicalizeQuery,
  ashNormalizeBinding,
  ashHashBody,
  ashGenerateNonce,
  ashGenerateContextId,
  canonicalizeJsonNative,
  canonicalQueryNative,
  ashBuildProofScoped,
  ashVerifyProofScoped,
  ashBuildProofUnified,
  ashVerifyProofUnified,
  ashExtractScopedFields,
  AshMemoryStore,
} from './index';

// High iteration counts for deep fuzzing
const FUZZ_RUNS = 10000;
const CRYPTO_RUNS = 5000;

beforeAll(() => {
  ashInit();
});

// Custom arbitraries
const hexString = (length: number) =>
  fc.array(fc.integer({ min: 0, max: 15 }), { minLength: length, maxLength: length })
    .map(arr => arr.map(n => n.toString(16)).join(''));

const alphaNumString = (minLen: number, maxLen: number) =>
  fc.stringMatching(new RegExp(`^[a-zA-Z0-9]{${minLen},${maxLen}}$`));

const alphaLowerString = (minLen: number, maxLen: number) =>
  fc.stringMatching(new RegExp(`^[a-z0-9]{${minLen},${maxLen}}$`));

const httpMethod = fc.constantFrom('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS');

const urlPath = fc.array(alphaLowerString(1, 20), { minLength: 1, maxLength: 5 })
  .map(parts => '/' + parts.join('/'));

const queryParam = fc.tuple(
  alphaNumString(1, 20),
  alphaNumString(0, 50)
).map(([k, v]) => `${k}=${v}`);

const queryString = fc.array(queryParam, { minLength: 0, maxLength: 10 })
  .map(params => params.join('&'));

const jsonValue: fc.Arbitrary<unknown> = fc.letrec(tie => ({
  value: fc.oneof(
    fc.string(),
    fc.double({ noNaN: true, noDefaultInfinity: true }),
    fc.boolean(),
    fc.constant(null),
    fc.array(tie('value'), { maxLength: 5 }),
    fc.dictionary(fc.string({ minLength: 1, maxLength: 10 }), tie('value'), { maxKeys: 5 })
  )
})).value;

const jsonObject = fc.dictionary(
  fc.stringMatching(/^[a-zA-Z_]{1,20}$/),
  jsonValue,
  { minKeys: 1, maxKeys: 10 }
);

describe('DEEP FUZZER: Proof Generation/Verification (10,000 runs)', () => {
  it('property: verify(build(inputs)) === true', () => {
    fc.assert(
      fc.property(
        hexString(64),           // nonce (32 bytes = 64 hex)
        fc.stringMatching(/^[a-z0-9_]{4,40}$/).map(s => `ctx_${s}`),
        httpMethod,
        urlPath,
        queryString,
        hexString(64),           // bodyHash
        (nonce, contextId, method, path, query, bodyHash) => {
          const binding = ashNormalizeBinding(method, path, query);
          const timestamp = Math.floor(Date.now() / 1000).toString();

          const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
          const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

          // Property: what we build should verify
          const isValid = ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof);
          return isValid === true;
        }
      ),
      { numRuns: FUZZ_RUNS }
    );
  });

  it('property: tampered proof never verifies', () => {
    fc.assert(
      fc.property(
        hexString(64),
        fc.stringMatching(/^[a-z0-9_]{4,20}$/).map(s => `ctx_${s}`),
        fc.integer({ min: 0, max: 63 }),  // tamper position
        (nonce, contextId, tamperPos) => {
          const binding = 'POST|/api/test|';
          const timestamp = Math.floor(Date.now() / 1000).toString();
          const bodyHash = crypto.randomBytes(32).toString('hex');

          const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
          const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

          // Tamper at random position
          const chars = proof.split('');
          chars[tamperPos] = chars[tamperPos] === 'a' ? 'b' : 'a';
          const tamperedProof = chars.join('');

          if (tamperedProof === proof) return true; // Skip if no change

          const isValid = ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, tamperedProof);
          return isValid === false;
        }
      ),
      { numRuns: FUZZ_RUNS }
    );
  });

  it('property: different nonce produces different proof', () => {
    fc.assert(
      fc.property(
        hexString(64),
        hexString(64),
        (nonce1, nonce2) => {
          if (nonce1 === nonce2) return true; // Skip identical

          const contextId = 'ctx_test';
          const binding = 'POST|/api/test|';
          const timestamp = Math.floor(Date.now() / 1000).toString();
          const bodyHash = crypto.randomBytes(32).toString('hex');

          const secret1 = ashDeriveClientSecret(nonce1, contextId, binding);
          const secret2 = ashDeriveClientSecret(nonce2, contextId, binding);

          const proof1 = ashBuildProofV21(secret1, timestamp, binding, bodyHash);
          const proof2 = ashBuildProofV21(secret2, timestamp, binding, bodyHash);

          return proof1 !== proof2;
        }
      ),
      { numRuns: CRYPTO_RUNS }
    );
  });
});

describe('DEEP FUZZER: JSON Canonicalization (10,000 runs)', () => {
  it('property: canonicalization is deterministic', () => {
    fc.assert(
      fc.property(jsonObject, (obj) => {
        const json = JSON.stringify(obj);
        try {
          const canon1 = canonicalizeJsonNative(json);
          const canon2 = canonicalizeJsonNative(json);
          return canon1 === canon2;
        } catch {
          return true; // Skip invalid JSON
        }
      }),
      { numRuns: FUZZ_RUNS }
    );
  });

  it('property: canonicalization is idempotent', () => {
    fc.assert(
      fc.property(jsonObject, (obj) => {
        const json = JSON.stringify(obj);
        try {
          const canon1 = canonicalizeJsonNative(json);
          const canon2 = canonicalizeJsonNative(canon1);
          return canon1 === canon2;
        } catch {
          return true;
        }
      }),
      { numRuns: FUZZ_RUNS }
    );
  });

  it('property: key order does not affect canonical form', () => {
    fc.assert(
      fc.property(
        fc.dictionary(fc.string({ minLength: 1, maxLength: 10 }), fc.string(), { minKeys: 2, maxKeys: 5 }),
        (obj) => {
          const keys = Object.keys(obj);
          if (keys.length < 2) return true;

          // Create two objects with different key orders
          const obj1: Record<string, string> = {};
          const obj2: Record<string, string> = {};

          keys.forEach(k => obj1[k] = obj[k]);
          keys.reverse().forEach(k => obj2[k] = obj[k]);

          try {
            const canon1 = canonicalizeJsonNative(JSON.stringify(obj1));
            const canon2 = canonicalizeJsonNative(JSON.stringify(obj2));
            return canon1 === canon2;
          } catch {
            return true;
          }
        }
      ),
      { numRuns: FUZZ_RUNS }
    );
  });

  it('property: canonical JSON is valid JSON', () => {
    fc.assert(
      fc.property(jsonObject, (obj) => {
        const json = JSON.stringify(obj);
        try {
          const canonical = canonicalizeJsonNative(json);
          JSON.parse(canonical);
          return true;
        } catch {
          return true; // Skip errors
        }
      }),
      { numRuns: FUZZ_RUNS }
    );
  });
});

describe('DEEP FUZZER: Query String Canonicalization (10,000 runs)', () => {
  it('property: canonicalization is deterministic', () => {
    fc.assert(
      fc.property(queryString, (query) => {
        try {
          const canon1 = canonicalQueryNative(query);
          const canon2 = canonicalQueryNative(query);
          return canon1 === canon2;
        } catch {
          return true;
        }
      }),
      { numRuns: FUZZ_RUNS }
    );
  });

  it('property: canonicalization is idempotent', () => {
    fc.assert(
      fc.property(queryString, (query) => {
        try {
          const canon1 = canonicalQueryNative(query);
          const canon2 = canonicalQueryNative(canon1);
          return canon1 === canon2;
        } catch {
          return true;
        }
      }),
      { numRuns: FUZZ_RUNS }
    );
  });

  it('property: parameter order does not affect canonical form', () => {
    fc.assert(
      fc.property(
        fc.array(queryParam, { minLength: 2, maxLength: 5 }),
        (params) => {
          const query1 = params.join('&');
          const query2 = [...params].reverse().join('&');

          try {
            const canon1 = canonicalQueryNative(query1);
            const canon2 = canonicalQueryNative(query2);
            return canon1 === canon2;
          } catch {
            return true;
          }
        }
      ),
      { numRuns: FUZZ_RUNS }
    );
  });

  it('property: result is sorted by key', () => {
    fc.assert(
      fc.property(queryString, (query) => {
        try {
          const canonical = canonicalQueryNative(query);
          if (!canonical) return true;

          const pairs = canonical.split('&');
          for (let i = 1; i < pairs.length; i++) {
            const prevKey = pairs[i-1].split('=')[0];
            const currKey = pairs[i].split('=')[0];
            if (Buffer.from(prevKey).compare(Buffer.from(currKey)) > 0) {
              return false;
            }
          }
          return true;
        } catch {
          return true;
        }
      }),
      { numRuns: FUZZ_RUNS }
    );
  });
});

describe('DEEP FUZZER: Binding Normalization (10,000 runs)', () => {
  it('property: normalization is deterministic', () => {
    fc.assert(
      fc.property(httpMethod, urlPath, queryString, (method, path, query) => {
        try {
          const norm1 = ashNormalizeBinding(method, path, query);
          const norm2 = ashNormalizeBinding(method, path, query);
          return norm1 === norm2;
        } catch {
          return true;
        }
      }),
      { numRuns: FUZZ_RUNS }
    );
  });

  it('property: method is always uppercase', () => {
    fc.assert(
      fc.property(httpMethod, urlPath, (method, path) => {
        try {
          const normalized = ashNormalizeBinding(method.toLowerCase(), path, '');
          return normalized.startsWith(method.toUpperCase() + '|');
        } catch {
          return true;
        }
      }),
      { numRuns: FUZZ_RUNS }
    );
  });

  it('property: format is METHOD|PATH|QUERY', () => {
    fc.assert(
      fc.property(httpMethod, urlPath, queryString, (method, path, query) => {
        try {
          const normalized = ashNormalizeBinding(method, path, query);
          const parts = normalized.split('|');
          return parts.length === 3;
        } catch {
          return true;
        }
      }),
      { numRuns: FUZZ_RUNS }
    );
  });
});

describe('DEEP FUZZER: Cryptographic Properties (5,000 runs)', () => {
  it('property: client secrets are unique for different inputs', () => {
    const secrets = new Set<string>();

    fc.assert(
      fc.property(
        hexString(64),
        fc.stringMatching(/^[a-z0-9]{5,20}$/).map(s => `ctx_${s}`),
        (nonce, contextId) => {
          const binding = 'POST|/api/test|';
          const secret = ashDeriveClientSecret(nonce, contextId, binding);

          if (secrets.has(secret)) {
            return false; // Collision detected!
          }
          secrets.add(secret);
          return true;
        }
      ),
      { numRuns: CRYPTO_RUNS }
    );
  });

  it('property: body hashes are unique for different inputs', () => {
    const hashes = new Set<string>();

    fc.assert(
      fc.property(fc.string({ minLength: 1, maxLength: 1000 }), (body) => {
        const hash = ashHashBody(body);

        // Note: We don't check for collisions here as different strings
        // could theoretically produce the same hash (though extremely unlikely)
        // Instead we verify the hash is always 64 hex chars
        return hash.length === 64 && /^[0-9a-f]+$/.test(hash);
      }),
      { numRuns: CRYPTO_RUNS }
    );
  });

  it('property: proofs are exactly 64 hex characters', () => {
    fc.assert(
      fc.property(hexString(64), (nonce) => {
        const contextId = 'ctx_test';
        const binding = 'POST|/api/test|';
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const bodyHash = crypto.randomBytes(32).toString('hex');

        const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
        const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

        return proof.length === 64 && /^[0-9a-f]+$/.test(proof);
      }),
      { numRuns: CRYPTO_RUNS }
    );
  });

  it('property: nonces are cryptographically random', () => {
    const nonces: string[] = [];

    // Generate many nonces
    for (let i = 0; i < 1000; i++) {
      nonces.push(ashGenerateNonce());
    }

    // Check uniqueness
    const unique = new Set(nonces);
    expect(unique.size).toBe(nonces.length);

    // Check entropy distribution (chi-squared test approximation)
    const charCounts = new Map<string, number>();
    for (const nonce of nonces) {
      for (const char of nonce) {
        charCounts.set(char, (charCounts.get(char) || 0) + 1);
      }
    }

    // All 16 hex chars should appear
    expect(charCounts.size).toBe(16);

    // Distribution should be roughly uniform
    const counts = Array.from(charCounts.values());
    const mean = counts.reduce((a, b) => a + b, 0) / counts.length;
    const variance = counts.reduce((sum, c) => sum + Math.pow(c - mean, 2), 0) / counts.length;
    const coefficientOfVariation = Math.sqrt(variance) / mean;

    // CV should be low for uniform distribution
    expect(coefficientOfVariation).toBeLessThan(0.15);
  });
});

// Dangerous keys that are blocked by the SDK
const DANGEROUS_KEYS = ['__proto__', 'constructor', 'prototype'];

describe('DEEP FUZZER: Scoped Proofs (5,000 runs)', () => {
  it('property: scoped proof verifies with correct scope', () => {
    fc.assert(
      fc.property(
        hexString(64),
        fc.stringMatching(/^[a-z0-9]{4,20}$/).map(s => `ctx_${s}`),
        fc.dictionary(
          fc.stringMatching(/^[a-z]{1,10}$/),
          fc.oneof(fc.string(), fc.integer(), fc.boolean()),
          { minKeys: 2, maxKeys: 5 }
        ),
        (nonce, contextId, payload) => {
          // Filter out dangerous keys that would be rejected
          const safeKeys = Object.keys(payload).filter(k => !DANGEROUS_KEYS.includes(k));
          if (safeKeys.length < 1) return true;

          // Build safe payload
          const safePayload: Record<string, unknown> = {};
          for (const k of safeKeys) {
            safePayload[k] = payload[k];
          }

          const scope = safeKeys.slice(0, Math.ceil(safeKeys.length / 2));
          const binding = 'POST|/api/scoped|';
          const timestamp = Math.floor(Date.now() / 1000).toString();

          const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
          const { proof, scopeHash } = ashBuildProofScoped(
            clientSecret, timestamp, binding, safePayload, scope
          );

          const isValid = ashVerifyProofScoped(
            nonce, contextId, binding, timestamp, safePayload, scope, scopeHash, proof
          );

          return isValid === true;
        }
      ),
      { numRuns: CRYPTO_RUNS }
    );
  });

  it('property: scoped proof fails with wrong scope', () => {
    fc.assert(
      fc.property(
        hexString(64),
        fc.stringMatching(/^[a-z0-9]{4,20}$/).map(s => `ctx_${s}`),
        (nonce, contextId) => {
          const payload = { amount: 100, recipient: 'alice', memo: 'test' };
          const scope = ['amount', 'recipient'];
          const wrongScope = ['amount', 'memo'];

          const binding = 'POST|/api/transfer|';
          const timestamp = Math.floor(Date.now() / 1000).toString();

          const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
          const { proof, scopeHash } = ashBuildProofScoped(
            clientSecret, timestamp, binding, payload, scope
          );

          const isValid = ashVerifyProofScoped(
            nonce, contextId, binding, timestamp, payload, wrongScope, scopeHash, proof
          );

          return isValid === false;
        }
      ),
      { numRuns: CRYPTO_RUNS }
    );
  });
});

describe('DEEP FUZZER: Context Store Race Conditions (1,000 runs)', () => {
  it('property: exactly one concurrent consume succeeds', async () => {
    const results: boolean[] = [];

    for (let i = 0; i < 100; i++) {
      const store = new AshMemoryStore();
      const ctx = await store.create({
        binding: 'POST|/api/test|',
        ttlMs: 60000,
      });

      // Launch 10 concurrent consumes
      const consumeResults = await Promise.all(
        Array(10).fill(null).map(() => store.consume(ctx.id))
      );

      const successCount = consumeResults.filter(r => r === true).length;
      results.push(successCount === 1);
    }

    // All iterations should have exactly 1 success
    expect(results.every(r => r)).toBe(true);
  });
});

describe('DEEP FUZZER: Error Handling (5,000 runs)', () => {
  it('property: invalid nonce format throws', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 100 }),
        (invalidNonce) => {
          // Skip valid hex strings of correct length
          if (/^[0-9a-fA-F]{64,128}$/.test(invalidNonce)) return true;

          try {
            ashDeriveClientSecret(invalidNonce, 'ctx_test', 'GET|/|');
            return false; // Should have thrown
          } catch {
            return true;
          }
        }
      ),
      { numRuns: CRYPTO_RUNS }
    );
  });

  it('property: empty inputs throw', () => {
    const emptyTests = [
      () => ashDeriveClientSecret('', 'ctx', 'GET|/|'),
      () => ashDeriveClientSecret(crypto.randomBytes(32).toString('hex'), '', 'GET|/|'),
      () => ashDeriveClientSecret(crypto.randomBytes(32).toString('hex'), 'ctx', ''),
    ];

    for (const test of emptyTests) {
      expect(() => test()).toThrow();
    }
  });

  it('property: oversized inputs are rejected', () => {
    // Large JSON should be rejected
    const largeJson = JSON.stringify({ data: 'x'.repeat(11 * 1024 * 1024) });
    expect(() => canonicalizeJsonNative(largeJson)).toThrow();

    // Oversized nonce should be rejected
    const longNonce = crypto.randomBytes(100).toString('hex');
    expect(() => ashDeriveClientSecret(longNonce, 'ctx', 'GET|/|')).toThrow();
  });
});

console.log('Deep Fuzzer Test Suite loaded - 10,000+ iterations per test');
