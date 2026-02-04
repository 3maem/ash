/**
 * Fuzzing and Property-Based Security Tests
 *
 * Tests the ASH SDK against:
 * 1. Random/malformed inputs (fuzzing)
 * 2. Security attack vectors (penetration testing)
 * 3. Edge cases and boundary conditions
 *
 * Note: These tests use native implementations to avoid WASM environment issues.
 */

import { describe, it, expect } from 'vitest';
import * as crypto from 'crypto';
import {
  ashBuildProofV21,
  ashVerifyProofV21,
  ashDeriveClientSecret,
  ashValidateTimestamp,
  ashExtractScopedFields,
  ashExtractScopedFieldsStrict,
  normalizeScopeFields,
  joinScopeFields,
  AshMemoryStore,
  ashHashBody,
} from './index';
import { SecureBuffer, SecureString } from './utils/secureMemory';

// Helper to generate random strings
function randomString(length: number, charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'): string {
  let result = '';
  for (let i = 0; i < length; i++) {
    result += charset[Math.floor(Math.random() * charset.length)];
  }
  return result;
}

// Helper to generate random bytes as hex
function randomHex(bytes: number): string {
  return crypto.randomBytes(bytes).toString('hex');
}

// Number of iterations for fuzz tests
const FUZZ_ITERATIONS = 500;

describe('Fuzzing Tests', () => {
  describe('Proof Generation/Verification Fuzzing', () => {
    it('should handle random valid inputs', () => {
      for (let i = 0; i < FUZZ_ITERATIONS; i++) {
        // Generate nonce and context ID
        const nonce = randomHex(32);
        const contextId = `ctx_${randomHex(16)}`;
        const binding = `${['GET', 'POST', 'PUT', 'DELETE'][Math.floor(Math.random() * 4)]}|/${randomString(20)}|`;
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const bodyHash = randomHex(32);

        // Derive client secret (as server does)
        const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

        // Build proof with client secret
        const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);
        expect(typeof proof).toBe('string');
        expect(proof.length).toBe(64); // SHA256 hex

        // Verify using nonce and contextId (as server does)
        const isValid = ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof);
        expect(isValid).toBe(true);
      }
    });

    it('should reject tampered proofs', () => {
      const nonce = randomHex(32);
      const contextId = `ctx_${randomHex(16)}`;
      const binding = 'GET|/api/test|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const bodyHash = randomHex(32);

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

      // Tamper with nonce
      expect(ashVerifyProofV21(randomHex(32), contextId, binding, timestamp, bodyHash, proof)).toBe(false);
      // Tamper with contextId
      expect(ashVerifyProofV21(nonce, 'ctx_wrong', binding, timestamp, bodyHash, proof)).toBe(false);
      // Tamper with binding
      expect(ashVerifyProofV21(nonce, contextId, 'POST|/api/test|', timestamp, bodyHash, proof)).toBe(false);
      // Tamper with timestamp
      expect(ashVerifyProofV21(nonce, contextId, binding, '0', bodyHash, proof)).toBe(false);
      // Tamper with body hash
      expect(ashVerifyProofV21(nonce, contextId, binding, timestamp, randomHex(32), proof)).toBe(false);

      // Tamper with proof itself
      // Ensure we actually change the proof (if first char is 'a', use 'b' instead)
      const tamperedChar = proof[0] === 'a' ? 'b' : 'a';
      const tamperedProof = tamperedChar + proof.slice(1);
      expect(tamperedProof).not.toBe(proof); // Verify tampering worked
      expect(ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, tamperedProof)).toBe(false);
    });
  });

  describe('Client Secret Derivation Fuzzing', () => {
    it('should handle random valid inputs', () => {
      for (let i = 0; i < FUZZ_ITERATIONS; i++) {
        const nonce = randomHex(32);
        const contextId = `ctx_${randomHex(16)}`;
        const binding = `GET|/${randomString(20)}|`;

        const secret = ashDeriveClientSecret(nonce, contextId, binding);
        expect(typeof secret).toBe('string');
        expect(secret.length).toBe(64);

        // Same inputs should produce same output (deterministic)
        const secret2 = ashDeriveClientSecret(nonce, contextId, binding);
        expect(secret).toBe(secret2);
      }
    });

    it('should reject invalid nonces', () => {
      const invalidNonces = [
        '',
        'short',
        'not-hex-characters!!!',
        randomString(31), // odd length
      ];

      for (const nonce of invalidNonces) {
        expect(() => ashDeriveClientSecret(nonce, 'ctx_test', 'GET|/|')).toThrow();
      }
    });
  });

  describe('Timestamp Validation Fuzzing', () => {
    it('should handle valid timestamps', () => {
      const now = Math.floor(Date.now() / 1000);

      // Valid timestamps
      expect(ashValidateTimestamp(now.toString())).toBe(true);
      expect(ashValidateTimestamp((now - 30).toString())).toBe(true);
      expect(ashValidateTimestamp((now + 30).toString())).toBe(true);
    });

    it('should reject invalid timestamp formats', () => {
      // SDK throws for invalid formats rather than returning false
      expect(() => ashValidateTimestamp('-1')).toThrow();
      expect(() => ashValidateTimestamp('abc')).toThrow();
      expect(() => ashValidateTimestamp('')).toThrow();
      expect(() => ashValidateTimestamp('1.5')).toThrow();
      expect(() => ashValidateTimestamp(' 123')).toThrow();
      expect(() => ashValidateTimestamp('123 ')).toThrow();
    });

    it('should reject negative parameters', () => {
      const now = Math.floor(Date.now() / 1000);
      expect(() => ashValidateTimestamp(now.toString(), { clockSkewSeconds: -1 })).toThrow();
      expect(() => ashValidateTimestamp(now.toString(), { maxAgeSeconds: -1 })).toThrow();
    });

    it('should reject Infinity/NaN parameters', () => {
      const now = Math.floor(Date.now() / 1000);
      expect(() => ashValidateTimestamp(now.toString(), { clockSkewSeconds: Infinity })).toThrow();
      expect(() => ashValidateTimestamp(now.toString(), { maxAgeSeconds: NaN })).toThrow();
    });
  });

  describe('Scope Extraction Fuzzing', () => {
    it('should handle random payloads with valid scope paths', () => {
      for (let i = 0; i < FUZZ_ITERATIONS; i++) {
        const payload: Record<string, unknown> = {
          id: randomString(10),
          name: randomString(20),
          count: Math.floor(Math.random() * 1000),
          active: Math.random() > 0.5,
          nested: {
            value: randomString(10),
            deep: {
              leaf: randomString(5),
            },
          },
        };

        const scopePaths = ['id', 'name', 'nested.value', 'nested.deep.leaf'];
        const result = ashExtractScopedFields(payload, scopePaths);
        expect(typeof result).toBe('object');
        expect(result.id).toBe(payload.id);
        expect(result.name).toBe(payload.name);
      }
    });

    it('should handle missing fields gracefully', () => {
      const payload = { existing: 'value' };
      const scopePaths = ['existing', 'missing', 'also.missing'];

      // Non-strict should not throw - returns object with existing fields only
      const result = ashExtractScopedFields(payload, scopePaths);
      expect(typeof result).toBe('object');
      expect(result.existing).toBe('value');

      // Strict should throw for missing required fields
      expect(() => ashExtractScopedFieldsStrict(payload, scopePaths)).toThrow();
    });

    it('should reject non-object payloads', () => {
      const invalidPayloads = [null, undefined, 'string', 123, true, []];

      for (const payload of invalidPayloads) {
        expect(() => ashExtractScopedFields(payload as Record<string, unknown>, ['field'])).toThrow();
      }
    });
  });

  describe('Scope Normalization Fuzzing', () => {
    it('should deduplicate and sort random scope arrays', () => {
      for (let i = 0; i < FUZZ_ITERATIONS; i++) {
        const scopes: string[] = [];
        const count = Math.floor(Math.random() * 20) + 1;
        for (let j = 0; j < count; j++) {
          scopes.push(randomString(Math.floor(Math.random() * 30) + 1));
        }
        // Add some duplicates
        if (scopes.length > 2) {
          scopes.push(scopes[0]);
          scopes.push(scopes[1]);
        }

        const normalized = normalizeScopeFields(scopes);

        // Should be sorted
        for (let k = 1; k < normalized.length; k++) {
          expect(normalized[k - 1] <= normalized[k]).toBe(true);
        }

        // Should have no duplicates
        const unique = new Set(normalized);
        expect(unique.size).toBe(normalized.length);
      }
    });
  });
});

describe('Security Penetration Tests', () => {
  describe('Prototype Pollution Prevention', () => {
    it('should reject dangerous metadata keys at creation', async () => {
      const store = new AshMemoryStore();

      // Use JSON.parse to simulate real-world metadata from API requests
      // (JavaScript object literals treat __proto__ specially, but JSON.parse creates real properties)

      // __proto__ from JSON.parse should be rejected
      await expect(store.create({
        binding: 'GET|/test|',
        ttlMs: 30000,
        metadata: JSON.parse('{"__proto__": {"polluted": true}}'),
      })).rejects.toThrow('dangerous key');

      // constructor should be rejected
      await expect(store.create({
        binding: 'GET|/test|',
        ttlMs: 30000,
        metadata: { 'constructor': 'dangerous' },
      })).rejects.toThrow('dangerous key');

      // prototype should be rejected
      await expect(store.create({
        binding: 'GET|/test|',
        ttlMs: 30000,
        metadata: { 'prototype': 'dangerous' },
      })).rejects.toThrow('dangerous key');
    });

    it('should allow safe metadata', async () => {
      const store = new AshMemoryStore();

      const ctx = await store.create({
        binding: 'GET|/test|',
        ttlMs: 30000,
        metadata: {
          userId: 'user123',
          action: 'transfer',
          amount: 100,
        },
      });

      const retrieved = await store.get(ctx.id);
      expect(retrieved?.metadata?.userId).toBe('user123');
      expect(retrieved?.metadata?.action).toBe('transfer');
      expect(retrieved?.metadata?.amount).toBe(100);
    });
  });

  describe('Timing Attack Resistance', () => {
    it('should have consistent timing for valid vs invalid proofs', () => {
      const nonce = randomHex(32);
      const contextId = `ctx_${randomHex(16)}`;
      const binding = 'GET|/api/test|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const bodyHash = randomHex(32);

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const validProof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);
      const invalidProof = randomHex(32);

      // Run multiple iterations to average timing
      const iterations = 1000;

      const startValid = performance.now();
      for (let i = 0; i < iterations; i++) {
        ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, validProof);
      }
      const validTime = performance.now() - startValid;

      const startInvalid = performance.now();
      for (let i = 0; i < iterations; i++) {
        ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, invalidProof);
      }
      const invalidTime = performance.now() - startInvalid;

      // Timing should be within 100% of each other (allowing for system noise)
      // A timing attack would show >10x difference, so 2x threshold is safe
      const ratio = Math.max(validTime, invalidTime) / Math.min(validTime, invalidTime);
      expect(ratio).toBeLessThan(2.0);
    });
  });

  describe('Input Length Attacks', () => {
    it('should reject overly long bindings', () => {
      const longBinding = 'GET|/' + 'a'.repeat(10000) + '|';

      // The SDK has a MAX_BINDING_LENGTH of 8192
      expect(() => ashDeriveClientSecret(randomHex(32), 'ctx_test', longBinding)).toThrow();
    });

    it('should reject overly long context IDs', () => {
      const longContextId = 'ctx_' + 'a'.repeat(300);

      // The SDK has a MAX_CONTEXT_ID_LENGTH of 256
      expect(() => ashDeriveClientSecret(randomHex(32), longContextId, 'GET|/|')).toThrow();
    });
  });

  describe('Integer Overflow/Underflow', () => {
    it('should reject extreme TTL values', async () => {
      const store = new AshMemoryStore();

      await expect(store.create({
        binding: 'GET|/test|',
        ttlMs: Number.MAX_SAFE_INTEGER,
      })).rejects.toThrow();

      await expect(store.create({
        binding: 'GET|/test|',
        ttlMs: Infinity,
      })).rejects.toThrow();

      await expect(store.create({
        binding: 'GET|/test|',
        ttlMs: -1,
      })).rejects.toThrow();

      await expect(store.create({
        binding: 'GET|/test|',
        ttlMs: 0,
      })).rejects.toThrow();

      await expect(store.create({
        binding: 'GET|/test|',
        ttlMs: NaN,
      })).rejects.toThrow();
    });
  });

  describe('Replay Attack Prevention', () => {
    it('should prevent double consumption of context', async () => {
      const store = new AshMemoryStore();

      const ctx = await store.create({
        binding: 'POST|/api/transfer|',
        ttlMs: 30000,
      });

      // First consumption should succeed
      expect(await store.consume(ctx.id)).toBe(true);

      // Second consumption should fail
      expect(await store.consume(ctx.id)).toBe(false);

      // Even with the same context ID
      expect(await store.consume(ctx.id)).toBe(false);
    });

    it('should prevent consumption of expired context', async () => {
      const store = new AshMemoryStore();

      const ctx = await store.create({
        binding: 'POST|/api/transfer|',
        ttlMs: 1, // 1ms TTL
      });

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 10));

      // Should fail
      expect(await store.consume(ctx.id)).toBe(false);
    });
  });
});

describe('SecureBuffer/SecureString Security Tests', () => {
  describe('SecureBuffer Security', () => {
    it('should reject invalid hex strings', () => {
      expect(() => new SecureBuffer('not-hex!')).toThrow();
      expect(() => new SecureBuffer('abc')).toThrow(); // Odd length
      expect(() => new SecureBuffer('GHIJ')).toThrow(); // Invalid chars
    });

    it('should reject negative or invalid sizes', () => {
      expect(() => new SecureBuffer(-1)).toThrow();
      expect(() => new SecureBuffer(1.5)).toThrow();
    });

    it('should properly clear memory', () => {
      const secret = new SecureBuffer(32);
      const originalHex = secret.toHex();
      expect(originalHex.length).toBe(64);

      secret.clear();

      expect(secret.isCleared).toBe(true);
      expect(() => secret.get()).toThrow();
      expect(() => secret.toHex()).toThrow();
    });

    it('should return copies, not references', () => {
      const secret = new SecureBuffer('deadbeef');
      const buf1 = secret.get();
      const buf2 = secret.get();

      // Should be different Buffer instances
      expect(buf1).not.toBe(buf2);

      // Modifying one should not affect the other
      buf1[0] = 0xFF;
      expect(buf2[0]).not.toBe(0xFF);
    });
  });

  describe('SecureString Security', () => {
    it('should properly clear memory', () => {
      const secret = new SecureString('supersecret');
      expect(secret.get()).toBe('supersecret');

      secret.clear();

      expect(secret.isCleared).toBe(true);
      expect(() => secret.get()).toThrow();
    });

    it('should not expose data in toString', () => {
      const secret = new SecureString('supersecret');
      const str = secret.toString();

      expect(str).not.toContain('supersecret');
      expect(str).toContain('SecureString');
    });
  });
});

describe('Edge Case Tests', () => {
  describe('Empty and Null Handling', () => {
    it('should handle empty scope arrays', () => {
      const normalized = normalizeScopeFields([]);
      expect(normalized).toEqual([]);

      const joined = joinScopeFields([]);
      expect(joined).toBe('');
    });

    it('should handle empty payload with no scopes', () => {
      const result = ashExtractScopedFields({}, []);
      expect(result).toEqual({});
    });
  });

  describe('Concurrent Operations', () => {
    it('should handle concurrent context creation', async () => {
      const store = new AshMemoryStore();

      const promises = Array(100).fill(null).map((_, i) =>
        store.create({
          binding: `POST|/api/item/${i}|`,
          ttlMs: 30000,
        })
      );

      const contexts = await Promise.all(promises);

      // All should have unique IDs
      const ids = new Set(contexts.map(c => c.id));
      expect(ids.size).toBe(100);
    });

    it('should handle concurrent consumption attempts', async () => {
      const store = new AshMemoryStore();

      const ctx = await store.create({
        binding: 'POST|/api/transfer|',
        ttlMs: 30000,
      });

      // Try to consume 100 times concurrently
      const promises = Array(100).fill(null).map(() => store.consume(ctx.id));
      const results = await Promise.all(promises);

      // Exactly one should succeed
      const successes = results.filter(r => r === true);
      expect(successes.length).toBe(1);
    });
  });
});

describe('Property-Based Tests (Extended)', () => {
  describe('Proof Invariants', () => {
    it('proof should be deterministic (same inputs = same output)', () => {
      for (let i = 0; i < FUZZ_ITERATIONS; i++) {
        const nonce = randomHex(32);
        const contextId = `ctx_${randomHex(16)}`;
        const binding = `GET|/${randomString(10)}|`;
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const bodyHash = randomHex(32);

        const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
        const proof1 = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);
        const proof2 = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

        expect(proof1).toBe(proof2);
      }
    });

    it('different inputs should produce different proofs', () => {
      const nonce = randomHex(32);
      const contextId = `ctx_${randomHex(16)}`;
      const binding = 'GET|/api/test|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const bodyHash = randomHex(32);

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const proof1 = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

      // Change each input and verify different proof
      const proof2 = ashBuildProofV21(clientSecret, (parseInt(timestamp) + 1).toString(), binding, bodyHash);
      const proof3 = ashBuildProofV21(clientSecret, timestamp, 'POST|/api/test|', bodyHash);
      const proof4 = ashBuildProofV21(clientSecret, timestamp, binding, randomHex(32));

      expect(proof1).not.toBe(proof2);
      expect(proof1).not.toBe(proof3);
      expect(proof1).not.toBe(proof4);
    });

    it('client secret should be deterministic', () => {
      for (let i = 0; i < FUZZ_ITERATIONS; i++) {
        const nonce = randomHex(32);
        const contextId = `ctx_${randomHex(16)}`;
        const binding = `GET|/${randomString(10)}|`;

        const secret1 = ashDeriveClientSecret(nonce, contextId, binding);
        const secret2 = ashDeriveClientSecret(nonce, contextId, binding);

        expect(secret1).toBe(secret2);
      }
    });
  });

  describe('Store Invariants', () => {
    it('context ID should always be unique', async () => {
      const store = new AshMemoryStore();
      const ids = new Set<string>();

      for (let i = 0; i < FUZZ_ITERATIONS; i++) {
        const ctx = await store.create({
          binding: `GET|/test/${i}|`,
          ttlMs: 60000,
        });
        expect(ids.has(ctx.id)).toBe(false);
        ids.add(ctx.id);
      }

      expect(ids.size).toBe(FUZZ_ITERATIONS);
    });

    it('nonce should always be unique', async () => {
      const store = new AshMemoryStore();
      const nonces = new Set<string>();

      for (let i = 0; i < FUZZ_ITERATIONS; i++) {
        const ctx = await store.create({
          binding: `GET|/test/${i}|`,
          ttlMs: 60000,
        });
        expect(nonces.has(ctx.nonce!)).toBe(false);
        nonces.add(ctx.nonce!);
      }

      expect(nonces.size).toBe(FUZZ_ITERATIONS);
    });

    it('consumed context should not be retrievable as unused', async () => {
      const store = new AshMemoryStore();

      for (let i = 0; i < 100; i++) {
        const ctx = await store.create({
          binding: `POST|/api/action/${i}|`,
          ttlMs: 60000,
        });

        // Consume it
        const consumed = await store.consume(ctx.id);
        expect(consumed).toBe(true);

        // Get should still return context but marked as used
        const retrieved = await store.get(ctx.id);
        expect(retrieved).not.toBeNull();
        expect(retrieved!.used).toBe(true);

        // Second consume should fail
        const consumedAgain = await store.consume(ctx.id);
        expect(consumedAgain).toBe(false);
      }
    });
  });

  describe('Scope Invariants', () => {
    it('normalization should be idempotent', () => {
      for (let i = 0; i < FUZZ_ITERATIONS; i++) {
        const scopes = Array(Math.floor(Math.random() * 10) + 1)
          .fill(null)
          .map(() => randomString(Math.floor(Math.random() * 20) + 1));

        const normalized1 = normalizeScopeFields(scopes);
        const normalized2 = normalizeScopeFields(normalized1);

        expect(normalized1).toEqual(normalized2);
      }
    });

    it('normalization should always produce sorted unique array', () => {
      for (let i = 0; i < FUZZ_ITERATIONS; i++) {
        const scopes = Array(Math.floor(Math.random() * 20) + 1)
          .fill(null)
          .map(() => randomString(Math.floor(Math.random() * 15) + 1));

        // Add duplicates
        if (scopes.length > 3) {
          scopes.push(scopes[0], scopes[1], scopes[2]);
        }

        const normalized = normalizeScopeFields(scopes);

        // Check sorted
        for (let j = 1; j < normalized.length; j++) {
          expect(normalized[j - 1] <= normalized[j]).toBe(true);
        }

        // Check unique
        expect(new Set(normalized).size).toBe(normalized.length);
      }
    });

    it('joining empty scopes should produce empty string', () => {
      expect(joinScopeFields([])).toBe('');
      expect(joinScopeFields(normalizeScopeFields([]))).toBe('');
    });
  });

  describe('Timestamp Invariants', () => {
    it('current timestamp should always be valid', () => {
      for (let i = 0; i < 100; i++) {
        const now = Math.floor(Date.now() / 1000);
        expect(ashValidateTimestamp(now.toString())).toBe(true);
      }
    });

    it('future timestamps within clock skew should be valid', () => {
      const now = Math.floor(Date.now() / 1000);
      // Default clock skew is 60 seconds
      expect(ashValidateTimestamp((now + 30).toString())).toBe(true);
      expect(ashValidateTimestamp((now + 59).toString())).toBe(true);
    });

    it('very old timestamps should be invalid', () => {
      const now = Math.floor(Date.now() / 1000);
      const veryOld = now - (365 * 24 * 60 * 60); // 1 year ago
      // With default maxAge of 300 seconds, this should throw
      expect(() => ashValidateTimestamp(veryOld.toString())).toThrow('expired');
    });
  });

  describe('Input Boundary Tests', () => {
    it('should handle minimum valid nonce length', () => {
      const minNonce = randomHex(16); // 32 hex chars = 16 bytes (minimum)
      const contextId = 'ctx_test';
      const binding = 'GET|/|';

      // Should not throw
      const secret = ashDeriveClientSecret(minNonce, contextId, binding);
      expect(secret.length).toBe(64);
    });

    it('should handle maximum valid nonce length', () => {
      const maxNonce = randomHex(64); // 128 hex chars = 64 bytes (maximum)
      const contextId = 'ctx_test';
      const binding = 'GET|/|';

      // Should not throw
      const secret = ashDeriveClientSecret(maxNonce, contextId, binding);
      expect(secret.length).toBe(64);
    });

    it('should reject nonce just under minimum', () => {
      const shortNonce = randomHex(15); // 30 hex chars (under 32 minimum)
      expect(() => ashDeriveClientSecret(shortNonce, 'ctx_test', 'GET|/|')).toThrow();
    });

    it('should reject nonce just over maximum', () => {
      const longNonce = randomHex(65); // 130 hex chars (over 128 maximum)
      expect(() => ashDeriveClientSecret(longNonce, 'ctx_test', 'GET|/|')).toThrow();
    });

    it('should handle various valid TTL values', async () => {
      const store = new AshMemoryStore();
      const validTtls = [1, 100, 1000, 60000, 3600000, 86400000];

      for (const ttl of validTtls) {
        const ctx = await store.create({
          binding: 'GET|/test|',
          ttlMs: ttl,
        });
        expect(ctx.id).toBeDefined();
      }
    });

    it('should handle binding at various lengths', () => {
      const lengths = [10, 100, 500, 1000, 4000, 8000];

      for (const len of lengths) {
        const path = '/' + 'a'.repeat(len);
        const binding = `GET|${path}|`;

        if (binding.length <= 8192) {
          // Should not throw
          const secret = ashDeriveClientSecret(randomHex(32), 'ctx_test', binding);
          expect(secret.length).toBe(64);
        }
      }
    });
  });

  describe('Metadata Edge Cases', () => {
    it('should handle deeply nested metadata', async () => {
      const store = new AshMemoryStore();

      const deepMetadata: Record<string, unknown> = {
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

      const ctx = await store.create({
        binding: 'GET|/test|',
        ttlMs: 30000,
        metadata: deepMetadata,
      });

      const retrieved = await store.get(ctx.id);
      expect((retrieved?.metadata as Record<string, unknown>)?.level1).toBeDefined();
    });

    it('should handle metadata with many keys', async () => {
      const store = new AshMemoryStore();

      const manyKeys: Record<string, unknown> = {};
      for (let i = 0; i < 100; i++) {
        manyKeys[`key${i}`] = `value${i}`;
      }

      const ctx = await store.create({
        binding: 'GET|/test|',
        ttlMs: 30000,
        metadata: manyKeys,
      });

      const retrieved = await store.get(ctx.id);
      expect(Object.keys(retrieved?.metadata || {}).length).toBe(100);
    });

    it('should handle metadata with various value types', async () => {
      const store = new AshMemoryStore();

      const mixedMetadata = {
        string: 'hello',
        number: 42,
        float: 3.14159,
        boolean: true,
        null: null,
        array: [1, 2, 3],
        object: { nested: 'value' },
      };

      const ctx = await store.create({
        binding: 'GET|/test|',
        ttlMs: 30000,
        metadata: mixedMetadata,
      });

      const retrieved = await store.get(ctx.id);
      expect(retrieved?.metadata).toBeDefined();
      expect((retrieved?.metadata as Record<string, unknown>).string).toBe('hello');
      expect((retrieved?.metadata as Record<string, unknown>).number).toBe(42);
      expect((retrieved?.metadata as Record<string, unknown>).boolean).toBe(true);
    });
  });
});
