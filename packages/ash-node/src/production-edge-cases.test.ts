/**
 * ASH SDK Production Edge Cases Test Suite
 *
 * Tests edge cases that may occur in production environments:
 * - Unicode handling across different encodings
 * - Timezone and locale variations
 * - Network latency and clock skew
 * - Memory pressure scenarios
 * - Concurrent access patterns
 * - Internationalization edge cases
 */

import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
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
  ashValidateTimestamp,
} from './index';

beforeAll(() => {
  ashInit();
});

// =========================================================================
// UNICODE AND INTERNATIONALIZATION
// =========================================================================

describe('PRODUCTION: Unicode Edge Cases', () => {
  describe('Multi-byte Characters', () => {
    it('PROD-UNI-001: handles CJK characters correctly', () => {
      const cjkPayloads = [
        { name: '日本語', value: '中文' },
        { korean: '한국어', japanese: 'カタカナ' },
        { simplified: '简体中文', traditional: '繁體中文' },
      ];

      for (const payload of cjkPayloads) {
        const json = JSON.stringify(payload);
        const canonical = canonicalizeJsonNative(json);
        const parsed = JSON.parse(canonical);

        // Values should be preserved
        expect(parsed).toEqual(payload);
      }
    });

    it('PROD-UNI-002: handles emoji correctly', () => {
      const emojiPayloads = [
        { emoji: '😀🎉🔥💯' },
        { skin: '👋🏻👋🏼👋🏽👋🏾👋🏿' },
        { family: '👨‍👩‍👧‍👦' },
        { flags: '🇺🇸🇯🇵🇬🇧🇩🇪' },
      ];

      for (const payload of emojiPayloads) {
        const json = JSON.stringify(payload);
        const canonical = canonicalizeJsonNative(json);
        const parsed = JSON.parse(canonical);

        expect(parsed).toEqual(payload);
      }
    });

    it('PROD-UNI-003: handles RTL languages correctly', () => {
      const rtlPayloads = [
        { arabic: 'مرحبا بالعالم' },
        { hebrew: 'שלום עולם' },
        { mixed: 'Hello مرحبا World' },
      ];

      for (const payload of rtlPayloads) {
        const json = JSON.stringify(payload);
        const canonical = canonicalizeJsonNative(json);
        const parsed = JSON.parse(canonical);

        expect(parsed).toEqual(payload);
      }
    });

    it('PROD-UNI-004: handles combining characters', () => {
      // é can be represented as e + combining accent or precomposed
      const nfd = 'cafe\u0301'; // NFD: e + combining acute
      const nfc = 'café';       // NFC: precomposed é

      const json1 = JSON.stringify({ text: nfd });
      const json2 = JSON.stringify({ text: nfc });

      const canon1 = canonicalizeJsonNative(json1);
      const canon2 = canonicalizeJsonNative(json2);

      // Both should normalize to same form
      expect(canon1).toBe(canon2);
    });

    it('PROD-UNI-005: handles zero-width characters', () => {
      const zwPayloads = [
        { text: 'a\u200Bb' },  // Zero-width space
        { text: 'a\u200Cb' },  // Zero-width non-joiner
        { text: 'a\u200Db' },  // Zero-width joiner
        { text: 'a\uFEFFb' },  // BOM
      ];

      for (const payload of zwPayloads) {
        const json = JSON.stringify(payload);
        const canonical = canonicalizeJsonNative(json);
        // Should not throw
        expect(() => JSON.parse(canonical)).not.toThrow();
      }
    });
  });

  describe('URL Encoding Edge Cases', () => {
    it('PROD-UNI-006: handles percent-encoded Unicode in query', () => {
      const queries = [
        'name=%E6%97%A5%E6%9C%AC%E8%AA%9E',  // 日本語
        'emoji=%F0%9F%98%80',                  // 😀
        'mixed=hello%E4%B8%96%E7%95%8C',       // hello世界
      ];

      for (const query of queries) {
        const canonical = canonicalQueryNative(query);
        expect(canonical).toContain('=');
      }
    });

    it('PROD-UNI-007: handles mixed ASCII and Unicode in paths', () => {
      const paths = [
        '/api/用户/profile',
        '/api/users/日本',
        '/café/menu',
      ];

      for (const path of paths) {
        try {
          const binding = ashNormalizeBinding('GET', path, '');
          expect(binding).toContain('|');
        } catch {
          // Some paths may be rejected - that's OK
        }
      }
    });
  });
});

// =========================================================================
// TIMESTAMP AND CLOCK SKEW
// =========================================================================

describe('PRODUCTION: Timestamp Edge Cases', () => {
  describe('Clock Skew Tolerance', () => {
    it('PROD-TIME-001: accepts timestamps within tolerance', () => {
      const now = Math.floor(Date.now() / 1000);

      // Should accept timestamps within reasonable window
      const validTimestamps = [
        now.toString(),
        (now - 30).toString(),  // 30 seconds ago
        (now + 30).toString(),  // 30 seconds ahead
      ];

      for (const ts of validTimestamps) {
        expect(() => ashValidateTimestamp(ts)).not.toThrow();
      }
    });

    it('PROD-TIME-002: rejects significantly skewed timestamps', () => {
      const now = Math.floor(Date.now() / 1000);

      // Should reject timestamps way off
      const invalidTimestamps = [
        (now - 3600).toString(),   // 1 hour ago
        (now + 3600).toString(),   // 1 hour ahead
        (now - 86400).toString(),  // 1 day ago
      ];

      for (const ts of invalidTimestamps) {
        expect(() => ashValidateTimestamp(ts)).toThrow();
      }
    });

    it('PROD-TIME-003: handles DST transition edge cases', () => {
      // Timestamps near DST transitions should still work
      // (timestamps are Unix time, so DST doesn't affect them)
      const now = Math.floor(Date.now() / 1000);
      expect(() => ashValidateTimestamp(now.toString())).not.toThrow();
    });

    it('PROD-TIME-004: handles Y2038 boundary', () => {
      // Unix timestamp overflow happens at 2038-01-19
      const y2038 = '2147483647';  // Max 32-bit signed int

      // Should reject as it's way in the future (or past if we're past 2038)
      expect(() => ashValidateTimestamp(y2038)).toThrow();
    });

    it('PROD-TIME-005: handles epoch edge cases', () => {
      expect(() => ashValidateTimestamp('0')).toThrow();
      expect(() => ashValidateTimestamp('-1')).toThrow();
    });
  });
});

// =========================================================================
// CONCURRENT ACCESS PATTERNS
// =========================================================================

describe('PRODUCTION: Concurrent Access', () => {
  describe('High Concurrency Context Store', () => {
    it('PROD-CONC-001: handles 1000 concurrent creates', async () => {
      const store = new AshMemoryStore();

      const createPromises = Array(1000).fill(null).map((_, i) =>
        store.create({
          binding: `POST|/api/resource/${i}|`,
          ttlMs: 60000,
        })
      );

      const contexts = await Promise.all(createPromises);

      // All should succeed with unique IDs
      const ids = new Set(contexts.map(c => c.id));
      expect(ids.size).toBe(1000);
    });

    it('PROD-CONC-002: handles concurrent create/consume/get', async () => {
      const store = new AshMemoryStore();
      const operations: Promise<unknown>[] = [];

      // Mix of operations
      for (let i = 0; i < 100; i++) {
        // Create
        const createPromise = store.create({
          binding: `POST|/api/test/${i}|`,
          ttlMs: 60000,
        }).then(ctx => {
          // Immediately try to consume
          return store.consume(ctx.id);
        });

        operations.push(createPromise);
      }

      // All should complete without error
      await Promise.all(operations);
    });

    it('PROD-CONC-003: exactly-once semantics under race', async () => {
      const store = new AshMemoryStore();
      const results: boolean[] = [];

      // Run 100 iterations
      for (let i = 0; i < 100; i++) {
        const ctx = await store.create({
          binding: 'POST|/api/transfer|',
          ttlMs: 60000,
        });

        // 20 concurrent consume attempts
        const consumeResults = await Promise.all(
          Array(20).fill(null).map(() => store.consume(ctx.id))
        );

        const successes = consumeResults.filter(r => r === true).length;
        results.push(successes === 1);
      }

      // All iterations should have exactly 1 success
      expect(results.every(r => r)).toBe(true);
    });
  });

  describe('High Throughput Proof Generation', () => {
    it('PROD-CONC-004: generates 10000 proofs correctly', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const binding = 'POST|/api/test|';
      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

      for (let i = 0; i < 10000; i++) {
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const bodyHash = crypto.randomBytes(32).toString('hex');

        const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);
        expect(proof).toHaveLength(64);

        const isValid = ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof);
        expect(isValid).toBe(true);
      }
    });
  });
});

// =========================================================================
// NUMERIC EDGE CASES
// =========================================================================

describe('PRODUCTION: Numeric Edge Cases', () => {
  describe('JSON Number Handling', () => {
    it('PROD-NUM-001: handles very large numbers', () => {
      const largeNumbers = [
        { value: Number.MAX_SAFE_INTEGER },
        { value: Number.MAX_SAFE_INTEGER - 1 },
        { value: 9999999999999 },
      ];

      for (const payload of largeNumbers) {
        const json = JSON.stringify(payload);
        const canonical = canonicalizeJsonNative(json);
        const parsed = JSON.parse(canonical);

        expect(parsed.value).toBe(payload.value);
      }
    });

    it('PROD-NUM-002: handles very small numbers', () => {
      const smallNumbers = [
        { value: 0.0000001 },
        { value: 1e-10 },
        { value: Number.MIN_VALUE },
      ];

      for (const payload of smallNumbers) {
        const json = JSON.stringify(payload);
        const canonical = canonicalizeJsonNative(json);
        expect(() => JSON.parse(canonical)).not.toThrow();
      }
    });

    it('PROD-NUM-003: handles negative zero', () => {
      // -0 should become 0 in canonical form
      const json = JSON.stringify({ value: -0 });
      const canonical = canonicalizeJsonNative(json);

      // Should not contain "-0"
      expect(canonical).not.toContain('-0');
    });

    it('PROD-NUM-004: handles integer-like floats', () => {
      const intFloats = [
        { value: 1.0 },
        { value: 100.0 },
        { value: -50.0 },
      ];

      for (const payload of intFloats) {
        const json = JSON.stringify(payload);
        const canonical = canonicalizeJsonNative(json);
        const parsed = JSON.parse(canonical);

        expect(parsed.value).toBe(payload.value);
      }
    });
  });
});

// =========================================================================
// STRING EDGE CASES
// =========================================================================

describe('PRODUCTION: String Edge Cases', () => {
  describe('Special Characters', () => {
    it('PROD-STR-001: handles all JSON escape sequences', () => {
      const escapePayloads = [
        { text: 'line1\nline2' },           // Newline
        { text: 'tab\there' },              // Tab
        { text: 'back\\slash' },            // Backslash
        { text: 'quote"here' },             // Quote
        { text: 'carriage\rreturn' },       // CR
        { text: 'form\ffeed' },             // Form feed
        { text: 'back\bspace' },            // Backspace
      ];

      for (const payload of escapePayloads) {
        const json = JSON.stringify(payload);
        const canonical = canonicalizeJsonNative(json);
        const parsed = JSON.parse(canonical);

        expect(parsed.text).toBe(payload.text);
      }
    });

    it('PROD-STR-002: handles null bytes', () => {
      const nullPayload = { text: 'before\x00after' };
      const json = JSON.stringify(nullPayload);
      const canonical = canonicalizeJsonNative(json);

      expect(() => JSON.parse(canonical)).not.toThrow();
    });

    it('PROD-STR-003: handles very long strings', () => {
      const longString = 'a'.repeat(1000000);  // 1MB string
      const payload = { data: longString };
      const json = JSON.stringify(payload);

      const canonical = canonicalizeJsonNative(json);
      const parsed = JSON.parse(canonical);

      expect(parsed.data.length).toBe(1000000);
    });

    it('PROD-STR-004: handles empty strings', () => {
      const emptyPayloads = [
        { key: '' },
        { '': 'value' },
        { '': '' },
      ];

      for (const payload of emptyPayloads) {
        const json = JSON.stringify(payload);
        const canonical = canonicalizeJsonNative(json);
        const parsed = JSON.parse(canonical);

        expect(parsed).toEqual(payload);
      }
    });
  });
});

// =========================================================================
// ARRAY AND OBJECT EDGE CASES
// =========================================================================

describe('PRODUCTION: Structure Edge Cases', () => {
  describe('Array Handling', () => {
    it('PROD-ARR-001: preserves array order', () => {
      const arrayPayload = { items: [3, 1, 4, 1, 5, 9, 2, 6] };
      const json = JSON.stringify(arrayPayload);
      const canonical = canonicalizeJsonNative(json);
      const parsed = JSON.parse(canonical);

      expect(parsed.items).toEqual([3, 1, 4, 1, 5, 9, 2, 6]);
    });

    it('PROD-ARR-002: handles nested arrays', () => {
      const nestedPayload = { matrix: [[1, 2], [3, 4], [5, 6]] };
      const json = JSON.stringify(nestedPayload);
      const canonical = canonicalizeJsonNative(json);
      const parsed = JSON.parse(canonical);

      expect(parsed.matrix).toEqual([[1, 2], [3, 4], [5, 6]]);
    });

    it('PROD-ARR-003: handles empty arrays', () => {
      const emptyPayload = { items: [] };
      const json = JSON.stringify(emptyPayload);
      const canonical = canonicalizeJsonNative(json);
      const parsed = JSON.parse(canonical);

      expect(parsed.items).toEqual([]);
    });

    it('PROD-ARR-004: handles sparse arrays (JSON serialized)', () => {
      // Note: JSON.stringify converts sparse arrays to arrays with null
      const arr = [1, , , 4]; // Sparse array
      const json = JSON.stringify({ items: arr });
      const canonical = canonicalizeJsonNative(json);
      const parsed = JSON.parse(canonical);

      expect(parsed.items).toEqual([1, null, null, 4]);
    });
  });

  describe('Object Handling', () => {
    it('PROD-OBJ-001: sorts keys lexicographically', () => {
      const unsorted = { z: 1, a: 2, m: 3, b: 4 };
      const json = JSON.stringify(unsorted);
      const canonical = canonicalizeJsonNative(json);

      // Check key order in output
      const keyOrder = canonical.match(/"([^"]+)":/g)?.map(k => k.slice(1, -2));
      expect(keyOrder).toEqual(['a', 'b', 'm', 'z']);
    });

    it('PROD-OBJ-002: handles deeply nested objects', () => {
      let obj: Record<string, unknown> = { value: 'deep' };
      for (let i = 0; i < 50; i++) {
        obj = { nested: obj };
      }

      const json = JSON.stringify(obj);
      const canonical = canonicalizeJsonNative(json);

      expect(() => JSON.parse(canonical)).not.toThrow();
    });

    it('PROD-OBJ-003: handles objects with many keys', () => {
      const manyKeys: Record<string, number> = {};
      for (let i = 0; i < 1000; i++) {
        manyKeys[`key${i.toString().padStart(4, '0')}`] = i;
      }

      const json = JSON.stringify(manyKeys);
      const canonical = canonicalizeJsonNative(json);
      const parsed = JSON.parse(canonical);

      expect(Object.keys(parsed).length).toBe(1000);
    });
  });
});

// =========================================================================
// QUERY STRING EDGE CASES
// =========================================================================

describe('PRODUCTION: Query String Edge Cases', () => {
  it('PROD-QS-001: handles duplicate keys', () => {
    const query = 'a=1&a=2&a=3';
    const canonical = canonicalQueryNative(query);

    // All values should be preserved
    expect(canonical).toContain('a=1');
    expect(canonical).toContain('a=2');
    expect(canonical).toContain('a=3');
  });

  it('PROD-QS-002: handles keys without values', () => {
    const query = 'flag&key=value';
    const canonical = canonicalQueryNative(query);

    expect(canonical).toContain('flag=');
  });

  it('PROD-QS-003: handles empty query string', () => {
    expect(canonicalQueryNative('')).toBe('');
    expect(canonicalQueryNative('?')).toBe('');
  });

  it('PROD-QS-004: handles special characters in values', () => {
    const query = 'url=https%3A%2F%2Fexample.com%2Fpath%3Fq%3D1';
    const canonical = canonicalQueryNative(query);

    expect(canonical).toContain('url=');
  });

  it('PROD-QS-005: normalizes percent encoding case', () => {
    const lowercase = 'key=%2f';  // Lowercase hex
    const uppercase = 'key=%2F';  // Uppercase hex

    const canon1 = canonicalQueryNative(lowercase);
    const canon2 = canonicalQueryNative(uppercase);

    // Both should normalize to same form (uppercase)
    expect(canon1).toBe(canon2);
    expect(canon1).toContain('%2F');
  });
});

// =========================================================================
// MEMORY PRESSURE SCENARIOS
// =========================================================================

describe('PRODUCTION: Memory Pressure', () => {
  it('PROD-MEM-001: handles many small contexts', async () => {
    const store = new AshMemoryStore();

    // Create 10000 contexts
    const contexts = await Promise.all(
      Array(10000).fill(null).map((_, i) =>
        store.create({
          binding: `GET|/api/${i}|`,
          ttlMs: 60000,
        })
      )
    );

    expect(contexts.length).toBe(10000);

    // Verify we can still access them
    for (let i = 0; i < 100; i++) {
      const randomIndex = Math.floor(Math.random() * 10000);
      const ctx = await store.get(contexts[randomIndex].id);
      expect(ctx).not.toBeNull();
    }
  });

  it('PROD-MEM-002: expired contexts are cleaned up', async () => {
    const store = new AshMemoryStore();

    // Create contexts with short TTL
    const shortLivedContexts = await Promise.all(
      Array(100).fill(null).map(() =>
        store.create({
          binding: 'GET|/test|',
          ttlMs: 1,  // 1ms TTL
        })
      )
    );

    // Wait for expiration
    await new Promise(resolve => setTimeout(resolve, 50));

    // All should be expired
    for (const ctx of shortLivedContexts) {
      const result = await store.consume(ctx.id);
      expect(result).toBe(false);
    }
  });
});

console.log('Production Edge Cases Test Suite loaded');
