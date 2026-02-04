/**
 * ASH SDK Cross-Platform Compatibility Tests
 *
 * Ensures consistent behavior across different SDK implementations.
 * Uses test vectors that should produce identical results in all SDKs.
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
  canonicalizeJsonNative,
  canonicalQueryNative,
  ashBuildProofScoped,
  ashVerifyProofScoped,
} from './index';

beforeAll(() => {
  ashInit();
});

// =========================================================================
// CROSS-SDK TEST VECTORS
// These vectors should produce identical results in Rust, Python, Go, etc.
// =========================================================================

describe('Cross-Platform: Canonical Test Vectors', () => {
  describe('JSON Canonicalization Vectors', () => {
    const jsonVectors = [
      {
        name: 'simple object with unsorted keys',
        input: '{"z":1,"a":2,"m":3}',
        expected: '{"a":2,"m":3,"z":1}',
      },
      {
        name: 'nested objects',
        input: '{"outer":{"z":1,"a":2},"first":true}',
        expected: '{"first":true,"outer":{"a":2,"z":1}}',
      },
      {
        name: 'array preservation',
        input: '{"arr":[3,1,2]}',
        expected: '{"arr":[3,1,2]}',
      },
      {
        name: 'negative zero normalization',
        input: '{"value":-0}',
        expected: '{"value":0}',
      },
      {
        name: 'unicode string',
        input: '{"greeting":"Hello, 世界!"}',
        expected: '{"greeting":"Hello, 世界!"}',
      },
      {
        name: 'escape sequences',
        input: '{"text":"line1\\nline2\\ttab"}',
        expected: '{"text":"line1\\nline2\\ttab"}',
      },
      {
        name: 'empty object',
        input: '{}',
        expected: '{}',
      },
      {
        name: 'empty array',
        input: '{"items":[]}',
        expected: '{"items":[]}',
      },
      {
        name: 'null value',
        input: '{"value":null}',
        expected: '{"value":null}',
      },
      {
        name: 'boolean values',
        input: '{"false":false,"true":true}',
        expected: '{"false":false,"true":true}',
      },
      {
        name: 'integer',
        input: '{"num":42}',
        expected: '{"num":42}',
      },
      {
        name: 'float',
        input: '{"num":3.14159}',
        expected: '{"num":3.14159}',
      },
      {
        name: 'scientific notation normalized',
        input: '{"num":1e2}',
        expected: '{"num":100}',
      },
    ];

    for (const vector of jsonVectors) {
      it(`should canonicalize: ${vector.name}`, () => {
        const result = canonicalizeJsonNative(vector.input);
        expect(result).toBe(vector.expected);
      });
    }
  });

  describe('Query String Canonicalization Vectors', () => {
    const queryVectors = [
      {
        name: 'simple sorting',
        input: 'z=3&a=1&m=2',
        expected: 'a=1&m=2&z=3',
      },
      {
        name: 'duplicate keys sorted by value',
        input: 'key=c&key=a&key=b',
        expected: 'key=a&key=b&key=c',
      },
      {
        name: 'percent encoding uppercase',
        input: 'key=%2f',
        expected: 'key=%2F',
      },
      {
        name: 'empty value',
        input: 'flag=&key=value',
        expected: 'flag=&key=value',
      },
      {
        name: 'leading question mark stripped',
        input: '?a=1&b=2',
        expected: 'a=1&b=2',
      },
      {
        name: 'fragment stripped',
        input: 'a=1&b=2#section',
        expected: 'a=1&b=2',
      },
      {
        name: 'empty query',
        input: '',
        expected: '',
      },
      {
        name: 'special characters encoded',
        input: 'url=https%3A%2F%2Fexample.com',
        expected: 'url=https%3A%2F%2Fexample.com',
      },
    ];

    for (const vector of queryVectors) {
      it(`should canonicalize: ${vector.name}`, () => {
        const result = canonicalQueryNative(vector.input);
        expect(result).toBe(vector.expected);
      });
    }
  });

  describe('Binding Normalization Vectors', () => {
    const bindingVectors = [
      {
        name: 'method uppercase',
        method: 'get',
        path: '/api/test',
        query: '',
        expected: 'GET|/api/test|',
      },
      {
        name: 'with query string',
        method: 'POST',
        path: '/api/search',
        query: 'q=test&page=1',
        expected: 'POST|/api/search|page=1&q=test',
      },
      {
        name: 'path normalization',
        method: 'GET',
        path: '/api//test/',
        query: '',
        expected: 'GET|/api/test|',
      },
      {
        name: 'dot segments resolved',
        method: 'GET',
        path: '/api/./test/../users',
        query: '',
        expected: 'GET|/api/users|',
      },
    ];

    for (const vector of bindingVectors) {
      it(`should normalize: ${vector.name}`, () => {
        const result = ashNormalizeBinding(vector.method, vector.path, vector.query);
        expect(result).toBe(vector.expected);
      });
    }
  });

  describe('Hash Body Vectors', () => {
    const hashVectors = [
      {
        name: 'empty string',
        input: '',
        expected: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      },
      {
        name: 'simple string',
        input: 'test',
        expected: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      },
      {
        name: 'JSON object',
        input: '{"a":1}',
        expected: crypto.createHash('sha256').update('{"a":1}').digest('hex'),
      },
    ];

    for (const vector of hashVectors) {
      it(`should hash: ${vector.name}`, () => {
        const result = ashHashBody(vector.input);
        expect(result).toBe(vector.expected);
      });
    }
  });

  describe('Client Secret Derivation Vectors', () => {
    it('should derive consistent secret from fixed inputs', () => {
      const nonce = 'a'.repeat(64);
      const contextId = 'ctx_test123';
      const binding = 'POST|/api/login|';

      const secret1 = ashDeriveClientSecret(nonce, contextId, binding);
      const secret2 = ashDeriveClientSecret(nonce, contextId, binding);

      expect(secret1).toBe(secret2);
      expect(secret1).toHaveLength(64);
      expect(/^[0-9a-f]+$/.test(secret1)).toBe(true);
    });

    it('should produce different secrets for different nonces', () => {
      const nonce1 = 'a'.repeat(64);
      const nonce2 = 'b'.repeat(64);
      const contextId = 'ctx_test123';
      const binding = 'POST|/api/login|';

      const secret1 = ashDeriveClientSecret(nonce1, contextId, binding);
      const secret2 = ashDeriveClientSecret(nonce2, contextId, binding);

      expect(secret1).not.toBe(secret2);
    });

    it('should produce different secrets for different contexts', () => {
      const nonce = 'a'.repeat(64);
      const binding = 'POST|/api/login|';

      const secret1 = ashDeriveClientSecret(nonce, 'ctx_user1', binding);
      const secret2 = ashDeriveClientSecret(nonce, 'ctx_user2', binding);

      expect(secret1).not.toBe(secret2);
    });

    it('should produce different secrets for different bindings', () => {
      const nonce = 'a'.repeat(64);
      const contextId = 'ctx_test123';

      const secret1 = ashDeriveClientSecret(nonce, contextId, 'GET|/api/read|');
      const secret2 = ashDeriveClientSecret(nonce, contextId, 'POST|/api/write|');

      expect(secret1).not.toBe(secret2);
    });
  });

  describe('Proof Generation/Verification Vectors', () => {
    it('should generate and verify proof with fixed inputs', () => {
      const nonce = 'a'.repeat(64);
      const contextId = 'ctx_test_vector';
      const binding = 'POST|/api/transfer|';
      const timestamp = '1700000000';
      const bodyHash = 'b'.repeat(64);

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

      expect(proof).toHaveLength(64);
      expect(/^[0-9a-f]+$/.test(proof)).toBe(true);

      const isValid = ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof);
      expect(isValid).toBe(true);
    });

    it('should reject proof with wrong nonce', () => {
      const nonce = 'a'.repeat(64);
      const wrongNonce = 'b'.repeat(64);
      const contextId = 'ctx_test_vector';
      const binding = 'POST|/api/transfer|';
      const timestamp = '1700000000';
      const bodyHash = 'c'.repeat(64);

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

      const isValid = ashVerifyProofV21(wrongNonce, contextId, binding, timestamp, bodyHash, proof);
      expect(isValid).toBe(false);
    });
  });
});

// =========================================================================
// ENDIANNESS AND BYTE ORDER TESTS
// =========================================================================

describe('Cross-Platform: Endianness Consistency', () => {
  it('should handle multi-byte Unicode consistently', () => {
    const unicodeInputs = [
      '{"emoji":"😀"}',
      '{"cjk":"日本語中文한국어"}',
      '{"mixed":"Hello 世界 🌍"}',
    ];

    for (const input of unicodeInputs) {
      const canonical = canonicalizeJsonNative(input);
      const hash = ashHashBody(canonical);

      // Hash should be consistent regardless of platform endianness
      expect(hash).toHaveLength(64);
      expect(/^[0-9a-f]+$/.test(hash)).toBe(true);

      // Re-canonicalizing should produce same result
      const canonical2 = canonicalizeJsonNative(canonical);
      expect(canonical).toBe(canonical2);
    }
  });

  it('should produce consistent byte ordering in query strings', () => {
    // Keys that would sort differently with different byte orders
    const query = 'zzz=1&aaa=2&ZZZ=3&AAA=4';
    const canonical = canonicalQueryNative(query);

    // Should be sorted by raw byte value
    expect(canonical).toBe('AAA=4&ZZZ=3&aaa=2&zzz=1');
  });

  it('should handle surrogate pairs consistently', () => {
    // Emoji that requires surrogate pairs in UTF-16
    const input = '{"emoji":"🎉🔥💯"}';
    const canonical = canonicalizeJsonNative(input);
    const parsed = JSON.parse(canonical);

    expect(parsed.emoji).toBe('🎉🔥💯');
  });
});

// =========================================================================
// INTEROPERABILITY SIMULATION
// =========================================================================

describe('Cross-Platform: Interoperability', () => {
  describe('Rust SDK Simulation', () => {
    it('should produce proofs verifiable by simulated Rust SDK', () => {
      // These test vectors would be validated against actual Rust SDK
      const testCases = [
        {
          nonce: '0'.repeat(64),
          contextId: 'ctx_rust_test',
          binding: 'GET|/api/data|',
          timestamp: '1700000000',
          body: '{}',
        },
        {
          nonce: 'f'.repeat(64),
          contextId: 'ctx_rust_test_2',
          binding: 'POST|/api/submit|a=1&b=2',
          timestamp: '1700000001',
          body: '{"key":"value"}',
        },
      ];

      for (const tc of testCases) {
        const bodyHash = ashHashBody(canonicalizeJsonNative(tc.body));
        const clientSecret = ashDeriveClientSecret(tc.nonce, tc.contextId, tc.binding);
        const proof = ashBuildProofV21(clientSecret, tc.timestamp, tc.binding, bodyHash);

        // Verify our own proof (simulating Rust SDK verification)
        const isValid = ashVerifyProofV21(
          tc.nonce, tc.contextId, tc.binding, tc.timestamp, bodyHash, proof
        );
        expect(isValid).toBe(true);
      }
    });
  });

  describe('Python SDK Simulation', () => {
    it('should handle Python-style JSON serialization', () => {
      // Python's json.dumps with sort_keys=True produces specific output
      const pythonStyleJson = '{"a": 1, "b": 2}';  // Note: spaces after colons

      // Our canonicalizer should handle this
      const canonical = canonicalizeJsonNative(pythonStyleJson);
      expect(canonical).toBe('{"a":1,"b":2}');
    });
  });

  describe('Go SDK Simulation', () => {
    it('should handle Go-style number formatting', () => {
      // Go may serialize floats differently
      const goStyleJson = '{"value":1.0}';
      const canonical = canonicalizeJsonNative(goStyleJson);

      // Result should be valid and parseable
      expect(() => JSON.parse(canonical)).not.toThrow();
    });
  });
});

// =========================================================================
// DETERMINISM VERIFICATION
// =========================================================================

describe('Cross-Platform: Determinism', () => {
  it('should produce identical output across 1000 iterations', () => {
    const nonce = crypto.randomBytes(32).toString('hex');
    const contextId = 'ctx_determinism_test';
    const binding = 'POST|/api/test|';
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const body = '{"test":"determinism","value":42}';

    const bodyHash = ashHashBody(canonicalizeJsonNative(body));
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const expectedProof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

    // Generate 1000 times and verify identical
    for (let i = 0; i < 1000; i++) {
      const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);
      expect(proof).toBe(expectedProof);
    }
  });

  it('should canonicalize identically across 1000 iterations', () => {
    const input = '{"z":{"nested":true},"a":[1,2,3],"m":null}';
    const expected = canonicalizeJsonNative(input);

    for (let i = 0; i < 1000; i++) {
      const result = canonicalizeJsonNative(input);
      expect(result).toBe(expected);
    }
  });
});

console.log('Cross-Platform Compatibility Tests loaded');
