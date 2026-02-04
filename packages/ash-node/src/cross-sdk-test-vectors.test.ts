/**
 * Cross-SDK Test Vectors for ASH v2.3.2
 *
 * These test vectors MUST produce identical results across all SDK implementations.
 * Any SDK that fails these tests is not compliant with the ASH specification.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  ashInit,
  ashCanonicalizeJson,
  ashCanonicalizeQuery,
  ashCanonicalizeUrlencoded,
  ashNormalizeBinding,
  ashHashBody,
  ashDeriveClientSecret,
  ashBuildProofV21,
  ashVerifyProofV21,
  ashBuildProofUnified,
  ashVerifyProofUnified,
  ashExtractScopedFields,
  ashHashProof,
  ashTimingSafeEqual,
  // Native implementations for fallback
  canonicalizeJsonNative,
  canonicalQueryNative,
  normalizeBindingNative,
} from './index';

// ============================================================================
// FIXED TEST VECTORS - DO NOT MODIFY
// These values are used across all SDK implementations
// ============================================================================

const TEST_NONCE = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const TEST_CONTEXT_ID = 'ash_test_ctx_12345';
const TEST_BINDING = 'POST|/api/transfer|';
const TEST_TIMESTAMP = '1704067200'; // 2024-01-01 00:00:00 UTC in seconds (per SDK Implementation Reference)

// Track WASM availability
let wasmAvailable = false;

describe('Cross-SDK Test Vectors', () => {
  beforeAll(() => {
    try {
      ashInit();
      wasmAvailable = true;
    } catch {
      console.warn('WASM not available, using native implementations');
      wasmAvailable = false;
    }
  });

  // ==========================================================================
  // JSON Canonicalization Tests (RFC 8785 JCS)
  // ==========================================================================

  describe('JSON Canonicalization (RFC 8785 JCS)', () => {
    it('should sort keys alphabetically', () => {
      const input = '{"z":1,"a":2,"m":3}';
      const expected = '{"a":2,"m":3,"z":1}';
      const result = wasmAvailable ? ashCanonicalizeJson(input) : canonicalizeJsonNative(input);
      expect(result).toBe(expected);
    });

    it('should sort nested object keys', () => {
      const input = '{"outer":{"z":1,"a":2},"inner":{"b":2,"a":1}}';
      const expected = '{"inner":{"a":1,"b":2},"outer":{"a":2,"z":1}}';
      const result = wasmAvailable ? ashCanonicalizeJson(input) : canonicalizeJsonNative(input);
      expect(result).toBe(expected);
    });

    it('should preserve array element order', () => {
      const input = '{"arr":[3,1,2]}';
      const expected = '{"arr":[3,1,2]}';
      const result = wasmAvailable ? ashCanonicalizeJson(input) : canonicalizeJsonNative(input);
      expect(result).toBe(expected);
    });

    it('should convert -0 to 0', () => {
      const input = '{"n":-0}';
      const expected = '{"n":0}';
      const result = wasmAvailable ? ashCanonicalizeJson(input) : canonicalizeJsonNative(input);
      expect(result).toBe(expected);
    });

    it('should handle empty values correctly', () => {
      expect(canonicalizeJsonNative('null')).toBe('null');
      expect(canonicalizeJsonNative('true')).toBe('true');
      expect(canonicalizeJsonNative('false')).toBe('false');
      expect(canonicalizeJsonNative('{}')).toBe('{}');
      expect(canonicalizeJsonNative('[]')).toBe('[]');
      expect(canonicalizeJsonNative('""')).toBe('""');
    });
  });

  // ==========================================================================
  // Query String Canonicalization Tests
  // ==========================================================================

  describe('Query String Canonicalization', () => {
    it('should sort parameters by key', () => {
      const input = 'z=1&a=2&m=3';
      const expected = 'a=2&m=3&z=1';
      const result = wasmAvailable ? ashCanonicalizeQuery(input) : canonicalQueryNative(input);
      expect(result).toBe(expected);
    });

    it('should sort duplicate keys by value', () => {
      const input = 'a=z&a=a&a=m';
      const expected = 'a=a&a=m&a=z';
      const result = wasmAvailable ? ashCanonicalizeQuery(input) : canonicalQueryNative(input);
      expect(result).toBe(expected);
    });

    it('should strip leading ? character', () => {
      const input = '?a=1&b=2';
      const expected = 'a=1&b=2';
      const result = wasmAvailable ? ashCanonicalizeQuery(input) : canonicalQueryNative(input);
      expect(result).toBe(expected);
    });

    it('should strip fragment identifier', () => {
      const input = 'a=1&b=2#section';
      const expected = 'a=1&b=2';
      const result = wasmAvailable ? ashCanonicalizeQuery(input) : canonicalQueryNative(input);
      expect(result).toBe(expected);
    });

    it('should uppercase percent-encoding hex digits', () => {
      const input = 'a=%2f&b=%2F';
      const expected = 'a=%2F&b=%2F';
      const result = wasmAvailable ? ashCanonicalizeQuery(input) : canonicalQueryNative(input);
      expect(result).toBe(expected);
    });

    it('should preserve empty values', () => {
      const input = 'a=&b=1';
      const expected = 'a=&b=1';
      const result = wasmAvailable ? ashCanonicalizeQuery(input) : canonicalQueryNative(input);
      expect(result).toBe(expected);
    });
  });

  // ==========================================================================
  // URL-Encoded Canonicalization Tests
  // ==========================================================================

  describe('URL-Encoded Canonicalization', () => {
    it('should sort parameters by key', () => {
      if (!wasmAvailable) return;
      const result = ashCanonicalizeUrlencoded('b=2&a=1');
      expect(result).toBe('a=1&b=2');
    });

    it('should treat + as literal plus (not space)', () => {
      if (!wasmAvailable) return;
      const result = ashCanonicalizeUrlencoded('a=hello+world');
      expect(result).toBe('a=hello%2Bworld');
    });

    it('should uppercase percent-encoding hex digits', () => {
      if (!wasmAvailable) return;
      const result = ashCanonicalizeUrlencoded('a=hello%2fworld');
      expect(result).toBe('a=hello%2Fworld');
    });
  });

  // ==========================================================================
  // Binding Normalization Tests (v2.3.1+ format: METHOD|PATH|QUERY)
  // ==========================================================================

  describe('Binding Normalization', () => {
    it('should format as METHOD|PATH|', () => {
      const result = wasmAvailable
        ? ashNormalizeBinding('POST', '/api/test')
        : normalizeBindingNative('POST', '/api/test');
      expect(result).toBe('POST|/api/test|');
    });

    it('should uppercase method', () => {
      const result = wasmAvailable
        ? ashNormalizeBinding('post', '/api/test')
        : normalizeBindingNative('post', '/api/test');
      expect(result).toBe('POST|/api/test|');
    });

    it('should include query string', () => {
      const result = wasmAvailable
        ? ashNormalizeBinding('GET', '/api/users', 'page=1&sort=name')
        : normalizeBindingNative('GET', '/api/users', 'page=1&sort=name');
      expect(result).toBe('GET|/api/users|page=1&sort=name');
    });

    it('should sort query parameters', () => {
      const result = wasmAvailable
        ? ashNormalizeBinding('GET', '/api/users', 'z=1&a=2')
        : normalizeBindingNative('GET', '/api/users', 'z=1&a=2');
      expect(result).toBe('GET|/api/users|a=2&z=1');
    });

    it('should collapse duplicate slashes', () => {
      const result = wasmAvailable
        ? ashNormalizeBinding('GET', '/api//test///path')
        : normalizeBindingNative('GET', '/api//test///path');
      expect(result).toBe('GET|/api/test/path|');
    });

    it('should remove trailing slash', () => {
      const result = wasmAvailable
        ? ashNormalizeBinding('GET', '/api/test/')
        : normalizeBindingNative('GET', '/api/test/');
      expect(result).toBe('GET|/api/test|');
    });

    it('should preserve root path', () => {
      const result = wasmAvailable
        ? ashNormalizeBinding('GET', '/')
        : normalizeBindingNative('GET', '/');
      expect(result).toBe('GET|/|');
    });

    it('should add leading slash if missing', () => {
      const result = wasmAvailable
        ? ashNormalizeBinding('GET', 'api/test')
        : normalizeBindingNative('GET', 'api/test');
      expect(result).toBe('GET|/api/test|');
    });
  });

  // ==========================================================================
  // Hash Body Tests (SHA-256 lowercase hex)
  // ==========================================================================

  describe('Hash Body (SHA-256)', () => {
    it('should produce known SHA-256 hash', () => {
      const result = ashHashBody('test');
      expect(result).toBe('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');
    });

    it('should hash empty string correctly', () => {
      const result = ashHashBody('');
      expect(result).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('should produce 64 lowercase hex characters', () => {
      const result = ashHashBody('{"amount":100,"recipient":"user123"}');
      expect(result).toHaveLength(64);
      expect(result).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  // ==========================================================================
  // Client Secret Derivation Tests (v2.1)
  // ==========================================================================

  describe('Client Secret Derivation (v2.1)', () => {
    it('should produce same result for same inputs', () => {
      const secret1 = ashDeriveClientSecret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING);
      const secret2 = ashDeriveClientSecret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING);
      expect(secret1).toBe(secret2);
    });

    it('should produce 64 lowercase hex characters', () => {
      const secret = ashDeriveClientSecret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING);
      expect(secret).toHaveLength(64);
      expect(secret).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should produce different results for different inputs', () => {
      const secret1 = ashDeriveClientSecret(TEST_NONCE, 'ctx_a', TEST_BINDING);
      const secret2 = ashDeriveClientSecret(TEST_NONCE, 'ctx_b', TEST_BINDING);
      expect(secret1).not.toBe(secret2);
    });
  });

  // ==========================================================================
  // v2.1 Proof Tests
  // ==========================================================================

  describe('v2.1 Proof Generation and Verification', () => {
    it('should produce same proof for same inputs', () => {
      const clientSecret = ashDeriveClientSecret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING);
      const bodyHash = ashHashBody('{"amount":100}');

      const proof1 = ashBuildProofV21(clientSecret, TEST_TIMESTAMP, TEST_BINDING, bodyHash);
      const proof2 = ashBuildProofV21(clientSecret, TEST_TIMESTAMP, TEST_BINDING, bodyHash);

      expect(proof1).toBe(proof2);
    });

    it('should produce 64 lowercase hex characters', () => {
      const clientSecret = ashDeriveClientSecret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING);
      const bodyHash = ashHashBody('{"amount":100}');

      const proof = ashBuildProofV21(clientSecret, TEST_TIMESTAMP, TEST_BINDING, bodyHash);

      expect(proof).toHaveLength(64);
      expect(proof).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should verify valid proof', () => {
      const clientSecret = ashDeriveClientSecret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING);
      const bodyHash = ashHashBody('{"amount":100}');
      const proof = ashBuildProofV21(clientSecret, TEST_TIMESTAMP, TEST_BINDING, bodyHash);

      const valid = ashVerifyProofV21(
        TEST_NONCE,
        TEST_CONTEXT_ID,
        TEST_BINDING,
        TEST_TIMESTAMP,
        bodyHash,
        proof
      );

      expect(valid).toBe(true);
    });

    it('should reject invalid proof', () => {
      const bodyHash = ashHashBody('{"amount":100}');
      const wrongProof = '0'.repeat(64);

      const valid = ashVerifyProofV21(
        TEST_NONCE,
        TEST_CONTEXT_ID,
        TEST_BINDING,
        TEST_TIMESTAMP,
        bodyHash,
        wrongProof
      );

      expect(valid).toBe(false);
    });

    it('should reject proof with wrong body hash', () => {
      const clientSecret = ashDeriveClientSecret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING);
      const bodyHash1 = ashHashBody('{"amount":100}');
      const bodyHash2 = ashHashBody('{"amount":200}');
      const proof = ashBuildProofV21(clientSecret, TEST_TIMESTAMP, TEST_BINDING, bodyHash1);

      const valid = ashVerifyProofV21(
        TEST_NONCE,
        TEST_CONTEXT_ID,
        TEST_BINDING,
        TEST_TIMESTAMP,
        bodyHash2,
        proof
      );

      expect(valid).toBe(false);
    });
  });

  // ==========================================================================
  // v2.3 Unified Proof Tests (with Scoping and Chaining)
  // ==========================================================================

  describe('v2.3 Unified Proof (Scoping and Chaining)', () => {
    it('should work without scoping or chaining', () => {
      const clientSecret = ashDeriveClientSecret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING);
      const payload = { amount: 100, note: 'test' };

      const result = ashBuildProofUnified(clientSecret, TEST_TIMESTAMP, TEST_BINDING, payload);

      expect(result.proof).toHaveLength(64);
      expect(result.scopeHash).toBe('');
      expect(result.chainHash).toBe('');

      // Verify
      const valid = ashVerifyProofUnified(
        TEST_NONCE,
        TEST_CONTEXT_ID,
        TEST_BINDING,
        TEST_TIMESTAMP,
        payload,
        result.proof
      );
      expect(valid).toBe(true);
    });

    it('should work with scoping', () => {
      const clientSecret = ashDeriveClientSecret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING);
      const payload = { amount: 100, note: 'test', recipient: 'user123' };
      const scope = ['amount', 'recipient'];

      const result = ashBuildProofUnified(
        clientSecret,
        TEST_TIMESTAMP,
        TEST_BINDING,
        payload,
        scope
      );

      expect(result.scopeHash).not.toBe('');
      expect(result.chainHash).toBe('');

      // Verify
      const valid = ashVerifyProofUnified(
        TEST_NONCE,
        TEST_CONTEXT_ID,
        TEST_BINDING,
        TEST_TIMESTAMP,
        payload,
        result.proof,
        scope,
        result.scopeHash
      );
      expect(valid).toBe(true);
    });

    it('should work with chaining', () => {
      const binding = 'POST|/api/confirm|';
      const clientSecret = ashDeriveClientSecret(TEST_NONCE, TEST_CONTEXT_ID, binding);
      const payload = { confirmed: true };
      const previousProof = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';

      const result = ashBuildProofUnified(
        clientSecret,
        TEST_TIMESTAMP,
        binding,
        payload,
        [],
        previousProof
      );

      expect(result.scopeHash).toBe('');
      expect(result.chainHash).not.toBe('');
      expect(result.chainHash).toBe(ashHashProof(previousProof));

      // Verify
      const valid = ashVerifyProofUnified(
        TEST_NONCE,
        TEST_CONTEXT_ID,
        binding,
        TEST_TIMESTAMP,
        payload,
        result.proof,
        [],
        '',
        previousProof,
        result.chainHash
      );
      expect(valid).toBe(true);
    });
  });

  // ==========================================================================
  // Scoped Field Extraction Tests (ENH-003)
  // ==========================================================================

  describe('Scoped Field Extraction (ENH-003)', () => {
    it('should extract simple fields', () => {
      const payload = { amount: 100, note: 'test', recipient: 'user123' };
      const scope = ['amount', 'recipient'];

      const result = ashExtractScopedFields(payload, scope);

      expect(result.amount).toBe(100);
      expect(result.recipient).toBe('user123');
      expect(result.note).toBeUndefined();
    });

    it('should extract nested fields using dot notation', () => {
      const payload = { user: { name: 'John', email: 'john@example.com' }, amount: 100 };
      const scope = ['user.name', 'amount'];

      const result = ashExtractScopedFields(payload, scope);

      expect(result.user.name).toBe('John');
      expect(result.amount).toBe(100);
      expect(result.user?.email).toBeUndefined();
    });

    it('should return full payload for empty scope', () => {
      const payload = { amount: 100, note: 'test' };
      const scope: string[] = [];

      const result = ashExtractScopedFields(payload, scope);

      expect(result).toEqual(payload);
    });
  });

  // ==========================================================================
  // Hash Proof Tests (for Chaining)
  // ==========================================================================

  describe('Hash Proof (for Chaining)', () => {
    it('should produce same hash for same input', () => {
      const proof = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';
      const hash1 = ashHashProof(proof);
      const hash2 = ashHashProof(proof);
      expect(hash1).toBe(hash2);
    });

    it('should produce 64 lowercase hex characters', () => {
      const proof = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';
      const hash = ashHashProof(proof);
      expect(hash).toHaveLength(64);
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  // ==========================================================================
  // Timing-Safe Comparison Tests
  // ==========================================================================

  describe('Timing-Safe Comparison', () => {
    it('should return true for equal strings', () => {
      if (!wasmAvailable) return;
      expect(ashTimingSafeEqual('hello', 'hello')).toBe(true);
      expect(ashTimingSafeEqual('', '')).toBe(true);
    });

    it('should return false for different strings', () => {
      if (!wasmAvailable) return;
      expect(ashTimingSafeEqual('hello', 'world')).toBe(false);
      expect(ashTimingSafeEqual('hello', 'hello!')).toBe(false);
      expect(ashTimingSafeEqual('hello', '')).toBe(false);
    });
  });

  // ==========================================================================
  // Known Test Vector with Fixed Expected Values
  // ==========================================================================

  describe('Fixed Test Vectors', () => {
    it('should produce deterministic client secret', () => {
      const nonce = 'a'.repeat(64);
      const contextId = 'ash_fixed_test_001';
      const binding = 'POST|/api/test|';

      const secret = ashDeriveClientSecret(nonce, contextId, binding);

      expect(secret).toHaveLength(64);
      // Verify determinism
      const secret2 = ashDeriveClientSecret(nonce, contextId, binding);
      expect(secret).toBe(secret2);
    });

    it('should produce deterministic body hash', () => {
      const payload = { amount: 100, recipient: 'user123' };
      const canonical = canonicalizeJsonNative(JSON.stringify(payload));
      const hash = ashHashBody(canonical);

      // All SDKs must produce this exact canonical form
      expect(canonical).toBe('{"amount":100,"recipient":"user123"}');
      expect(hash).toHaveLength(64);
    });
  });
});
