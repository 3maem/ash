/**
 * ASH SDK RFC and Protocol Compliance Tests
 *
 * Verifies compliance with relevant RFCs and the ASH protocol specification.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'crypto';
import {
  ashInit,
  ashBuildProofV21,
  ashVerifyProofV21,
  ashDeriveClientSecret,
  ashHashBody,
  ashGenerateNonce,
  ashGenerateContextId,
  canonicalizeJsonNative,
  canonicalQueryNative,
  ashNormalizeBinding,
  ashCanonicalizeUrlencoded,
  ashTimingSafeEqual,
  ashBuildProofScoped,
  ashBuildProofUnified,
} from './index';

beforeAll(() => {
  ashInit();
});

// =========================================================================
// RFC 8785: JSON Canonicalization Scheme (JCS)
// =========================================================================

describe('Compliance: RFC 8785 - JSON Canonicalization Scheme', () => {
  describe('3.2.2.1 Primitive Literals', () => {
    it('should serialize null correctly', () => {
      const result = canonicalizeJsonNative('{"value":null}');
      expect(result).toContain('null');
    });

    it('should serialize true correctly', () => {
      const result = canonicalizeJsonNative('{"value":true}');
      expect(result).toContain('true');
    });

    it('should serialize false correctly', () => {
      const result = canonicalizeJsonNative('{"value":false}');
      expect(result).toContain('false');
    });
  });

  describe('3.2.2.2 Numbers', () => {
    it('should serialize integers without decimal point', () => {
      const result = canonicalizeJsonNative('{"value":42}');
      expect(result).toBe('{"value":42}');
    });

    it('should normalize -0 to 0', () => {
      const result = canonicalizeJsonNative('{"value":-0}');
      expect(result).not.toContain('-0');
      expect(result).toContain(':0');
    });

    it('should serialize floats with minimal representation', () => {
      const result = canonicalizeJsonNative('{"value":3.14}');
      expect(result).toBe('{"value":3.14}');
    });

    it('should handle scientific notation', () => {
      const result = canonicalizeJsonNative('{"value":1e10}');
      // Should be serialized as integer if possible
      const parsed = JSON.parse(result);
      expect(parsed.value).toBe(1e10);
    });
  });

  describe('3.2.2.3 Strings', () => {
    it('should properly escape control characters', () => {
      const result = canonicalizeJsonNative('{"text":"line1\\nline2"}');
      expect(result).toContain('\\n');
    });

    it('should properly escape backslash', () => {
      const result = canonicalizeJsonNative('{"text":"path\\\\file"}');
      expect(result).toContain('\\\\');
    });

    it('should properly escape double quote', () => {
      const result = canonicalizeJsonNative('{"text":"say \\"hello\\""}');
      expect(result).toContain('\\"');
    });

    it('should handle Unicode correctly', () => {
      const result = canonicalizeJsonNative('{"text":"日本語"}');
      const parsed = JSON.parse(result);
      expect(parsed.text).toBe('日本語');
    });
  });

  describe('3.2.3 Arrays', () => {
    it('should preserve array element order', () => {
      const result = canonicalizeJsonNative('{"arr":[3,1,4,1,5,9]}');
      const parsed = JSON.parse(result);
      expect(parsed.arr).toEqual([3, 1, 4, 1, 5, 9]);
    });

    it('should handle empty arrays', () => {
      const result = canonicalizeJsonNative('{"arr":[]}');
      expect(result).toBe('{"arr":[]}');
    });

    it('should handle nested arrays', () => {
      const result = canonicalizeJsonNative('{"matrix":[[1,2],[3,4]]}');
      const parsed = JSON.parse(result);
      expect(parsed.matrix).toEqual([[1, 2], [3, 4]]);
    });
  });

  describe('3.2.4 Objects', () => {
    it('should sort object keys lexicographically', () => {
      const result = canonicalizeJsonNative('{"z":1,"a":2,"m":3}');
      expect(result).toBe('{"a":2,"m":3,"z":1}');
    });

    it('should sort nested object keys', () => {
      const result = canonicalizeJsonNative('{"outer":{"z":1,"a":2}}');
      expect(result).toBe('{"outer":{"a":2,"z":1}}');
    });

    it('should handle empty objects', () => {
      const result = canonicalizeJsonNative('{}');
      expect(result).toBe('{}');
    });

    it('should remove whitespace', () => {
      const result = canonicalizeJsonNative('{ "key" : "value" }');
      expect(result).not.toContain(' ');
      expect(result).toBe('{"key":"value"}');
    });
  });

  describe('3.2.5 Unicode Normalization', () => {
    it('should normalize to NFC form', () => {
      // e + combining acute accent should normalize to precomposed é
      const nfd = 'cafe\u0301';  // NFD form
      const nfc = 'café';         // NFC form

      const result1 = canonicalizeJsonNative(JSON.stringify({ text: nfd }));
      const result2 = canonicalizeJsonNative(JSON.stringify({ text: nfc }));

      expect(result1).toBe(result2);
    });
  });
});

// =========================================================================
// RFC 4648: Base16 Encoding (Hex)
// =========================================================================

describe('Compliance: RFC 4648 - Base16 (Hex) Encoding', () => {
  it('should use lowercase hex for hashes', () => {
    const hash = ashHashBody('test');
    expect(hash).toMatch(/^[0-9a-f]+$/);
    expect(hash).not.toMatch(/[A-F]/);
  });

  it('should use lowercase hex for proofs', () => {
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/test|';
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const bodyHash = ashHashBody('{}');

    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

    expect(proof).toMatch(/^[0-9a-f]+$/);
  });

  it('should generate 64-character hex strings (32 bytes)', () => {
    const nonce = ashGenerateNonce();
    expect(nonce).toHaveLength(64);

    const hash = ashHashBody('test');
    expect(hash).toHaveLength(64);
  });
});

// =========================================================================
// RFC 2104: HMAC-SHA256
// =========================================================================

describe('Compliance: RFC 2104 - HMAC', () => {
  it('should produce consistent HMAC output', () => {
    const nonce = 'a'.repeat(64);
    const contextId = 'ctx_test';
    const binding = 'POST|/api/test|';
    const timestamp = '1700000000';
    const bodyHash = 'b'.repeat(64);

    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

    // Multiple calls should produce same proof
    const proof1 = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);
    const proof2 = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

    expect(proof1).toBe(proof2);
  });

  it('should produce 256-bit (32 byte, 64 hex char) output', () => {
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/test|';
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const bodyHash = ashHashBody('{}');

    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

    expect(proof).toHaveLength(64);
  });

  it('should use key for HMAC correctly', () => {
    const binding = 'POST|/api/test|';
    const timestamp = '1700000000';
    const bodyHash = ashHashBody('{}');

    // Different secrets should produce different proofs
    const nonce1 = 'a'.repeat(64);
    const nonce2 = 'b'.repeat(64);
    const contextId = 'ctx_test';

    const secret1 = ashDeriveClientSecret(nonce1, contextId, binding);
    const secret2 = ashDeriveClientSecret(nonce2, contextId, binding);

    const proof1 = ashBuildProofV21(secret1, timestamp, binding, bodyHash);
    const proof2 = ashBuildProofV21(secret2, timestamp, binding, bodyHash);

    expect(proof1).not.toBe(proof2);
  });
});

// =========================================================================
// RFC 3986: URI Encoding
// =========================================================================

describe('Compliance: RFC 3986 - URI Encoding', () => {
  describe('Percent Encoding', () => {
    it('should uppercase percent-encoding hex digits', () => {
      const result = canonicalQueryNative('key=%2f');
      expect(result).toBe('key=%2F');
    });

    it('should preserve already-uppercase encoding', () => {
      const result = canonicalQueryNative('key=%2F');
      expect(result).toBe('key=%2F');
    });

    it('should handle double-encoded values', () => {
      // %252F is double-encoded /
      const result = canonicalQueryNative('key=%252F');
      expect(result).toContain('%252F');
    });
  });

  describe('Query String Parsing', () => {
    it('should handle & as parameter separator', () => {
      const result = canonicalQueryNative('a=1&b=2&c=3');
      expect(result).toContain('&');
    });

    it('should handle = in parameter values', () => {
      const result = canonicalQueryNative('equation=1%2B1%3D2');
      expect(result).toContain('equation=');
    });

    it('should strip fragment identifier', () => {
      const result = canonicalQueryNative('a=1#section');
      expect(result).not.toContain('#');
      expect(result).toBe('a=1');
    });

    it('should strip leading ?', () => {
      const result = canonicalQueryNative('?a=1&b=2');
      expect(result).not.toContain('?');
      expect(result).toBe('a=1&b=2');
    });
  });
});

// =========================================================================
// ASH PROTOCOL SPECIFICATION
// =========================================================================

describe('Compliance: ASH Protocol', () => {
  describe('Section 3.1: Nonce Requirements', () => {
    it('nonce should be 256 bits (64 hex chars)', () => {
      const nonce = ashGenerateNonce();
      expect(nonce).toHaveLength(64);
    });

    it('nonce should be hex-encoded', () => {
      const nonce = ashGenerateNonce();
      expect(/^[0-9a-f]+$/.test(nonce)).toBe(true);
    });

    it('nonce should be cryptographically random', () => {
      const nonces = new Set<string>();
      for (let i = 0; i < 1000; i++) {
        nonces.add(ashGenerateNonce());
      }
      expect(nonces.size).toBe(1000);
    });
  });

  describe('Section 3.2: Context ID Format', () => {
    it('context ID should have ash_ prefix', () => {
      const contextId = ashGenerateContextId();
      expect(contextId).toMatch(/^ash_/);
    });

    it('context ID should be unique', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 1000; i++) {
        ids.add(ashGenerateContextId());
      }
      expect(ids.size).toBe(1000);
    });
  });

  describe('Section 4.1: Binding Format', () => {
    it('binding should be METHOD|PATH|QUERY format', () => {
      const binding = ashNormalizeBinding('POST', '/api/users', 'page=1');
      const parts = binding.split('|');

      expect(parts).toHaveLength(3);
      expect(parts[0]).toBe('POST');
      expect(parts[1]).toBe('/api/users');
      expect(parts[2]).toBe('page=1');
    });

    it('method should be uppercase', () => {
      const binding = ashNormalizeBinding('get', '/api', '');
      expect(binding).toMatch(/^GET\|/);
    });

    it('should have trailing pipe even with empty query', () => {
      const binding = ashNormalizeBinding('GET', '/api', '');
      expect(binding).toBe('GET|/api|');
    });
  });

  describe('Section 4.2: Proof Construction', () => {
    it('proof should be HMAC-SHA256 of message', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const binding = 'POST|/api/test|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const bodyHash = ashHashBody('{}');

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

      // Verify manually with Node crypto
      // Note: The SDK uses clientSecret as a string key, not hex-decoded
      const message = `${timestamp}|${binding}|${bodyHash}`;
      const expectedProof = crypto
        .createHmac('sha256', clientSecret)
        .update(message)
        .digest('hex');

      expect(proof).toBe(expectedProof);
    });
  });

  describe('Section 5.1: Scoped Fields', () => {
    it('scope should be normalized (sorted, deduplicated)', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const binding = 'POST|/api/test|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const payload = { c: 3, a: 1, b: 2 };

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

      // Same scope in different order should produce same result
      const result1 = ashBuildProofScoped(clientSecret, timestamp, binding, payload, ['a', 'b', 'c']);
      const result2 = ashBuildProofScoped(clientSecret, timestamp, binding, payload, ['c', 'a', 'b']);

      expect(result1.scopeHash).toBe(result2.scopeHash);
    });

    it('should reject dangerous scope paths', () => {
      expect(() => {
        const nonce = ashGenerateNonce();
        const contextId = ashGenerateContextId();
        const binding = 'POST|/api/test|';
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const payload = { a: 1 };
        const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

        ashBuildProofScoped(clientSecret, timestamp, binding, payload, ['__proto__']);
      }).toThrow();
    });
  });

  describe('Section 5.2: Proof Chaining', () => {
    it('chain hash should include previous proof', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const timestamp = Math.floor(Date.now() / 1000).toString();

      const binding1 = 'POST|/api/step1|';
      const payload1 = { step: 1 };
      const clientSecret1 = ashDeriveClientSecret(nonce, contextId, binding1);
      const result1 = ashBuildProofUnified(clientSecret1, timestamp, binding1, payload1, []);

      const binding2 = 'POST|/api/step2|';
      const payload2 = { step: 2 };
      const clientSecret2 = ashDeriveClientSecret(nonce, contextId, binding2);
      const result2 = ashBuildProofUnified(clientSecret2, timestamp, binding2, payload2, [], result1.proof);

      // Chain hash should be different from no-chain version
      const resultNoChain = ashBuildProofUnified(clientSecret2, timestamp, binding2, payload2, []);

      expect(result2.chainHash).not.toBe(resultNoChain.chainHash);
    });
  });
});

// =========================================================================
// TIMING SAFETY COMPLIANCE
// =========================================================================

describe('Compliance: Timing-Safe Operations', () => {
  it('should use constant-time comparison', () => {
    // The function should exist and work correctly
    expect(ashTimingSafeEqual('abc', 'abc')).toBe(true);
    expect(ashTimingSafeEqual('abc', 'def')).toBe(false);
    expect(ashTimingSafeEqual('abc', 'abcd')).toBe(false);
  });

  it('timing-safe comparison should be symmetric', () => {
    expect(ashTimingSafeEqual('a', 'b')).toBe(ashTimingSafeEqual('b', 'a'));
  });
});

// =========================================================================
// URL-ENCODED BODY COMPLIANCE
// =========================================================================

describe('Compliance: URL-Encoded Body', () => {
  it('should treat + as literal plus (encode as %2B)', () => {
    const result = ashCanonicalizeUrlencoded('key=a+b');
    expect(result).toContain('%2B');
  });

  it('should preserve %20 as space', () => {
    const result = ashCanonicalizeUrlencoded('key=a%20b');
    expect(result).toContain('%20');
  });

  it('should sort parameters', () => {
    const result = ashCanonicalizeUrlencoded('z=3&a=1&m=2');
    expect(result).toBe('a=1&m=2&z=3');
  });
});

console.log('RFC and Protocol Compliance Tests loaded');
