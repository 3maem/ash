import { describe, it, expect, beforeAll } from 'vitest';
import {
  ashInit,
  ashCanonicalizeJson,
  ashCanonicalizeUrlencoded,
  ashBuildProof,
  ashVerifyProof,
  ashNormalizeBinding,
  ashTimingSafeEqual,
  ashVersion,
  ashLibraryVersion,
  ashHashBody,
  ashCanonicalizeQuery,
  // v2.3.1 exports
  ASH_SDK_VERSION,
  ASH_VERSION_PREFIX,
  ASH_VERSION_PREFIX_V21,
  ASH_VERSION_PREFIX_V23,
  ash,
  ashCanon,
  ashUtils,
  ashBinding,
  ashProof,
  // Native implementations
  canonicalizeJsonNative,
  canonicalQueryNative,
  normalizeBindingNative,
} from './index';

// Track if WASM is available
let wasmAvailable = false;

describe('ASH Node.js SDK', () => {
  beforeAll(() => {
    try {
      ashInit();
      wasmAvailable = true;
    } catch (error) {
      console.warn('WASM not available, skipping WASM-dependent tests');
      wasmAvailable = false;
    }
  });

  describe('Version Constants (v2.3.1)', () => {
    it('exports ASH_SDK_VERSION as 2.3.1', () => {
      expect(ASH_SDK_VERSION).toBe('2.3.1');
    });

    it('exports ASH_VERSION_PREFIX', () => {
      expect(ASH_VERSION_PREFIX).toBe('ASHv1');
    });

    it('exports ASH_VERSION_PREFIX_V21', () => {
      expect(ASH_VERSION_PREFIX_V21).toBe('ASHv2.1');
    });

    it('exports ASH_VERSION_PREFIX_V23', () => {
      expect(ASH_VERSION_PREFIX_V23).toBe('ASHv2.3');
    });
  });

  describe('ash.* Namespace Structure (v2.3.1)', () => {
    it('has ash.canon namespace', () => {
      expect(ash.canon).toBeDefined();
      expect(ash.canon.json).toBe(ashCanonicalizeJson);
      expect(ash.canon.query).toBe(ashCanonicalizeQuery);
    });

    it('has ash.utils namespace', () => {
      expect(ash.utils).toBeDefined();
      expect(ash.utils.hashBody).toBe(ashHashBody);
      expect(ash.utils.timingSafeEqual).toBe(ashTimingSafeEqual);
    });

    it('has ash.binding namespace', () => {
      expect(ash.binding).toBeDefined();
      expect(ash.binding.normalize).toBe(ashNormalizeBinding);
    });

    it('has ash.proof namespace', () => {
      expect(ash.proof).toBeDefined();
      expect(ash.proof.build).toBe(ashBuildProof);
      expect(ash.proof.verify).toBe(ashVerifyProof);
    });

    it('includes native implementations in namespaces', () => {
      expect(ashCanon.jsonNative).toBe(canonicalizeJsonNative);
      expect(ashCanon.queryNative).toBe(canonicalQueryNative);
      expect(ashBinding.normalizeNative).toBe(normalizeBindingNative);
    });
  });

  describe('ashVersion (WASM)', () => {
    it('returns protocol version', () => {
      if (!wasmAvailable) return;
      const version = ashVersion();
      expect(version).toBe('ASHv2.1');
    });
  });

  describe('ashLibraryVersion (WASM)', () => {
    it('returns library version', () => {
      if (!wasmAvailable) return;
      const version = ashLibraryVersion();
      expect(version).toMatch(/^\d+\.\d+\.\d+$/);
    });
  });

  describe('ashCanonicalizeJson (WASM)', () => {
    it('sorts keys alphabetically', () => {
      if (!wasmAvailable) return;
      const result = ashCanonicalizeJson('{"z":1,"a":2,"m":3}');
      expect(result).toBe('{"a":2,"m":3,"z":1}');
    });

    it('handles nested objects', () => {
      if (!wasmAvailable) return;
      const result = ashCanonicalizeJson('{"b":{"y":1,"x":2},"a":1}');
      expect(result).toBe('{"a":1,"b":{"x":2,"y":1}}');
    });

    it('handles arrays', () => {
      if (!wasmAvailable) return;
      const result = ashCanonicalizeJson('{"a":[3,1,2]}');
      expect(result).toBe('{"a":[3,1,2]}');
    });

    it('handles empty object', () => {
      if (!wasmAvailable) return;
      const result = ashCanonicalizeJson('{}');
      expect(result).toBe('{}');
    });
  });

  describe('ashCanonicalizeUrlencoded (WASM)', () => {
    it('sorts parameters alphabetically', () => {
      if (!wasmAvailable) return;
      const result = ashCanonicalizeUrlencoded('z=1&a=2&m=3');
      expect(result).toBe('a=2&m=3&z=1');
    });

    it('handles empty string', () => {
      if (!wasmAvailable) return;
      const result = ashCanonicalizeUrlencoded('');
      expect(result).toBe('');
    });

    it('handles single parameter', () => {
      if (!wasmAvailable) return;
      const result = ashCanonicalizeUrlencoded('foo=bar');
      expect(result).toBe('foo=bar');
    });
  });

  describe('ashNormalizeBinding (WASM)', () => {
    it('uppercases method and uses pipe format', () => {
      if (!wasmAvailable) return;
      const result = ashNormalizeBinding('post', '/api/test');
      expect(result).toBe('POST|/api/test|');
    });

    it('removes trailing slashes', () => {
      if (!wasmAvailable) return;
      const result = ashNormalizeBinding('GET', '/api/test/');
      expect(result).toBe('GET|/api/test|');
    });

    it('removes duplicate slashes', () => {
      if (!wasmAvailable) return;
      const result = ashNormalizeBinding('GET', '/api//test');
      expect(result).toBe('GET|/api/test|');
    });

    it('includes canonicalized query string', () => {
      if (!wasmAvailable) return;
      const result = ashNormalizeBinding('GET', '/api/test', 'z=1&a=2');
      expect(result).toBe('GET|/api/test|a=2&z=1');
    });
  });

  describe('ashBuildProof (WASM)', () => {
    it('generates consistent proofs', () => {
      if (!wasmAvailable) return;
      const proof1 = ashBuildProof(
        'balanced',
        'POST /api/test',
        'ctx123',
        null,
        '{"a":1}'
      );
      const proof2 = ashBuildProof(
        'balanced',
        'POST /api/test',
        'ctx123',
        null,
        '{"a":1}'
      );
      expect(proof1).toBe(proof2);
    });

    it('generates different proofs for different payloads', () => {
      if (!wasmAvailable) return;
      const proof1 = ashBuildProof(
        'balanced',
        'POST /api/test',
        'ctx123',
        null,
        '{"a":1}'
      );
      const proof2 = ashBuildProof(
        'balanced',
        'POST /api/test',
        'ctx123',
        null,
        '{"a":2}'
      );
      expect(proof1).not.toBe(proof2);
    });
  });

  describe('ashVerifyProof (WASM)', () => {
    it('returns true for matching proofs', () => {
      if (!wasmAvailable) return;
      const proof = ashBuildProof(
        'balanced',
        'POST /api/test',
        'ctx123',
        null,
        '{"a":1}'
      );
      expect(ashVerifyProof(proof, proof)).toBe(true);
    });

    it('returns false for non-matching proofs', () => {
      if (!wasmAvailable) return;
      const proof1 = ashBuildProof(
        'balanced',
        'POST /api/test',
        'ctx123',
        null,
        '{"a":1}'
      );
      const proof2 = ashBuildProof(
        'balanced',
        'POST /api/test',
        'ctx123',
        null,
        '{"a":2}'
      );
      expect(ashVerifyProof(proof1, proof2)).toBe(false);
    });
  });

  describe('ashTimingSafeEqual (WASM)', () => {
    it('returns true for equal strings', () => {
      if (!wasmAvailable) return;
      expect(ashTimingSafeEqual('hello', 'hello')).toBe(true);
    });

    it('returns false for different strings', () => {
      if (!wasmAvailable) return;
      expect(ashTimingSafeEqual('hello', 'world')).toBe(false);
    });

    it('returns false for different lengths', () => {
      if (!wasmAvailable) return;
      expect(ashTimingSafeEqual('hello', 'hi')).toBe(false);
    });
  });

  // =========================================================================
  // v2.3.1 Specification Compliance Tests
  // =========================================================================

  describe('JCS Canonicalization (RFC 8785) - Native Implementation', () => {
    it('sorts object keys lexicographically (byte-wise)', () => {
      const result = canonicalizeJsonNative('{"z":1,"a":2,"m":3}');
      expect(result).toBe('{"a":2,"m":3,"z":1}');
    });

    it('handles nested objects', () => {
      const result = canonicalizeJsonNative('{"b":{"y":1,"x":2},"a":1}');
      expect(result).toBe('{"a":1,"b":{"x":2,"y":1}}');
    });

    it('preserves array order', () => {
      const result = canonicalizeJsonNative('{"a":[3,1,2]}');
      expect(result).toBe('{"a":[3,1,2]}');
    });

    it('handles -0 as 0', () => {
      const result = canonicalizeJsonNative('{"n":-0}');
      expect(result).toBe('{"n":0}');
    });

    it('rejects NaN', () => {
      expect(() => canonicalizeJsonNative('{"n":NaN}')).toThrow();
    });

    it('rejects Infinity', () => {
      expect(() => canonicalizeJsonNative('{"n":Infinity}')).toThrow();
    });

    it('uses minimal escaping for control characters', () => {
      // Tab should be \t, not \u0009
      const result = canonicalizeJsonNative('{"s":"a\\tb"}');
      expect(result).toBe('{"s":"a\\tb"}');
    });

    it('uses lowercase hex for other control characters', () => {
      // Control char 0x01 should be \u0001
      const input = JSON.stringify({ s: '\u0001' });
      const result = canonicalizeJsonNative(input);
      expect(result).toBe('{"s":"\\u0001"}');
    });
  });

  describe('Canonical Query (v2.3.1 Spec) - Native Implementation', () => {
    it('removes leading ?', () => {
      const result = canonicalQueryNative('?a=1&b=2');
      expect(result).toBe('a=1&b=2');
    });

    it('strips fragment', () => {
      const result = canonicalQueryNative('a=1&b=2#fragment');
      expect(result).toBe('a=1&b=2');
    });

    it('sorts by key, then by value (byte-wise)', () => {
      const result = canonicalQueryNative('z=1&a=2&m=3');
      expect(result).toBe('a=2&m=3&z=1');
    });

    it('sorts duplicate keys by value', () => {
      const result = canonicalQueryNative('a=z&a=a&a=m');
      expect(result).toBe('a=a&a=m&a=z');
    });

    it('uppercases percent-encoding hex', () => {
      const result = canonicalQueryNative('a=%2f&b=%2F');
      expect(result).toBe('a=%2F&b=%2F');
    });

    it('preserves empty values', () => {
      const result = canonicalQueryNative('a=&b=1');
      expect(result).toBe('a=&b=1');
    });

    it('treats + as literal plus (not space)', () => {
      const result = canonicalQueryNative('a+b=1');
      expect(result).toBe('a+b=1');
    });
  });

  describe('Binding Format (v2.3.1 Spec) - Native Implementation', () => {
    it('formats as METHOD|PATH|QUERY', () => {
      const result = normalizeBindingNative('POST', '/api/test', 'a=1');
      expect(result).toBe('POST|/api/test|a=1');
    });

    it('uppercases method', () => {
      const result = normalizeBindingNative('post', '/api/test');
      expect(result).toBe('POST|/api/test|');
    });

    it('ensures path starts with /', () => {
      const result = normalizeBindingNative('GET', 'api/test');
      expect(result).toBe('GET|/api/test|');
    });

    it('includes trailing pipe even if query is empty', () => {
      const result = normalizeBindingNative('GET', '/api/test');
      expect(result).toBe('GET|/api/test|');
    });

    it('removes trailing slashes', () => {
      const result = normalizeBindingNative('GET', '/api/test/');
      expect(result).toBe('GET|/api/test|');
    });

    it('removes duplicate slashes', () => {
      const result = normalizeBindingNative('GET', '/api//test');
      expect(result).toBe('GET|/api/test|');
    });

    it('canonicalizes query string', () => {
      const result = normalizeBindingNative('GET', '/api/test', 'z=1&a=2');
      expect(result).toBe('GET|/api/test|a=2&z=1');
    });
  });

  describe('Hash Encoding (v2.3.1 Spec)', () => {
    it('produces lowercase hex SHA-256 hash (64 characters)', () => {
      const hash = ashHashBody('test');
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
      // Should not contain uppercase
      expect(hash).not.toMatch(/[A-F]/);
    });
  });

  describe('Native vs WASM Parity', () => {
    it('canonicalizeJsonNative matches ashCanonicalizeJson', () => {
      if (!wasmAvailable) return;
      const inputs = [
        '{"z":1,"a":2}',
        '{"nested":{"b":2,"a":1},"outer":1}',
        '{"arr":[1,2,3]}',
        '{}',
      ];
      for (const input of inputs) {
        expect(canonicalizeJsonNative(input)).toBe(ashCanonicalizeJson(input));
      }
    });

    it('canonicalQueryNative matches ashCanonicalizeQuery', () => {
      if (!wasmAvailable) return;
      const inputs = [
        'z=1&a=2',
        '?a=1&b=2',
        'a=%2f&b=%2F',
        '',
      ];
      for (const input of inputs) {
        expect(canonicalQueryNative(input)).toBe(ashCanonicalizeQuery(input));
      }
    });

    it('normalizeBindingNative matches ashNormalizeBinding', () => {
      if (!wasmAvailable) return;
      const cases = [
        ['post', '/api/test', ''],
        ['GET', '/api/users', 'page=1&sort=name'],
        ['PUT', '/api/items/', 'z=1&a=2'],
      ] as const;
      for (const [method, path, query] of cases) {
        expect(normalizeBindingNative(method, path, query)).toBe(
          ashNormalizeBinding(method, path, query)
        );
      }
    });
  });
});
