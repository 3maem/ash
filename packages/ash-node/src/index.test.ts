import { describe, it, expect, beforeAll } from 'vitest';
import {
  ashInit,
  ashCanonicalizeJson,
  ashCanonicalizeUrlencoded,
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
  ashBinding,
  // Native implementations
  canonicalizeJsonNative,
  canonicalQueryNative,
  normalizeBindingNative,
  // v2.3.4 security constants
  MIN_NONCE_BYTES,
  MIN_NONCE_HEX_CHARS,
  MAX_NONCE_LENGTH,
  MAX_CONTEXT_ID_LENGTH,
  MAX_BINDING_LENGTH,
  MAX_SCOPE_FIELD_NAME_LENGTH,
  MAX_TOTAL_SCOPE_LENGTH,
  MAX_SCOPE_FIELDS,
  MAX_ARRAY_INDEX,
  MAX_TOTAL_ARRAY_ALLOCATION,
  MAX_SCOPE_PATH_DEPTH,
  MAX_RECURSION_DEPTH,
  MAX_PAYLOAD_SIZE,
  MAX_TIMESTAMP,
  SHA256_HEX_LENGTH,
  CHUNK_SIZE,
  FIXED_ITERATIONS,
  FIXED_WORK_SIZE,
  SCOPE_FIELD_DELIMITER,
  // v2.3.4 security-validated functions
  ashDeriveClientSecret,
  ashBuildProof,
  ashVerifyProof,
  joinScopeFields,
  validateScopeFields,
  normalizeScopeFields,
  ashValidateTimestampFormat,
  ashValidateTimestamp,
  ashHashScope,
  // Bug fix verification imports
  ashExtractScopedFields,
  secureDeriveClientSecret,
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

  describe('Version Constants (v2.3.4)', () => {
    it('exports ASH_SDK_VERSION as 2.3.4', () => {
      expect(ASH_SDK_VERSION).toBe('2.3.4');
    });

    it('exports ASH_VERSION_PREFIX as ASHv2.1 per SDK Implementation Reference', () => {
      expect(ASH_VERSION_PREFIX).toBe('ASHv2.1');
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

  // =========================================================================
  // v2.3.4 Security Guardrails Tests
  // =========================================================================

  describe('Security Constants (v2.3.4)', () => {
    it('exports MIN_NONCE_HEX_CHARS as 32', () => {
      expect(MIN_NONCE_HEX_CHARS).toBe(32);
    });

    it('exports MAX_NONCE_LENGTH as 128', () => {
      expect(MAX_NONCE_LENGTH).toBe(128);
    });

    it('exports MAX_CONTEXT_ID_LENGTH as 256', () => {
      expect(MAX_CONTEXT_ID_LENGTH).toBe(256);
    });

    it('exports MAX_BINDING_LENGTH as 8192', () => {
      expect(MAX_BINDING_LENGTH).toBe(8192);
    });

    it('exports MAX_SCOPE_FIELD_NAME_LENGTH as 64', () => {
      expect(MAX_SCOPE_FIELD_NAME_LENGTH).toBe(64);
    });

    it('exports MAX_TOTAL_SCOPE_LENGTH as 4096', () => {
      expect(MAX_TOTAL_SCOPE_LENGTH).toBe(4096);
    });

    it('exports MAX_SCOPE_FIELDS as 100', () => {
      expect(MAX_SCOPE_FIELDS).toBe(100);
    });

    it('exports SCOPE_FIELD_DELIMITER as \\x1F', () => {
      expect(SCOPE_FIELD_DELIMITER).toBe('\x1F');
    });
  });

  describe('SEC-NONCE-001: Nonce Validation', () => {
    const validNonce = '0'.repeat(32);  // Minimum valid nonce
    const validContextId = 'ctx_test123';
    const validBinding = 'POST|/api/test|';

    it('accepts valid nonce at minimum length', () => {
      expect(() => ashDeriveClientSecret(validNonce, validContextId, validBinding)).not.toThrow();
    });

    it('rejects nonce below minimum length', () => {
      const shortNonce = '0'.repeat(31);
      expect(() => ashDeriveClientSecret(shortNonce, validContextId, validBinding)).toThrow(
        /at least 32 hex characters/
      );
    });

    it('rejects nonce above maximum length', () => {
      const longNonce = '0'.repeat(129);
      expect(() => ashDeriveClientSecret(longNonce, validContextId, validBinding)).toThrow(
        /exceeds maximum length of 128/
      );
    });

    it('accepts nonce at maximum length', () => {
      const maxNonce = '0'.repeat(128);
      expect(() => ashDeriveClientSecret(maxNonce, validContextId, validBinding)).not.toThrow();
    });

    it('rejects non-hex characters in nonce', () => {
      const invalidNonce = '0'.repeat(30) + 'GG';
      expect(() => ashDeriveClientSecret(invalidNonce, validContextId, validBinding)).toThrow(
        /hexadecimal characters/
      );
    });

    it('accepts uppercase hex in nonce', () => {
      const upperNonce = 'ABCDEF'.repeat(6);  // 36 chars
      expect(() => ashDeriveClientSecret(upperNonce, validContextId, validBinding)).not.toThrow();
    });
  });

  describe('SEC-CTX-001: Context ID Validation', () => {
    const validNonce = '0'.repeat(32);
    const validBinding = 'POST|/api/test|';

    it('accepts valid context_id', () => {
      expect(() => ashDeriveClientSecret(validNonce, 'ctx_test123', validBinding)).not.toThrow();
    });

    it('accepts context_id with allowed special characters', () => {
      expect(() => ashDeriveClientSecret(validNonce, 'ctx-test.123_abc', validBinding)).not.toThrow();
    });

    it('rejects empty context_id', () => {
      expect(() => ashDeriveClientSecret(validNonce, '', validBinding)).toThrow(
        /cannot be empty/
      );
    });

    it('rejects context_id exceeding max length', () => {
      const longContextId = 'a'.repeat(257);
      expect(() => ashDeriveClientSecret(validNonce, longContextId, validBinding)).toThrow(
        /exceeds maximum length of 256/
      );
    });

    it('accepts context_id at max length', () => {
      const maxContextId = 'a'.repeat(256);
      expect(() => ashDeriveClientSecret(validNonce, maxContextId, validBinding)).not.toThrow();
    });

    it('rejects context_id with pipe character', () => {
      expect(() => ashDeriveClientSecret(validNonce, 'ctx|test', validBinding)).toThrow(
        /alphanumeric/
      );
    });

    it('rejects context_id with space', () => {
      expect(() => ashDeriveClientSecret(validNonce, 'ctx test', validBinding)).toThrow(
        /alphanumeric/
      );
    });

    it('rejects context_id with special characters', () => {
      expect(() => ashDeriveClientSecret(validNonce, 'ctx@test!', validBinding)).toThrow(
        /alphanumeric/
      );
    });
  });

  describe('SEC-AUDIT-004: Binding Validation', () => {
    const validNonce = '0'.repeat(32);
    const validContextId = 'ctx_test123';

    it('rejects empty binding in ashDeriveClientSecret', () => {
      expect(() => ashDeriveClientSecret(validNonce, validContextId, '')).toThrow(
        /cannot be empty/
      );
    });

    it('rejects binding exceeding max length', () => {
      const longBinding = 'a'.repeat(8193);
      expect(() => ashDeriveClientSecret(validNonce, validContextId, longBinding)).toThrow(
        /exceeds maximum length of 8192/
      );
    });

    it('accepts binding at max length', () => {
      const maxBinding = 'a'.repeat(8192);
      expect(() => ashDeriveClientSecret(validNonce, validContextId, maxBinding)).not.toThrow();
    });
  });

  describe('SEC-SCOPE-001: Scope Field Validation', () => {
    it('rejects empty scope field name', () => {
      expect(() => validateScopeFields(['field1', '', 'field3'])).toThrow(
        /cannot be empty/
      );
    });

    it('rejects scope field exceeding max length', () => {
      const longField = 'a'.repeat(65);
      expect(() => validateScopeFields([longField])).toThrow(
        /exceeds maximum length of 64/
      );
    });

    it('accepts scope field at max length', () => {
      const maxField = 'a'.repeat(64);
      expect(() => validateScopeFields([maxField])).not.toThrow();
    });

    it('rejects scope field containing delimiter', () => {
      expect(() => validateScopeFields(['field\x1Fname'])).toThrow(
        /reserved delimiter/
      );
    });

    it('rejects total scope exceeding max length', () => {
      // Create fields that together exceed 4096 bytes
      const fields = Array(100).fill('a'.repeat(50));  // 100 * 50 = 5000 chars (+ delimiters)
      expect(() => validateScopeFields(fields)).toThrow(
        /Total scope length exceeds/
      );
    });

    it('rejects too many scope fields', () => {
      const fields = Array(101).fill('field');
      expect(() => validateScopeFields(fields)).toThrow(
        /exceeds maximum of 100/
      );
    });

    it('accepts scope at max field count', () => {
      const fields = Array(100).fill('a');
      expect(() => validateScopeFields(fields)).not.toThrow();
    });
  });

  describe('joinScopeFields with validation', () => {
    it('joins valid scope fields with delimiter', () => {
      const result = joinScopeFields(['field1', 'field2', 'field3']);
      expect(result).toContain('\x1F');
    });

    it('normalizes (sorts and deduplicates) before joining', () => {
      const result = joinScopeFields(['z', 'a', 'b', 'a']);
      expect(result).toBe('a\x1Fb\x1Fz');
    });

    it('validates and rejects invalid scope', () => {
      expect(() => joinScopeFields(['field\x1Fname'])).toThrow();
    });
  });

  describe('ashBuildProof Validation', () => {
    const validClientSecret = 'a'.repeat(64);
    const validTimestamp = '1704067200';
    const validBinding = 'POST|/api/test|';
    const validBodyHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    it('accepts valid inputs', () => {
      expect(() => ashBuildProof(validClientSecret, validTimestamp, validBinding, validBodyHash)).not.toThrow();
    });

    it('rejects empty client_secret', () => {
      expect(() => ashBuildProof('', validTimestamp, validBinding, validBodyHash)).toThrow(
        /cannot be empty/
      );
    });

    it('rejects empty timestamp', () => {
      expect(() => ashBuildProof(validClientSecret, '', validBinding, validBodyHash)).toThrow(
        /cannot be empty/
      );
    });

    it('rejects timestamp with leading zeros', () => {
      expect(() => ashBuildProof(validClientSecret, '01234567890', validBinding, validBodyHash)).toThrow(
        /leading zeros/
      );
    });

    it('rejects timestamp with non-digits', () => {
      expect(() => ashBuildProof(validClientSecret, '1234abc', validBinding, validBodyHash)).toThrow(
        /only digits/
      );
    });

    it('rejects empty binding', () => {
      expect(() => ashBuildProof(validClientSecret, validTimestamp, '', validBodyHash)).toThrow(
        /cannot be empty/
      );
    });

    it('rejects body_hash with wrong length', () => {
      expect(() => ashBuildProof(validClientSecret, validTimestamp, validBinding, 'abc123')).toThrow(
        /64 hex characters/
      );
    });

    it('rejects body_hash with non-hex characters', () => {
      const invalidHash = 'g'.repeat(64);
      expect(() => ashBuildProof(validClientSecret, validTimestamp, validBinding, invalidHash)).toThrow(
        /hexadecimal characters/
      );
    });
  });

  describe('ashVerifyProof with validation', () => {
    const validNonce = '0'.repeat(32);
    const validContextId = 'ctx_test123';
    const validBinding = 'POST|/api/test|';
    const validTimestamp = '1704067200';
    const validBodyHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    it('returns false for invalid timestamp format', () => {
      // Should not throw, but return false
      const result = ashVerifyProof(
        validNonce,
        validContextId,
        validBinding,
        '01234',  // Invalid: leading zero
        validBodyHash,
        'someproof'
      );
      expect(result).toBe(false);
    });

    it('returns false for non-digit timestamp', () => {
      const result = ashVerifyProof(
        validNonce,
        validContextId,
        validBinding,
        '1234abc',
        validBodyHash,
        'someproof'
      );
      expect(result).toBe(false);
    });
  });

  // BUG-21 to BUG-36 Fix Verification Tests
  describe('Bug Fix Verification', () => {
    describe('BUG-28: Leading zeros in array indices', () => {
      it('rejects leading zeros in bracket notation', () => {
        const payload = { items: [1, 2, 3, 4, 5, 6, 7, 8] };

        // Valid index should work
        expect(() => ashExtractScopedFields(payload, ['items[7]'])).not.toThrow();

        // Leading zeros should fail - regex now requires 0 or [1-9]\d*
        expect(() => ashExtractScopedFields(payload, ['items[007]'])).toThrow();
      });

      it('accepts valid array indices', () => {
        const payload = { items: [1, 2, 3] };

        // Index 0 is valid
        expect(ashExtractScopedFields(payload, ['items[0]'])).toEqual({ items: [1] });

        // Index without leading zeros is valid
        expect(ashExtractScopedFields(payload, ['items[2]'])).toEqual({ items: [undefined, undefined, 3] });
      });
    });

    describe('BUG-30: Empty scope path validation', () => {
      it('rejects empty scope paths', () => {
        const payload = { a: 1 };

        expect(() => ashExtractScopedFields(payload, [''])).toThrow(/cannot be empty/);
      });
    });

    describe('BUG-35: Hex case normalization', () => {
      it('accepts uppercase body hash and normalizes it', () => {
        // Uppercase hash should work (gets normalized internally)
        const upperHash = 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855';
        const lowerHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        const clientSecret = 'testsecret';
        const timestamp = '1704067200';
        const binding = 'POST|/api/test|';

        // Both should produce the same proof (lowercase is used internally)
        const proofUpper = ashBuildProof(clientSecret, timestamp, binding, upperHash);
        const proofLower = ashBuildProof(clientSecret, timestamp, binding, lowerHash);

        expect(proofUpper).toBe(proofLower);
      });
    });

    describe('BUG-21: secureDeriveClientSecret compatibility', () => {
      it('produces compatible secrets with ashDeriveClientSecret', () => {
        const nonce = '0'.repeat(64);
        const contextId = 'ctx_test123';
        const binding = 'POST|/api/test|';

        const standardSecret = ashDeriveClientSecret(nonce, contextId, binding);
        const secureSecretObj = secureDeriveClientSecret(nonce, contextId, binding);
        const secureSecret = secureSecretObj.get();
        secureSecretObj.clear();

        expect(secureSecret).toBe(standardSecret);
      });
    });
  });

  // SDK Implementation Reference Compliance Tests
  describe('SDK Implementation Reference Compliance', () => {
    describe('Section 1: Constants', () => {
      it('has all required security limit constants per Section 1.1', () => {
        // Per SDK Implementation Reference Section 1.1
        expect(MIN_NONCE_BYTES).toBe(16);
        expect(MIN_NONCE_HEX_CHARS).toBe(32);
        expect(MAX_NONCE_LENGTH).toBe(128);
        expect(MAX_CONTEXT_ID_LENGTH).toBe(256);
        expect(MAX_BINDING_LENGTH).toBe(8192);
        expect(MAX_SCOPE_FIELD_NAME_LENGTH).toBe(64);
        expect(MAX_TOTAL_SCOPE_LENGTH).toBe(4096);
        expect(MAX_SCOPE_FIELDS).toBe(100);
        expect(MAX_ARRAY_INDEX).toBe(10000);
        expect(MAX_TOTAL_ARRAY_ALLOCATION).toBe(10000);
        expect(MAX_SCOPE_PATH_DEPTH).toBe(32);
        expect(MAX_RECURSION_DEPTH).toBe(64);
        expect(MAX_PAYLOAD_SIZE).toBe(10485760);
        expect(MAX_TIMESTAMP).toBe(32503680000);
        expect(SHA256_HEX_LENGTH).toBe(64);
      });

      it('has correct protocol constants per Section 1.2', () => {
        expect(ASH_SDK_VERSION).toBe('2.3.4');
        expect(ASH_VERSION_PREFIX).toBe('ASHv2.1');
        expect(SCOPE_FIELD_DELIMITER).toBe('\x1F');
      });

      it('has correct timing-safe comparison constants per Section 1.3', () => {
        expect(CHUNK_SIZE).toBe(256);
        expect(FIXED_ITERATIONS).toBe(8);
        expect(FIXED_WORK_SIZE).toBe(2048);
      });
    });

    describe('Section 6.1: Timestamp Format Validation', () => {
      it('validates correct timestamps', () => {
        expect(ashValidateTimestampFormat('0')).toBe(0);
        expect(ashValidateTimestampFormat('1704067200')).toBe(1704067200);
        expect(ashValidateTimestampFormat('32503680000')).toBe(32503680000);
      });

      it('rejects empty timestamp', () => {
        expect(() => ashValidateTimestampFormat('')).toThrow('Timestamp cannot be empty');
      });

      it('rejects non-digit characters', () => {
        expect(() => ashValidateTimestampFormat('123abc')).toThrow('Timestamp must contain only digits');
      });

      it('rejects leading zeros', () => {
        expect(() => ashValidateTimestampFormat('01234')).toThrow('Timestamp must not have leading zeros');
      });

      it('rejects timestamps exceeding MAX_TIMESTAMP', () => {
        expect(() => ashValidateTimestampFormat('32503680001')).toThrow('Timestamp exceeds maximum allowed value');
      });
    });

    describe('Section 6.2: Timestamp Freshness Validation', () => {
      it('validates timestamp exactly at max_age_seconds (inclusive boundary)', () => {
        const maxAge = 300;
        const clockSkew = 60;
        const now = Math.floor(Date.now() / 1000);
        const exactlyAtMaxAge = (now - maxAge).toString();

        // Should NOT throw - boundary is inclusive
        expect(() => ashValidateTimestamp(exactlyAtMaxAge, maxAge, clockSkew)).not.toThrow();
      });

      it('validates timestamp exactly at clock_skew_seconds in future (inclusive boundary)', () => {
        const maxAge = 300;
        const clockSkew = 60;
        const now = Math.floor(Date.now() / 1000);
        const exactlyAtClockSkew = (now + clockSkew).toString();

        // Should NOT throw - boundary is inclusive
        expect(() => ashValidateTimestamp(exactlyAtClockSkew, maxAge, clockSkew)).not.toThrow();
      });

      it('rejects timestamp beyond clock_skew_seconds in future', () => {
        const maxAge = 300;
        const clockSkew = 60;
        const now = Math.floor(Date.now() / 1000);
        const beyondClockSkew = (now + clockSkew + 1).toString();

        expect(() => ashValidateTimestamp(beyondClockSkew, maxAge, clockSkew)).toThrow('Timestamp is in the future');
      });

      it('rejects expired timestamp', () => {
        const maxAge = 300;
        const clockSkew = 60;
        const now = Math.floor(Date.now() / 1000);
        const expired = (now - maxAge - 1).toString();

        expect(() => ashValidateTimestamp(expired, maxAge, clockSkew)).toThrow('Timestamp has expired');
      });
    });

    describe('Section 5.1: Scope Normalization', () => {
      it('sorts and deduplicates scope fields per spec example', () => {
        // Per SDK Implementation Reference Section 5.1
        const input = ['z', 'a', 'b', 'a'];
        const expected = ['a', 'b', 'z'];
        expect(normalizeScopeFields(input)).toEqual(expected);
      });
    });

    describe('Section 5.2: Scope Hash', () => {
      it('returns empty string for empty scope', () => {
        expect(ashHashScope([])).toBe('');
      });

      it('uses SCOPE_FIELD_DELIMITER (\\x1F) for joining', () => {
        // Per SDK Implementation Reference Section 5.2
        const scope = ['a', 'b', 'z'];
        const expectedJoined = 'a\x1Fb\x1Fz';
        const expectedHash = ashHashBody(expectedJoined);
        expect(ashHashScope(scope)).toBe(expectedHash);
      });

      it('normalizes before hashing', () => {
        // Different order should produce same hash
        const scope1 = ['z', 'a', 'b'];
        const scope2 = ['a', 'b', 'z'];
        expect(ashHashScope(scope1)).toBe(ashHashScope(scope2));
      });
    });
  });
});
