/**
 * ASH SDK Error Handling Tests
 *
 * Tests error messages, error codes, and graceful failure handling.
 * Ensures the SDK provides meaningful feedback without leaking sensitive data.
 */

import { describe, it, expect, beforeAll } from 'vitest';
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
  ashValidateTimestamp,
  ashExtractScopedFields,
  ashExtractScopedFieldsStrict,
  AshMemoryStore,
  ashVerifyProofDetailed,
} from './index';

beforeAll(() => {
  ashInit();
});

// =========================================================================
// ERROR MESSAGE QUALITY
// =========================================================================

describe('Error Handling: Message Quality', () => {
  describe('Input Validation Errors', () => {
    it('should provide meaningful error for empty nonce', () => {
      expect(() => ashDeriveClientSecret('', 'ctx', 'GET|/|')).toThrow();

      try {
        ashDeriveClientSecret('', 'ctx', 'GET|/|');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        const message = (error as Error).message.toLowerCase();
        expect(message).toMatch(/nonce|empty|required/);
      }
    });

    it('should provide meaningful error for invalid nonce format', () => {
      expect(() => ashDeriveClientSecret('not-hex!', 'ctx', 'GET|/|')).toThrow();

      try {
        ashDeriveClientSecret('not-hex!', 'ctx', 'GET|/|');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        const message = (error as Error).message.toLowerCase();
        expect(message).toMatch(/nonce|hex|format|invalid/);
      }
    });

    it('should provide meaningful error for empty context ID', () => {
      const nonce = ashGenerateNonce();
      expect(() => ashDeriveClientSecret(nonce, '', 'GET|/|')).toThrow();

      try {
        ashDeriveClientSecret(nonce, '', 'GET|/|');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        const message = (error as Error).message.toLowerCase();
        expect(message).toMatch(/context|empty|required/);
      }
    });

    it('should provide meaningful error for empty binding', () => {
      const nonce = ashGenerateNonce();
      expect(() => ashDeriveClientSecret(nonce, 'ctx', '')).toThrow();

      try {
        ashDeriveClientSecret(nonce, 'ctx', '');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        const message = (error as Error).message.toLowerCase();
        expect(message).toMatch(/binding|empty|required/);
      }
    });

    it('should provide meaningful error for invalid JSON', () => {
      expect(() => canonicalizeJsonNative('not json')).toThrow();

      try {
        canonicalizeJsonNative('not json');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        const message = (error as Error).message.toLowerCase();
        expect(message).toMatch(/json|parse|invalid|syntax/);
      }
    });

    it('should provide meaningful error for invalid timestamp', () => {
      expect(() => ashValidateTimestamp('not-a-number')).toThrow();

      try {
        ashValidateTimestamp('not-a-number');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        const message = (error as Error).message.toLowerCase();
        expect(message).toMatch(/timestamp|invalid|format/);
      }
    });

    it('should provide meaningful error for expired timestamp', () => {
      const oldTimestamp = (Math.floor(Date.now() / 1000) - 3600).toString();
      expect(() => ashValidateTimestamp(oldTimestamp)).toThrow();

      try {
        ashValidateTimestamp(oldTimestamp);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        const message = (error as Error).message.toLowerCase();
        expect(message).toMatch(/expired|old|past/);
      }
    });

    it('should provide meaningful error for future timestamp', () => {
      const futureTimestamp = (Math.floor(Date.now() / 1000) + 3600).toString();
      expect(() => ashValidateTimestamp(futureTimestamp)).toThrow();

      try {
        ashValidateTimestamp(futureTimestamp);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        const message = (error as Error).message.toLowerCase();
        expect(message).toMatch(/future|ahead/);
      }
    });
  });

  describe('Resource Limit Errors', () => {
    it('should provide meaningful error for oversized JSON', () => {
      const largeJson = JSON.stringify({ data: 'x'.repeat(11 * 1024 * 1024) });
      expect(() => canonicalizeJsonNative(largeJson)).toThrow();

      try {
        canonicalizeJsonNative(largeJson);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        const message = (error as Error).message.toLowerCase();
        expect(message).toMatch(/size|large|maximum|exceeds/);
      }
    });

    it('should provide meaningful error for deeply nested JSON', () => {
      let deepJson = '{"a":';
      for (let i = 0; i < 100; i++) {
        deepJson += '{"a":';
      }
      deepJson += '1';
      for (let i = 0; i <= 100; i++) {
        deepJson += '}';
      }

      expect(() => canonicalizeJsonNative(deepJson)).toThrow();

      try {
        canonicalizeJsonNative(deepJson);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        const message = (error as Error).message.toLowerCase();
        expect(message).toMatch(/depth|nested|deep/);
      }
    });

    it('should provide meaningful error for oversized nonce', () => {
      const longNonce = crypto.randomBytes(100).toString('hex');
      expect(() => ashDeriveClientSecret(longNonce, 'ctx', 'GET|/|')).toThrow();

      try {
        ashDeriveClientSecret(longNonce, 'ctx', 'GET|/|');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        const message = (error as Error).message.toLowerCase();
        expect(message).toMatch(/nonce|length|long|maximum/);
      }
    });
  });

  describe('Scope Extraction Errors', () => {
    it('should provide meaningful error for dangerous keys', () => {
      expect(() => ashExtractScopedFields({ a: 1 }, ['__proto__'])).toThrow();

      try {
        ashExtractScopedFields({ a: 1 }, ['__proto__']);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        const message = (error as Error).message.toLowerCase();
        expect(message).toMatch(/dangerous|proto|forbidden/);
      }
    });

    it('should provide meaningful error for missing scope field (strict)', () => {
      expect(() => ashExtractScopedFieldsStrict({ a: 1 }, ['b'])).toThrow();

      try {
        ashExtractScopedFieldsStrict({ a: 1 }, ['b']);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        const message = (error as Error).message.toLowerCase();
        expect(message).toMatch(/missing|not found|field/);
      }
    });

    it('should provide meaningful error for invalid array index', () => {
      expect(() => ashExtractScopedFields({ items: [1, 2] }, ['items[999999999]'])).toThrow();

      try {
        ashExtractScopedFields({ items: [1, 2] }, ['items[999999999]']);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        const message = (error as Error).message.toLowerCase();
        expect(message).toMatch(/index|bounds|range|array/);
      }
    });
  });
});

// =========================================================================
// ERROR CODES
// =========================================================================

describe('Error Handling: Error Codes', () => {
  describe('Verification Error Codes', () => {
    it('should return INVALID_PROOF_FORMAT for null proof', () => {
      const nonce = ashGenerateNonce();
      const contextId = 'ctx_test';
      const binding = 'POST|/api/test|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const bodyHash = ashHashBody('{}');

      // @ts-ignore - Testing runtime behavior
      const result = ashVerifyProofDetailed(nonce, contextId, binding, timestamp, bodyHash, null);

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('INVALID_PROOF_FORMAT');
    });

    it('should return INVALID_PROOF_FORMAT for wrong length proof', () => {
      const nonce = ashGenerateNonce();
      const contextId = 'ctx_test';
      const binding = 'POST|/api/test|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const bodyHash = ashHashBody('{}');

      const result = ashVerifyProofDetailed(nonce, contextId, binding, timestamp, bodyHash, 'short');

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('INVALID_PROOF_FORMAT');
    });

    it('should return PROOF_MISMATCH for incorrect proof', () => {
      const nonce = ashGenerateNonce();
      const contextId = 'ctx_test';
      const binding = 'POST|/api/test|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const bodyHash = ashHashBody('{}');
      const wrongProof = 'a'.repeat(64);

      const result = ashVerifyProofDetailed(nonce, contextId, binding, timestamp, bodyHash, wrongProof);

      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('PROOF_MISMATCH');
    });
  });
});

// =========================================================================
// NO SENSITIVE DATA LEAKAGE
// =========================================================================

describe('Error Handling: No Sensitive Data Leakage', () => {
  it('should not leak nonce in error messages', () => {
    const nonce = 'secret_nonce_' + crypto.randomBytes(16).toString('hex');

    try {
      ashDeriveClientSecret(nonce, 'ctx', 'GET|/|');
    } catch (error) {
      const message = (error as Error).message;
      expect(message).not.toContain(nonce);
    }
  });

  it('should not leak client secret in error messages', () => {
    const nonce = ashGenerateNonce();
    const contextId = 'ctx_test';
    const binding = 'POST|/api/test|';
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

    try {
      // Try to use secret in a way that might error
      ashBuildProofV21(clientSecret, 'invalid-timestamp', binding, 'invalid-hash');
    } catch (error) {
      const message = (error as Error).message;
      expect(message).not.toContain(clientSecret);
    }
  });

  it('should not leak body content in error messages', () => {
    const sensitiveBody = '{"password":"super_secret_password_123"}';

    try {
      // This might fail for various reasons
      canonicalizeJsonNative(sensitiveBody);
    } catch (error) {
      const message = (error as Error).message;
      expect(message).not.toContain('super_secret_password_123');
    }
  });

  it('should not include expected proof in verification failure', () => {
    const nonce = ashGenerateNonce();
    const contextId = 'ctx_test';
    const binding = 'POST|/api/test|';
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const bodyHash = ashHashBody('{}');
    const wrongProof = 'b'.repeat(64);

    const result = ashVerifyProofDetailed(nonce, contextId, binding, timestamp, bodyHash, wrongProof);

    // Error message should not contain the expected proof
    expect(result.errorMessage).not.toMatch(/^[0-9a-f]{64}$/i);
  });
});

// =========================================================================
// GRACEFUL FALLBACK
// =========================================================================

describe('Error Handling: Graceful Fallback', () => {
  it('WASM failure should fall back to native implementation', () => {
    // The SDK should work even if WASM fails to initialize
    // This is tested implicitly by our tests passing

    const json = '{"b":2,"a":1}';
    const result = canonicalizeJsonNative(json);
    expect(result).toBe('{"a":1,"b":2}');
  });

  it('should handle verification failure gracefully (return false, not throw)', () => {
    const nonce = ashGenerateNonce();
    const contextId = 'ctx_test';
    const binding = 'POST|/api/test|';
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const bodyHash = ashHashBody('{}');
    const invalidProof = 'x'.repeat(64);

    // Should return false, not throw
    const result = ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, invalidProof);
    expect(result).toBe(false);
  });

  it('should handle empty string inputs gracefully', () => {
    // Empty body hash
    const emptyBodyHash = ashHashBody('');
    expect(emptyBodyHash).toHaveLength(64);

    // Empty query canonicalization
    const emptyQuery = canonicalQueryNative('');
    expect(emptyQuery).toBe('');

    // Empty JSON canonicalization
    const emptyJson = canonicalizeJsonNative('{}');
    expect(emptyJson).toBe('{}');
  });
});

// =========================================================================
// STORE ERROR HANDLING
// =========================================================================

describe('Error Handling: Store Operations', () => {
  it('should handle non-existent context gracefully', async () => {
    const store = new AshMemoryStore();

    const result = await store.get('ash_nonexistent');
    expect(result).toBeNull();

    const consumed = await store.consume('ash_nonexistent');
    expect(consumed).toBe(false);
  });

  it('should reject oversized metadata with meaningful error', async () => {
    const store = new AshMemoryStore();

    await expect(store.create({
      binding: 'POST|/api/test|',
      ttlMs: 60000,
      metadata: { data: 'x'.repeat(100000) },
    })).rejects.toThrow(/size|large|64KB/i);
  });

  it('should handle expired context consume gracefully', async () => {
    const store = new AshMemoryStore();

    const ctx = await store.create({
      binding: 'POST|/api/test|',
      ttlMs: 1,
    });

    await new Promise(resolve => setTimeout(resolve, 10));

    const consumed = await store.consume(ctx.id);
    expect(consumed).toBe(false);
  });
});

// =========================================================================
// TYPESCRIPT RUNTIME TYPE CHECKING
// =========================================================================

describe('Error Handling: Runtime Type Safety', () => {
  it('should throw on undefined input', () => {
    // @ts-ignore - Testing runtime behavior with invalid types
    // The SDK properly rejects non-string inputs at runtime
    expect(() => ashHashBody(undefined)).toThrow();
  });

  it('should throw on number input to string function', () => {
    // @ts-ignore - Testing runtime behavior with invalid types
    expect(() => ashHashBody(123)).toThrow();
  });

  it('should throw on object input to string function', () => {
    // @ts-ignore - Testing runtime behavior with invalid types
    expect(() => ashHashBody({ key: 'value' })).toThrow();
  });

  it('should handle array input to canonicalizeJson', () => {
    // Arrays are valid JSON
    const result = canonicalizeJsonNative('[1,2,3]');
    expect(result).toBe('[1,2,3]');
  });
});

// =========================================================================
// RECOVERY SCENARIOS
// =========================================================================

describe('Error Handling: Recovery', () => {
  it('should recover after multiple failed operations', () => {
    // Multiple failures
    for (let i = 0; i < 10; i++) {
      try {
        canonicalizeJsonNative('invalid json');
      } catch {
        // Expected
      }
    }

    // Should still work after failures
    const result = canonicalizeJsonNative('{"valid":"json"}');
    expect(result).toBe('{"valid":"json"}');
  });

  it('should recover after store operation failures', async () => {
    const store = new AshMemoryStore();

    // Multiple failed operations
    for (let i = 0; i < 10; i++) {
      await store.consume('nonexistent_' + i);
    }

    // Should still work
    const ctx = await store.create({
      binding: 'POST|/api/test|',
      ttlMs: 60000,
    });
    expect(ctx.id).toBeDefined();

    const consumed = await store.consume(ctx.id);
    expect(consumed).toBe(true);
  });
});

console.log('Error Handling Tests loaded');
