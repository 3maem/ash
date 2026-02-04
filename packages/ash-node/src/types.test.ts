/**
 * ASH SDK TypeScript Types Tests
 *
 * Tests type exports, type inference, and type safety.
 * These tests verify that the SDK's TypeScript declarations are correct
 * and that the types can be used as documented.
 */

import { describe, it, expect, beforeAll } from 'vitest';
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
  ashBuildProofScoped,
  ashVerifyProofScoped,
  ashBuildProofUnified,
  ashVerifyProofUnified,
  ashValidateTimestamp,
  ashTimingSafeEqual,
  AshMemoryStore,
  canonicalizeJsonNative,
  canonicalQueryNative,
  ashExtractScopedFields,
  ashExtractScopedFieldsStrict,
  // Type exports
  type AshContext,
  type AshContextOptions,
  type AshContextStore,
  type AshMode,
  type AshScopedProofResult,
  type AshUnifiedProofResult,
  type AshVerifyDetailedResult,
} from './index';

beforeAll(() => {
  ashInit();
});

// =========================================================================
// TYPE EXPORTS VERIFICATION
// =========================================================================

describe('Types: Exports Exist', () => {
  it('should export all core functions', () => {
    expect(typeof ashInit).toBe('function');
    expect(typeof ashBuildProofV21).toBe('function');
    expect(typeof ashVerifyProofV21).toBe('function');
    expect(typeof ashDeriveClientSecret).toBe('function');
    expect(typeof ashCanonicalizeJson).toBe('function');
    expect(typeof ashCanonicalizeUrlencoded).toBe('function');
    expect(typeof ashCanonicalizeQuery).toBe('function');
    expect(typeof ashNormalizeBinding).toBe('function');
    expect(typeof ashHashBody).toBe('function');
    expect(typeof ashGenerateNonce).toBe('function');
    expect(typeof ashGenerateContextId).toBe('function');
  });

  it('should export v2.2 scoped proof functions', () => {
    expect(typeof ashBuildProofScoped).toBe('function');
    expect(typeof ashVerifyProofScoped).toBe('function');
  });

  it('should export v2.3 unified proof functions', () => {
    expect(typeof ashBuildProofUnified).toBe('function');
    expect(typeof ashVerifyProofUnified).toBe('function');
  });

  it('should export utility functions', () => {
    expect(typeof ashValidateTimestamp).toBe('function');
    expect(typeof ashTimingSafeEqual).toBe('function');
    expect(typeof ashExtractScopedFields).toBe('function');
    expect(typeof ashExtractScopedFieldsStrict).toBe('function');
  });

  it('should export native implementations', () => {
    expect(typeof canonicalizeJsonNative).toBe('function');
    expect(typeof canonicalQueryNative).toBe('function');
  });

  it('should export store class', () => {
    expect(typeof AshMemoryStore).toBe('function');
    expect(AshMemoryStore.prototype.create).toBeDefined();
    expect(AshMemoryStore.prototype.get).toBeDefined();
    expect(AshMemoryStore.prototype.consume).toBeDefined();
  });
});

// =========================================================================
// TYPE INFERENCE TESTS
// =========================================================================

describe('Types: Inference', () => {
  it('ashGenerateNonce should return string', () => {
    const nonce = ashGenerateNonce();
    // TypeScript should infer this as string
    const length: number = nonce.length;
    expect(typeof nonce).toBe('string');
    expect(length).toBe(64);
  });

  it('ashGenerateContextId should return string', () => {
    const contextId = ashGenerateContextId();
    // TypeScript should infer this as string
    const includes: boolean = contextId.includes('_');
    expect(typeof contextId).toBe('string');
    expect(includes).toBe(true);
  });

  it('ashHashBody should return string', () => {
    const hash = ashHashBody('test');
    // TypeScript should infer this as string
    const hex: boolean = /^[0-9a-f]+$/.test(hash);
    expect(typeof hash).toBe('string');
    expect(hex).toBe(true);
  });

  it('ashBuildProofV21 should return string', () => {
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/test|';
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const bodyHash = ashHashBody('{}');

    const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);
    expect(typeof proof).toBe('string');
    expect(proof.length).toBe(64);
  });

  it('ashVerifyProofV21 should return boolean', () => {
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/test|';
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const bodyHash = ashHashBody('{}');
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

    const isValid = ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof);
    expect(typeof isValid).toBe('boolean');
  });

  it('ashBuildProofScoped should return AshScopedProofResult', () => {
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/test|';
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const payload = { amount: 100 };
    const scope = ['amount'];

    const result: AshScopedProofResult = ashBuildProofScoped(
      clientSecret, timestamp, binding, payload, scope
    );

    expect(result).toHaveProperty('proof');
    expect(result).toHaveProperty('scopeHash');
    expect(typeof result.proof).toBe('string');
    expect(typeof result.scopeHash).toBe('string');
  });

  it('ashBuildProofUnified should return AshUnifiedProofResult', () => {
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/test|';
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const payload = { step: 1 };

    const result: AshUnifiedProofResult = ashBuildProofUnified(
      clientSecret, timestamp, binding, payload, []
    );

    expect(result).toHaveProperty('proof');
    expect(result).toHaveProperty('scopeHash');
    expect(result).toHaveProperty('chainHash');
    expect(typeof result.proof).toBe('string');
    expect(typeof result.scopeHash).toBe('string');
    expect(typeof result.chainHash).toBe('string');
  });
});

// =========================================================================
// TYPE COMPATIBILITY TESTS
// =========================================================================

describe('Types: AshContext', () => {
  it('should have correct shape from store.create', async () => {
    const store = new AshMemoryStore(0);
    const ctx: AshContext = await store.create({
      binding: 'POST|/api/test|',
      ttlMs: 60000,
    });

    // Verify all required fields
    expect(ctx.id).toBeDefined();
    expect(ctx.binding).toBeDefined();
    expect(ctx.expiresAt).toBeDefined();
    expect(ctx.mode).toBeDefined();
    expect(ctx.used).toBeDefined();
    expect(ctx.nonce).toBeDefined();

    // Verify types
    expect(typeof ctx.id).toBe('string');
    expect(typeof ctx.binding).toBe('string');
    expect(typeof ctx.expiresAt).toBe('number');
    expect(typeof ctx.mode).toBe('string');
    expect(typeof ctx.used).toBe('boolean');
    expect(typeof ctx.nonce).toBe('string');

    store.destroy();
  });

  it('should accept metadata', async () => {
    const store = new AshMemoryStore(0);
    const metadata: Record<string, unknown> = {
      userId: '123',
      action: 'test',
      count: 42,
      nested: { key: 'value' },
    };

    const ctx: AshContext = await store.create({
      binding: 'POST|/api/test|',
      ttlMs: 60000,
      metadata,
    });

    expect(ctx.metadata).toEqual(metadata);
    store.destroy();
  });
});

describe('Types: AshContextOptions', () => {
  it('should accept valid options', async () => {
    const store = new AshMemoryStore(0);

    // Minimal options
    const options1: AshContextOptions = {
      binding: 'POST|/api/test|',
      ttlMs: 60000,
    };
    const ctx1 = await store.create(options1);
    expect(ctx1.id).toBeDefined();

    // With mode
    const options2: AshContextOptions = {
      binding: 'POST|/api/test|',
      ttlMs: 60000,
      mode: 'strict',
    };
    const ctx2 = await store.create(options2);
    expect(ctx2.mode).toBe('strict');

    // With metadata
    const options3: AshContextOptions = {
      binding: 'POST|/api/test|',
      ttlMs: 60000,
      metadata: { key: 'value' },
    };
    const ctx3 = await store.create(options3);
    expect(ctx3.metadata).toEqual({ key: 'value' });

    store.destroy();
  });
});

describe('Types: AshMode', () => {
  it('should accept valid mode values', async () => {
    const store = new AshMemoryStore(0);

    const modes: AshMode[] = ['minimal', 'balanced', 'strict'];

    for (const mode of modes) {
      const ctx = await store.create({
        binding: 'POST|/api/test|',
        ttlMs: 60000,
        mode,
      });
      expect(ctx.mode).toBe(mode);
    }

    store.destroy();
  });
});

describe('Types: AshContextStore Interface', () => {
  it('AshMemoryStore should implement AshContextStore', () => {
    const store: AshContextStore = new AshMemoryStore(0);

    // Interface methods
    expect(typeof store.create).toBe('function');
    expect(typeof store.get).toBe('function');
    expect(typeof store.consume).toBe('function');
    expect(typeof store.cleanup).toBe('function');

    (store as AshMemoryStore).destroy();
  });
});

// =========================================================================
// GENERIC TYPE SAFETY TESTS
// =========================================================================

describe('Types: Function Signatures', () => {
  it('ashDeriveClientSecret has correct signature', () => {
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/test|';

    // All arguments must be strings
    const secret: string = ashDeriveClientSecret(nonce, contextId, binding);
    expect(typeof secret).toBe('string');
  });

  it('ashNormalizeBinding has correct signature', () => {
    // All arguments are strings, returns string
    const binding: string = ashNormalizeBinding('POST', '/api/test', 'a=1');
    expect(typeof binding).toBe('string');
    expect(binding).toContain('|');
  });

  it('ashCanonicalizeJson has correct signature', () => {
    const input = '{"b":2,"a":1}';
    const output: string = ashCanonicalizeJson(input);
    expect(typeof output).toBe('string');
  });

  it('ashTimingSafeEqual has correct signature', () => {
    const result: boolean = ashTimingSafeEqual('abc', 'abc');
    expect(typeof result).toBe('boolean');
  });

  it('ashValidateTimestamp has correct signature', () => {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const result: boolean = ashValidateTimestamp(timestamp);
    expect(typeof result).toBe('boolean');
  });
});

describe('Types: Optional Parameters', () => {
  it('ashValidateTimestamp should accept optional parameters', () => {
    const timestamp = Math.floor(Date.now() / 1000).toString();

    // With defaults
    const result1 = ashValidateTimestamp(timestamp);
    expect(result1).toBe(true);

    // With custom maxAge
    const result2 = ashValidateTimestamp(timestamp, 120);
    expect(result2).toBe(true);

    // With custom maxAge and clockSkew
    const result3 = ashValidateTimestamp(timestamp, 120, 30);
    expect(result3).toBe(true);
  });

  it('ashBuildProofUnified should accept optional previousProof', () => {
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/test|';
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const payload = { step: 1 };

    // Without previousProof
    const result1 = ashBuildProofUnified(clientSecret, timestamp, binding, payload, []);
    expect(result1.proof).toBeDefined();

    // With previousProof
    const result2 = ashBuildProofUnified(
      clientSecret, timestamp, binding, payload, [], result1.proof
    );
    expect(result2.proof).toBeDefined();
  });
});

// =========================================================================
// ARRAY AND OBJECT TYPE TESTS
// =========================================================================

describe('Types: Array Parameters', () => {
  it('ashBuildProofScoped should accept string array for scope', () => {
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/test|';
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const payload = { a: 1, b: 2, c: 3 };

    const scope: string[] = ['a', 'b'];
    const result = ashBuildProofScoped(clientSecret, timestamp, binding, payload, scope);
    expect(result.proof).toBeDefined();
  });

  it('ashExtractScopedFields should accept object and string array', () => {
    const payload: Record<string, unknown> = { name: 'test', value: 123 };
    const fields: string[] = ['name'];

    const extracted = ashExtractScopedFields(payload, fields);
    expect(extracted).toHaveProperty('name');
  });
});

describe('Types: Object Parameters', () => {
  it('ashBuildProofScoped should accept Record<string, unknown> for payload', () => {
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/test|';
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const timestamp = Math.floor(Date.now() / 1000).toString();

    const payload: Record<string, unknown> = {
      string: 'value',
      number: 42,
      boolean: true,
      null: null,
      array: [1, 2, 3],
      nested: { key: 'value' },
    };

    const result = ashBuildProofScoped(clientSecret, timestamp, binding, payload, ['string']);
    expect(result.proof).toBeDefined();
  });
});

// =========================================================================
// ASYNC TYPE TESTS
// =========================================================================

describe('Types: Async Operations', () => {
  it('store.create should return Promise<AshContext>', async () => {
    const store = new AshMemoryStore(0);

    const promise = store.create({
      binding: 'POST|/api/test|',
      ttlMs: 60000,
    });

    expect(promise).toBeInstanceOf(Promise);

    const ctx: AshContext = await promise;
    expect(ctx.id).toBeDefined();

    store.destroy();
  });

  it('store.get should return Promise<AshContext | null>', async () => {
    const store = new AshMemoryStore(0);
    const ctx = await store.create({
      binding: 'POST|/api/test|',
      ttlMs: 60000,
    });

    const retrieved: AshContext | null = await store.get(ctx.id);
    expect(retrieved).not.toBeNull();

    const notFound: AshContext | null = await store.get('ctx_nonexistent');
    expect(notFound).toBeNull();

    store.destroy();
  });

  it('store.consume should return Promise<boolean>', async () => {
    const store = new AshMemoryStore(0);
    const ctx = await store.create({
      binding: 'POST|/api/test|',
      ttlMs: 60000,
    });

    const consumed: boolean = await store.consume(ctx.id);
    expect(typeof consumed).toBe('boolean');
    expect(consumed).toBe(true);

    store.destroy();
  });

  it('store.cleanup should return Promise<number>', async () => {
    const store = new AshMemoryStore(0);

    const cleaned: number = await store.cleanup();
    expect(typeof cleaned).toBe('number');

    store.destroy();
  });
});

// =========================================================================
// RETURN TYPE VERIFICATION
// =========================================================================

describe('Types: Return Values', () => {
  it('all hash functions return 64-char hex strings', () => {
    const nonce = ashGenerateNonce();
    const bodyHash = ashHashBody('test');

    expect(nonce.length).toBe(64);
    expect(bodyHash.length).toBe(64);
    expect(/^[0-9a-f]+$/.test(nonce)).toBe(true);
    expect(/^[0-9a-f]+$/.test(bodyHash)).toBe(true);
  });

  it('proof functions return 64-char hex strings', () => {
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/test|';
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const bodyHash = ashHashBody('{}');

    const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);
    expect(proof.length).toBe(64);
    expect(/^[0-9a-f]+$/.test(proof)).toBe(true);
  });

  it('scoped proof result has correct structure', () => {
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/test|';
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const timestamp = Math.floor(Date.now() / 1000).toString();

    const result = ashBuildProofScoped(clientSecret, timestamp, binding, { a: 1 }, ['a']);

    // Structure check
    const keys = Object.keys(result);
    expect(keys).toContain('proof');
    expect(keys).toContain('scopeHash');
  });

  it('unified proof result has correct structure', () => {
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/test|';
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const timestamp = Math.floor(Date.now() / 1000).toString();

    const result = ashBuildProofUnified(clientSecret, timestamp, binding, { a: 1 }, []);

    // Structure check
    const keys = Object.keys(result);
    expect(keys).toContain('proof');
    expect(keys).toContain('scopeHash');
    expect(keys).toContain('chainHash');
  });
});

console.log('TypeScript Types Tests loaded');
