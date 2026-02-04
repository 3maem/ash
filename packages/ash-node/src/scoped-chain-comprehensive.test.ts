/**
 * Scoped and Chained Proofs Comprehensive Tests
 *
 * Tests for scoped and chained proof functionality covering:
 * - Field extraction with dot notation
 * - Scope hashing and normalization
 * - Scoped proof building and verification
 * - Chained proof building and verification
 * - Unified proofs (scoping + chaining)
 * - Edge cases and error handling
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  ashInit,
  ashExtractScopedFields,
  ashExtractScopedFieldsStrict,
  ashHashScope,
  ashHashScopedBody,
  ashHashScopedBodyStrict,
  ashBuildProofScoped,
  ashVerifyProofScoped,
  ashBuildProofUnified,
  ashVerifyProofUnified,
  ashHashProof,
  ashNormalizeScopeFields,
  ashValidateScopeFields,
  ashJoinScopeFields,
  ashDeriveClientSecret,
  ashGenerateNonce,
  ashGenerateContextId,
  ashNormalizeBinding,
  ashHashBody,
  SCOPE_FIELD_DELIMITER,
  MAX_SCOPE_FIELDS,
  MAX_SCOPE_FIELD_NAME_LENGTH,
  MAX_ARRAY_INDEX,
  MAX_SCOPE_PATH_DEPTH,
} from './index';

// Initialize WASM
beforeAll(() => {
  try {
    ashInit();
  } catch {
    // WASM not available, tests will use native fallback
  }
});

// Helper to create proof setup
function createProofSetup() {
  const nonce = ashGenerateNonce();
  const contextId = ashGenerateContextId();
  const binding = ashNormalizeBinding('POST', '/api/test');
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

  return { nonce, contextId, binding, timestamp, clientSecret };
}

describe('Scoped and Chained Proofs Comprehensive Tests', () => {
  describe('Field Extraction - Basic', () => {
    it('extracts top-level fields', () => {
      const payload = { name: 'John', age: 30, city: 'NYC' };
      const result = ashExtractScopedFields(payload, ['name']);
      expect(result).toEqual({ name: 'John' });
    });

    it('extracts multiple top-level fields', () => {
      const payload = { name: 'John', age: 30, city: 'NYC' };
      const result = ashExtractScopedFields(payload, ['name', 'age']);
      expect(result).toEqual({ name: 'John', age: 30 });
    });

    it('extracts all fields with empty scope', () => {
      const payload = { name: 'John', age: 30 };
      const result = ashExtractScopedFields(payload, []);
      expect(result).toEqual(payload);
    });

    it('ignores missing fields', () => {
      const payload = { name: 'John' };
      const result = ashExtractScopedFields(payload, ['name', 'missing']);
      expect(result).toEqual({ name: 'John' });
    });
  });

  describe('Field Extraction - Nested Objects', () => {
    it('extracts nested fields with dot notation', () => {
      const payload = { user: { name: 'John', address: { city: 'NYC' } } };
      const result = ashExtractScopedFields(payload, ['user.name']);
      expect(result).toEqual({ user: { name: 'John' } });
    });

    it('extracts deeply nested fields', () => {
      const payload = { a: { b: { c: { d: { e: 'value' } } } } };
      const result = ashExtractScopedFields(payload, ['a.b.c.d.e']);
      expect(result).toEqual({ a: { b: { c: { d: { e: 'value' } } } } });
    });

    it('extracts multiple nested fields', () => {
      const payload = { user: { name: 'John', email: 'john@example.com' } };
      const result = ashExtractScopedFields(payload, ['user.name', 'user.email']);
      expect(result).toEqual({ user: { name: 'John', email: 'john@example.com' } });
    });

    it('handles missing intermediate path', () => {
      const payload = { user: { name: 'John' } };
      const result = ashExtractScopedFields(payload, ['user.address.city']);
      expect(result).toEqual({});
    });
  });

  describe('Field Extraction - Arrays', () => {
    it('extracts array elements with bracket notation', () => {
      const payload = { items: ['a', 'b', 'c'] };
      const result = ashExtractScopedFields(payload, ['items[0]']);
      expect(result).toEqual({ items: ['a'] });
    });

    it('extracts specific array index', () => {
      const payload = { items: [1, 2, 3, 4, 5] };
      const result = ashExtractScopedFields(payload, ['items[2]']);
      expect(result).toEqual({ items: [undefined, undefined, 3] });
    });

    it('extracts nested object in array', () => {
      const payload = { users: [{ name: 'Alice' }, { name: 'Bob' }] };
      const result = ashExtractScopedFields(payload, ['users[0].name']);
      expect(result).toEqual({ users: [{ name: 'Alice' }] });
    });

    it('extracts array within nested object', () => {
      const payload = { data: { items: [1, 2, 3] } };
      const result = ashExtractScopedFields(payload, ['data.items[1]']);
      expect(result).toEqual({ data: { items: [undefined, 2] } });
    });

    it('handles multi-dimensional arrays', () => {
      const payload = { matrix: [[1, 2], [3, 4]] };
      const result = ashExtractScopedFields(payload, ['matrix[0][1]']);
      expect(result).toEqual({ matrix: [[undefined, 2]] });
    });

    it('rejects leading zeros in array index', () => {
      const payload = { items: [1, 2, 3] };
      expect(() => ashExtractScopedFields(payload, ['items[007]'])).toThrow(/leading zeros/);
    });

    it('accepts index 0', () => {
      const payload = { items: [1, 2, 3] };
      const result = ashExtractScopedFields(payload, ['items[0]']);
      expect(result).toEqual({ items: [1] });
    });
  });

  describe('Field Extraction - Strict Mode', () => {
    it('throws when field is missing in strict mode', () => {
      const payload = { name: 'John' };
      expect(() => ashExtractScopedFieldsStrict(payload, ['missing'])).toThrow(/missing/i);
    });

    it('succeeds when all fields exist in strict mode', () => {
      const payload = { name: 'John', age: 30 };
      const result = ashExtractScopedFieldsStrict(payload, ['name', 'age']);
      expect(result).toEqual({ name: 'John', age: 30 });
    });

    it('uses generic error message to prevent field enumeration', () => {
      const payload = { name: 'John' };
      try {
        ashExtractScopedFieldsStrict(payload, ['secret']);
      } catch (e) {
        // Should NOT reveal which field was missing
        expect((e as Error).message).not.toContain('secret');
      }
    });
  });

  describe('Field Extraction - Security', () => {
    it('blocks __proto__ in scope paths', () => {
      const payload = { data: 'value' };
      expect(() => ashExtractScopedFields(payload, ['__proto__'])).toThrow(/dangerous/i);
    });

    it('blocks constructor in scope paths', () => {
      const payload = { data: 'value' };
      expect(() => ashExtractScopedFields(payload, ['constructor'])).toThrow(/dangerous/i);
    });

    it('blocks prototype in scope paths', () => {
      const payload = { data: 'value' };
      expect(() => ashExtractScopedFields(payload, ['prototype'])).toThrow(/dangerous/i);
    });

    it('blocks __proto__ in nested paths', () => {
      const payload = { data: { value: 1 } };
      expect(() => ashExtractScopedFields(payload, ['data.__proto__'])).toThrow(/dangerous/i);
    });

    it('rejects empty scope path', () => {
      const payload = { data: 'value' };
      expect(() => ashExtractScopedFields(payload, [''])).toThrow(/empty/i);
    });

    it('rejects whitespace-only scope path', () => {
      const payload = { data: 'value' };
      expect(() => ashExtractScopedFields(payload, ['   '])).toThrow(/whitespace/i);
    });

    it('rejects path exceeding max depth', () => {
      const payload = { a: 'value' };
      const deepPath = Array(MAX_SCOPE_PATH_DEPTH + 5).fill('a').join('.');
      expect(() => ashExtractScopedFields(payload, [deepPath])).toThrow(/depth/i);
    });

    it('rejects array index exceeding max', () => {
      const payload = { items: [1] };
      expect(() => ashExtractScopedFields(payload, [`items[${MAX_ARRAY_INDEX}]`])).toThrow(/exceeds/i);
    });

    it('rejects non-object payload', () => {
      expect(() => ashExtractScopedFields(null as any, ['field'])).toThrow(/plain object/i);
      expect(() => ashExtractScopedFields([] as any, ['field'])).toThrow(/plain object/i);
    });
  });

  describe('Scope Normalization', () => {
    it('sorts scope fields alphabetically', () => {
      const result = ashNormalizeScopeFields(['z', 'a', 'm']);
      expect(result).toEqual(['a', 'm', 'z']);
    });

    it('deduplicates scope fields', () => {
      const result = ashNormalizeScopeFields(['a', 'b', 'a', 'c', 'b']);
      expect(result).toEqual(['a', 'b', 'c']);
    });

    it('sorts and deduplicates together', () => {
      const result = ashNormalizeScopeFields(['z', 'a', 'z', 'a']);
      expect(result).toEqual(['a', 'z']);
    });

    it('uses byte-wise sorting for Unicode', () => {
      const result = ashNormalizeScopeFields(['β', 'α']);
      expect(result).toEqual(['α', 'β']);
    });

    it('handles empty scope array', () => {
      const result = ashNormalizeScopeFields([]);
      expect(result).toEqual([]);
    });
  });

  describe('Scope Validation', () => {
    it('accepts valid scope fields', () => {
      expect(() => ashValidateScopeFields(['field1', 'field2'])).not.toThrow();
    });

    it('rejects empty field name', () => {
      expect(() => ashValidateScopeFields(['field', ''])).toThrow(/empty/i);
    });

    it('rejects field name exceeding max length', () => {
      const longField = 'a'.repeat(MAX_SCOPE_FIELD_NAME_LENGTH + 1);
      expect(() => ashValidateScopeFields([longField])).toThrow(/exceeds/i);
    });

    it('accepts field at max length', () => {
      const maxField = 'a'.repeat(MAX_SCOPE_FIELD_NAME_LENGTH);
      expect(() => ashValidateScopeFields([maxField])).not.toThrow();
    });

    it('rejects too many scope fields', () => {
      const fields = Array(MAX_SCOPE_FIELDS + 1).fill('field');
      expect(() => ashValidateScopeFields(fields)).toThrow(/maximum/i);
    });

    it('accepts scope at max field count', () => {
      const fields = Array(MAX_SCOPE_FIELDS).fill('a');
      expect(() => ashValidateScopeFields(fields)).not.toThrow();
    });

    it('rejects field containing delimiter', () => {
      expect(() => ashValidateScopeFields([`field${SCOPE_FIELD_DELIMITER}name`])).toThrow(/delimiter/i);
    });
  });

  describe('Scope Joining', () => {
    it('joins with unit separator', () => {
      const result = ashJoinScopeFields(['a', 'b', 'c']);
      expect(result).toBe(`a${SCOPE_FIELD_DELIMITER}b${SCOPE_FIELD_DELIMITER}c`);
    });

    it('normalizes before joining', () => {
      const result = ashJoinScopeFields(['c', 'a', 'b']);
      expect(result).toBe(`a${SCOPE_FIELD_DELIMITER}b${SCOPE_FIELD_DELIMITER}c`);
    });

    it('deduplicates before joining', () => {
      const result = ashJoinScopeFields(['a', 'a', 'b']);
      expect(result).toBe(`a${SCOPE_FIELD_DELIMITER}b`);
    });

    it('handles single field', () => {
      const result = ashJoinScopeFields(['field']);
      expect(result).toBe('field');
    });

    it('validates during join', () => {
      expect(() => ashJoinScopeFields([''])).toThrow(/empty/i);
    });
  });

  describe('Scope Hashing', () => {
    it('returns empty string for empty scope', () => {
      expect(ashHashScope([])).toBe('');
    });

    it('produces consistent hash for same scope', () => {
      const scope = ['field1', 'field2'];
      const hash1 = ashHashScope(scope);
      const hash2 = ashHashScope(scope);
      expect(hash1).toBe(hash2);
    });

    it('produces same hash regardless of input order', () => {
      const hash1 = ashHashScope(['b', 'a']);
      const hash2 = ashHashScope(['a', 'b']);
      expect(hash1).toBe(hash2);
    });

    it('produces different hash for different scope', () => {
      const hash1 = ashHashScope(['field1']);
      const hash2 = ashHashScope(['field2']);
      expect(hash1).not.toBe(hash2);
    });

    it('returns 64-char hex hash', () => {
      const hash = ashHashScope(['field']);
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('Scoped Body Hashing', () => {
    it('hashes only scoped fields', () => {
      const payload = { a: 1, b: 2, c: 3 };
      const scopedHash = ashHashScopedBody(payload, ['a']);
      const fullHash = ashHashBody(JSON.stringify(payload));
      expect(scopedHash).not.toBe(fullHash);
    });

    it('produces consistent hash for same scope', () => {
      const payload = { a: 1, b: 2 };
      const hash1 = ashHashScopedBody(payload, ['a']);
      const hash2 = ashHashScopedBody(payload, ['a']);
      expect(hash1).toBe(hash2);
    });

    it('hash is independent of scope order', () => {
      const payload = { a: 1, b: 2 };
      const hash1 = ashHashScopedBody(payload, ['b', 'a']);
      const hash2 = ashHashScopedBody(payload, ['a', 'b']);
      expect(hash1).toBe(hash2);
    });

    it('strict mode throws for missing field', () => {
      const payload = { a: 1 };
      expect(() => ashHashScopedBodyStrict(payload, ['a', 'missing'])).toThrow();
    });
  });

  describe('Scoped Proof Building and Verification', () => {
    it('builds and verifies scoped proof', () => {
      const setup = createProofSetup();
      const payload = { public: 'data', secret: 'hidden' };
      const scope = ['public'];

      const { proof, scopeHash } = ashBuildProofScoped(
        setup.clientSecret,
        setup.timestamp,
        setup.binding,
        payload,
        scope
      );

      const result = ashVerifyProofScoped(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        payload,
        scope,
        scopeHash,
        proof
      );
      expect(result).toBe(true);
    });

    it('rejects proof with wrong scope', () => {
      const setup = createProofSetup();
      const payload = { a: 1, b: 2 };

      const { proof, scopeHash } = ashBuildProofScoped(
        setup.clientSecret,
        setup.timestamp,
        setup.binding,
        payload,
        ['a']
      );

      // Verify with different scope
      const result = ashVerifyProofScoped(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        payload,
        ['b'], // Different scope
        scopeHash,
        proof
      );
      expect(result).toBe(false);
    });

    it('rejects proof with wrong scope hash', () => {
      const setup = createProofSetup();
      const payload = { a: 1 };
      const scope = ['a'];

      const { proof } = ashBuildProofScoped(
        setup.clientSecret,
        setup.timestamp,
        setup.binding,
        payload,
        scope
      );

      const wrongScopeHash = '0'.repeat(64);

      const result = ashVerifyProofScoped(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        payload,
        scope,
        wrongScopeHash,
        proof
      );
      expect(result).toBe(false);
    });

    it('rejects empty scope with non-empty scope hash', () => {
      const setup = createProofSetup();
      const payload = { a: 1 };

      const { proof } = ashBuildProofScoped(
        setup.clientSecret,
        setup.timestamp,
        setup.binding,
        payload,
        []
      );

      const result = ashVerifyProofScoped(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        payload,
        [],
        '0'.repeat(64), // Non-empty hash with empty scope
        proof
      );
      expect(result).toBe(false);
    });

    it('rejects non-empty scope with empty scope hash', () => {
      const setup = createProofSetup();
      const payload = { a: 1 };
      const scope = ['a'];

      const { proof } = ashBuildProofScoped(
        setup.clientSecret,
        setup.timestamp,
        setup.binding,
        payload,
        scope
      );

      const result = ashVerifyProofScoped(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        payload,
        scope,
        '', // Empty hash with non-empty scope
        proof
      );
      expect(result).toBe(false);
    });
  });

  describe('Chain Hashing', () => {
    it('hashes proof for chaining', () => {
      const proof = 'a'.repeat(64);
      const hash = ashHashProof(proof);
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('produces consistent chain hash', () => {
      const proof = 'abc123';
      const hash1 = ashHashProof(proof);
      const hash2 = ashHashProof(proof);
      expect(hash1).toBe(hash2);
    });

    it('produces different hash for different proofs', () => {
      const hash1 = ashHashProof('proof1');
      const hash2 = ashHashProof('proof2');
      expect(hash1).not.toBe(hash2);
    });

    it('rejects empty proof for chain hashing', () => {
      expect(() => ashHashProof('')).toThrow(/empty/i);
    });
  });

  describe('Unified Proof - Basic', () => {
    it('builds unified proof without scoping or chaining', () => {
      const setup = createProofSetup();
      const payload = { data: 'value' };

      const { proof, scopeHash, chainHash } = ashBuildProofUnified(
        setup.clientSecret,
        setup.timestamp,
        setup.binding,
        payload
      );

      expect(proof).toMatch(/^[0-9a-f]{64}$/);
      expect(scopeHash).toBe('');
      expect(chainHash).toBe('');
    });

    it('builds unified proof with scoping only', () => {
      const setup = createProofSetup();
      const payload = { a: 1, b: 2 };

      const { proof, scopeHash, chainHash } = ashBuildProofUnified(
        setup.clientSecret,
        setup.timestamp,
        setup.binding,
        payload,
        ['a']
      );

      expect(proof).toMatch(/^[0-9a-f]{64}$/);
      expect(scopeHash).toMatch(/^[0-9a-f]{64}$/);
      expect(chainHash).toBe('');
    });

    it('builds unified proof with chaining only', () => {
      const setup = createProofSetup();
      const payload = { data: 'value' };
      const previousProof = 'p'.repeat(64);

      const { proof, scopeHash, chainHash } = ashBuildProofUnified(
        setup.clientSecret,
        setup.timestamp,
        setup.binding,
        payload,
        [],
        previousProof
      );

      expect(proof).toMatch(/^[0-9a-f]{64}$/);
      expect(scopeHash).toBe('');
      expect(chainHash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('builds unified proof with both scoping and chaining', () => {
      const setup = createProofSetup();
      const payload = { a: 1, b: 2 };
      const previousProof = 'p'.repeat(64);

      const { proof, scopeHash, chainHash } = ashBuildProofUnified(
        setup.clientSecret,
        setup.timestamp,
        setup.binding,
        payload,
        ['a'],
        previousProof
      );

      expect(proof).toMatch(/^[0-9a-f]{64}$/);
      expect(scopeHash).toMatch(/^[0-9a-f]{64}$/);
      expect(chainHash).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('Unified Proof - Verification', () => {
    it('verifies unified proof without scoping or chaining', () => {
      const setup = createProofSetup();
      const payload = { data: 'value' };

      const { proof } = ashBuildProofUnified(
        setup.clientSecret,
        setup.timestamp,
        setup.binding,
        payload
      );

      const result = ashVerifyProofUnified(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        payload,
        proof
      );
      expect(result).toBe(true);
    });

    it('verifies unified proof with scoping', () => {
      const setup = createProofSetup();
      const payload = { a: 1, b: 2 };
      const scope = ['a'];

      const { proof, scopeHash } = ashBuildProofUnified(
        setup.clientSecret,
        setup.timestamp,
        setup.binding,
        payload,
        scope
      );

      const result = ashVerifyProofUnified(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        payload,
        proof,
        scope,
        scopeHash
      );
      expect(result).toBe(true);
    });

    it('verifies unified proof with chaining', () => {
      const setup = createProofSetup();
      const payload = { data: 'value' };
      const previousProof = 'p'.repeat(64);

      const { proof, chainHash } = ashBuildProofUnified(
        setup.clientSecret,
        setup.timestamp,
        setup.binding,
        payload,
        [],
        previousProof
      );

      const result = ashVerifyProofUnified(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        payload,
        proof,
        [],
        '',
        previousProof,
        chainHash
      );
      expect(result).toBe(true);
    });

    it('verifies unified proof with both scoping and chaining', () => {
      const setup = createProofSetup();
      const payload = { a: 1, b: 2 };
      const scope = ['a'];
      const previousProof = 'p'.repeat(64);

      const { proof, scopeHash, chainHash } = ashBuildProofUnified(
        setup.clientSecret,
        setup.timestamp,
        setup.binding,
        payload,
        scope,
        previousProof
      );

      const result = ashVerifyProofUnified(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        payload,
        proof,
        scope,
        scopeHash,
        previousProof,
        chainHash
      );
      expect(result).toBe(true);
    });
  });

  describe('Unified Proof - Error Cases', () => {
    it('rejects invalid proof format', () => {
      const setup = createProofSetup();
      const payload = { data: 'value' };

      const result = ashVerifyProofUnified(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        payload,
        'invalid'
      );
      expect(result).toBe(false);
    });

    it('rejects wrong chain hash', () => {
      const setup = createProofSetup();
      const payload = { data: 'value' };
      const previousProof = 'p'.repeat(64);

      const { proof } = ashBuildProofUnified(
        setup.clientSecret,
        setup.timestamp,
        setup.binding,
        payload,
        [],
        previousProof
      );

      const wrongChainHash = '0'.repeat(64);

      const result = ashVerifyProofUnified(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        payload,
        proof,
        [],
        '',
        previousProof,
        wrongChainHash
      );
      expect(result).toBe(false);
    });

    it('rejects chain hash without previous proof', () => {
      const setup = createProofSetup();
      const payload = { data: 'value' };

      const { proof } = ashBuildProofUnified(
        setup.clientSecret,
        setup.timestamp,
        setup.binding,
        payload
      );

      const result = ashVerifyProofUnified(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        payload,
        proof,
        [],
        '',
        null,
        '0'.repeat(64) // Chain hash without previous proof
      );
      expect(result).toBe(false);
    });
  });

  describe('Request Chain Workflow', () => {
    it('builds and verifies a chain of 3 requests', () => {
      const setup = createProofSetup();

      // Request 1 - no previous proof
      const payload1 = { step: 1 };
      const result1 = ashBuildProofUnified(
        setup.clientSecret,
        setup.timestamp,
        setup.binding,
        payload1
      );

      expect(ashVerifyProofUnified(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        payload1,
        result1.proof
      )).toBe(true);

      // Request 2 - chained to request 1
      const payload2 = { step: 2 };
      const ts2 = (parseInt(setup.timestamp) + 1).toString();
      const result2 = ashBuildProofUnified(
        setup.clientSecret,
        ts2,
        setup.binding,
        payload2,
        [],
        result1.proof
      );

      expect(ashVerifyProofUnified(
        setup.nonce,
        setup.contextId,
        setup.binding,
        ts2,
        payload2,
        result2.proof,
        [],
        '',
        result1.proof,
        result2.chainHash
      )).toBe(true);

      // Request 3 - chained to request 2
      const payload3 = { step: 3 };
      const ts3 = (parseInt(setup.timestamp) + 2).toString();
      const result3 = ashBuildProofUnified(
        setup.clientSecret,
        ts3,
        setup.binding,
        payload3,
        [],
        result2.proof
      );

      expect(ashVerifyProofUnified(
        setup.nonce,
        setup.contextId,
        setup.binding,
        ts3,
        payload3,
        result3.proof,
        [],
        '',
        result2.proof,
        result3.chainHash
      )).toBe(true);
    });

    it('detects broken chain', () => {
      const setup = createProofSetup();

      // Request 1
      const payload1 = { step: 1 };
      const result1 = ashBuildProofUnified(
        setup.clientSecret,
        setup.timestamp,
        setup.binding,
        payload1
      );

      // Request 2 with wrong previous proof
      const payload2 = { step: 2 };
      const ts2 = (parseInt(setup.timestamp) + 1).toString();
      const result2 = ashBuildProofUnified(
        setup.clientSecret,
        ts2,
        setup.binding,
        payload2,
        [],
        result1.proof
      );

      // Verify with different previous proof
      const wrongPrevProof = '0'.repeat(64);
      const result = ashVerifyProofUnified(
        setup.nonce,
        setup.contextId,
        setup.binding,
        ts2,
        payload2,
        result2.proof,
        [],
        '',
        wrongPrevProof, // Wrong previous proof
        result2.chainHash
      );
      expect(result).toBe(false);
    });
  });

  describe('Scoped Chain Workflow', () => {
    it('builds chain with scoped proofs', () => {
      const setup = createProofSetup();

      // Request 1 with scope
      const payload1 = { public: 'data1', private: 'secret1' };
      const scope1 = ['public'];
      const result1 = ashBuildProofUnified(
        setup.clientSecret,
        setup.timestamp,
        setup.binding,
        payload1,
        scope1
      );

      expect(ashVerifyProofUnified(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        payload1,
        result1.proof,
        scope1,
        result1.scopeHash
      )).toBe(true);

      // Request 2 with different scope, chained
      const payload2 = { public: 'data2', private: 'secret2' };
      const scope2 = ['private'];
      const ts2 = (parseInt(setup.timestamp) + 1).toString();
      const result2 = ashBuildProofUnified(
        setup.clientSecret,
        ts2,
        setup.binding,
        payload2,
        scope2,
        result1.proof
      );

      expect(ashVerifyProofUnified(
        setup.nonce,
        setup.contextId,
        setup.binding,
        ts2,
        payload2,
        result2.proof,
        scope2,
        result2.scopeHash,
        result1.proof,
        result2.chainHash
      )).toBe(true);
    });
  });
});
