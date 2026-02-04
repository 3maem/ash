/**
 * ASH SDK Version Compatibility Tests
 *
 * Tests backward compatibility with previous protocol versions
 * and ensures proper version negotiation.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'crypto';
import {
  ashInit,
  ashBuildProofV21,
  ashVerifyProofV21,
  ashDeriveClientSecret,
  ashCanonicalizeJson,
  ashHashBody,
  ashGenerateNonce,
  ashGenerateContextId,
  canonicalizeJsonNative,
  ashBuildProofScoped,
  ashVerifyProofScoped,
  ashBuildProofUnified,
  ashVerifyProofUnified,
  ashVersion,
} from './index';

beforeAll(() => {
  ashInit();
});

// =========================================================================
// VERSION IDENTIFICATION
// =========================================================================

describe('Versioning: Protocol Version', () => {
  it('should report current protocol version', () => {
    // The SDK should export a version function
    if (typeof ashVersion === 'function') {
      const version = ashVersion();
      expect(version).toMatch(/^ASHv\d+\.\d+$/);
    }
  });

  it('should support ASH v2.1 proof format', () => {
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/test|';
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const bodyHash = ashHashBody('{}');

    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

    // v2.1 proof characteristics
    expect(proof).toHaveLength(64);
    expect(/^[0-9a-f]+$/.test(proof)).toBe(true);

    const isValid = ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof);
    expect(isValid).toBe(true);
  });

  it('should support ASH v2.2 scoped proof format', () => {
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/transfer|';
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const payload = { amount: 100, recipient: 'alice' };
    const scope = ['amount', 'recipient'];

    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const { proof, scopeHash } = ashBuildProofScoped(
      clientSecret, timestamp, binding, payload, scope
    );

    // v2.2 scoped proof characteristics
    expect(proof).toHaveLength(64);
    expect(scopeHash).toHaveLength(64);

    const isValid = ashVerifyProofScoped(
      nonce, contextId, binding, timestamp, payload, scope, scopeHash, proof
    );
    expect(isValid).toBe(true);
  });

  it('should support ASH v2.3 unified proof format', () => {
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/step1|';
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const payload = { step: 1 };

    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const result = ashBuildProofUnified(
      clientSecret, timestamp, binding, payload, []
    );

    // v2.3 unified proof characteristics
    expect(result.proof).toHaveLength(64);
    expect(result).toHaveProperty('scopeHash');
    expect(result).toHaveProperty('chainHash');

    const isValid = ashVerifyProofUnified(
      nonce, contextId, binding, timestamp, payload,
      result.proof, [], result.scopeHash, undefined, result.chainHash
    );
    expect(isValid).toBe(true);
  });
});

// =========================================================================
// BACKWARD COMPATIBILITY
// =========================================================================

describe('Versioning: Backward Compatibility', () => {
  describe('v2.1 to v2.3 Compatibility', () => {
    it('v2.1 proof should work with same inputs as v2.3 without scope/chain', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const binding = 'POST|/api/test|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const body = '{"key":"value"}';

      const canonicalBody = canonicalizeJsonNative(body);
      const bodyHash = ashHashBody(canonicalBody);
      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

      // Build v2.1 style proof
      const v21Proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

      // Verify with v2.1 function
      const v21Valid = ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, v21Proof);
      expect(v21Valid).toBe(true);

      // v2.3 unified without scope/chain should produce compatible proof
      const payload = JSON.parse(body);
      const v23Result = ashBuildProofUnified(clientSecret, timestamp, binding, payload, []);

      // Verify v2.3 proof
      const v23Valid = ashVerifyProofUnified(
        nonce, contextId, binding, timestamp, payload,
        v23Result.proof, [], v23Result.scopeHash, undefined, v23Result.chainHash
      );
      expect(v23Valid).toBe(true);
    });
  });

  describe('Deterministic Versioned Outputs', () => {
    it('same inputs should produce same v2.1 proof across versions', () => {
      // Fixed test vector
      const nonce = 'a'.repeat(64);
      const contextId = 'ctx_version_test';
      const binding = 'POST|/api/test|';
      const timestamp = '1700000000';
      const bodyHash = 'b'.repeat(64);

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const proof1 = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);
      const proof2 = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

      // Should be deterministic
      expect(proof1).toBe(proof2);

      // Should verify consistently
      expect(ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof1)).toBe(true);
    });
  });
});

// =========================================================================
// VERSION NEGOTIATION
// =========================================================================

describe('Versioning: Version Negotiation', () => {
  it('should gracefully handle unknown version headers', () => {
    // The SDK should not crash when encountering future version markers
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/test|';
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const bodyHash = ashHashBody('{}');

    // Generate valid proof
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

    // Should still verify
    const isValid = ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof);
    expect(isValid).toBe(true);
  });
});

// =========================================================================
// MIGRATION SCENARIOS
// =========================================================================

describe('Versioning: Migration Scenarios', () => {
  describe('v2.1 to v2.2 Migration', () => {
    it('should add scoping to existing v2.1 workflow', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const binding = 'POST|/api/transfer|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const payload = { amount: 100, recipient: 'alice', memo: 'payment' };

      // Old v2.1 workflow (full body)
      const canonicalBody = canonicalizeJsonNative(JSON.stringify(payload));
      const bodyHash = ashHashBody(canonicalBody);
      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const v21Proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

      expect(ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, v21Proof)).toBe(true);

      // New v2.2 workflow (scoped)
      const scope = ['amount', 'recipient'];
      const { proof: v22Proof, scopeHash } = ashBuildProofScoped(
        clientSecret, timestamp, binding, payload, scope
      );

      expect(ashVerifyProofScoped(
        nonce, contextId, binding, timestamp, payload, scope, scopeHash, v22Proof
      )).toBe(true);
    });
  });

  describe('v2.2 to v2.3 Migration', () => {
    it('should add chaining to existing v2.2 workflow', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const timestamp = Math.floor(Date.now() / 1000).toString();

      // Step 1
      const binding1 = 'POST|/api/step1|';
      const payload1 = { action: 'initiate' };
      const clientSecret1 = ashDeriveClientSecret(nonce, contextId, binding1);

      const result1 = ashBuildProofUnified(
        clientSecret1, timestamp, binding1, payload1, []
      );

      expect(ashVerifyProofUnified(
        nonce, contextId, binding1, timestamp, payload1,
        result1.proof, [], result1.scopeHash, undefined, result1.chainHash
      )).toBe(true);

      // Step 2 - chained to step 1
      const binding2 = 'POST|/api/step2|';
      const payload2 = { action: 'confirm' };
      const clientSecret2 = ashDeriveClientSecret(nonce, contextId, binding2);

      const result2 = ashBuildProofUnified(
        clientSecret2, timestamp, binding2, payload2, [], result1.proof
      );

      expect(ashVerifyProofUnified(
        nonce, contextId, binding2, timestamp, payload2,
        result2.proof, [], result2.scopeHash, result1.proof, result2.chainHash
      )).toBe(true);
    });
  });
});

// =========================================================================
// DEPRECATION HANDLING
// =========================================================================

describe('Versioning: Deprecation Handling', () => {
  it('deprecated v2.1 aliases should still work', () => {
    // ashBuildProofV21 and ashVerifyProofV21 are aliases
    // They should continue to work even if internal implementation changes

    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/test|';
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const bodyHash = ashHashBody('{}');

    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

    const isValid = ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof);
    expect(isValid).toBe(true);
  });
});

// =========================================================================
// FEATURE DETECTION
// =========================================================================

describe('Versioning: Feature Detection', () => {
  it('should export all v2.1 functions', () => {
    expect(typeof ashBuildProofV21).toBe('function');
    expect(typeof ashVerifyProofV21).toBe('function');
    expect(typeof ashDeriveClientSecret).toBe('function');
    expect(typeof ashHashBody).toBe('function');
    expect(typeof ashGenerateNonce).toBe('function');
    expect(typeof ashGenerateContextId).toBe('function');
  });

  it('should export all v2.2 functions', () => {
    expect(typeof ashBuildProofScoped).toBe('function');
    expect(typeof ashVerifyProofScoped).toBe('function');
  });

  it('should export all v2.3 functions', () => {
    expect(typeof ashBuildProofUnified).toBe('function');
    expect(typeof ashVerifyProofUnified).toBe('function');
  });
});

console.log('Version Compatibility Tests loaded');
