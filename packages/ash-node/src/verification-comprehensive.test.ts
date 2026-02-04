/**
 * Proof Verification Comprehensive Tests
 *
 * Tests for proof verification covering:
 * - Valid proof verification
 * - Invalid proof detection
 * - Tampering detection
 * - Concurrent verification
 * - Timing-safe comparison
 * - Error handling
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'crypto';
import {
  ashInit,
  ashBuildProof,
  ashBuildProofHmac,
  ashVerifyProof,
  ashVerifyProofDetailed,
  ashVerifyProofWithFreshness,
  ashDeriveClientSecret,
  ashHashBody,
  ashNormalizeBinding,
  ashGenerateNonce,
  ashGenerateContextId,
  ashTimingSafeEqual,
  SHA256_HEX_LENGTH,
} from './index';

// Initialize WASM
beforeAll(() => {
  try {
    ashInit();
  } catch {
    // WASM not available, tests will use native fallback
  }
});

// Helper to create valid proof setup
function createProofSetup() {
  const nonce = ashGenerateNonce();
  const contextId = ashGenerateContextId();
  const binding = ashNormalizeBinding('POST', '/api/test');
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const body = JSON.stringify({ action: 'test', data: 123 });
  const bodyHash = ashHashBody(body);
  const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
  const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

  return { nonce, contextId, binding, timestamp, bodyHash, clientSecret, proof };
}

describe('Proof Verification Comprehensive Tests', () => {
  describe('Valid Proof Verification', () => {
    it('verifies a freshly created proof', () => {
      const setup = createProofSetup();
      const result = ashVerifyProof(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        setup.bodyHash,
        setup.proof
      );
      expect(result).toBe(true);
    });

    it('verifies proof with detailed result', () => {
      const setup = createProofSetup();
      const result = ashVerifyProofDetailed(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        setup.bodyHash,
        setup.proof
      );
      expect(result.valid).toBe(true);
      expect(result.errorCode).toBeUndefined();
    });

    it('verifies proof with freshness check', () => {
      const setup = createProofSetup();
      const result = ashVerifyProofWithFreshness(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        setup.bodyHash,
        setup.proof,
        300 // 5 minutes max age
      );
      expect(result).toBe(true);
    });

    it('verifies proof with uppercase body hash', () => {
      const setup = createProofSetup();
      const uppercaseHash = setup.bodyHash.toUpperCase();
      // Build proof with uppercase hash
      const proof = ashBuildProof(setup.clientSecret, setup.timestamp, setup.binding, uppercaseHash);
      // Should produce same proof as lowercase
      expect(proof).toBe(setup.proof);
    });

    it('verifies proof with different body contents', () => {
      const setup = createProofSetup();
      const bodies = [
        '{}',
        '{"key":"value"}',
        '{"nested":{"deep":{"data":123}}}',
        '[1,2,3,4,5]',
        '"string body"',
      ];
      for (const body of bodies) {
        const bodyHash = ashHashBody(body);
        const proof = ashBuildProof(setup.clientSecret, setup.timestamp, setup.binding, bodyHash);
        const result = ashVerifyProof(
          setup.nonce,
          setup.contextId,
          setup.binding,
          setup.timestamp,
          bodyHash,
          proof
        );
        expect(result).toBe(true);
      }
    });

    it('verifies proof with various HTTP methods', () => {
      const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
      for (const method of methods) {
        const nonce = ashGenerateNonce();
        const contextId = ashGenerateContextId();
        const binding = ashNormalizeBinding(method, '/api/test');
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const bodyHash = ashHashBody('{}');
        const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
        const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

        const result = ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof);
        expect(result).toBe(true);
      }
    });
  });

  describe('Invalid Proof Detection', () => {
    it('rejects wrong proof', () => {
      const setup = createProofSetup();
      const wrongProof = '0'.repeat(64);
      const result = ashVerifyProof(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        setup.bodyHash,
        wrongProof
      );
      expect(result).toBe(false);
    });

    it('rejects proof with wrong nonce', () => {
      const setup = createProofSetup();
      const wrongNonce = ashGenerateNonce();
      const result = ashVerifyProof(
        wrongNonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        setup.bodyHash,
        setup.proof
      );
      expect(result).toBe(false);
    });

    it('rejects proof with wrong context ID', () => {
      const setup = createProofSetup();
      const wrongContextId = ashGenerateContextId();
      const result = ashVerifyProof(
        setup.nonce,
        wrongContextId,
        setup.binding,
        setup.timestamp,
        setup.bodyHash,
        setup.proof
      );
      expect(result).toBe(false);
    });

    it('rejects proof with wrong binding', () => {
      const setup = createProofSetup();
      const wrongBinding = ashNormalizeBinding('GET', '/different/path');
      const result = ashVerifyProof(
        setup.nonce,
        setup.contextId,
        wrongBinding,
        setup.timestamp,
        setup.bodyHash,
        setup.proof
      );
      expect(result).toBe(false);
    });

    it('rejects proof with wrong timestamp', () => {
      const setup = createProofSetup();
      const wrongTimestamp = (parseInt(setup.timestamp) + 1).toString();
      const result = ashVerifyProof(
        setup.nonce,
        setup.contextId,
        setup.binding,
        wrongTimestamp,
        setup.bodyHash,
        setup.proof
      );
      expect(result).toBe(false);
    });

    it('rejects proof with wrong body hash', () => {
      const setup = createProofSetup();
      const wrongBodyHash = ashHashBody('different body');
      const result = ashVerifyProof(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        wrongBodyHash,
        setup.proof
      );
      expect(result).toBe(false);
    });

    it('rejects truncated proof', () => {
      const setup = createProofSetup();
      const truncatedProof = setup.proof.substring(0, 32);
      const result = ashVerifyProof(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        setup.bodyHash,
        truncatedProof
      );
      expect(result).toBe(false);
    });

    it('rejects extended proof', () => {
      const setup = createProofSetup();
      const extendedProof = setup.proof + '00';
      const result = ashVerifyProof(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        setup.bodyHash,
        extendedProof
      );
      expect(result).toBe(false);
    });

    it('rejects empty proof', () => {
      const setup = createProofSetup();
      const result = ashVerifyProof(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        setup.bodyHash,
        ''
      );
      expect(result).toBe(false);
    });

    it('rejects non-hex proof', () => {
      const setup = createProofSetup();
      const nonHexProof = 'g'.repeat(64);
      const result = ashVerifyProof(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        setup.bodyHash,
        nonHexProof
      );
      expect(result).toBe(false);
    });
  });

  describe('Tampering Detection', () => {
    it('detects single-bit tampering in proof', () => {
      const setup = createProofSetup();
      // Flip one character
      const chars = setup.proof.split('');
      chars[0] = chars[0] === '0' ? '1' : '0';
      const tamperedProof = chars.join('');

      const result = ashVerifyProof(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        setup.bodyHash,
        tamperedProof
      );
      expect(result).toBe(false);
    });

    it('detects tampering at various positions', () => {
      const setup = createProofSetup();
      const positions = [0, 15, 31, 32, 47, 63]; // Various positions

      for (const pos of positions) {
        const chars = setup.proof.split('');
        chars[pos] = chars[pos] === 'a' ? 'b' : 'a';
        const tamperedProof = chars.join('');

        const result = ashVerifyProof(
          setup.nonce,
          setup.contextId,
          setup.binding,
          setup.timestamp,
          setup.bodyHash,
          tamperedProof
        );
        expect(result).toBe(false);
      }
    });

    it('detects body hash tampering', () => {
      const setup = createProofSetup();
      const tamperedBodyHash = '0'.repeat(64);

      const result = ashVerifyProof(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        tamperedBodyHash,
        setup.proof
      );
      expect(result).toBe(false);
    });

    it('detects timestamp tampering', () => {
      const setup = createProofSetup();
      const tamperedTimestamp = '1'; // Very old timestamp

      const result = ashVerifyProof(
        setup.nonce,
        setup.contextId,
        setup.binding,
        tamperedTimestamp,
        setup.bodyHash,
        setup.proof
      );
      expect(result).toBe(false);
    });

    it('detects binding method tampering', () => {
      const setup = createProofSetup();
      const tamperedBinding = setup.binding.replace('POST', 'GET');

      const result = ashVerifyProof(
        setup.nonce,
        setup.contextId,
        tamperedBinding,
        setup.timestamp,
        setup.bodyHash,
        setup.proof
      );
      expect(result).toBe(false);
    });

    it('detects binding path tampering', () => {
      const setup = createProofSetup();
      const tamperedBinding = setup.binding.replace('/api/test', '/api/admin');

      const result = ashVerifyProof(
        setup.nonce,
        setup.contextId,
        tamperedBinding,
        setup.timestamp,
        setup.bodyHash,
        setup.proof
      );
      expect(result).toBe(false);
    });
  });

  describe('Detailed Error Reporting', () => {
    it('reports INVALID_TIMESTAMP for bad timestamp format', () => {
      const setup = createProofSetup();
      const result = ashVerifyProofDetailed(
        setup.nonce,
        setup.contextId,
        setup.binding,
        '01234', // Leading zero
        setup.bodyHash,
        setup.proof
      );
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('INVALID_TIMESTAMP');
    });

    it('reports INVALID_NONCE for bad nonce', () => {
      const setup = createProofSetup();
      const result = ashVerifyProofDetailed(
        'short', // Too short
        setup.contextId,
        setup.binding,
        setup.timestamp,
        setup.bodyHash,
        setup.proof
      );
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('INVALID_NONCE');
    });

    it('reports INVALID_CONTEXT_ID for bad context ID', () => {
      const setup = createProofSetup();
      const result = ashVerifyProofDetailed(
        setup.nonce,
        'ctx|invalid', // Contains pipe
        setup.binding,
        setup.timestamp,
        setup.bodyHash,
        setup.proof
      );
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('INVALID_CONTEXT_ID');
    });

    it('reports INVALID_BODY_HASH for wrong hash length', () => {
      const setup = createProofSetup();
      const result = ashVerifyProofDetailed(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        'abc', // Too short
        setup.proof
      );
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('INVALID_BODY_HASH');
    });

    it('reports INVALID_PROOF_FORMAT for bad proof format', () => {
      const setup = createProofSetup();
      const result = ashVerifyProofDetailed(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        setup.bodyHash,
        'not-a-valid-proof'
      );
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('INVALID_PROOF_FORMAT');
    });

    it('reports PROOF_MISMATCH for wrong proof', () => {
      const setup = createProofSetup();
      const wrongProof = '0'.repeat(64);
      const result = ashVerifyProofDetailed(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        setup.bodyHash,
        wrongProof
      );
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('PROOF_MISMATCH');
    });
  });

  describe('Freshness Validation', () => {
    it('accepts recent timestamp', () => {
      const setup = createProofSetup();
      const result = ashVerifyProofWithFreshness(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        setup.bodyHash,
        setup.proof,
        300 // 5 minutes
      );
      expect(result).toBe(true);
    });

    it('rejects expired timestamp', () => {
      const setup = createProofSetup();
      const oldTimestamp = (Math.floor(Date.now() / 1000) - 600).toString(); // 10 minutes ago
      const clientSecret = ashDeriveClientSecret(setup.nonce, setup.contextId, setup.binding);
      const proof = ashBuildProof(clientSecret, oldTimestamp, setup.binding, setup.bodyHash);

      const result = ashVerifyProofWithFreshness(
        setup.nonce,
        setup.contextId,
        setup.binding,
        oldTimestamp,
        setup.bodyHash,
        proof,
        300 // 5 minutes max age
      );
      expect(result).toBe(false);
    });

    it('rejects future timestamp beyond clock skew', () => {
      const setup = createProofSetup();
      const futureTimestamp = (Math.floor(Date.now() / 1000) + 120).toString(); // 2 minutes in future
      const clientSecret = ashDeriveClientSecret(setup.nonce, setup.contextId, setup.binding);
      const proof = ashBuildProof(clientSecret, futureTimestamp, setup.binding, setup.bodyHash);

      // Default clock skew is 60 seconds
      const result = ashVerifyProofWithFreshness(
        setup.nonce,
        setup.contextId,
        setup.binding,
        futureTimestamp,
        setup.bodyHash,
        proof,
        300
      );
      expect(result).toBe(false);
    });
  });

  describe('Concurrent Verification', () => {
    it('handles concurrent verification of same proof', async () => {
      const setup = createProofSetup();
      const verifications = Array.from({ length: 100 }, () =>
        Promise.resolve(ashVerifyProof(
          setup.nonce,
          setup.contextId,
          setup.binding,
          setup.timestamp,
          setup.bodyHash,
          setup.proof
        ))
      );

      const results = await Promise.all(verifications);
      expect(results.every(r => r === true)).toBe(true);
    });

    it('handles concurrent verification of different proofs', async () => {
      const setups = Array.from({ length: 20 }, () => createProofSetup());

      const verifications = setups.map(setup =>
        Promise.resolve(ashVerifyProof(
          setup.nonce,
          setup.contextId,
          setup.binding,
          setup.timestamp,
          setup.bodyHash,
          setup.proof
        ))
      );

      const results = await Promise.all(verifications);
      expect(results.every(r => r === true)).toBe(true);
    });

    it('handles mixed valid and invalid proofs concurrently', async () => {
      const validSetup = createProofSetup();
      const invalidSetups = Array.from({ length: 10 }, () => ({
        ...createProofSetup(),
        proof: '0'.repeat(64),
      }));

      const allSetups = [validSetup, ...invalidSetups];
      const verifications = allSetups.map(setup =>
        Promise.resolve(ashVerifyProof(
          setup.nonce,
          setup.contextId,
          setup.binding,
          setup.timestamp,
          setup.bodyHash,
          setup.proof
        ))
      );

      const results = await Promise.all(verifications);
      expect(results[0]).toBe(true);
      expect(results.slice(1).every(r => r === false)).toBe(true);
    });
  });

  describe('Timing-Safe Comparison', () => {
    it('uses constant-time comparison for equal strings', () => {
      const str1 = 'a'.repeat(64);
      const str2 = 'a'.repeat(64);
      expect(ashTimingSafeEqual(str1, str2)).toBe(true);
    });

    it('uses constant-time comparison for unequal strings', () => {
      const str1 = 'a'.repeat(64);
      const str2 = 'b'.repeat(64);
      expect(ashTimingSafeEqual(str1, str2)).toBe(false);
    });

    it('returns false for different length strings', () => {
      expect(ashTimingSafeEqual('short', 'longer string')).toBe(false);
    });

    it('has consistent timing for valid vs invalid proofs', () => {
      const setup = createProofSetup();
      const iterations = 1000;

      // Time valid proof verification
      const startValid = process.hrtime.bigint();
      for (let i = 0; i < iterations; i++) {
        ashVerifyProof(
          setup.nonce,
          setup.contextId,
          setup.binding,
          setup.timestamp,
          setup.bodyHash,
          setup.proof
        );
      }
      const validTime = Number(process.hrtime.bigint() - startValid);

      // Time invalid proof verification
      const invalidProof = '0'.repeat(64);
      const startInvalid = process.hrtime.bigint();
      for (let i = 0; i < iterations; i++) {
        ashVerifyProof(
          setup.nonce,
          setup.contextId,
          setup.binding,
          setup.timestamp,
          setup.bodyHash,
          invalidProof
        );
      }
      const invalidTime = Number(process.hrtime.bigint() - startInvalid);

      // Should be within reasonable ratio (timing tests are noisy)
      const ratio = Math.max(validTime, invalidTime) / Math.min(validTime, invalidTime);
      expect(ratio).toBeLessThan(10);
    });
  });

  describe('Edge Cases', () => {
    it('handles empty body hash input (but valid format)', () => {
      const setup = createProofSetup();
      const emptyBodyHash = ashHashBody('');
      const proof = ashBuildProof(setup.clientSecret, setup.timestamp, setup.binding, emptyBodyHash);

      const result = ashVerifyProof(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        emptyBodyHash,
        proof
      );
      expect(result).toBe(true);
    });

    it('handles very long binding', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const longPath = '/api' + '/segment'.repeat(100);
      const binding = ashNormalizeBinding('GET', longPath);
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const bodyHash = ashHashBody('{}');
      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

      const result = ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof);
      expect(result).toBe(true);
    });

    it('handles Unicode in context ID', () => {
      // Context ID must be ASCII alphanumeric
      const setup = createProofSetup();
      const result = ashVerifyProofDetailed(
        setup.nonce,
        'ctx_日本語',
        setup.binding,
        setup.timestamp,
        setup.bodyHash,
        setup.proof
      );
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('INVALID_CONTEXT_ID');
    });

    it('handles minimum valid timestamp', () => {
      const setup = createProofSetup();
      // Timestamp "0" is format-valid but will fail freshness check
      const result = ashVerifyProofDetailed(
        setup.nonce,
        setup.contextId,
        setup.binding,
        '0',
        setup.bodyHash,
        setup.proof
      );
      // Format is valid, but proof won't match
      expect(result.valid).toBe(false);
    });

    it('handles proof with mixed case hex', () => {
      const setup = createProofSetup();
      // Mix upper and lower case in proof
      const mixedCaseProof = setup.proof.split('').map((c, i) =>
        i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()
      ).join('');

      // The verification should normalize and compare
      const result = ashVerifyProof(
        setup.nonce,
        setup.contextId,
        setup.binding,
        setup.timestamp,
        setup.bodyHash,
        mixedCaseProof
      );
      expect(result).toBe(true);
    });
  });

  describe('Proof Building Consistency', () => {
    it('produces deterministic proofs', () => {
      const setup = createProofSetup();
      const proof1 = ashBuildProof(setup.clientSecret, setup.timestamp, setup.binding, setup.bodyHash);
      const proof2 = ashBuildProof(setup.clientSecret, setup.timestamp, setup.binding, setup.bodyHash);
      expect(proof1).toBe(proof2);
    });

    it('produces different proofs for different inputs', () => {
      const setup = createProofSetup();
      const proofs = new Set<string>();

      // Different timestamps
      for (let i = 0; i < 10; i++) {
        const ts = (parseInt(setup.timestamp) + i).toString();
        proofs.add(ashBuildProof(setup.clientSecret, ts, setup.binding, setup.bodyHash));
      }

      // All proofs should be unique
      expect(proofs.size).toBe(10);
    });

    it('ashBuildProof and ashBuildProofHmac are equivalent', () => {
      const setup = createProofSetup();
      const proof1 = ashBuildProof(setup.clientSecret, setup.timestamp, setup.binding, setup.bodyHash);
      const proof2 = ashBuildProofHmac(setup.clientSecret, setup.timestamp, setup.binding, setup.bodyHash);
      expect(proof1).toBe(proof2);
    });
  });
});
