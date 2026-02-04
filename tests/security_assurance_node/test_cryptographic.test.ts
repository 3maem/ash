/**
 * ASH Security Assurance Pack - Cryptographic Tests (Node.js)
 * ============================================================
 * D. Cryptographic Tests:
 * - Constant-time comparison validation
 * - Algorithm strength verification
 * - No exposure of secrets/nonces
 */

import { describe, it, expect } from 'vitest';
import {
  ashTimingSafeEqual,
  ashDeriveClientSecret,
  ashBuildProofV21,
  ashHashBody,
  ashBuildProof,
} from '../../packages/ash-node/src';

describe('Constant-Time Comparison', () => {
  it('equal strings should return true', () => {
    expect(ashTimingSafeEqual('test123', 'test123')).toBe(true);
    expect(ashTimingSafeEqual('a'.repeat(1000), 'a'.repeat(1000))).toBe(true);
    expect(ashTimingSafeEqual('', '')).toBe(true);
  });

  it('unequal strings should return false', () => {
    expect(ashTimingSafeEqual('test123', 'test124')).toBe(false);
    expect(ashTimingSafeEqual('abc', 'abd')).toBe(false);
    expect(ashTimingSafeEqual('short', 'longer')).toBe(false);
  });

  it('different length strings should return false', () => {
    expect(ashTimingSafeEqual('short', 'longer_string')).toBe(false);
    expect(ashTimingSafeEqual('a', 'aa')).toBe(false);
    expect(ashTimingSafeEqual('', 'nonempty')).toBe(false);
  });

  it('should have similar timing for early vs late differences', () => {
    const iterations = 1000;
    const base = 'a'.repeat(64);
    const earlyDiff = 'b' + 'a'.repeat(63);
    const lateDiff = 'a'.repeat(63) + 'b';

    // Measure early difference timing
    const earlyTimes: number[] = [];
    for (let i = 0; i < iterations; i++) {
      const start = process.hrtime.bigint();
      ashTimingSafeEqual(base, earlyDiff);
      earlyTimes.push(Number(process.hrtime.bigint() - start));
    }

    // Measure late difference timing
    const lateTimes: number[] = [];
    for (let i = 0; i < iterations; i++) {
      const start = process.hrtime.bigint();
      ashTimingSafeEqual(base, lateDiff);
      lateTimes.push(Number(process.hrtime.bigint() - start));
    }

    // Calculate medians
    const earlyMedian = earlyTimes.sort((a, b) => a - b)[Math.floor(iterations / 2)];
    const lateMedian = lateTimes.sort((a, b) => a - b)[Math.floor(iterations / 2)];

    // The ratio should be small for constant-time comparison
    const ratio = Math.max(earlyMedian, lateMedian) / Math.min(earlyMedian, lateMedian);

    // Allow up to 3x variance due to system noise
    expect(ratio).toBeLessThan(3.0);
  });

  it('should have similar timing for equal vs unequal strings', () => {
    const iterations = 1000;
    const str1 = 'a'.repeat(64);
    const str2Equal = 'a'.repeat(64);
    const str2Unequal = 'b'.repeat(64);

    // Measure equal comparison timing
    const equalTimes: number[] = [];
    for (let i = 0; i < iterations; i++) {
      const start = process.hrtime.bigint();
      ashTimingSafeEqual(str1, str2Equal);
      equalTimes.push(Number(process.hrtime.bigint() - start));
    }

    // Measure unequal comparison timing
    const unequalTimes: number[] = [];
    for (let i = 0; i < iterations; i++) {
      const start = process.hrtime.bigint();
      ashTimingSafeEqual(str1, str2Unequal);
      unequalTimes.push(Number(process.hrtime.bigint() - start));
    }

    // Calculate medians
    const equalMedian = equalTimes.sort((a, b) => a - b)[Math.floor(iterations / 2)];
    const unequalMedian = unequalTimes.sort((a, b) => a - b)[Math.floor(iterations / 2)];

    const ratio = Math.max(equalMedian, unequalMedian) / Math.min(equalMedian, unequalMedian);

    expect(ratio).toBeLessThan(3.0);
  });
});

describe('Algorithm Strength', () => {
  it('proof should use SHA-256 (43-44 base64url chars)', () => {
    const proof = ashBuildProof('balanced', 'POST /test', 'ctx123', 'nonce', '{}');

    // Base64URL encoded SHA-256 should be 43 characters (no padding)
    expect(proof.length).toBe(43);
  });

  it('v21 proof should use HMAC-SHA256 (64 hex chars)', () => {
    const clientSecret = 'a'.repeat(64);
    const timestamp = '1704067200000';
    const binding = 'POST|/api/test|';
    const bodyHash = ashHashBody('{}');

    const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

    // HMAC-SHA256 output is 32 bytes = 64 hex chars
    expect(proof.length).toBe(64);
    expect(/^[0-9a-f]+$/.test(proof)).toBe(true);
  });

  it('body hash should use SHA-256 (64 hex chars)', () => {
    const bodyHash = ashHashBody('{"test":"data"}');

    expect(bodyHash.length).toBe(64);
    expect(/^[0-9a-f]+$/.test(bodyHash)).toBe(true);
  });

  it('client secret derivation should use HMAC-SHA256', () => {
    const nonce = '0123456789abcdef'.repeat(4);
    const contextId = 'ash_test';
    const binding = 'POST|/api/test|';

    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

    expect(clientSecret.length).toBe(64);
  });

  it('different inputs should produce different outputs', () => {
    // Test hashBody
    const hash1 = ashHashBody('{"a":1}');
    const hash2 = ashHashBody('{"a":2}');
    expect(hash1).not.toBe(hash2);

    // Test deriveClientSecret
    const secret1 = ashDeriveClientSecret('a'.repeat(64), 'ctx1', 'POST|/a|');
    const secret2 = ashDeriveClientSecret('a'.repeat(64), 'ctx2', 'POST|/a|');
    expect(secret1).not.toBe(secret2);

    // Test buildProofV21
    const proof1 = ashBuildProofV21('a'.repeat(64), '100', 'POST|/a|', hash1);
    const proof2 = ashBuildProofV21('a'.repeat(64), '100', 'POST|/a|', hash2);
    expect(proof1).not.toBe(proof2);
  });

  it('outputs should have high entropy (no obvious patterns)', () => {
    // Generate multiple hashes
    const hashes = Array.from({ length: 100 }, (_, i) => ashHashBody(`{"n":${i}}`));
    const uniqueHashes = new Set(hashes);
    expect(uniqueHashes.size).toBe(100);

    // Check character distribution
    const allChars = hashes.join('');
    const charCounts: Record<string, number> = {};
    for (const c of allChars) {
      charCounts[c] = (charCounts[c] || 0) + 1;
    }

    // Each hex character should appear roughly 6.25% of the time
    const totalChars = allChars.length;
    for (const [char, count] of Object.entries(charCounts)) {
      const percentage = (count / totalChars) * 100;
      expect(percentage).toBeGreaterThan(2);
      expect(percentage).toBeLessThan(12);
    }
  });
});

describe('No Secret Exposure', () => {
  it('nonce should not appear in proof', () => {
    const nonce = 'supersecretnoncevalue1234567890123456789012345678901234';
    const contextId = 'ash_test';
    const binding = 'POST|/api/test|';

    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const bodyHash = ashHashBody('{}');
    const proof = ashBuildProofV21(clientSecret, '1234567890', binding, bodyHash);

    expect(proof).not.toContain(nonce);
    expect(clientSecret).not.toContain(nonce);
  });

  it('client secret should not appear in proof', () => {
    const clientSecret = 'a1b2c3d4e5f6'.repeat(5) + 'ab'; // 64 chars
    const bodyHash = ashHashBody('{}');

    const proof = ashBuildProofV21(clientSecret, '1234567890', 'POST|/api|', bodyHash);

    expect(proof).not.toContain(clientSecret);
  });

  it('input data should not be recoverable from hash', () => {
    const sensitiveData = '{"password":"supersecret123","ssn":"123-45-6789"}';
    const bodyHash = ashHashBody(sensitiveData);

    expect(bodyHash).not.toContain('supersecret');
    expect(bodyHash).not.toContain('123-45-6789');
    expect(bodyHash).not.toContain('password');
  });

  it('v21 proof should include all security-relevant components', () => {
    const clientSecret = 'a'.repeat(64);
    const bodyHash = ashHashBody('{"amount":100}');

    // Same secret, different timestamps = different proofs
    const proof1 = ashBuildProofV21(clientSecret, '1000', 'POST|/api|', bodyHash);
    const proof2 = ashBuildProofV21(clientSecret, '2000', 'POST|/api|', bodyHash);
    expect(proof1).not.toBe(proof2);

    // Same secret, different bindings = different proofs
    const proof3 = ashBuildProofV21(clientSecret, '1000', 'POST|/api/a|', bodyHash);
    const proof4 = ashBuildProofV21(clientSecret, '1000', 'POST|/api/b|', bodyHash);
    expect(proof3).not.toBe(proof4);

    // Same everything, different body = different proofs
    const hash1 = ashHashBody('{"a":1}');
    const hash2 = ashHashBody('{"a":2}');
    const proof5 = ashBuildProofV21(clientSecret, '1000', 'POST|/api|', hash1);
    const proof6 = ashBuildProofV21(clientSecret, '1000', 'POST|/api|', hash2);
    expect(proof5).not.toBe(proof6);
  });
});

describe('Cryptographic Edge Cases', () => {
  it('empty input should produce valid hash', () => {
    const hashEmpty = ashHashBody('');
    expect(hashEmpty.length).toBe(64);
  });

  it('very long inputs should be handled correctly', () => {
    const longInput = '{"data":"' + 'x'.repeat(100000) + '"}';
    const hashLong = ashHashBody(longInput);
    expect(hashLong.length).toBe(64);
  });

  it('unicode inputs should be handled correctly', () => {
    const unicodeInput = '{"emoji":"🎉","chinese":"中文","arabic":"العربية"}';
    const hashUnicode = ashHashBody(unicodeInput);
    expect(hashUnicode.length).toBe(64);
  });

  it('binary-like strings in JSON should be handled', () => {
    const binaryLike = '{"data":"\\u0000\\u0001\\u0002"}';
    const hashResult = ashHashBody(binaryLike);
    expect(hashResult.length).toBe(64);
  });

  it('special JSON values should be hashed correctly', () => {
    const hashNull = ashHashBody('{"value":null}');
    const hashBool = ashHashBody('{"value":true}');
    const hashZero = ashHashBody('{"value":0}');

    expect(hashNull.length).toBe(64);
    expect(hashBool.length).toBe(64);
    expect(hashZero.length).toBe(64);

    // All should be different
    const uniqueHashes = new Set([hashNull, hashBool, hashZero]);
    expect(uniqueHashes.size).toBe(3);
  });
});
