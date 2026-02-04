/**
 * ASH Security Assurance Pack - Unit Tests (Node.js)
 * ===================================================
 * A. Unit Tests:
 * - Deterministic signature generation for identical inputs
 * - Verification failure on single-byte mutation
 * - Rejection of missing/invalid headers
 */

import { describe, it, expect } from 'vitest';
import {
  ashCanonicalizeJson,
  ashCanonicalizeUrlencoded,
  ashNormalizeBinding,
  ashTimingSafeEqual,
  ashDeriveClientSecret,
  ashBuildProofV21,
  ashVerifyProofV21,
  ashHashBody,
  ashBuildProof,
} from '../../packages/ash-node/src';

describe('Deterministic Signature Generation', () => {
  it('canonicalizeJson should be deterministic', () => {
    const input = '{"z":1,"a":2,"m":3}';
    const results = Array.from({ length: 100 }, () => ashCanonicalizeJson(input));

    expect(results.every(r => r === results[0])).toBe(true);
    expect(results[0]).toBe('{"a":2,"m":3,"z":1}');
  });

  it('canonicalizeJson should produce same output regardless of key order', () => {
    const input1 = '{"z":1,"a":2}';
    const input2 = '{"a":2,"z":1}';

    const result1 = ashCanonicalizeJson(input1);
    const result2 = ashCanonicalizeJson(input2);

    expect(result1).toBe(result2);
  });

  it('buildProof should be deterministic', () => {
    const proofs = Array.from({ length: 100 }, () =>
      ashBuildProof('balanced', 'POST /api/test', 'ctx_test_123', 'nonce123', '{"amount":100}')
    );

    expect(proofs.every(p => p === proofs[0])).toBe(true);
  });

  it('buildProofV21 should be deterministic', () => {
    const clientSecret = 'a'.repeat(64);
    const timestamp = '1704067200000';
    const binding = 'POST|/api/test|';
    const bodyHash = ashHashBody('{"test":1}');

    const proofs = Array.from({ length: 100 }, () =>
      ashBuildProofV21(clientSecret, timestamp, binding, bodyHash)
    );

    expect(proofs.every(p => p === proofs[0])).toBe(true);
  });

  it('deriveClientSecret should be deterministic', () => {
    const nonce = '0123456789abcdef'.repeat(4);
    const contextId = 'ash_test_ctx';
    const binding = 'POST|/api/test|';

    const secrets = Array.from({ length: 100 }, () =>
      ashDeriveClientSecret(nonce, contextId, binding)
    );

    expect(secrets.every(s => s === secrets[0])).toBe(true);
  });

  it('normalizeBinding should be deterministic', () => {
    const method = 'post';
    const path = '/api//test/';
    const query = 'z=1&a=2';

    const results = Array.from({ length: 100 }, () =>
      ashNormalizeBinding(method, path, query)
    );

    expect(results.every(r => r === results[0])).toBe(true);
  });

  it('hashBody should be deterministic', () => {
    const body = '{"critical":"data"}';
    const hashes = Array.from({ length: 100 }, () => ashHashBody(body));

    expect(hashes.every(h => h === hashes[0])).toBe(true);
  });
});

describe('Single-Byte Mutation Detection', () => {
  it('should detect single byte change in payload', () => {
    const original = '{"amount":100}';
    const mutated = '{"amount":101}';

    const proof1 = ashBuildProof('balanced', 'POST /test', 'ctx1', 'nonce', original);
    const proof2 = ashBuildProof('balanced', 'POST /test', 'ctx1', 'nonce', mutated);

    expect(proof1).not.toBe(proof2);
  });

  it('should detect single character change in key', () => {
    const original = '{"amount":100}';
    const mutated = '{"amounT":100}';

    const proof1 = ashBuildProof('balanced', 'POST /test', 'ctx1', 'nonce', original);
    const proof2 = ashBuildProof('balanced', 'POST /test', 'ctx1', 'nonce', mutated);

    expect(proof1).not.toBe(proof2);
  });

  it('should detect field addition', () => {
    const original = '{"a":1}';
    const mutated = '{"a":1,"b":2}';

    const canon1 = ashCanonicalizeJson(original);
    const canon2 = ashCanonicalizeJson(mutated);

    expect(canon1).not.toBe(canon2);
  });

  it('should detect single byte change in context ID', () => {
    const proof1 = ashBuildProof('balanced', 'POST /test', 'ctx_abc123', 'nonce', '{}');
    const proof2 = ashBuildProof('balanced', 'POST /test', 'ctx_abc124', 'nonce', '{}');

    expect(proof1).not.toBe(proof2);
  });

  it('should detect single byte change in binding', () => {
    const proof1 = ashBuildProof('balanced', 'POST /api', 'ctx1', 'nonce', '{}');
    const proof2 = ashBuildProof('balanced', 'POST /apj', 'ctx1', 'nonce', '{}');

    expect(proof1).not.toBe(proof2);
  });

  it('v21 verification should detect body hash mutation', () => {
    const nonce = 'a'.repeat(64);
    const contextId = 'ash_test';
    const binding = 'POST|/api|';
    const timestamp = '1704067200000';

    const bodyHash1 = ashHashBody('{"amount":100}');
    const bodyHash2 = ashHashBody('{"amount":101}');

    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash1);

    // Verify with correct hash should pass
    expect(ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash1, proof)).toBe(true);

    // Verify with mutated hash should fail
    expect(ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash2, proof)).toBe(false);
  });
});

describe('Missing/Invalid Header Rejection', () => {
  it('empty context ID should produce different proof', () => {
    const proofValid = ashBuildProof('balanced', 'POST /test', 'valid_ctx', 'nonce', '{}');
    const proofEmpty = ashBuildProof('balanced', 'POST /test', '', 'nonce', '{}');

    expect(proofValid).not.toBe(proofEmpty);
  });

  it('empty binding should produce different proof', () => {
    const proofValid = ashBuildProof('balanced', 'POST /test', 'ctx1', 'nonce', '{}');
    const proofEmpty = ashBuildProof('balanced', '', 'ctx1', 'nonce', '{}');

    expect(proofValid).not.toBe(proofEmpty);
  });

  it('different modes should produce different proofs', () => {
    const proofBalanced = ashBuildProof('balanced', 'POST /test', 'ctx1', 'nonce', '{}');
    const proofMinimal = ashBuildProof('minimal', 'POST /test', 'ctx1', 'nonce', '{}');
    const proofStrict = ashBuildProof('strict', 'POST /test', 'ctx1', 'nonce', '{}');

    expect(proofBalanced).not.toBe(proofMinimal);
    expect(proofBalanced).not.toBe(proofStrict);
    expect(proofMinimal).not.toBe(proofStrict);
  });

  it('empty timestamp should produce different v21 proof', () => {
    const clientSecret = 'a'.repeat(64);
    const binding = 'POST|/api|';
    const bodyHash = ashHashBody('{}');

    const proofValid = ashBuildProofV21(clientSecret, '1704067200000', binding, bodyHash);
    const proofEmpty = ashBuildProofV21(clientSecret, '', binding, bodyHash);

    expect(proofValid).not.toBe(proofEmpty);
  });

  it('wrong nonce should fail v21 verification', () => {
    const nonceCorrect = 'a'.repeat(64);
    const nonceWrong = 'b'.repeat(64);
    const contextId = 'ash_test';
    const binding = 'POST|/api|';
    const timestamp = '1704067200000';
    const bodyHash = ashHashBody('{}');

    const clientSecret = ashDeriveClientSecret(nonceCorrect, contextId, binding);
    const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

    // Correct nonce should verify
    expect(ashVerifyProofV21(nonceCorrect, contextId, binding, timestamp, bodyHash, proof)).toBe(true);

    // Wrong nonce should fail
    expect(ashVerifyProofV21(nonceWrong, contextId, binding, timestamp, bodyHash, proof)).toBe(false);
  });
});

describe('Canonicalization Consistency', () => {
  it('should apply Unicode NFC normalization', () => {
    // e\u0301 as single char vs e + combining accent
    const input1 = '{"caf\u00e9":1}';  // e with acute as single codepoint
    const input2 = '{"cafe\u0301":1}'; // e + combining acute accent

    const canon1 = ashCanonicalizeJson(input1);
    const canon2 = ashCanonicalizeJson(input2);

    expect(canon1).toBe(canon2);
  });

  it('should normalize negative zero to positive zero', () => {
    const result = ashCanonicalizeJson('{"value":-0}');
    expect(result).toBe('{"value":0}');
  });

  it('should sort nested object keys at all levels', () => {
    const input = '{"z":{"z":1,"a":2},"a":{"z":3,"a":4}}';
    const result = ashCanonicalizeJson(input);
    const expected = '{"a":{"a":4,"z":3},"z":{"a":2,"z":1}}';

    expect(result).toBe(expected);
  });

  it('should preserve array order', () => {
    const result = ashCanonicalizeJson('{"arr":[3,1,2]}');
    expect(result).toContain('"arr":[3,1,2]');
  });

  it('should properly escape special characters', () => {
    const input = '{"text":"line1\\nline2\\ttab\\"quote\\\\backslash"}';
    const result = ashCanonicalizeJson(input);

    expect(result).toContain('\\n');
    expect(result).toContain('\\t');
    expect(result).toContain('\\"');
    expect(result).toContain('\\\\');
  });

  it('should sort URL-encoded data by key', () => {
    const result = ashCanonicalizeUrlencoded('z=1&a=2&m=3');
    expect(result).toBe('a=2&m=3&z=1');
  });

  it('should use uppercase hex in percent encoding', () => {
    const result = ashCanonicalizeUrlencoded('key=hello%20world');
    expect(result).toContain('%20');
    // Should not contain lowercase hex in percent encoding
    const lowercaseHex = /%[0-9A-Fa-f][a-f]|%[a-f][0-9A-Fa-f]/;
    expect(lowercaseHex.test(result)).toBe(false);
  });
});
