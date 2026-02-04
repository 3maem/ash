/**
 * ASH SDK Property-Based Testing Suite
 *
 * Uses fast-check for property-based testing to discover edge cases.
 * Tests mathematical properties and invariants of the cryptographic system.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as fc from 'fast-check';
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
  canonicalizeJsonNative,
  canonicalQueryNative,
  ashBuildProofScoped,
  ashVerifyProofScoped,
  ashBuildProofUnified,
  ashVerifyProofUnified,
  ashExtractScopedFields,
  ashExtractScopedFieldsStrict,
  normalizeScopeFields,
  joinScopeFields,
  AshMemoryStore,
  ashValidateTimestamp,
  ashTimingSafeEqual,
} from './index';

const PROPERTY_RUNS = 5000;

// Helper arbitraries for fast-check 4.x API
const hexString64 = () =>
  fc.array(fc.integer({ min: 0, max: 15 }), { minLength: 64, maxLength: 64 })
    .map(arr => arr.map(n => n.toString(16)).join(''));

const alphaLowerString = (minLen: number, maxLen: number) =>
  fc.stringMatching(new RegExp(`^[a-z]{${minLen},${maxLen}}$`));

const alphaNumLowerString = (minLen: number, maxLen: number) =>
  fc.stringMatching(new RegExp(`^[a-z0-9]{${minLen},${maxLen}}$`));

const alphaNumUnderscoreString = (minLen: number, maxLen: number) =>
  fc.stringMatching(new RegExp(`^[a-z0-9_]{${minLen},${maxLen}}$`));

beforeAll(() => {
  ashInit();
});

// =========================================================================
// CRYPTOGRAPHIC INVARIANTS
// =========================================================================

describe('PROPERTY: Cryptographic Invariants', () => {
  describe('Hash Function Properties', () => {
    it('determinism: H(x) = H(x) always', () => {
      fc.assert(
        fc.property(fc.string({ maxLength: 10000 }), (input) => {
          const hash1 = ashHashBody(input);
          const hash2 = ashHashBody(input);
          return hash1 === hash2;
        }),
        { numRuns: PROPERTY_RUNS }
      );
    });

    it('fixed output length: |H(x)| = 64 for all x', () => {
      fc.assert(
        fc.property(fc.string({ maxLength: 10000 }), (input) => {
          const hash = ashHashBody(input);
          return hash.length === 64;
        }),
        { numRuns: PROPERTY_RUNS }
      );
    });

    it('hex encoding: H(x) contains only [0-9a-f]', () => {
      fc.assert(
        fc.property(fc.string({ maxLength: 10000 }), (input) => {
          const hash = ashHashBody(input);
          return /^[0-9a-f]{64}$/.test(hash);
        }),
        { numRuns: PROPERTY_RUNS }
      );
    });

    it('avalanche: small change in input causes large change in output', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 10, maxLength: 1000 }),
          fc.integer({ min: 0, max: 9 }),
          (input, pos) => {
            const modified = input.slice(0, pos) +
              String.fromCharCode(input.charCodeAt(pos) ^ 1) +
              input.slice(pos + 1);

            if (input === modified) return true;

            const hash1 = ashHashBody(input);
            const hash2 = ashHashBody(modified);

            // Count differing hex characters
            let diff = 0;
            for (let i = 0; i < 64; i++) {
              if (hash1[i] !== hash2[i]) diff++;
            }

            // At least 30% of characters should differ (avalanche effect)
            return diff >= 19;
          }
        ),
        { numRuns: PROPERTY_RUNS }
      );
    });
  });

  describe('HMAC Properties', () => {
    it('keyed determinism: HMAC(k, m) = HMAC(k, m)', () => {
      fc.assert(
        fc.property(
          hexString64(),
          (nonce) => {
            const contextId = 'ctx_test';
            const binding = 'POST|/api|';
            const timestamp = Math.floor(Date.now() / 1000).toString();
            const bodyHash = crypto.randomBytes(32).toString('hex');

            const secret = ashDeriveClientSecret(nonce, contextId, binding);
            const proof1 = ashBuildProofV21(secret, timestamp, binding, bodyHash);
            const proof2 = ashBuildProofV21(secret, timestamp, binding, bodyHash);

            return proof1 === proof2;
          }
        ),
        { numRuns: PROPERTY_RUNS }
      );
    });

    it('key sensitivity: different key produces different output', () => {
      fc.assert(
        fc.property(
          hexString64(),
          hexString64(),
          (nonce1, nonce2) => {
            if (nonce1 === nonce2) return true;

            const contextId = 'ctx_test';
            const binding = 'POST|/api|';

            const secret1 = ashDeriveClientSecret(nonce1, contextId, binding);
            const secret2 = ashDeriveClientSecret(nonce2, contextId, binding);

            return secret1 !== secret2;
          }
        ),
        { numRuns: PROPERTY_RUNS }
      );
    });
  });
});

// =========================================================================
// CANONICALIZATION PROPERTIES
// =========================================================================

describe('PROPERTY: Canonicalization Invariants', () => {
  describe('JSON Canonicalization', () => {
    it('idempotence: C(C(x)) = C(x)', () => {
      fc.assert(
        fc.property(
          fc.dictionary(
            fc.string({ minLength: 1, maxLength: 10 }),
            fc.oneof(fc.string(), fc.integer(), fc.boolean(), fc.constant(null)),
            { minKeys: 1, maxKeys: 10 }
          ),
          (obj) => {
            const json = JSON.stringify(obj);
            try {
              const c1 = canonicalizeJsonNative(json);
              const c2 = canonicalizeJsonNative(c1);
              return c1 === c2;
            } catch {
              return true;
            }
          }
        ),
        { numRuns: PROPERTY_RUNS }
      );
    });

    it('commutativity of key insertion: C({a, b}) = C({b, a})', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 10 }),
          fc.string({ minLength: 1, maxLength: 10 }),
          fc.string(),
          fc.string(),
          (key1, key2, val1, val2) => {
            if (key1 === key2) return true;

            const obj1: Record<string, string> = {};
            obj1[key1] = val1;
            obj1[key2] = val2;

            const obj2: Record<string, string> = {};
            obj2[key2] = val2;
            obj2[key1] = val1;

            try {
              const c1 = canonicalizeJsonNative(JSON.stringify(obj1));
              const c2 = canonicalizeJsonNative(JSON.stringify(obj2));
              return c1 === c2;
            } catch {
              return true;
            }
          }
        ),
        { numRuns: PROPERTY_RUNS }
      );
    });

    it('preservation: C(x) parses to equivalent object', () => {
      fc.assert(
        fc.property(
          fc.dictionary(
            alphaLowerString(1, 10),
            fc.oneof(fc.string(), fc.integer({ min: -1000, max: 1000 }), fc.boolean(), fc.constant(null)),
            { minKeys: 1, maxKeys: 5 }
          ),
          (obj) => {
            try {
              const canonical = canonicalizeJsonNative(JSON.stringify(obj));
              const parsed = JSON.parse(canonical);

              // Check all keys and values match
              const origKeys = Object.keys(obj).sort();
              const parsedKeys = Object.keys(parsed).sort();

              if (origKeys.length !== parsedKeys.length) return false;

              for (const key of origKeys) {
                if (obj[key] !== parsed[key]) return false;
              }

              return true;
            } catch {
              return true;
            }
          }
        ),
        { numRuns: PROPERTY_RUNS }
      );
    });
  });

  describe('Query String Canonicalization', () => {
    it('idempotence: C(C(q)) = C(q)', () => {
      fc.assert(
        fc.property(
          fc.array(
            fc.tuple(
              alphaLowerString(1, 10),
              alphaNumLowerString(0, 20)
            ),
            { maxLength: 5 }
          ),
          (params) => {
            const query = params.map(([k, v]) => `${k}=${v}`).join('&');
            try {
              const c1 = canonicalQueryNative(query);
              const c2 = canonicalQueryNative(c1);
              return c1 === c2;
            } catch {
              return true;
            }
          }
        ),
        { numRuns: PROPERTY_RUNS }
      );
    });

    it('commutativity: C(a&b) = C(b&a)', () => {
      fc.assert(
        fc.property(
          alphaLowerString(1, 10),
          alphaLowerString(1, 10),
          fc.string({ maxLength: 20 }),
          fc.string({ maxLength: 20 }),
          (key1, key2, val1, val2) => {
            const q1 = `${key1}=${encodeURIComponent(val1)}&${key2}=${encodeURIComponent(val2)}`;
            const q2 = `${key2}=${encodeURIComponent(val2)}&${key1}=${encodeURIComponent(val1)}`;

            try {
              const c1 = canonicalQueryNative(q1);
              const c2 = canonicalQueryNative(q2);
              return c1 === c2;
            } catch {
              return true;
            }
          }
        ),
        { numRuns: PROPERTY_RUNS }
      );
    });

    it('sorted output: keys in canonical form are byte-sorted', () => {
      fc.assert(
        fc.property(
          fc.array(
            fc.tuple(
              alphaLowerString(1, 10),
              fc.string({ maxLength: 20 })
            ),
            { minLength: 2, maxLength: 10 }
          ),
          (params) => {
            const query = params.map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
            try {
              const canonical = canonicalQueryNative(query);
              if (!canonical) return true;

              const pairs = canonical.split('&');
              for (let i = 1; i < pairs.length; i++) {
                const prevKey = pairs[i-1].split('=')[0];
                const currKey = pairs[i].split('=')[0];
                if (Buffer.from(prevKey).compare(Buffer.from(currKey)) > 0) {
                  return false;
                }
              }
              return true;
            } catch {
              return true;
            }
          }
        ),
        { numRuns: PROPERTY_RUNS }
      );
    });
  });
});

// =========================================================================
// PROOF SYSTEM PROPERTIES
// =========================================================================

describe('PROPERTY: Proof System Invariants', () => {
  describe('Soundness', () => {
    it('valid proofs verify: Verify(Build(x)) = true', () => {
      fc.assert(
        fc.property(
          hexString64(),
          alphaNumUnderscoreString(4, 30),
          (nonce, ctxSuffix) => {
            const contextId = `ctx_${ctxSuffix}`;
            const binding = 'POST|/api/test|';
            const timestamp = Math.floor(Date.now() / 1000).toString();
            const bodyHash = crypto.randomBytes(32).toString('hex');

            const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
            const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);
            const isValid = ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof);

            return isValid === true;
          }
        ),
        { numRuns: PROPERTY_RUNS }
      );
    });

    it('invalid proofs fail: Verify(tamper(Build(x))) = false', () => {
      fc.assert(
        fc.property(
          hexString64(),
          fc.integer({ min: 0, max: 63 }),
          (nonce, tamperPos) => {
            const contextId = 'ctx_test';
            const binding = 'POST|/api/test|';
            const timestamp = Math.floor(Date.now() / 1000).toString();
            const bodyHash = crypto.randomBytes(32).toString('hex');

            const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
            const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

            // Tamper with proof
            const chars = proof.split('');
            chars[tamperPos] = chars[tamperPos] === 'a' ? 'b' : 'a';
            const tampered = chars.join('');

            if (tampered === proof) return true;

            const isValid = ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, tampered);
            return isValid === false;
          }
        ),
        { numRuns: PROPERTY_RUNS }
      );
    });
  });

  describe('Non-Malleability', () => {
    it('binding change invalidates proof', () => {
      fc.assert(
        fc.property(
          hexString64(),
          fc.constantFrom('GET', 'POST', 'PUT', 'DELETE'),
          fc.constantFrom('GET', 'POST', 'PUT', 'DELETE'),
          (nonce, method1, method2) => {
            if (method1 === method2) return true;

            const contextId = 'ctx_test';
            const binding1 = `${method1}|/api/test|`;
            const binding2 = `${method2}|/api/test|`;
            const timestamp = Math.floor(Date.now() / 1000).toString();
            const bodyHash = crypto.randomBytes(32).toString('hex');

            const clientSecret = ashDeriveClientSecret(nonce, contextId, binding1);
            const proof = ashBuildProofV21(clientSecret, timestamp, binding1, bodyHash);

            // Try to verify with different binding
            const isValid = ashVerifyProofV21(nonce, contextId, binding2, timestamp, bodyHash, proof);
            return isValid === false;
          }
        ),
        { numRuns: PROPERTY_RUNS }
      );
    });

    it('timestamp change invalidates proof', () => {
      fc.assert(
        fc.property(
          hexString64(),
          fc.integer({ min: 1, max: 100 }),
          (nonce, offset) => {
            const contextId = 'ctx_test';
            const binding = 'POST|/api/test|';
            const now = Math.floor(Date.now() / 1000);
            const timestamp1 = now.toString();
            const timestamp2 = (now + offset).toString();
            const bodyHash = crypto.randomBytes(32).toString('hex');

            const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
            const proof = ashBuildProofV21(clientSecret, timestamp1, binding, bodyHash);

            // Try to verify with different timestamp
            const isValid = ashVerifyProofV21(nonce, contextId, binding, timestamp2, bodyHash, proof);
            return isValid === false;
          }
        ),
        { numRuns: PROPERTY_RUNS }
      );
    });

    it('body change invalidates proof', () => {
      fc.assert(
        fc.property(
          hexString64(),
          hexString64(),
          hexString64(),
          (nonce, bodyHash1, bodyHash2) => {
            if (bodyHash1 === bodyHash2) return true;

            const contextId = 'ctx_test';
            const binding = 'POST|/api/test|';
            const timestamp = Math.floor(Date.now() / 1000).toString();

            const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
            const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash1);

            // Try to verify with different body
            const isValid = ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash2, proof);
            return isValid === false;
          }
        ),
        { numRuns: PROPERTY_RUNS }
      );
    });
  });
});

// =========================================================================
// SCOPE EXTRACTION PROPERTIES
// =========================================================================

describe('PROPERTY: Scope Extraction Invariants', () => {
  it('extracted fields match source', () => {
    fc.assert(
      fc.property(
        fc.dictionary(
          alphaLowerString(1, 10),
          fc.oneof(fc.string(), fc.integer(), fc.boolean()),
          { minKeys: 2, maxKeys: 10 }
        ),
        (obj) => {
          const keys = Object.keys(obj);
          const scope = keys.slice(0, Math.ceil(keys.length / 2));

          try {
            const extracted = ashExtractScopedFields(obj, scope);

            // All scope keys should be in extracted
            for (const key of scope) {
              if (!(key in extracted)) return false;
              if (extracted[key] !== obj[key]) return false;
            }

            // No extra keys should be in extracted
            if (Object.keys(extracted).length !== scope.length) return false;

            return true;
          } catch {
            return true;
          }
        }
      ),
      { numRuns: PROPERTY_RUNS }
    );
  });

  it('scope normalization is deterministic', () => {
    fc.assert(
      fc.property(
        fc.array(fc.string({ minLength: 1, maxLength: 20 }), { minLength: 1, maxLength: 10 }),
        (scope) => {
          const norm1 = normalizeScopeFields(scope);
          const norm2 = normalizeScopeFields(scope);
          return JSON.stringify(norm1) === JSON.stringify(norm2);
        }
      ),
      { numRuns: PROPERTY_RUNS }
    );
  });

  it('scope normalization removes duplicates', () => {
    fc.assert(
      fc.property(
        fc.array(fc.string({ minLength: 1, maxLength: 10 }), { minLength: 2, maxLength: 10 }),
        (scope) => {
          // Add duplicates
          const withDupes = [...scope, ...scope];
          const normalized = normalizeScopeFields(withDupes);

          // Check no duplicates in result
          const unique = new Set(normalized);
          return unique.size === normalized.length;
        }
      ),
      { numRuns: PROPERTY_RUNS }
    );
  });

  it('scope normalization sorts consistently', () => {
    fc.assert(
      fc.property(
        fc.array(fc.string({ minLength: 1, maxLength: 10 }), { minLength: 2, maxLength: 10 }),
        (scope) => {
          const shuffled = [...scope].sort(() => Math.random() - 0.5);
          const norm1 = normalizeScopeFields(scope);
          const norm2 = normalizeScopeFields(shuffled);

          return JSON.stringify(norm1) === JSON.stringify(norm2);
        }
      ),
      { numRuns: PROPERTY_RUNS }
    );
  });
});

// =========================================================================
// TIMING SAFETY PROPERTIES
// =========================================================================

describe('PROPERTY: Timing Safety', () => {
  it('timingSafeEqual returns correct result', () => {
    fc.assert(
      fc.property(fc.string(), fc.string(), (a, b) => {
        const result = ashTimingSafeEqual(a, b);
        return result === (a === b);
      }),
      { numRuns: PROPERTY_RUNS }
    );
  });

  it('timingSafeEqual is symmetric', () => {
    fc.assert(
      fc.property(fc.string(), fc.string(), (a, b) => {
        return ashTimingSafeEqual(a, b) === ashTimingSafeEqual(b, a);
      }),
      { numRuns: PROPERTY_RUNS }
    );
  });

  it('timingSafeEqual is reflexive', () => {
    fc.assert(
      fc.property(fc.string(), (a) => {
        return ashTimingSafeEqual(a, a) === true;
      }),
      { numRuns: PROPERTY_RUNS }
    );
  });
});

// =========================================================================
// TIMESTAMP VALIDATION PROPERTIES
// =========================================================================

describe('PROPERTY: Timestamp Validation', () => {
  it('current timestamps are valid', () => {
    fc.assert(
      fc.property(fc.integer({ min: -30, max: 30 }), (offset) => {
        const now = Math.floor(Date.now() / 1000);
        const timestamp = (now + offset).toString();

        try {
          ashValidateTimestamp(timestamp);
          return true;
        } catch (e) {
          // Small offsets should be valid
          if (Math.abs(offset) <= 30) {
            return false;
          }
          return true;
        }
      }),
      { numRuns: 1000 }
    );
  });

  it('very old timestamps are rejected', () => {
    fc.assert(
      fc.property(fc.integer({ min: 3600, max: 86400 }), (age) => {
        const now = Math.floor(Date.now() / 1000);
        const oldTimestamp = (now - age).toString();

        try {
          ashValidateTimestamp(oldTimestamp);
          return false; // Should have thrown
        } catch {
          return true;
        }
      }),
      { numRuns: 1000 }
    );
  });

  it('future timestamps are rejected', () => {
    fc.assert(
      fc.property(fc.integer({ min: 120, max: 86400 }), (future) => {
        const now = Math.floor(Date.now() / 1000);
        const futureTimestamp = (now + future).toString();

        try {
          ashValidateTimestamp(futureTimestamp);
          return false; // Should have thrown
        } catch {
          return true;
        }
      }),
      { numRuns: 1000 }
    );
  });
});

console.log('Property-Based Testing Suite loaded');
