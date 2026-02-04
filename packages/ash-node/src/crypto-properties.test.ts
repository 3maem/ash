/**
 * Cryptographic Properties Comprehensive Tests
 *
 * Tests for cryptographic properties covering:
 * - Avalanche effect (small input changes cause large output changes)
 * - Collision resistance
 * - Timing-safe comparison
 * - Entropy analysis
 * - Hash distribution
 * - Key derivation properties
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as crypto from 'crypto';
import {
  ashInit,
  ashHashBody,
  ashHashProof,
  ashHashScope,
  ashDeriveClientSecret,
  ashBuildProof,
  ashGenerateNonce,
  ashGenerateContextId,
  ashGenerateContextId256,
  ashTimingSafeEqual,
  ashNormalizeBinding,
  MIN_NONCE_BYTES,
  MIN_NONCE_HEX_CHARS,
  MAX_NONCE_LENGTH,
} from './index';

// Initialize WASM
beforeAll(() => {
  try {
    ashInit();
  } catch {
    // WASM not available, tests will use native fallback
  }
});

describe('Cryptographic Properties Comprehensive Tests', () => {
  describe('Avalanche Effect - Hashing', () => {
    it('single bit change produces vastly different hash', () => {
      const input1 = 'Hello, World!';
      const input2 = 'Hello, World?'; // Changed ! to ?

      const hash1 = ashHashBody(input1);
      const hash2 = ashHashBody(input2);

      // Count differing hex characters
      let diffCount = 0;
      for (let i = 0; i < hash1.length; i++) {
        if (hash1[i] !== hash2[i]) diffCount++;
      }

      // Should differ in roughly 50% of characters (avalanche effect)
      expect(diffCount).toBeGreaterThan(hash1.length * 0.3);
    });

    it('adjacent values produce uncorrelated hashes', () => {
      const hashes: string[] = [];
      for (let i = 0; i < 100; i++) {
        hashes.push(ashHashBody(i.toString()));
      }

      // Check that consecutive hashes are significantly different
      for (let i = 0; i < hashes.length - 1; i++) {
        let diffCount = 0;
        for (let j = 0; j < hashes[i].length; j++) {
          if (hashes[i][j] !== hashes[i + 1][j]) diffCount++;
        }
        // Each pair should differ significantly
        expect(diffCount).toBeGreaterThan(10);
      }
    });

    it('prefix addition changes entire hash', () => {
      const base = 'test message';
      const prefixed = 'a' + base;

      const hash1 = ashHashBody(base);
      const hash2 = ashHashBody(prefixed);

      let diffCount = 0;
      for (let i = 0; i < hash1.length; i++) {
        if (hash1[i] !== hash2[i]) diffCount++;
      }

      expect(diffCount).toBeGreaterThan(hash1.length * 0.3);
    });

    it('suffix addition changes entire hash', () => {
      const base = 'test message';
      const suffixed = base + 'z';

      const hash1 = ashHashBody(base);
      const hash2 = ashHashBody(suffixed);

      let diffCount = 0;
      for (let i = 0; i < hash1.length; i++) {
        if (hash1[i] !== hash2[i]) diffCount++;
      }

      expect(diffCount).toBeGreaterThan(hash1.length * 0.3);
    });

    it('case change produces different hash', () => {
      const hash1 = ashHashBody('HELLO');
      const hash2 = ashHashBody('hello');

      expect(hash1).not.toBe(hash2);

      let diffCount = 0;
      for (let i = 0; i < hash1.length; i++) {
        if (hash1[i] !== hash2[i]) diffCount++;
      }

      expect(diffCount).toBeGreaterThan(hash1.length * 0.3);
    });
  });

  describe('Avalanche Effect - HMAC Proofs', () => {
    it('timestamp change produces vastly different proof', () => {
      const secret = 'secret'.repeat(10);
      const binding = 'GET|/api/test|';
      const bodyHash = ashHashBody('{}');

      const proof1 = ashBuildProof(secret, '1000000000', binding, bodyHash);
      const proof2 = ashBuildProof(secret, '1000000001', binding, bodyHash);

      let diffCount = 0;
      for (let i = 0; i < proof1.length; i++) {
        if (proof1[i] !== proof2[i]) diffCount++;
      }

      expect(diffCount).toBeGreaterThan(proof1.length * 0.3);
    });

    it('secret change produces vastly different proof', () => {
      const binding = 'GET|/api/test|';
      const bodyHash = ashHashBody('{}');
      const timestamp = '1000000000';

      const proof1 = ashBuildProof('secret1', timestamp, binding, bodyHash);
      const proof2 = ashBuildProof('secret2', timestamp, binding, bodyHash);

      let diffCount = 0;
      for (let i = 0; i < proof1.length; i++) {
        if (proof1[i] !== proof2[i]) diffCount++;
      }

      expect(diffCount).toBeGreaterThan(proof1.length * 0.3);
    });

    it('binding change produces vastly different proof', () => {
      const secret = 'secret'.repeat(10);
      const bodyHash = ashHashBody('{}');
      const timestamp = '1000000000';

      const proof1 = ashBuildProof(secret, timestamp, 'GET|/api/test|', bodyHash);
      const proof2 = ashBuildProof(secret, timestamp, 'POST|/api/test|', bodyHash);

      let diffCount = 0;
      for (let i = 0; i < proof1.length; i++) {
        if (proof1[i] !== proof2[i]) diffCount++;
      }

      expect(diffCount).toBeGreaterThan(proof1.length * 0.3);
    });
  });

  describe('Collision Resistance', () => {
    it('no collisions in 10000 random hashes', () => {
      const hashes = new Set<string>();
      for (let i = 0; i < 10000; i++) {
        const input = crypto.randomBytes(32).toString('hex');
        const hash = ashHashBody(input);
        expect(hashes.has(hash)).toBe(false);
        hashes.add(hash);
      }
      expect(hashes.size).toBe(10000);
    });

    it('no collisions in sequential integers', () => {
      const hashes = new Set<string>();
      for (let i = 0; i < 10000; i++) {
        const hash = ashHashBody(i.toString());
        expect(hashes.has(hash)).toBe(false);
        hashes.add(hash);
      }
      expect(hashes.size).toBe(10000);
    });

    it('no collisions in similar strings', () => {
      const hashes = new Set<string>();
      const base = 'transaction_';
      for (let i = 0; i < 1000; i++) {
        const hash = ashHashBody(base + i);
        expect(hashes.has(hash)).toBe(false);
        hashes.add(hash);
      }
      expect(hashes.size).toBe(1000);
    });

    it('no collisions in proofs with same secret different timestamps', () => {
      const secret = 'testsecret123';
      const binding = 'POST|/api/test|';
      const bodyHash = ashHashBody('{}');

      const proofs = new Set<string>();
      for (let i = 0; i < 1000; i++) {
        const timestamp = (1700000000 + i).toString();
        const proof = ashBuildProof(secret, timestamp, binding, bodyHash);
        expect(proofs.has(proof)).toBe(false);
        proofs.add(proof);
      }
      expect(proofs.size).toBe(1000);
    });
  });

  describe('Timing-Safe Comparison', () => {
    it('equal strings return true', () => {
      const str = 'a'.repeat(64);
      expect(ashTimingSafeEqual(str, str)).toBe(true);
    });

    it('different strings return false', () => {
      const str1 = 'a'.repeat(64);
      const str2 = 'b'.repeat(64);
      expect(ashTimingSafeEqual(str1, str2)).toBe(false);
    });

    it('strings differing by one char return false', () => {
      const str1 = 'a'.repeat(64);
      const str2 = 'a'.repeat(63) + 'b';
      expect(ashTimingSafeEqual(str1, str2)).toBe(false);
    });

    it('different length strings return false', () => {
      expect(ashTimingSafeEqual('short', 'longer')).toBe(false);
      expect(ashTimingSafeEqual('longer', 'short')).toBe(false);
    });

    it('empty strings return true', () => {
      expect(ashTimingSafeEqual('', '')).toBe(true);
    });

    it('timing is consistent regardless of difference position', () => {
      const base = 'a'.repeat(64);
      const positions = [0, 16, 32, 48, 63];
      const iterations = 1000;
      const timings: number[] = [];

      for (const pos of positions) {
        const modified = base.substring(0, pos) + 'b' + base.substring(pos + 1);
        const start = process.hrtime.bigint();
        for (let i = 0; i < iterations; i++) {
          ashTimingSafeEqual(base, modified);
        }
        timings.push(Number(process.hrtime.bigint() - start));
      }

      // All timings should be within reasonable ratio
      const maxTime = Math.max(...timings);
      const minTime = Math.min(...timings);
      const ratio = maxTime / minTime;
      expect(ratio).toBeLessThan(5);
    });
  });

  describe('Entropy Analysis - Nonce Generation', () => {
    it('generates minimum required entropy', () => {
      const nonce = ashGenerateNonce();
      // Default is 32 bytes = 64 hex chars
      expect(nonce.length).toBe(64);
    });

    it('generates cryptographically random nonces', () => {
      const nonces = new Set<string>();
      for (let i = 0; i < 10000; i++) {
        nonces.add(ashGenerateNonce());
      }
      expect(nonces.size).toBe(10000);
    });

    it('nonce bytes have uniform distribution', () => {
      const nibbleCounts = new Array(16).fill(0);
      const iterations = 10000;

      for (let i = 0; i < iterations; i++) {
        const nonce = ashGenerateNonce();
        for (const char of nonce) {
          nibbleCounts[parseInt(char, 16)]++;
        }
      }

      // Check for roughly uniform distribution
      const totalNibbles = iterations * 64;
      const expected = totalNibbles / 16;
      const tolerance = expected * 0.1; // 10% tolerance

      for (const count of nibbleCounts) {
        expect(count).toBeGreaterThan(expected - tolerance);
        expect(count).toBeLessThan(expected + tolerance);
      }
    });

    it('generates nonces with specified byte length', () => {
      expect(ashGenerateNonce(16).length).toBe(32); // 16 bytes = 32 hex chars
      expect(ashGenerateNonce(32).length).toBe(64); // 32 bytes = 64 hex chars
      expect(ashGenerateNonce(64).length).toBe(128); // 64 bytes = 128 hex chars
    });

    it('rejects nonce below minimum bytes', () => {
      expect(() => ashGenerateNonce(MIN_NONCE_BYTES - 1)).toThrow(/at least/);
    });

    it('rejects nonce above maximum bytes', () => {
      const maxBytes = MAX_NONCE_LENGTH / 2;
      expect(() => ashGenerateNonce(maxBytes + 1)).toThrow(/cannot exceed/);
    });
  });

  describe('Entropy Analysis - Context ID Generation', () => {
    it('generates unique context IDs', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 10000; i++) {
        ids.add(ashGenerateContextId());
      }
      expect(ids.size).toBe(10000);
    });

    it('context ID has correct format', () => {
      const id = ashGenerateContextId();
      expect(id).toMatch(/^ash_[0-9a-f]{32}$/);
    });

    it('context ID 256-bit version has correct format', () => {
      const id = ashGenerateContextId256();
      expect(id).toMatch(/^ash_[0-9a-f]{64}$/);
    });

    it('256-bit context IDs are unique', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 10000; i++) {
        ids.add(ashGenerateContextId256());
      }
      expect(ids.size).toBe(10000);
    });
  });

  describe('Key Derivation Properties', () => {
    it('derived secret is deterministic', () => {
      const nonce = 'a'.repeat(64);
      const contextId = 'ctx_test';
      const binding = 'POST|/api/test|';

      const secret1 = ashDeriveClientSecret(nonce, contextId, binding);
      const secret2 = ashDeriveClientSecret(nonce, contextId, binding);

      expect(secret1).toBe(secret2);
    });

    it('different nonces produce different secrets', () => {
      const contextId = 'ctx_test';
      const binding = 'POST|/api/test|';

      const secret1 = ashDeriveClientSecret('a'.repeat(64), contextId, binding);
      const secret2 = ashDeriveClientSecret('b'.repeat(64), contextId, binding);

      expect(secret1).not.toBe(secret2);
    });

    it('different context IDs produce different secrets', () => {
      const nonce = 'a'.repeat(64);
      const binding = 'POST|/api/test|';

      const secret1 = ashDeriveClientSecret(nonce, 'ctx_test1', binding);
      const secret2 = ashDeriveClientSecret(nonce, 'ctx_test2', binding);

      expect(secret1).not.toBe(secret2);
    });

    it('different bindings produce different secrets', () => {
      const nonce = 'a'.repeat(64);
      const contextId = 'ctx_test';

      const secret1 = ashDeriveClientSecret(nonce, contextId, 'GET|/path1|');
      const secret2 = ashDeriveClientSecret(nonce, contextId, 'GET|/path2|');

      expect(secret1).not.toBe(secret2);
    });

    it('derived secret has correct length', () => {
      const nonce = 'a'.repeat(64);
      const contextId = 'ctx_test';
      const binding = 'POST|/api/test|';

      const secret = ashDeriveClientSecret(nonce, contextId, binding);
      expect(secret.length).toBe(64); // SHA-256 hex output
    });

    it('derived secret is lowercase hex', () => {
      const nonce = 'A'.repeat(64);
      const contextId = 'ctx_test';
      const binding = 'POST|/api/test|';

      const secret = ashDeriveClientSecret(nonce, contextId, binding);
      expect(secret).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('Hash Distribution', () => {
    it('hash output is evenly distributed across hex chars', () => {
      const charCounts: Record<string, number> = {};
      for (let c = 0; c < 16; c++) {
        charCounts[c.toString(16)] = 0;
      }

      for (let i = 0; i < 1000; i++) {
        const hash = ashHashBody(i.toString());
        for (const char of hash) {
          charCounts[char]++;
        }
      }

      // Check distribution
      const values = Object.values(charCounts);
      const mean = values.reduce((a, b) => a + b, 0) / values.length;
      const variance = values.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / values.length;
      const stdDev = Math.sqrt(variance);

      // Standard deviation should be relatively small compared to mean
      expect(stdDev / mean).toBeLessThan(0.1);
    });

    it('hash first char distribution is uniform', () => {
      const firstCharCounts: Record<string, number> = {};
      for (let c = 0; c < 16; c++) {
        firstCharCounts[c.toString(16)] = 0;
      }

      for (let i = 0; i < 10000; i++) {
        const hash = ashHashBody(crypto.randomBytes(32).toString('hex'));
        firstCharCounts[hash[0]]++;
      }

      // Each char should appear roughly 625 times (10000 / 16)
      const values = Object.values(firstCharCounts);
      const min = Math.min(...values);
      const max = Math.max(...values);

      // Max should not be more than 2x min for uniform distribution
      expect(max / min).toBeLessThan(2);
    });
  });

  describe('Proof Properties', () => {
    it('proof is deterministic for same inputs', () => {
      const secret = 'testsecret';
      const timestamp = '1700000000';
      const binding = 'POST|/api/test|';
      const bodyHash = ashHashBody('{}');

      const proof1 = ashBuildProof(secret, timestamp, binding, bodyHash);
      const proof2 = ashBuildProof(secret, timestamp, binding, bodyHash);

      expect(proof1).toBe(proof2);
    });

    it('proof changes with any input change', () => {
      const base = {
        secret: 'testsecret',
        timestamp: '1700000000',
        binding: 'POST|/api/test|',
        bodyHash: ashHashBody('{}'),
      };

      const baseProof = ashBuildProof(base.secret, base.timestamp, base.binding, base.bodyHash);

      // Change secret
      expect(ashBuildProof('different', base.timestamp, base.binding, base.bodyHash)).not.toBe(baseProof);

      // Change timestamp
      expect(ashBuildProof(base.secret, '1700000001', base.binding, base.bodyHash)).not.toBe(baseProof);

      // Change binding
      expect(ashBuildProof(base.secret, base.timestamp, 'GET|/other|', base.bodyHash)).not.toBe(baseProof);

      // Change body hash
      expect(ashBuildProof(base.secret, base.timestamp, base.binding, ashHashBody('different'))).not.toBe(baseProof);
    });

    it('proof is 64 hex characters', () => {
      const proof = ashBuildProof('secret', '1700000000', 'GET|/path|', ashHashBody('{}'));
      expect(proof).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('Scope Hash Properties', () => {
    it('scope hash is deterministic', () => {
      const scope = ['field1', 'field2'];
      const hash1 = ashHashScope(scope);
      const hash2 = ashHashScope(scope);
      expect(hash1).toBe(hash2);
    });

    it('scope hash is order-independent', () => {
      const hash1 = ashHashScope(['a', 'b', 'c']);
      const hash2 = ashHashScope(['c', 'a', 'b']);
      expect(hash1).toBe(hash2);
    });

    it('scope hash handles duplicates', () => {
      const hash1 = ashHashScope(['a', 'b']);
      const hash2 = ashHashScope(['a', 'b', 'a', 'b']);
      expect(hash1).toBe(hash2);
    });

    it('different scopes produce different hashes', () => {
      const hash1 = ashHashScope(['a']);
      const hash2 = ashHashScope(['b']);
      expect(hash1).not.toBe(hash2);
    });

    it('empty scope returns empty string', () => {
      expect(ashHashScope([])).toBe('');
    });
  });

  describe('Chain Hash Properties', () => {
    it('chain hash is deterministic', () => {
      const proof = 'a'.repeat(64);
      const hash1 = ashHashProof(proof);
      const hash2 = ashHashProof(proof);
      expect(hash1).toBe(hash2);
    });

    it('different proofs produce different chain hashes', () => {
      const hash1 = ashHashProof('a'.repeat(64));
      const hash2 = ashHashProof('b'.repeat(64));
      expect(hash1).not.toBe(hash2);
    });

    it('chain hash has avalanche effect', () => {
      const proof1 = 'a'.repeat(64);
      const proof2 = 'a'.repeat(63) + 'b';

      const hash1 = ashHashProof(proof1);
      const hash2 = ashHashProof(proof2);

      let diffCount = 0;
      for (let i = 0; i < hash1.length; i++) {
        if (hash1[i] !== hash2[i]) diffCount++;
      }

      expect(diffCount).toBeGreaterThan(hash1.length * 0.3);
    });
  });
});
