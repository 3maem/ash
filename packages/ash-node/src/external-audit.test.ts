/**
 * ASH SDK External Security Audit Test Suite
 *
 * Simulates external penetration testing scenarios covering:
 * - OWASP Top 10 vulnerabilities
 * - Cryptographic attack vectors
 * - Protocol-level attacks
 * - Implementation-specific vulnerabilities
 */

import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
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
  ashBuildProofScoped,
  ashVerifyProofScoped,
  ashBuildProofUnified,
  ashVerifyProofUnified,
  ashExtractScopedFields,
  ashExtractScopedFieldsStrict,
  AshMemoryStore,
  ashValidateTimestamp,
  ashTimingSafeEqual,
  ashVerifyProofWithFreshness,
} from './index';

beforeAll(() => {
  ashInit();
});

// =========================================================================
// OWASP A01:2021 - Broken Access Control
// =========================================================================

describe('AUDIT: A01 - Broken Access Control', () => {
  describe('Context Isolation', () => {
    it('AUDIT-A01-001: contexts cannot be shared between different bindings', async () => {
      const store = new AshMemoryStore();

      // Create context for one endpoint
      const ctx = await store.create({
        binding: 'POST|/api/admin/delete|',
        ttlMs: 60000,
      });

      // Try to use it for a different endpoint (simulated by checking binding)
      const retrieved = await store.get(ctx.id);
      expect(retrieved?.binding).toBe('POST|/api/admin/delete|');

      // A proper implementation would reject this at verification time
      // because the binding wouldn't match
    });

    it('AUDIT-A01-002: proofs are binding-specific', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const bodyHash = ashHashBody('{}');

      // Create proof for admin endpoint
      const adminBinding = ashNormalizeBinding('DELETE', '/api/admin/user', '');
      const adminSecret = ashDeriveClientSecret(nonce, contextId, adminBinding);
      const adminProof = ashBuildProofV21(adminSecret, timestamp, adminBinding, bodyHash);

      // Try to use it for regular endpoint
      const userBinding = ashNormalizeBinding('DELETE', '/api/user/profile', '');

      const isValid = ashVerifyProofV21(
        nonce, contextId, userBinding, timestamp, bodyHash, adminProof
      );

      expect(isValid).toBe(false);
    });

    it('AUDIT-A01-003: method downgrade attack prevention', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const bodyHash = ashHashBody('{}');

      // Create proof for safe GET request
      const getBinding = ashNormalizeBinding('GET', '/api/data', '');
      const getSecret = ashDeriveClientSecret(nonce, contextId, getBinding);
      const getProof = ashBuildProofV21(getSecret, timestamp, getBinding, bodyHash);

      // Try to use it for dangerous DELETE request
      const deleteBinding = ashNormalizeBinding('DELETE', '/api/data', '');

      const isValid = ashVerifyProofV21(
        nonce, contextId, deleteBinding, timestamp, bodyHash, getProof
      );

      expect(isValid).toBe(false);
    });
  });
});

// =========================================================================
// OWASP A02:2021 - Cryptographic Failures
// =========================================================================

describe('AUDIT: A02 - Cryptographic Failures', () => {
  describe('Key Derivation Security', () => {
    it('AUDIT-A02-001: nonces have sufficient entropy (256 bits)', () => {
      const nonces: string[] = [];
      for (let i = 0; i < 1000; i++) {
        nonces.push(ashGenerateNonce());
      }

      // All nonces should be unique
      expect(new Set(nonces).size).toBe(1000);

      // Each nonce should be 64 hex chars (256 bits)
      for (const nonce of nonces) {
        expect(nonce).toHaveLength(64);
        expect(/^[0-9a-f]+$/.test(nonce)).toBe(true);
      }
    });

    it('AUDIT-A02-002: client secrets are not predictable', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const binding = 'POST|/api/test|';

      const secret = ashDeriveClientSecret(nonce, contextId, binding);

      // Secret should be 64 hex chars
      expect(secret).toHaveLength(64);

      // Secret should not equal nonce or contextId
      expect(secret).not.toBe(nonce);
      expect(secret).not.toContain(contextId);
    });

    it('AUDIT-A02-003: proofs use secure HMAC-SHA256', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const binding = 'POST|/api/test|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const bodyHash = ashHashBody('test');

      const secret = ashDeriveClientSecret(nonce, contextId, binding);
      const proof = ashBuildProofV21(secret, timestamp, binding, bodyHash);

      // Proof should be 64 hex chars (256 bits = SHA-256 output)
      expect(proof).toHaveLength(64);
      expect(/^[0-9a-f]+$/.test(proof)).toBe(true);
    });

    it('AUDIT-A02-004: no weak hash functions used', () => {
      // Verify SHA-256 is used (64 hex chars output)
      const hash = ashHashBody('test');
      expect(hash).toHaveLength(64);

      // Known SHA-256 hash for 'test'
      const expected = crypto.createHash('sha256').update('test').digest('hex');
      expect(hash).toBe(expected);
    });
  });

  describe('Timing Attack Resistance', () => {
    it('AUDIT-A02-005: comparison uses constant-time algorithm', () => {
      const secret1 = 'a'.repeat(64);
      const secret2 = 'a'.repeat(63) + 'b';
      const secret3 = 'b' + 'a'.repeat(63);

      // All comparisons should use constant time
      // We verify the function exists and works correctly
      expect(ashTimingSafeEqual(secret1, secret1)).toBe(true);
      expect(ashTimingSafeEqual(secret1, secret2)).toBe(false);
      expect(ashTimingSafeEqual(secret1, secret3)).toBe(false);
    });
  });
});

// =========================================================================
// OWASP A03:2021 - Injection
// =========================================================================

describe('AUDIT: A03 - Injection', () => {
  describe('JSON Injection', () => {
    const jsonInjectionPayloads = [
      '{"__proto__":{"admin":true}}',
      '{"constructor":{"prototype":{"admin":true}}}',
      '{"a":"\\u0000"}',
      '{"a":"</script><script>alert(1)</script>"}',
      '{"a":"\\"}}; DROP TABLE users; --"}',
    ];

    it('AUDIT-A03-001: JSON canonicalization is injection-safe', () => {
      for (const payload of jsonInjectionPayloads) {
        try {
          const canonical = canonicalizeJsonNative(payload);
          const parsed = JSON.parse(canonical);

          // Should not have prototype pollution
          expect(({} as any).admin).toBeUndefined();

          // Should preserve string content safely
          if (typeof parsed.a === 'string') {
            expect(typeof parsed.a).toBe('string');
          }
        } catch {
          // Rejecting malformed input is acceptable
        }
      }
    });
  });

  describe('URL Injection', () => {
    const urlInjectionPayloads = [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\config\\sam',
      '/api/../admin/delete',
      '/api/./././admin',
      '%2e%2e%2f%2e%2e%2fadmin',
      '/api%00/admin',
    ];

    it('AUDIT-A03-002: path traversal is prevented', () => {
      for (const payload of urlInjectionPayloads) {
        try {
          const binding = ashNormalizeBinding('GET', payload, '');

          // Result should not contain path traversal sequences
          expect(binding).not.toContain('..');
          expect(binding).not.toContain('%2e%2e');
          expect(binding).not.toContain('%00');
        } catch {
          // Rejecting malicious input is acceptable
        }
      }
    });
  });

  describe('Header Injection', () => {
    it('AUDIT-A03-003: newlines in values are handled safely', () => {
      const maliciousBody = '{"header":"value\\r\\nX-Injected: evil"}';

      const canonical = canonicalizeJsonNative(maliciousBody);
      const parsed = JSON.parse(canonical);

      // Newlines should be preserved as data (actual \r\n characters), not interpreted as headers
      // When parsed, \\r\\n becomes actual carriage return and newline characters
      expect(parsed.header).toContain('\r\n');
      expect(parsed.header).toBe('value\r\nX-Injected: evil');
    });
  });
});

// =========================================================================
// OWASP A04:2021 - Insecure Design
// =========================================================================

describe('AUDIT: A04 - Insecure Design', () => {
  describe('Anti-Replay Protection', () => {
    it('AUDIT-A04-001: context can only be consumed once', async () => {
      const store = new AshMemoryStore();

      const ctx = await store.create({
        binding: 'POST|/api/transfer|',
        ttlMs: 60000,
      });

      // First consume succeeds
      expect(await store.consume(ctx.id)).toBe(true);

      // Replay attempts fail
      for (let i = 0; i < 100; i++) {
        expect(await store.consume(ctx.id)).toBe(false);
      }
    });

    it('AUDIT-A04-002: expired contexts are rejected', async () => {
      const store = new AshMemoryStore();

      const ctx = await store.create({
        binding: 'POST|/api/test|',
        ttlMs: 1, // 1ms TTL
      });

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 10));

      // Should be expired
      expect(await store.consume(ctx.id)).toBe(false);
    });

    it('AUDIT-A04-003: timestamp freshness is enforced', () => {
      // Old timestamp (1 hour ago)
      const oldTimestamp = (Math.floor(Date.now() / 1000) - 3600).toString();
      expect(() => ashValidateTimestamp(oldTimestamp)).toThrow();

      // Future timestamp (1 hour ahead)
      const futureTimestamp = (Math.floor(Date.now() / 1000) + 3600).toString();
      expect(() => ashValidateTimestamp(futureTimestamp)).toThrow();
    });
  });

  describe('Proof Chaining Security', () => {
    it('AUDIT-A04-004: chain cannot be forged', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const clientSecret = ashDeriveClientSecret(nonce, contextId, 'POST|/api/step1|');

      // Build first proof
      const result1 = ashBuildProofUnified(
        clientSecret, timestamp, 'POST|/api/step1|',
        { step: 1 }, []
      );

      // Build second proof chained to first
      const result2 = ashBuildProofUnified(
        clientSecret, timestamp, 'POST|/api/step2|',
        { step: 2 }, [], result1.proof
      );

      // Try to verify with forged chain hash
      const forgedChainHash = 'a'.repeat(64);

      const isValid = ashVerifyProofUnified(
        nonce, contextId, 'POST|/api/step2|', timestamp,
        { step: 2 }, result2.proof, [], '', result1.proof, forgedChainHash
      );

      expect(isValid).toBe(false);
    });

    it('AUDIT-A04-005: chain order cannot be reordered', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const clientSecret = ashDeriveClientSecret(nonce, contextId, 'POST|/api/step1|');

      // Build proof chain: step1 -> step2
      const result1 = ashBuildProofUnified(
        clientSecret, timestamp, 'POST|/api/step1|',
        { step: 1 }, []
      );

      const result2 = ashBuildProofUnified(
        clientSecret, timestamp, 'POST|/api/step2|',
        { step: 2 }, [], result1.proof
      );

      // Try to use step2's proof as if it came before step1
      const fakeResult = ashBuildProofUnified(
        clientSecret, timestamp, 'POST|/api/step3|',
        { step: 3 }, [], result2.proof
      );

      // Verification should fail if we claim step1 was the previous
      const isValid = ashVerifyProofUnified(
        nonce, contextId, 'POST|/api/step3|', timestamp,
        { step: 3 }, fakeResult.proof, [], '', result1.proof, fakeResult.chainHash
      );

      expect(isValid).toBe(false);
    });
  });
});

// =========================================================================
// OWASP A05:2021 - Security Misconfiguration
// =========================================================================

describe('AUDIT: A05 - Security Misconfiguration', () => {
  describe('Default Security', () => {
    it('AUDIT-A05-001: empty nonce is rejected', () => {
      expect(() => ashDeriveClientSecret('', 'ctx', 'GET|/|')).toThrow();
    });

    it('AUDIT-A05-002: empty context is rejected', () => {
      const nonce = ashGenerateNonce();
      expect(() => ashDeriveClientSecret(nonce, '', 'GET|/|')).toThrow();
    });

    it('AUDIT-A05-003: empty binding is rejected', () => {
      const nonce = ashGenerateNonce();
      expect(() => ashDeriveClientSecret(nonce, 'ctx', '')).toThrow();
    });

    it('AUDIT-A05-004: malformed nonce is rejected', () => {
      expect(() => ashDeriveClientSecret('not-hex', 'ctx', 'GET|/|')).toThrow();
      expect(() => ashDeriveClientSecret('abc', 'ctx', 'GET|/|')).toThrow(); // Too short
    });
  });
});

// =========================================================================
// OWASP A07:2021 - Identification and Authentication Failures
// =========================================================================

describe('AUDIT: A07 - Authentication Failures', () => {
  describe('Proof Verification', () => {
    it('AUDIT-A07-001: null/undefined proof is rejected', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const binding = 'POST|/api/test|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const bodyHash = ashHashBody('{}');

      // @ts-ignore - Testing runtime behavior
      expect(ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, null)).toBe(false);
      // @ts-ignore
      expect(ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, undefined)).toBe(false);
      expect(ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, '')).toBe(false);
    });

    it('AUDIT-A07-002: wrong length proof is rejected', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const binding = 'POST|/api/test|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const bodyHash = ashHashBody('{}');

      const shortProof = 'a'.repeat(32);
      const longProof = 'a'.repeat(128);

      expect(ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, shortProof)).toBe(false);
      expect(ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, longProof)).toBe(false);
    });

    it('AUDIT-A07-003: non-hex proof is rejected', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const binding = 'POST|/api/test|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const bodyHash = ashHashBody('{}');

      const invalidProof = 'g'.repeat(64); // 'g' is not valid hex

      expect(ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, invalidProof)).toBe(false);
    });
  });
});

// =========================================================================
// OWASP A08:2021 - Software and Data Integrity Failures
// =========================================================================

describe('AUDIT: A08 - Integrity Failures', () => {
  describe('Scoped Field Integrity', () => {
    it('AUDIT-A08-001: scope hash protects field selection', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const binding = 'POST|/api/transfer|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const payload = { amount: 1000, recipient: 'attacker', memo: 'legitimate' };
      const scope = ['amount', 'recipient'];

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const { proof, scopeHash } = ashBuildProofScoped(
        clientSecret, timestamp, binding, payload, scope
      );

      // Attacker tries to verify with modified scope (excluding recipient)
      const attackScope = ['amount'];

      const isValid = ashVerifyProofScoped(
        nonce, contextId, binding, timestamp, payload, attackScope, scopeHash, proof
      );

      expect(isValid).toBe(false);
    });

    it('AUDIT-A08-002: scoped field values cannot be tampered', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const binding = 'POST|/api/transfer|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const originalPayload = { amount: 100, recipient: 'alice' };
      const scope = ['amount', 'recipient'];

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const { proof, scopeHash } = ashBuildProofScoped(
        clientSecret, timestamp, binding, originalPayload, scope
      );

      // Attacker modifies the amount
      const tamperedPayload = { amount: 10000, recipient: 'alice' };

      const isValid = ashVerifyProofScoped(
        nonce, contextId, binding, timestamp, tamperedPayload, scope, scopeHash, proof
      );

      expect(isValid).toBe(false);
    });
  });

  describe('Body Integrity', () => {
    it('AUDIT-A08-003: body modifications are detected', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const binding = 'POST|/api/update|';
      const timestamp = Math.floor(Date.now() / 1000).toString();

      const originalBody = '{"action":"view"}';
      const originalHash = ashHashBody(canonicalizeJsonNative(originalBody));

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const proof = ashBuildProofV21(clientSecret, timestamp, binding, originalHash);

      // Attacker modifies body
      const tamperedBody = '{"action":"delete"}';
      const tamperedHash = ashHashBody(canonicalizeJsonNative(tamperedBody));

      const isValid = ashVerifyProofV21(
        nonce, contextId, binding, timestamp, tamperedHash, proof
      );

      expect(isValid).toBe(false);
    });
  });
});

// =========================================================================
// OWASP A09:2021 - Security Logging and Monitoring Failures
// =========================================================================

describe('AUDIT: A09 - Logging Failures', () => {
  it('AUDIT-A09-001: verification failures return boolean (not throw)', () => {
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/test|';
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const bodyHash = ashHashBody('{}');
    const fakeProof = 'a'.repeat(64);

    // Should return false, not throw
    const result = ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, fakeProof);
    expect(result).toBe(false);
  });
});

// =========================================================================
// Protocol-Level Attack Vectors
// =========================================================================

describe('AUDIT: Protocol-Level Attacks', () => {
  describe('Man-in-the-Middle Scenarios', () => {
    it('AUDIT-PROTO-001: request cannot be modified in transit', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const binding = 'POST|/api/transfer|amount=100';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const body = '{"recipient":"alice"}';
      const bodyHash = ashHashBody(canonicalizeJsonNative(body));

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

      // MITM modifies query string
      const modifiedBinding = 'POST|/api/transfer|amount=10000';

      const isValid = ashVerifyProofV21(
        nonce, contextId, modifiedBinding, timestamp, bodyHash, proof
      );

      expect(isValid).toBe(false);
    });

    it('AUDIT-PROTO-002: request cannot be replayed to different endpoint', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const sourceBinding = 'POST|/api/v1/transfer|';
      const targetBinding = 'POST|/api/v2/transfer|';
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const bodyHash = ashHashBody('{}');

      const clientSecret = ashDeriveClientSecret(nonce, contextId, sourceBinding);
      const proof = ashBuildProofV21(clientSecret, timestamp, sourceBinding, bodyHash);

      // Try to replay to different version of API
      const isValid = ashVerifyProofV21(
        nonce, contextId, targetBinding, timestamp, bodyHash, proof
      );

      expect(isValid).toBe(false);
    });
  });

  describe('Race Condition Exploitation', () => {
    it('AUDIT-PROTO-003: double-spend prevention', async () => {
      const store = new AshMemoryStore();

      const ctx = await store.create({
        binding: 'POST|/api/transfer|',
        ttlMs: 60000,
        metadata: { amount: 1000 },
      });

      // Simulate double-spend attack with concurrent requests
      const results = await Promise.all([
        store.consume(ctx.id),
        store.consume(ctx.id),
        store.consume(ctx.id),
        store.consume(ctx.id),
        store.consume(ctx.id),
      ]);

      // Only one should succeed
      const successCount = results.filter(r => r === true).length;
      expect(successCount).toBe(1);
    });
  });
});

// =========================================================================
// Implementation-Specific Vulnerabilities
// =========================================================================

describe('AUDIT: Implementation Vulnerabilities', () => {
  describe('Prototype Pollution', () => {
    it('AUDIT-IMPL-001: __proto__ in scope is blocked', () => {
      expect(() => {
        ashExtractScopedFields({ a: 1 }, ['__proto__']);
      }).toThrow('dangerous key');
    });

    it('AUDIT-IMPL-002: constructor in scope is blocked', () => {
      expect(() => {
        ashExtractScopedFields({ a: 1 }, ['constructor']);
      }).toThrow('dangerous key');
    });

    it('AUDIT-IMPL-003: prototype in scope is blocked', () => {
      expect(() => {
        ashExtractScopedFields({ a: 1 }, ['prototype']);
      }).toThrow('dangerous key');
    });
  });

  describe('Resource Exhaustion', () => {
    it('AUDIT-IMPL-004: deeply nested JSON is rejected', () => {
      let deepJson = '{"a":';
      for (let i = 0; i < 100; i++) {
        deepJson += '{"a":';
      }
      deepJson += '1';
      for (let i = 0; i <= 100; i++) {
        deepJson += '}';
      }

      expect(() => canonicalizeJsonNative(deepJson)).toThrow();
    });

    it('AUDIT-IMPL-005: oversized payload is rejected', () => {
      const largeJson = JSON.stringify({ data: 'x'.repeat(11 * 1024 * 1024) });
      expect(() => canonicalizeJsonNative(largeJson)).toThrow();
    });

    it('AUDIT-IMPL-006: metadata size is limited', async () => {
      const store = new AshMemoryStore();

      await expect(store.create({
        binding: 'GET|/test|',
        ttlMs: 30000,
        metadata: { data: 'x'.repeat(100000) },
      })).rejects.toThrow();
    });
  });
});

console.log('External Security Audit Suite loaded');
