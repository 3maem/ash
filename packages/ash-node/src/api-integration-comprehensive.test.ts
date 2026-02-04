/**
 * API Integration Comprehensive Tests
 *
 * Tests for API integration patterns covering:
 * - REST API patterns
 * - GraphQL patterns
 * - Webhook handling
 * - Multi-step transactions
 * - Error scenarios
 * - Real-world use cases
 */

import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import {
  ashInit,
  ashBuildProof,
  ashVerifyProof,
  ashBuildProofUnified,
  ashVerifyProofUnified,
  ashBuildProofScoped,
  ashVerifyProofScoped,
  ashDeriveClientSecret,
  ashHashBody,
  ashCanonicalizeJson,
  ashCanonicalizeJsonNative,
  ashNormalizeBinding,
  ashGenerateNonce,
  ashGenerateContextId,
  ashValidateTimestamp,
  AshMemoryStore,
} from './index';

// Initialize WASM
beforeAll(() => {
  try {
    ashInit();
  } catch {
    // WASM not available, tests will use native fallback
  }
});

// Helper to simulate server-side context
class MockServer {
  private store = new AshMemoryStore();

  async createContext(binding: string) {
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

    await this.store.create({
      binding,
      ttlMs: 60000,
      metadata: { nonce },
    });

    return {
      contextId,
      binding,
      clientSecret,
      nonce, // Server keeps this secret
    };
  }

  verify(nonce: string, contextId: string, binding: string, timestamp: string, bodyHash: string, proof: string) {
    return ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof);
  }
}

// Helper to simulate client-side operations
class MockClient {
  private clientSecret: string;
  private contextId: string;
  private binding: string;

  constructor(ctx: { clientSecret: string; contextId: string; binding: string }) {
    this.clientSecret = ctx.clientSecret;
    this.contextId = ctx.contextId;
    this.binding = ctx.binding;
  }

  buildProof(body: string) {
    const canonicalBody = ashCanonicalizeJsonNative(body);
    const bodyHash = ashHashBody(canonicalBody);
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const proof = ashBuildProof(this.clientSecret, timestamp, this.binding, bodyHash);

    return { proof, timestamp, bodyHash };
  }
}

describe('API Integration Comprehensive Tests', () => {
  describe('REST API Patterns', () => {
    describe('GET Requests', () => {
      it('protects GET request with query parameters', () => {
        const binding = ashNormalizeBinding('GET', '/api/users', 'page=1&limit=10');
        const nonce = ashGenerateNonce();
        const contextId = ashGenerateContextId();
        const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
        const bodyHash = ashHashBody(''); // Empty body for GET
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

        const valid = ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof);
        expect(valid).toBe(true);
      });

      it('protects GET request with path parameters', () => {
        const binding = ashNormalizeBinding('GET', '/api/users/123');
        const nonce = ashGenerateNonce();
        const contextId = ashGenerateContextId();
        const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
        const bodyHash = ashHashBody('');
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

        const valid = ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof);
        expect(valid).toBe(true);
      });

      it('protects GET with complex query filters', () => {
        const binding = ashNormalizeBinding('GET', '/api/products',
          'category=electronics&price_min=100&price_max=500&sort=price&order=asc');
        const nonce = ashGenerateNonce();
        const contextId = ashGenerateContextId();
        const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
        const bodyHash = ashHashBody('');
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

        const valid = ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof);
        expect(valid).toBe(true);
      });
    });

    describe('POST Requests', () => {
      it('protects POST request with JSON body', () => {
        const binding = ashNormalizeBinding('POST', '/api/users');
        const nonce = ashGenerateNonce();
        const contextId = ashGenerateContextId();
        const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

        const body = JSON.stringify({ name: 'John Doe', email: 'john@example.com' });
        const canonicalBody = ashCanonicalizeJsonNative(body);
        const bodyHash = ashHashBody(canonicalBody);
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

        const valid = ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof);
        expect(valid).toBe(true);
      });

      it('protects POST with nested JSON body', () => {
        const binding = ashNormalizeBinding('POST', '/api/orders');
        const nonce = ashGenerateNonce();
        const contextId = ashGenerateContextId();
        const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

        const body = JSON.stringify({
          customer: { id: 123, name: 'John' },
          items: [
            { productId: 1, quantity: 2 },
            { productId: 2, quantity: 1 },
          ],
          shipping: { address: '123 Main St', city: 'NYC' },
        });
        const canonicalBody = ashCanonicalizeJsonNative(body);
        const bodyHash = ashHashBody(canonicalBody);
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

        const valid = ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof);
        expect(valid).toBe(true);
      });
    });

    describe('PUT/PATCH Requests', () => {
      it('protects PUT request (full update)', () => {
        const binding = ashNormalizeBinding('PUT', '/api/users/123');
        const nonce = ashGenerateNonce();
        const contextId = ashGenerateContextId();
        const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

        const body = JSON.stringify({ name: 'Jane Doe', email: 'jane@example.com', role: 'admin' });
        const canonicalBody = ashCanonicalizeJsonNative(body);
        const bodyHash = ashHashBody(canonicalBody);
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

        const valid = ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof);
        expect(valid).toBe(true);
      });

      it('protects PATCH request (partial update)', () => {
        const binding = ashNormalizeBinding('PATCH', '/api/users/123');
        const nonce = ashGenerateNonce();
        const contextId = ashGenerateContextId();
        const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

        const body = JSON.stringify({ email: 'new@example.com' });
        const canonicalBody = ashCanonicalizeJsonNative(body);
        const bodyHash = ashHashBody(canonicalBody);
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

        const valid = ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof);
        expect(valid).toBe(true);
      });
    });

    describe('DELETE Requests', () => {
      it('protects DELETE request', () => {
        const binding = ashNormalizeBinding('DELETE', '/api/users/123');
        const nonce = ashGenerateNonce();
        const contextId = ashGenerateContextId();
        const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
        const bodyHash = ashHashBody('');
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

        const valid = ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof);
        expect(valid).toBe(true);
      });

      it('protects DELETE with body', () => {
        const binding = ashNormalizeBinding('DELETE', '/api/bulk');
        const nonce = ashGenerateNonce();
        const contextId = ashGenerateContextId();
        const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

        const body = JSON.stringify({ ids: [1, 2, 3, 4, 5] });
        const canonicalBody = ashCanonicalizeJsonNative(body);
        const bodyHash = ashHashBody(canonicalBody);
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

        const valid = ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof);
        expect(valid).toBe(true);
      });
    });
  });

  describe('GraphQL Patterns', () => {
    it('protects GraphQL query', () => {
      const binding = ashNormalizeBinding('POST', '/graphql');
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

      const body = JSON.stringify({
        query: '{ users { id name email } }',
        variables: {},
      });
      const canonicalBody = ashCanonicalizeJsonNative(body);
      const bodyHash = ashHashBody(canonicalBody);
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

      const valid = ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof);
      expect(valid).toBe(true);
    });

    it('protects GraphQL mutation', () => {
      const binding = ashNormalizeBinding('POST', '/graphql');
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

      const body = JSON.stringify({
        query: 'mutation CreateUser($input: UserInput!) { createUser(input: $input) { id } }',
        variables: { input: { name: 'John', email: 'john@example.com' } },
      });
      const canonicalBody = ashCanonicalizeJsonNative(body);
      const bodyHash = ashHashBody(canonicalBody);
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

      const valid = ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof);
      expect(valid).toBe(true);
    });

    it('protects GraphQL subscription setup', () => {
      const binding = ashNormalizeBinding('POST', '/graphql');
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

      const body = JSON.stringify({
        query: 'subscription OnNewMessage { messageCreated { id content } }',
        variables: {},
      });
      const canonicalBody = ashCanonicalizeJsonNative(body);
      const bodyHash = ashHashBody(canonicalBody);
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

      const valid = ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof);
      expect(valid).toBe(true);
    });
  });

  describe('Webhook Patterns', () => {
    it('protects incoming webhook', () => {
      const binding = ashNormalizeBinding('POST', '/webhooks/stripe');
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

      const body = JSON.stringify({
        type: 'payment.succeeded',
        data: { amount: 1000, currency: 'usd' },
      });
      const canonicalBody = ashCanonicalizeJsonNative(body);
      const bodyHash = ashHashBody(canonicalBody);
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

      const valid = ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof);
      expect(valid).toBe(true);
    });

    it('protects webhook with scoped fields', () => {
      const binding = ashNormalizeBinding('POST', '/webhooks/github');
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

      const payload = {
        action: 'push',
        repository: { full_name: 'user/repo' },
        commits: [{ id: 'abc123', message: 'Update' }],
        sender: { login: 'user' },
      };

      // Only protect action and repository
      const scope = ['action', 'repository.full_name'];
      const { proof, scopeHash } = ashBuildProofScoped(
        clientSecret,
        Math.floor(Date.now() / 1000).toString(),
        binding,
        payload,
        scope
      );

      const valid = ashVerifyProofScoped(
        nonce,
        contextId,
        binding,
        Math.floor(Date.now() / 1000).toString(),
        payload,
        scope,
        scopeHash,
        proof
      );
      expect(valid).toBe(true);
    });
  });

  describe('Multi-Step Transaction Patterns', () => {
    it('protects 3-step transaction with chaining', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const binding = ashNormalizeBinding('POST', '/api/transaction');
      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

      // Step 1: Initialize
      const step1Payload = { step: 'init', orderId: 'ORD-123' };
      const step1Ts = Math.floor(Date.now() / 1000).toString();
      const step1Result = ashBuildProofUnified(
        clientSecret, step1Ts, binding, step1Payload
      );

      expect(ashVerifyProofUnified(
        nonce, contextId, binding, step1Ts, step1Payload, step1Result.proof
      )).toBe(true);

      // Step 2: Process payment (chained to step 1)
      const step2Payload = { step: 'payment', amount: 100 };
      const step2Ts = (parseInt(step1Ts) + 1).toString();
      const step2Result = ashBuildProofUnified(
        clientSecret, step2Ts, binding, step2Payload, [], step1Result.proof
      );

      expect(ashVerifyProofUnified(
        nonce, contextId, binding, step2Ts, step2Payload, step2Result.proof,
        [], '', step1Result.proof, step2Result.chainHash
      )).toBe(true);

      // Step 3: Confirm (chained to step 2)
      const step3Payload = { step: 'confirm', status: 'completed' };
      const step3Ts = (parseInt(step2Ts) + 1).toString();
      const step3Result = ashBuildProofUnified(
        clientSecret, step3Ts, binding, step3Payload, [], step2Result.proof
      );

      expect(ashVerifyProofUnified(
        nonce, contextId, binding, step3Ts, step3Payload, step3Result.proof,
        [], '', step2Result.proof, step3Result.chainHash
      )).toBe(true);
    });

    it('detects out-of-order chain attempt', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const binding = ashNormalizeBinding('POST', '/api/transaction');
      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

      // Step 1
      const step1Payload = { step: 'init' };
      const step1Ts = Math.floor(Date.now() / 1000).toString();
      const step1Result = ashBuildProofUnified(
        clientSecret, step1Ts, binding, step1Payload
      );

      // Step 2
      const step2Payload = { step: 'process' };
      const step2Ts = (parseInt(step1Ts) + 1).toString();
      const step2Result = ashBuildProofUnified(
        clientSecret, step2Ts, binding, step2Payload, [], step1Result.proof
      );

      // Step 3 - try to chain to step 1 instead of step 2 (skip step 2)
      const step3Payload = { step: 'confirm' };
      const step3Ts = (parseInt(step2Ts) + 1).toString();
      const step3Result = ashBuildProofUnified(
        clientSecret, step3Ts, binding, step3Payload, [], step1Result.proof
      );

      // Verify with claim that previous proof was step 2
      const valid = ashVerifyProofUnified(
        nonce, contextId, binding, step3Ts, step3Payload, step3Result.proof,
        [], '', step2Result.proof, step3Result.chainHash
      );
      expect(valid).toBe(false); // Should fail because chainHash doesn't match
    });
  });

  describe('Scoped Request Patterns', () => {
    it('protects sensitive fields in payment request', () => {
      const binding = ashNormalizeBinding('POST', '/api/payments');
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

      const payload = {
        amount: 1000,
        currency: 'USD',
        card: { number: '4111111111111111', cvv: '123' },
        billing: { name: 'John Doe', address: '123 Main St' },
      };

      // Only scope critical fields (not card details)
      const scope = ['amount', 'currency', 'billing.name'];
      const timestamp = Math.floor(Date.now() / 1000).toString();

      const { proof, scopeHash } = ashBuildProofScoped(
        clientSecret, timestamp, binding, payload, scope
      );

      const valid = ashVerifyProofScoped(
        nonce, contextId, binding, timestamp, payload, scope, scopeHash, proof
      );
      expect(valid).toBe(true);

      // Verify that non-scoped fields can change without affecting proof
      const modifiedPayload = {
        ...payload,
        card: { number: '5555555555554444', cvv: '456' }, // Changed card
      };

      const stillValid = ashVerifyProofScoped(
        nonce, contextId, binding, timestamp, modifiedPayload, scope, scopeHash, proof
      );
      expect(stillValid).toBe(true); // Still valid because card is not in scope
    });

    it('detects tampering of scoped fields', () => {
      const binding = ashNormalizeBinding('POST', '/api/transfer');
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

      const payload = {
        from: 'ACC-001',
        to: 'ACC-002',
        amount: 100,
      };

      const scope = ['from', 'to', 'amount'];
      const timestamp = Math.floor(Date.now() / 1000).toString();

      const { proof, scopeHash } = ashBuildProofScoped(
        clientSecret, timestamp, binding, payload, scope
      );

      // Tamper with scoped field
      const tamperedPayload = { ...payload, amount: 10000 };

      const valid = ashVerifyProofScoped(
        nonce, contextId, binding, timestamp, tamperedPayload, scope, scopeHash, proof
      );
      expect(valid).toBe(false); // Should fail because amount changed
    });
  });

  describe('Client-Server Flow Simulation', () => {
    let server: MockServer;

    beforeEach(() => {
      server = new MockServer();
    });

    it('simulates complete request flow', async () => {
      const binding = ashNormalizeBinding('POST', '/api/orders');

      // Server creates context
      const ctx = await server.createContext(binding);

      // Client uses context to build proof
      const client = new MockClient(ctx);
      const body = JSON.stringify({ product: 'Widget', quantity: 5 });
      const { proof, timestamp, bodyHash } = client.buildProof(body);

      // Server verifies proof
      const valid = server.verify(ctx.nonce, ctx.contextId, binding, timestamp, bodyHash, proof);
      expect(valid).toBe(true);
    });

    it('rejects proof with wrong context', async () => {
      const binding = ashNormalizeBinding('POST', '/api/orders');

      // Server creates two contexts
      const ctx1 = await server.createContext(binding);
      const ctx2 = await server.createContext(binding);

      // Client uses ctx1 to build proof
      const client = new MockClient(ctx1);
      const body = JSON.stringify({ product: 'Widget' });
      const { proof, timestamp, bodyHash } = client.buildProof(body);

      // Server tries to verify with ctx2's nonce
      const valid = server.verify(ctx2.nonce, ctx1.contextId, binding, timestamp, bodyHash, proof);
      expect(valid).toBe(false);
    });
  });

  describe('Error Handling Patterns', () => {
    it('handles expired timestamp', () => {
      const binding = ashNormalizeBinding('POST', '/api/test');
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

      // Use timestamp from 10 minutes ago
      const oldTimestamp = (Math.floor(Date.now() / 1000) - 600).toString();
      const bodyHash = ashHashBody('{}');
      const proof = ashBuildProof(clientSecret, oldTimestamp, binding, bodyHash);

      // Verify timestamp freshness
      expect(() => ashValidateTimestamp(oldTimestamp, 300)).toThrow(/expired/);
    });

    it('handles malformed JSON body', () => {
      const malformedBodies = [
        '{invalid}',
        '{"key": undefined}',
        'not json',
      ];

      for (const body of malformedBodies) {
        expect(() => ashCanonicalizeJsonNative(body)).toThrow();
      }
    });

    it('handles empty body consistently', () => {
      const binding = ashNormalizeBinding('GET', '/api/test');
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

      const emptyBodyHash = ashHashBody('');
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const proof = ashBuildProof(clientSecret, timestamp, binding, emptyBodyHash);

      const valid = ashVerifyProof(nonce, contextId, binding, timestamp, emptyBodyHash, proof);
      expect(valid).toBe(true);
    });
  });

  describe('Real-World Use Cases', () => {
    it('e-commerce checkout flow', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();

      // Step 1: Create order
      const createBinding = ashNormalizeBinding('POST', '/api/checkout/create');
      const createSecret = ashDeriveClientSecret(nonce, contextId, createBinding);
      const createPayload = { items: [{ sku: 'SKU-001', qty: 2 }], total: 50 };
      const createBody = ashCanonicalizeJsonNative(JSON.stringify(createPayload));
      const createHash = ashHashBody(createBody);
      const createTs = Math.floor(Date.now() / 1000).toString();
      const createProof = ashBuildProof(createSecret, createTs, createBinding, createHash);

      expect(ashVerifyProof(nonce, contextId, createBinding, createTs, createHash, createProof)).toBe(true);

      // Step 2: Confirm payment
      const payBinding = ashNormalizeBinding('POST', '/api/checkout/pay');
      const paySecret = ashDeriveClientSecret(nonce, contextId, payBinding);
      const payPayload = { paymentMethod: 'card', token: 'tok_123' };
      const payBody = ashCanonicalizeJsonNative(JSON.stringify(payPayload));
      const payHash = ashHashBody(payBody);
      const payTs = (parseInt(createTs) + 1).toString();
      const payProof = ashBuildProof(paySecret, payTs, payBinding, payHash);

      expect(ashVerifyProof(nonce, contextId, payBinding, payTs, payHash, payProof)).toBe(true);
    });

    it('user authentication flow', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const binding = ashNormalizeBinding('POST', '/api/auth/login');
      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

      const payload = { email: 'user@example.com', password: 'hashed_password' };
      const body = ashCanonicalizeJsonNative(JSON.stringify(payload));
      const bodyHash = ashHashBody(body);
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

      expect(ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof)).toBe(true);
    });

    it('file upload metadata protection', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const binding = ashNormalizeBinding('POST', '/api/files/upload');
      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

      // Protect file metadata (actual file content hashed separately)
      const metadata = {
        filename: 'document.pdf',
        size: 1024000,
        contentType: 'application/pdf',
        checksum: 'sha256:abc123...',
      };

      const body = ashCanonicalizeJsonNative(JSON.stringify(metadata));
      const bodyHash = ashHashBody(body);
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

      expect(ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof)).toBe(true);
    });

    it('API rate limit with proof', () => {
      const nonce = ashGenerateNonce();
      const contextId = ashGenerateContextId();
      const binding = ashNormalizeBinding('GET', '/api/data');
      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const bodyHash = ashHashBody('');

      // Simulate 10 requests within rate limit window
      for (let i = 0; i < 10; i++) {
        const timestamp = (Math.floor(Date.now() / 1000) + i).toString();
        const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);
        const valid = ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof);
        expect(valid).toBe(true);
      }
    });
  });
});
