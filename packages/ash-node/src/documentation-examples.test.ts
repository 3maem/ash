/**
 * ASH SDK Documentation Examples Tests
 *
 * Tests all code examples from documentation to ensure they work correctly.
 * If these tests fail, the documentation needs to be updated.
 */

import { describe, it, expect, beforeAll } from 'vitest';
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
  AshMemoryStore,
  ashValidateTimestamp,
} from './index';

beforeAll(() => {
  ashInit();
});

// =========================================================================
// README QUICK START EXAMPLE
// =========================================================================

describe('Documentation: README Quick Start', () => {
  it('Quick Start example should work', () => {
    // Initialize (should be done once at app startup)
    ashInit();

    // Server: Generate context for client
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/transfer|';

    // Server sends nonce and contextId to client
    // Client: Build proof
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const body = JSON.stringify({ amount: 100, recipient: 'alice' });
    const canonicalBody = ashCanonicalizeJson(body);
    const bodyHash = ashHashBody(canonicalBody);
    const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

    // Client sends proof, timestamp, and body to server
    // Server: Verify proof
    const isValid = ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof);

    expect(isValid).toBe(true);
  });
});

// =========================================================================
// BASIC USAGE EXAMPLES
// =========================================================================

describe('Documentation: Basic Usage', () => {
  it('JSON canonicalization example should work', () => {
    const json = '{"z":1,"a":2,"m":3}';
    const canonical = ashCanonicalizeJson(json);

    expect(canonical).toBe('{"a":2,"m":3,"z":1}');
  });

  it('Query string canonicalization example should work', () => {
    const query = 'z=3&a=1&b=2';
    const canonical = ashCanonicalizeQuery(query);

    expect(canonical).toBe('a=1&b=2&z=3');
  });

  it('Binding normalization example should work', () => {
    const binding = ashNormalizeBinding('post', '/api/users/', 'page=1&sort=name');

    expect(binding).toMatch(/^POST\|/);
    expect(binding).toContain('|/api/users|');
  });

  it('Body hashing example should work', () => {
    const body = '{"key":"value"}';
    const hash = ashHashBody(body);

    expect(hash).toHaveLength(64);
    expect(/^[0-9a-f]+$/.test(hash)).toBe(true);
  });
});

// =========================================================================
// PROOF LIFECYCLE EXAMPLE
// =========================================================================

describe('Documentation: Proof Lifecycle', () => {
  it('Full proof lifecycle example should work', async () => {
    // === SERVER SETUP ===
    const store = new AshMemoryStore();

    // Create a new context for the client
    const ctx = await store.create({
      binding: 'POST|/api/transfer|',
      ttlMs: 300000, // 5 minutes
    });

    // Send ctx.id and ctx.nonce to client (via secure channel)
    const { id: contextId, nonce, binding } = ctx;

    // === CLIENT SIDE ===
    // Receive contextId, nonce, binding from server

    // Prepare the request
    const requestBody = { amount: 100, recipient: 'alice@example.com' };
    const canonicalBody = ashCanonicalizeJson(JSON.stringify(requestBody));
    const bodyHash = ashHashBody(canonicalBody);
    const timestamp = Math.floor(Date.now() / 1000).toString();

    // Derive client secret and build proof
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

    // Send request with proof headers to server
    const request = {
      body: requestBody,
      headers: {
        'X-ASH-Proof': proof,
        'X-ASH-Timestamp': timestamp,
        'X-ASH-Context-Id': contextId,
      },
    };

    // === SERVER VERIFICATION ===
    // Receive request with proof
    const receivedContextId = request.headers['X-ASH-Context-Id'];
    const receivedProof = request.headers['X-ASH-Proof'];
    const receivedTimestamp = request.headers['X-ASH-Timestamp'];
    const receivedBody = request.body;

    // Get context from store
    const storedCtx = await store.get(receivedContextId);
    expect(storedCtx).not.toBeNull();

    // Verify binding matches
    expect(storedCtx!.binding).toBe(binding);

    // Rebuild body hash from received body
    const receivedCanonicalBody = ashCanonicalizeJson(JSON.stringify(receivedBody));
    const receivedBodyHash = ashHashBody(receivedCanonicalBody);

    // Verify the proof
    const isValid = ashVerifyProofV21(
      storedCtx!.nonce,
      receivedContextId,
      storedCtx!.binding,
      receivedTimestamp,
      receivedBodyHash,
      receivedProof
    );

    expect(isValid).toBe(true);

    // Consume context (single-use)
    const consumed = await store.consume(receivedContextId);
    expect(consumed).toBe(true);

    // Replay should fail
    const replay = await store.consume(receivedContextId);
    expect(replay).toBe(false);
  });
});

// =========================================================================
// SCOPED PROOF EXAMPLE
// =========================================================================

describe('Documentation: Scoped Proofs', () => {
  it('Scoped proof example should work', () => {
    // Setup
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/transfer|';
    const timestamp = Math.floor(Date.now() / 1000).toString();

    // Full payload with many fields
    const payload = {
      amount: 1000,
      recipient: 'alice@example.com',
      memo: 'Monthly payment',
      reference: 'INV-2024-001',
      metadata: {
        source: 'web',
        ip: '192.168.1.1',
      },
    };

    // Only protect critical fields
    const scope = ['amount', 'recipient'];

    // Build scoped proof
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const { proof, scopeHash } = ashBuildProofScoped(
      clientSecret,
      timestamp,
      binding,
      payload,
      scope
    );

    // Verify scoped proof
    const isValid = ashVerifyProofScoped(
      nonce,
      contextId,
      binding,
      timestamp,
      payload,
      scope,
      scopeHash,
      proof
    );

    expect(isValid).toBe(true);

    // Non-scoped field changes don't invalidate proof
    const modifiedPayload = {
      ...payload,
      memo: 'Updated memo', // Changed!
    };

    const stillValid = ashVerifyProofScoped(
      nonce,
      contextId,
      binding,
      timestamp,
      modifiedPayload,
      scope,
      scopeHash,
      proof
    );

    expect(stillValid).toBe(true);

    // Scoped field changes DO invalidate proof
    const tamperedPayload = {
      ...payload,
      amount: 10000, // Tampered!
    };

    const invalid = ashVerifyProofScoped(
      nonce,
      contextId,
      binding,
      timestamp,
      tamperedPayload,
      scope,
      scopeHash,
      proof
    );

    expect(invalid).toBe(false);
  });
});

// =========================================================================
// CHAINED PROOF EXAMPLE
// =========================================================================

describe('Documentation: Chained Proofs', () => {
  it('Chained proof example should work', () => {
    // Setup
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const timestamp = Math.floor(Date.now() / 1000).toString();

    // Step 1: Initiate transaction
    const binding1 = 'POST|/api/transaction/initiate|';
    const payload1 = { action: 'initiate', amount: 1000 };
    const clientSecret1 = ashDeriveClientSecret(nonce, contextId, binding1);

    const step1 = ashBuildProofUnified(
      clientSecret1,
      timestamp,
      binding1,
      payload1,
      ['action', 'amount'] // Scope
    );

    // Verify step 1
    const step1Valid = ashVerifyProofUnified(
      nonce,
      contextId,
      binding1,
      timestamp,
      payload1,
      step1.proof,
      ['action', 'amount'],
      step1.scopeHash,
      undefined, // No previous proof
      step1.chainHash
    );
    expect(step1Valid).toBe(true);

    // Step 2: Confirm transaction (chained to step 1)
    const binding2 = 'POST|/api/transaction/confirm|';
    const payload2 = { action: 'confirm', otp: '123456' };
    const clientSecret2 = ashDeriveClientSecret(nonce, contextId, binding2);

    const step2 = ashBuildProofUnified(
      clientSecret2,
      timestamp,
      binding2,
      payload2,
      ['action'],
      step1.proof // Chain to previous proof
    );

    // Verify step 2 with chain
    const step2Valid = ashVerifyProofUnified(
      nonce,
      contextId,
      binding2,
      timestamp,
      payload2,
      step2.proof,
      ['action'],
      step2.scopeHash,
      step1.proof, // Previous proof in chain
      step2.chainHash
    );
    expect(step2Valid).toBe(true);

    // Cannot verify with wrong previous proof
    const wrongChain = ashVerifyProofUnified(
      nonce,
      contextId,
      binding2,
      timestamp,
      payload2,
      step2.proof,
      ['action'],
      step2.scopeHash,
      'a'.repeat(64), // Wrong previous proof!
      step2.chainHash
    );
    expect(wrongChain).toBe(false);
  });
});

// =========================================================================
// CONTEXT STORE EXAMPLE
// =========================================================================

describe('Documentation: Context Store', () => {
  it('Memory store example should work', async () => {
    // Create store
    const store = new AshMemoryStore();

    // Create context
    const ctx = await store.create({
      binding: 'POST|/api/payment|',
      ttlMs: 60000, // 1 minute
      metadata: {
        userId: 'user123',
        action: 'payment',
      },
    });

    // Context has required properties
    expect(ctx.id).toMatch(/^ctx_/);
    expect(ctx.nonce).toHaveLength(64);
    expect(ctx.binding).toBe('POST|/api/payment|');
    expect(ctx.metadata).toEqual({ userId: 'user123', action: 'payment' });

    // Get context
    const retrieved = await store.get(ctx.id);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.id).toBe(ctx.id);

    // Consume context (single-use)
    const consumed = await store.consume(ctx.id);
    expect(consumed).toBe(true);

    // Cannot consume again
    const consumeAgain = await store.consume(ctx.id);
    expect(consumeAgain).toBe(false);
  });
});

// =========================================================================
// ERROR HANDLING EXAMPLE
// =========================================================================

describe('Documentation: Error Handling', () => {
  it('Error handling example should work', () => {
    // Invalid JSON
    expect(() => {
      ashCanonicalizeJson('not valid json');
    }).toThrow();

    // Empty nonce
    expect(() => {
      ashDeriveClientSecret('', 'ctx_test', 'GET|/api|');
    }).toThrow();

    // Invalid timestamp
    expect(() => {
      ashValidateTimestamp('not-a-number');
    }).toThrow();

    // Expired timestamp
    const oldTimestamp = (Math.floor(Date.now() / 1000) - 3600).toString();
    expect(() => {
      ashValidateTimestamp(oldTimestamp);
    }).toThrow();

    // Verification failure returns false (doesn't throw)
    const nonce = ashGenerateNonce();
    const contextId = ashGenerateContextId();
    const binding = 'POST|/api/test|';
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const bodyHash = ashHashBody('{}');
    const wrongProof = 'a'.repeat(64);

    const isValid = ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, wrongProof);
    expect(isValid).toBe(false);
  });
});

// =========================================================================
// URL-ENCODED FORM DATA EXAMPLE
// =========================================================================

describe('Documentation: URL-Encoded Forms', () => {
  it('Form data example should work', () => {
    // URL-encoded form data
    const formData = 'username=john&password=secret123&remember=true';

    // Canonicalize (sorts parameters, handles + as %2B)
    const canonical = ashCanonicalizeUrlencoded(formData);

    // Hash the canonical form
    const hash = ashHashBody(canonical);

    expect(hash).toHaveLength(64);

    // The canonical form is sorted
    expect(canonical).toMatch(/^password=.*&remember=.*&username=/);
  });
});

// =========================================================================
// COMPLETE API FLOW EXAMPLE
// =========================================================================

describe('Documentation: Complete API Flow', () => {
  it('Complete flow example should work', async () => {
    // 1. Initialize SDK
    ashInit();

    // 2. Server creates context
    const store = new AshMemoryStore();
    const ctx = await store.create({
      binding: ashNormalizeBinding('POST', '/api/v1/transfer', 'confirm=true'),
      ttlMs: 300000,
    });

    // 3. Server sends context info to client (e.g., in response headers)
    const clientReceives = {
      contextId: ctx.id,
      nonce: ctx.nonce,
      binding: ctx.binding,
    };

    // 4. Client prepares request
    const requestBody = {
      from: 'account-123',
      to: 'account-456',
      amount: 500,
      currency: 'USD',
    };

    // 5. Client builds proof
    const canonicalBody = ashCanonicalizeJson(JSON.stringify(requestBody));
    const bodyHash = ashHashBody(canonicalBody);
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const clientSecret = ashDeriveClientSecret(
      clientReceives.nonce,
      clientReceives.contextId,
      clientReceives.binding
    );
    const proof = ashBuildProofV21(clientSecret, timestamp, clientReceives.binding, bodyHash);

    // 6. Client sends request
    const apiRequest = {
      method: 'POST',
      path: '/api/v1/transfer?confirm=true',
      headers: {
        'Content-Type': 'application/json',
        'X-ASH-Context-Id': clientReceives.contextId,
        'X-ASH-Timestamp': timestamp,
        'X-ASH-Proof': proof,
      },
      body: requestBody,
    };

    // 7. Server receives and validates
    const storedCtx = await store.get(apiRequest.headers['X-ASH-Context-Id']);
    expect(storedCtx).not.toBeNull();

    const serverCanonicalBody = ashCanonicalizeJson(JSON.stringify(apiRequest.body));
    const serverBodyHash = ashHashBody(serverCanonicalBody);

    const isValid = ashVerifyProofV21(
      storedCtx!.nonce,
      apiRequest.headers['X-ASH-Context-Id'],
      storedCtx!.binding,
      apiRequest.headers['X-ASH-Timestamp'],
      serverBodyHash,
      apiRequest.headers['X-ASH-Proof']
    );

    expect(isValid).toBe(true);

    // 8. Server consumes context
    const consumed = await store.consume(apiRequest.headers['X-ASH-Context-Id']);
    expect(consumed).toBe(true);
  });
});

console.log('Documentation Examples Tests loaded');
