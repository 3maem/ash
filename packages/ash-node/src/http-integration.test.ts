/**
 * ASH SDK HTTP Integration Tests
 *
 * Tests real-world HTTP request signing and verification scenarios.
 * Simulates Express/Fastify middleware and fetch/axios interceptors.
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
  AshMemoryStore,
  ashVerifyProofWithFreshness,
} from './index';

beforeAll(() => {
  ashInit();
});

// =========================================================================
// SIMULATED HTTP REQUEST TYPES
// =========================================================================

interface MockHttpRequest {
  method: string;
  path: string;
  query?: Record<string, string>;
  headers: Record<string, string>;
  body?: string | Record<string, unknown>;
}

interface MockHttpResponse {
  statusCode: number;
  body: unknown;
}

// =========================================================================
// HELPER FUNCTIONS (Simulating Middleware)
// =========================================================================

function buildQueryString(query?: Record<string, string>): string {
  if (!query || Object.keys(query).length === 0) return '';
  return Object.entries(query)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
}

function signRequest(
  req: MockHttpRequest,
  nonce: string,
  contextId: string
): { proof: string; timestamp: string; bodyHash: string } {
  const queryString = buildQueryString(req.query);
  const binding = ashNormalizeBinding(req.method, req.path, queryString);

  let bodyString = '';
  if (req.body) {
    if (typeof req.body === 'string') {
      const contentType = req.headers['content-type'] || '';
      if (contentType.includes('application/x-www-form-urlencoded')) {
        bodyString = ashCanonicalizeUrlencoded(req.body);
      } else {
        bodyString = canonicalizeJsonNative(req.body);
      }
    } else {
      bodyString = canonicalizeJsonNative(JSON.stringify(req.body));
    }
  }

  const bodyHash = ashHashBody(bodyString);
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
  const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

  return { proof, timestamp, bodyHash };
}

function verifyRequest(
  req: MockHttpRequest,
  nonce: string,
  contextId: string,
  proof: string,
  timestamp: string
): boolean {
  const queryString = buildQueryString(req.query);
  const binding = ashNormalizeBinding(req.method, req.path, queryString);

  let bodyString = '';
  if (req.body) {
    if (typeof req.body === 'string') {
      const contentType = req.headers['content-type'] || '';
      if (contentType.includes('application/x-www-form-urlencoded')) {
        bodyString = ashCanonicalizeUrlencoded(req.body);
      } else {
        bodyString = canonicalizeJsonNative(req.body);
      }
    } else {
      bodyString = canonicalizeJsonNative(JSON.stringify(req.body));
    }
  }

  const bodyHash = ashHashBody(bodyString);
  return ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof);
}

// =========================================================================
// HTTP METHOD TESTS
// =========================================================================

describe('HTTP Integration: Request Methods', () => {
  const nonce = crypto.randomBytes(32).toString('hex');
  const contextId = 'ctx_http_test';

  it('should sign and verify GET request', () => {
    const req: MockHttpRequest = {
      method: 'GET',
      path: '/api/users',
      headers: {},
    };

    const { proof, timestamp } = signRequest(req, nonce, contextId);
    const isValid = verifyRequest(req, nonce, contextId, proof, timestamp);

    expect(isValid).toBe(true);
  });

  it('should sign and verify GET request with query parameters', () => {
    const req: MockHttpRequest = {
      method: 'GET',
      path: '/api/search',
      query: { q: 'test', page: '1', sort: 'name' },
      headers: {},
    };

    const { proof, timestamp } = signRequest(req, nonce, contextId);
    const isValid = verifyRequest(req, nonce, contextId, proof, timestamp);

    expect(isValid).toBe(true);
  });

  it('should sign and verify POST request with JSON body', () => {
    const req: MockHttpRequest = {
      method: 'POST',
      path: '/api/users',
      headers: { 'content-type': 'application/json' },
      body: { name: 'John Doe', email: 'john@example.com' },
    };

    const { proof, timestamp } = signRequest(req, nonce, contextId);
    const isValid = verifyRequest(req, nonce, contextId, proof, timestamp);

    expect(isValid).toBe(true);
  });

  it('should sign and verify POST request with form-urlencoded body', () => {
    const req: MockHttpRequest = {
      method: 'POST',
      path: '/api/login',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'username=john&password=secret123',
    };

    const { proof, timestamp } = signRequest(req, nonce, contextId);
    const isValid = verifyRequest(req, nonce, contextId, proof, timestamp);

    expect(isValid).toBe(true);
  });

  it('should sign and verify PUT request', () => {
    const req: MockHttpRequest = {
      method: 'PUT',
      path: '/api/users/123',
      headers: { 'content-type': 'application/json' },
      body: { name: 'Jane Doe' },
    };

    const { proof, timestamp } = signRequest(req, nonce, contextId);
    const isValid = verifyRequest(req, nonce, contextId, proof, timestamp);

    expect(isValid).toBe(true);
  });

  it('should sign and verify PATCH request', () => {
    const req: MockHttpRequest = {
      method: 'PATCH',
      path: '/api/users/123',
      headers: { 'content-type': 'application/json' },
      body: { email: 'jane@example.com' },
    };

    const { proof, timestamp } = signRequest(req, nonce, contextId);
    const isValid = verifyRequest(req, nonce, contextId, proof, timestamp);

    expect(isValid).toBe(true);
  });

  it('should sign and verify DELETE request', () => {
    const req: MockHttpRequest = {
      method: 'DELETE',
      path: '/api/users/123',
      headers: {},
    };

    const { proof, timestamp } = signRequest(req, nonce, contextId);
    const isValid = verifyRequest(req, nonce, contextId, proof, timestamp);

    expect(isValid).toBe(true);
  });

  it('should sign and verify HEAD request', () => {
    const req: MockHttpRequest = {
      method: 'HEAD',
      path: '/api/status',
      headers: {},
    };

    const { proof, timestamp } = signRequest(req, nonce, contextId);
    const isValid = verifyRequest(req, nonce, contextId, proof, timestamp);

    expect(isValid).toBe(true);
  });

  it('should sign and verify OPTIONS request', () => {
    const req: MockHttpRequest = {
      method: 'OPTIONS',
      path: '/api/users',
      headers: {},
    };

    const { proof, timestamp } = signRequest(req, nonce, contextId);
    const isValid = verifyRequest(req, nonce, contextId, proof, timestamp);

    expect(isValid).toBe(true);
  });
});

// =========================================================================
// EXPRESS MIDDLEWARE SIMULATION
// =========================================================================

describe('HTTP Integration: Express Middleware Simulation', () => {
  let store: AshMemoryStore;

  beforeEach(() => {
    store = new AshMemoryStore();
  });

  // Simulated Express middleware
  async function ashMiddleware(
    req: MockHttpRequest,
    contextId: string
  ): Promise<{ success: boolean; error?: string }> {
    try {
      // Extract ASH headers
      const proof = req.headers['x-ash-proof'];
      const timestamp = req.headers['x-ash-timestamp'];

      if (!proof || !timestamp) {
        return { success: false, error: 'Missing ASH headers' };
      }

      // Get context from store
      const context = await store.get(contextId);
      if (!context) {
        return { success: false, error: 'Context not found' };
      }

      // Verify binding matches
      const queryString = buildQueryString(req.query);
      const requestBinding = ashNormalizeBinding(req.method, req.path, queryString);

      if (requestBinding !== context.binding) {
        return { success: false, error: 'Binding mismatch' };
      }

      // Verify proof
      let bodyString = '';
      if (req.body) {
        if (typeof req.body === 'string') {
          const contentType = req.headers['content-type'] || '';
          if (contentType.includes('application/x-www-form-urlencoded')) {
            bodyString = ashCanonicalizeUrlencoded(req.body);
          } else {
            bodyString = canonicalizeJsonNative(req.body);
          }
        } else {
          bodyString = canonicalizeJsonNative(JSON.stringify(req.body));
        }
      }

      const bodyHash = ashHashBody(bodyString);
      const isValid = ashVerifyProofV21(
        context.nonce, contextId, context.binding, timestamp, bodyHash, proof
      );

      if (!isValid) {
        return { success: false, error: 'Invalid proof' };
      }

      // Consume context (single-use)
      const consumed = await store.consume(contextId);
      if (!consumed) {
        return { success: false, error: 'Context already consumed' };
      }

      return { success: true };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  it('should process valid request through middleware', async () => {
    // Setup: Create context (store generates its own nonce)
    const binding = 'POST|/api/transfer|';
    const ctx = await store.create({ binding, ttlMs: 60000 });

    // Client: Build proof using ctx.nonce from the store
    const body = { amount: 100, recipient: 'alice' };
    const bodyString = canonicalizeJsonNative(JSON.stringify(body));
    const bodyHash = ashHashBody(bodyString);
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const clientSecret = ashDeriveClientSecret(ctx.nonce, ctx.id, binding);
    const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

    // Request with ASH headers
    const req: MockHttpRequest = {
      method: 'POST',
      path: '/api/transfer',
      headers: {
        'content-type': 'application/json',
        'x-ash-proof': proof,
        'x-ash-timestamp': timestamp,
      },
      body,
    };

    const result = await ashMiddleware(req, ctx.id);
    expect(result.success).toBe(true);
  });

  it('should reject request with missing proof header', async () => {
    const binding = 'POST|/api/transfer|';
    const ctx = await store.create({ binding, ttlMs: 60000 });

    const req: MockHttpRequest = {
      method: 'POST',
      path: '/api/transfer',
      headers: {
        'content-type': 'application/json',
        'x-ash-timestamp': Math.floor(Date.now() / 1000).toString(),
      },
      body: { amount: 100 },
    };

    const result = await ashMiddleware(req, ctx.id);
    expect(result.success).toBe(false);
    expect(result.error).toContain('Missing');
  });

  it('should reject request with wrong binding', async () => {
    const binding = 'POST|/api/transfer|';
    const ctx = await store.create({ binding, ttlMs: 60000 });

    // Build proof for correct binding
    const bodyHash = ashHashBody('{}');
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const clientSecret = ashDeriveClientSecret(ctx.nonce, ctx.id, binding);
    const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

    // Request to DIFFERENT endpoint
    const req: MockHttpRequest = {
      method: 'POST',
      path: '/api/admin/delete',  // Wrong path!
      headers: {
        'content-type': 'application/json',
        'x-ash-proof': proof,
        'x-ash-timestamp': timestamp,
      },
      body: {},
    };

    const result = await ashMiddleware(req, ctx.id);
    expect(result.success).toBe(false);
    expect(result.error).toContain('Binding mismatch');
  });

  it('should reject replay attack', async () => {
    const binding = 'POST|/api/transfer|';
    const ctx = await store.create({ binding, ttlMs: 60000 });

    const body = { amount: 100 };
    const bodyString = canonicalizeJsonNative(JSON.stringify(body));
    const bodyHash = ashHashBody(bodyString);
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const clientSecret = ashDeriveClientSecret(ctx.nonce, ctx.id, binding);
    const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

    const req: MockHttpRequest = {
      method: 'POST',
      path: '/api/transfer',
      headers: {
        'content-type': 'application/json',
        'x-ash-proof': proof,
        'x-ash-timestamp': timestamp,
      },
      body,
    };

    // First request succeeds
    const result1 = await ashMiddleware(req, ctx.id);
    expect(result1.success).toBe(true);

    // Replay attack fails
    const result2 = await ashMiddleware(req, ctx.id);
    expect(result2.success).toBe(false);
    expect(result2.error).toContain('consumed');
  });
});

// =========================================================================
// FETCH/AXIOS INTERCEPTOR SIMULATION
// =========================================================================

describe('HTTP Integration: Fetch Interceptor Simulation', () => {
  // Simulated fetch with ASH signing
  async function ashFetch(
    url: string,
    options: {
      method?: string;
      headers?: Record<string, string>;
      body?: string;
    },
    nonce: string,
    contextId: string
  ): Promise<{ url: string; options: typeof options & { headers: Record<string, string> } }> {
    const urlObj = new URL(url, 'http://localhost');
    const method = options.method || 'GET';
    const path = urlObj.pathname;
    const queryString = urlObj.search.slice(1); // Remove leading ?

    const binding = ashNormalizeBinding(method, path, queryString);

    let bodyHash: string;
    if (options.body) {
      const contentType = options.headers?.['content-type'] || 'application/json';
      if (contentType.includes('application/x-www-form-urlencoded')) {
        bodyHash = ashHashBody(ashCanonicalizeUrlencoded(options.body));
      } else {
        bodyHash = ashHashBody(canonicalizeJsonNative(options.body));
      }
    } else {
      bodyHash = ashHashBody('');
    }

    const timestamp = Math.floor(Date.now() / 1000).toString();
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

    return {
      url,
      options: {
        ...options,
        headers: {
          ...options.headers,
          'x-ash-proof': proof,
          'x-ash-timestamp': timestamp,
          'x-ash-context-id': contextId,
        },
      },
    };
  }

  it('should add ASH headers to fetch request', async () => {
    const nonce = crypto.randomBytes(32).toString('hex');
    const contextId = 'ctx_fetch_test';

    const result = await ashFetch(
      'http://api.example.com/users?page=1',
      { method: 'GET' },
      nonce,
      contextId
    );

    expect(result.options.headers['x-ash-proof']).toHaveLength(64);
    expect(result.options.headers['x-ash-timestamp']).toMatch(/^\d+$/);
    expect(result.options.headers['x-ash-context-id']).toBe(contextId);
  });

  it('should sign POST request with body', async () => {
    const nonce = crypto.randomBytes(32).toString('hex');
    const contextId = 'ctx_fetch_post';

    const result = await ashFetch(
      'http://api.example.com/users',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'John' }),
      },
      nonce,
      contextId
    );

    // Verify the proof is valid
    const binding = ashNormalizeBinding('POST', '/users', '');
    const bodyHash = ashHashBody(canonicalizeJsonNative(JSON.stringify({ name: 'John' })));

    const isValid = ashVerifyProofV21(
      nonce,
      contextId,
      binding,
      result.options.headers['x-ash-timestamp'],
      bodyHash,
      result.options.headers['x-ash-proof']
    );

    expect(isValid).toBe(true);
  });
});

// =========================================================================
// SPECIAL CASES
// =========================================================================

describe('HTTP Integration: Special Cases', () => {
  const nonce = crypto.randomBytes(32).toString('hex');
  const contextId = 'ctx_special';

  it('should handle empty body', () => {
    const req: MockHttpRequest = {
      method: 'POST',
      path: '/api/empty',
      headers: { 'content-type': 'application/json' },
      body: '',
    };

    const { proof, timestamp } = signRequest(req, nonce, contextId);

    // Manually verify
    const binding = ashNormalizeBinding('POST', '/api/empty', '');
    const bodyHash = ashHashBody('');
    const isValid = ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof);

    expect(isValid).toBe(true);
  });

  it('should handle null body', () => {
    const req: MockHttpRequest = {
      method: 'POST',
      path: '/api/null',
      headers: { 'content-type': 'application/json' },
      body: 'null',
    };

    const { proof, timestamp } = signRequest(req, nonce, contextId);
    const isValid = verifyRequest(req, nonce, contextId, proof, timestamp);

    expect(isValid).toBe(true);
  });

  it('should handle deeply nested JSON body', () => {
    const deepBody = {
      level1: {
        level2: {
          level3: {
            level4: {
              value: 'deep',
            },
          },
        },
      },
    };

    const req: MockHttpRequest = {
      method: 'POST',
      path: '/api/deep',
      headers: { 'content-type': 'application/json' },
      body: deepBody,
    };

    const { proof, timestamp } = signRequest(req, nonce, contextId);
    const isValid = verifyRequest(req, nonce, contextId, proof, timestamp);

    expect(isValid).toBe(true);
  });

  it('should handle array body', () => {
    const req: MockHttpRequest = {
      method: 'POST',
      path: '/api/batch',
      headers: { 'content-type': 'application/json' },
      body: [1, 2, 3, 4, 5],
    };

    const { proof, timestamp } = signRequest(req, nonce, contextId);
    const isValid = verifyRequest(req, nonce, contextId, proof, timestamp);

    expect(isValid).toBe(true);
  });

  it('should handle Unicode in path', () => {
    const req: MockHttpRequest = {
      method: 'GET',
      path: '/api/users/日本語',
      headers: {},
    };

    const { proof, timestamp } = signRequest(req, nonce, contextId);
    const isValid = verifyRequest(req, nonce, contextId, proof, timestamp);

    expect(isValid).toBe(true);
  });

  it('should handle Unicode in query parameters', () => {
    const req: MockHttpRequest = {
      method: 'GET',
      path: '/api/search',
      query: { q: '日本語', lang: 'ja' },
      headers: {},
    };

    const { proof, timestamp } = signRequest(req, nonce, contextId);
    const isValid = verifyRequest(req, nonce, contextId, proof, timestamp);

    expect(isValid).toBe(true);
  });

  it('should handle special characters in form data', () => {
    const req: MockHttpRequest = {
      method: 'POST',
      path: '/api/form',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'message=Hello%20World%21&special=%26%3D%3F',
    };

    const { proof, timestamp } = signRequest(req, nonce, contextId);
    const isValid = verifyRequest(req, nonce, contextId, proof, timestamp);

    expect(isValid).toBe(true);
  });
});

// =========================================================================
// CONTENT TYPE HANDLING
// =========================================================================

describe('HTTP Integration: Content Type Handling', () => {
  const nonce = crypto.randomBytes(32).toString('hex');
  const contextId = 'ctx_content';

  it('should handle application/json', () => {
    const req: MockHttpRequest = {
      method: 'POST',
      path: '/api/json',
      headers: { 'content-type': 'application/json' },
      body: { key: 'value' },
    };

    const { proof, timestamp } = signRequest(req, nonce, contextId);
    const isValid = verifyRequest(req, nonce, contextId, proof, timestamp);

    expect(isValid).toBe(true);
  });

  it('should handle application/json with charset', () => {
    const req: MockHttpRequest = {
      method: 'POST',
      path: '/api/json',
      headers: { 'content-type': 'application/json; charset=utf-8' },
      body: { key: 'value' },
    };

    const { proof, timestamp } = signRequest(req, nonce, contextId);
    const isValid = verifyRequest(req, nonce, contextId, proof, timestamp);

    expect(isValid).toBe(true);
  });

  it('should handle application/x-www-form-urlencoded', () => {
    const req: MockHttpRequest = {
      method: 'POST',
      path: '/api/form',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'key=value&another=test',
    };

    const { proof, timestamp } = signRequest(req, nonce, contextId);
    const isValid = verifyRequest(req, nonce, contextId, proof, timestamp);

    expect(isValid).toBe(true);
  });

  it('should handle text/plain as raw string', () => {
    const req: MockHttpRequest = {
      method: 'POST',
      path: '/api/text',
      headers: { 'content-type': 'text/plain' },
      body: 'Hello, World!',
    };

    // For text/plain, we hash the raw body
    const binding = ashNormalizeBinding('POST', '/api/text', '');
    const bodyHash = ashHashBody('Hello, World!');
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

    const isValid = ashVerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof);
    expect(isValid).toBe(true);
  });
});

console.log('HTTP Integration Tests loaded');
