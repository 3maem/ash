/**
 * Fastify plugin for ASH verification.
 *
 * Supports ASH v2.3 unified proof features:
 * - Context scoping (selective field protection)
 * - Request chaining (workflow integrity)
 */

import type { FastifyPluginAsync, FastifyRequest, FastifyReply } from 'fastify';
import type { AshContextStore, AshMode } from '../index';
import {
  ashBuildProof,
  ashCanonicalizeJson,
  ashCanonicalizeUrlencoded,
  ashNormalizeBinding,
  ashVerifyProof,
  ashVerifyProofUnified,
} from '../index';

/**
 * Fastify plugin configuration.
 */
export interface AshFastifyOptions {
  /** Context store instance */
  store: AshContextStore;
  /** Routes to protect (glob patterns or exact paths) */
  routes?: string[];
  /** Security mode (default: balanced) */
  mode?: AshMode;
  /** Skip verification for certain requests */
  skip?: (req: FastifyRequest) => boolean;
  /** Enable v2.3 unified verification (scoping + chaining) */
  enableUnified?: boolean;
}

/**
 * Header names for ASH protocol (v2.3 unified).
 */
const HEADERS = {
  CONTEXT_ID: 'x-ash-context-id',
  PROOF: 'x-ash-proof',
  MODE: 'x-ash-mode',
  TIMESTAMP: 'x-ash-timestamp',
  SCOPE: 'x-ash-scope',
  SCOPE_HASH: 'x-ash-scope-hash',
  CHAIN_HASH: 'x-ash-chain-hash',
};

/**
 * ASH Fastify plugin for request verification.
 *
 * @example
 * ```typescript
 * import Fastify from 'fastify';
 * import { AshMemoryStore, ashFastifyPlugin } from '@3maem/ash-node';
 *
 * const fastify = Fastify();
 * const store = new AshMemoryStore();
 *
 * fastify.register(ashFastifyPlugin, {
 *   store,
 *   routes: ['/api/*'],
 * });
 *
 * fastify.post('/api/update', async (req, reply) => {
 *   // Request is verified
 *   return { success: true };
 * });
 * ```
 */
export const ashFastifyPlugin: FastifyPluginAsync<AshFastifyOptions> = async (
  fastify,
  options
) => {
  const { store, mode = 'balanced', routes = [], skip, enableUnified = false } = options;

  // Decorate request with ASH context and v2.3 info
  fastify.decorateRequest('ashContext', null);
  fastify.decorateRequest('ashScope', []);
  fastify.decorateRequest('ashChainHash', '');

  // Add preHandler hook
  fastify.addHook('preHandler', async (request: FastifyRequest, reply: FastifyReply) => {
    // Check if route should be protected
    const url = request.url.split('?')[0];
    const shouldVerify = routes.length === 0 || routes.some((pattern) => {
      if (pattern.endsWith('*')) {
        return url.startsWith(pattern.slice(0, -1));
      }
      return url === pattern;
    });

    if (!shouldVerify) {
      return;
    }

    // Check skip condition
    if (skip?.(request)) {
      return;
    }

    // Get required headers
    const contextId = request.headers[HEADERS.CONTEXT_ID] as string | undefined;
    const proof = request.headers[HEADERS.PROOF] as string | undefined;

    // Get optional v2.3 headers
    const timestamp = (request.headers[HEADERS.TIMESTAMP] as string) ?? '';
    const scopeHeader = (request.headers[HEADERS.SCOPE] as string) ?? '';
    const scopeHash = (request.headers[HEADERS.SCOPE_HASH] as string) ?? '';
    const chainHash = (request.headers[HEADERS.CHAIN_HASH] as string) ?? '';

    // Parse scope fields
    const scope: string[] = scopeHeader
      ? scopeHeader.split(',').map(s => s.trim()).filter(s => s !== '')
      : [];

    if (!contextId) {
      reply.code(403).send({
        error: 'MISSING_CONTEXT_ID',
        message: 'Missing X-ASH-Context-ID header',
      });
      return;
    }

    if (!proof) {
      reply.code(403).send({
        error: 'MISSING_PROOF',
        message: 'Missing X-ASH-Proof header',
      });
      return;
    }

    // Get and validate context
    const context = await store.get(contextId);

    if (!context) {
      reply.code(403).send({
        error: 'INVALID_CONTEXT',
        message: 'Invalid or expired context',
      });
      return;
    }

    if (context.used) {
      reply.code(403).send({
        error: 'CONTEXT_USED',
        message: 'Context already used (replay detected)',
      });
      return;
    }

    // Normalize binding from request
    const actualBinding = ashNormalizeBinding(request.method, url);

    // Check binding match
    if (context.binding !== actualBinding) {
      reply.code(403).send({
        error: 'BINDING_MISMATCH',
        message: `Binding mismatch: expected ${context.binding}, got ${actualBinding}`,
      });
      return;
    }

    // Canonicalize payload
    let canonicalPayload: string;
    const contentType = request.headers['content-type'] ?? '';

    try {
      if (contentType.includes('application/json')) {
        canonicalPayload = ashCanonicalizeJson(JSON.stringify(request.body));
      } else if (contentType.includes('application/x-www-form-urlencoded')) {
        const body = request.body as Record<string, string>;
        const params = new URLSearchParams(body);
        canonicalPayload = ashCanonicalizeUrlencoded(params.toString());
      } else {
        canonicalPayload = '';
      }
    } catch (error) {
      reply.code(400).send({
        error: 'CANONICALIZATION_FAILED',
        message: 'Failed to canonicalize request body',
      });
      return;
    }

    // Build expected proof
    const expectedProof = ashBuildProof(
      context.mode ?? mode,
      context.binding,
      contextId,
      context.nonce ?? null,
      canonicalPayload
    );

    // Verify proof (v2.3 unified or legacy)
    let verificationPassed = false;

    if (enableUnified && (scope.length > 0 || chainHash !== '')) {
      // v2.3 unified verification with scoping/chaining
      if (!context.nonce) {
        reply.code(403).send({
          error: 'INVALID_CONTEXT',
          message: 'Context missing nonce for unified verification',
        });
        return;
      }

      // Parse payload for scoping
      let payload: Record<string, unknown> = {};
      try {
        if (contentType.includes('application/json') && request.body) {
          payload = typeof request.body === 'string' ? JSON.parse(request.body as string) : request.body as Record<string, unknown>;
        }
      } catch {
        payload = {};
      }

      verificationPassed = ashVerifyProofUnified(
        context.nonce,
        contextId,
        context.binding,
        timestamp,
        payload,
        proof,
        scope,
        scopeHash,
        context.metadata?.previousProof as string | undefined,
        chainHash
      );

      if (!verificationPassed) {
        // Determine specific error
        if (scope.length > 0 && scopeHash !== '') {
          reply.code(403).send({
            error: 'SCOPE_MISMATCH',
            message: 'Scope hash verification failed',
          });
          return;
        }
        if (chainHash !== '') {
          reply.code(403).send({
            error: 'CHAIN_BROKEN',
            message: 'Chain hash verification failed',
          });
          return;
        }
        reply.code(403).send({
          error: 'PROOF_MISMATCH',
          message: 'Proof verification failed',
        });
        return;
      }
    } else {
      // Legacy verification
      if (!ashVerifyProof(expectedProof, proof)) {
        reply.code(403).send({
          error: 'PROOF_MISMATCH',
          message: 'Proof verification failed',
        });
        return;
      }
      verificationPassed = true;
    }

    // Consume context
    const consumed = await store.consume(contextId);
    if (!consumed) {
      reply.code(403).send({
        error: 'CONTEXT_USED',
        message: 'Context already used (replay detected)',
      });
      return;
    }

    // Attach context and v2.3 info to request
    (request as unknown as { ashContext: typeof context; ashScope: string[]; ashChainHash: string }).ashContext = context;
    (request as unknown as { ashScope: string[] }).ashScope = scope;
    (request as unknown as { ashChainHash: string }).ashChainHash = chainHash;
  });
};
