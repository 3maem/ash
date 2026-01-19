/**
 * Fastify plugin for ASH verification.
 */

import type { FastifyPluginAsync, FastifyRequest, FastifyReply } from 'fastify';
import type { AshContextStore, AshMode } from '../index';
import {
  ashBuildProof,
  ashCanonicalizeJson,
  ashCanonicalizeUrlencoded,
  ashNormalizeBinding,
  ashVerifyProof,
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
}

/**
 * Header names for ASH protocol.
 */
const HEADERS = {
  CONTEXT_ID: 'x-ash-context-id',
  PROOF: 'x-ash-proof',
  MODE: 'x-ash-mode',
};

/**
 * ASH Fastify plugin for request verification.
 *
 * @example
 * ```typescript
 * import Fastify from 'fastify';
 * import { AshMemoryStore, ashFastifyPlugin } from '@3meam/ash-node';
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
  const { store, mode = 'balanced', routes = [], skip } = options;

  // Decorate request with ASH context
  fastify.decorateRequest('ashContext', null);

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

    // Get headers
    const contextId = request.headers[HEADERS.CONTEXT_ID] as string | undefined;
    const proof = request.headers[HEADERS.PROOF] as string | undefined;

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

    // Verify proof
    if (!ashVerifyProof(expectedProof, proof)) {
      reply.code(403).send({
        error: 'PROOF_MISMATCH',
        message: 'Proof verification failed',
      });
      return;
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

    // Attach context to request
    (request as unknown as { ashContext: typeof context }).ashContext = context;
  });
};
