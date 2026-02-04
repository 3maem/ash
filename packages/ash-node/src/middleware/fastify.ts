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
  ashCanonicalizeJson,
  ashCanonicalizeUrlencoded,
  ashNormalizeBinding,
  ashHashBody,
  ashVerifyProof,
  ashVerifyProofUnified,
  ashValidateTimestamp,
  ashNormalizeScopeFields,
  ashGetClientIp,
  DEFAULT_MAX_TIMESTAMP_AGE_SECONDS,
  MAX_CONTEXT_ID_LENGTH,
  SHA256_HEX_LENGTH,
  SCOPE_FIELD_DELIMITER,
} from '../index';
import { ashGetScopePolicy } from '../config/scopePolicies';

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
  /**
   * BUG-22 FIX: Maximum age for timestamps in seconds.
   * Set to 0 to disable timestamp freshness validation (not recommended).
   * Default: 300 (5 minutes)
   */
  maxTimestampAgeSeconds?: number;
  /**
   * v2.3.4: Enforce IP address binding.
   * Verifies that the request IP matches the context IP.
   */
  enforceIp?: boolean;
  /**
   * v2.3.4: Enforce user binding.
   * Verifies that the authenticated user matches the context user_id.
   * Set to true to use req.user?.id, or provide a custom extractor function.
   */
  enforceUser?: boolean | ((req: FastifyRequest) => string | number | undefined);
}

/**
 * Header names for ASH protocol (v2.3 unified).
 * VULN-016 NOTE: HTTP headers are case-insensitive per RFC 7230.
 * Fastify normalizes all header names to lowercase, so these
 * lowercase names will correctly match headers sent as
 * "X-ASH-Context-ID", "x-ash-context-id", etc.
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
  const {
    store,
    // BUG-43 FIX: mode is accepted for API compatibility but not currently used
    // in verification. The context's mode is stored and can be accessed via req.ashContext.mode
    mode: _mode = 'balanced',
    routes = [],
    skip,
    enableUnified = false,
    maxTimestampAgeSeconds = DEFAULT_MAX_TIMESTAMP_AGE_SECONDS,
    enforceIp = false,
    enforceUser = false,
  } = options;

  // Decorate request with ASH context and v2.3 info
  fastify.decorateRequest('ashContext', null);
  fastify.decorateRequest('ashScope', []);
  fastify.decorateRequest('ashScopePolicy', []);
  fastify.decorateRequest('ashChainHash', '');

  // Add preHandler hook
  fastify.addHook('preHandler', async (request: FastifyRequest, reply: FastifyReply) => {
    // BUG-LOGIC-066 FIX: Wrap entire handler in try-catch to prevent stack trace leaks
    try {
    // Check if route should be protected
    // Split URL to get path and query string separately
    const urlParts = request.url.split('?');
    const path = urlParts[0];
    // BUG-48 FIX: Strip fragment from query string (matching Express middleware)
    // In practice, browsers don't send fragments to servers, but be consistent
    const queryString = urlParts[1]?.split('#')[0] ?? '';
    const shouldVerify = routes.length === 0 || routes.some((pattern) => {
      if (pattern.endsWith('/*')) {
        // BUG-LOGIC-008 FIX: Handle /api/* pattern consistently
        // Should match /api, /api/, and /api/anything
        const base = pattern.slice(0, -2); // Remove '/*'
        return path === base || path === base + '/' || path.startsWith(base + '/');
      }
      if (pattern.endsWith('*')) {
        // Single * at end: prefix match (e.g., '/api*' matches '/api', '/api123')
        return path.startsWith(pattern.slice(0, -1));
      }
      return path === pattern;
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

    // Parse client scope fields
    const clientScope: string[] = scopeHeader
      ? scopeHeader.split(',').map(s => s.trim()).filter(s => s !== '')
      : [];

    // BUG-23 FIX: Reject scope headers when unified mode is disabled
    if (!enableUnified && (clientScope.length > 0 || scopeHash !== '' || chainHash !== '')) {
      reply.code(400).send({
        error: 'ASH_MODE_VIOLATION',
        message: 'Scope/chain headers are not supported without enableUnified=true. ' +
          'Either enable unified mode on the server or remove scope/chain headers from the request.',
      });
      return;
    }

    // Normalize binding from request for policy lookup
    const binding = ashNormalizeBinding(request.method, path, queryString);

    // BUG-020: Check server-side scope policy (matching Express middleware)
    const policyScope = ashGetScopePolicy(binding);
    const hasPolicyScope = policyScope.length > 0;

    // BUG-39 FIX: If server has a scope policy but unified mode is disabled,
    // the configuration is invalid. Provide a clear error message.
    // BUG-LOGIC-120 FIX: Use environment-aware error handling like Express middleware
    if (hasPolicyScope && !enableUnified) {
      const message = process.env.NODE_ENV === 'production'
        ? 'Server configuration error: unified mode required for this endpoint'
        : `Server has a scope policy for "${binding}" but enableUnified=false. ` +
          'Scope policies require enableUnified=true in middleware options.';
      reply.code(400).send({
        error: 'ASH_MODE_VIOLATION',
        message,
      });
      return;
    }

    // Determine effective scope
    let scope = clientScope;

    if (hasPolicyScope) {
      // If server has a policy, client MUST use it
      if (clientScope.length === 0) {
        reply.code(400).send({
          error: 'ASH_SCOPE_POLICY_REQUIRED',
          message: `This endpoint requires scope headers per server policy. Required scope: ${policyScope.join(', ')}`,
        });
        return;
      }

      // Verify client scope matches server policy
      // BUG-POTENTIAL-001 FIX: Use normalizeScopeFields for consistent byte-wise sorting
      // This matches the sorting used in proof verification (normalizeScopeFields uses Buffer.compare)
      const normalizedClientScope = ashNormalizeScopeFields(clientScope);
      const normalizedPolicyScope = ashNormalizeScopeFields(policyScope);

      // Compare using the same delimiter as proof verification
      if (normalizedClientScope.join(SCOPE_FIELD_DELIMITER) !== normalizedPolicyScope.join(SCOPE_FIELD_DELIMITER)) {
        reply.code(475).send({  // v2.3.4: Verification error
          error: 'ASH_SCOPE_POLICY_VIOLATION',
          message: `Request scope does not match server policy. Expected: ${policyScope.join(', ')}, Received: ${clientScope.join(', ')}`,
        });
        return;
      }

      scope = policyScope;
    }

    if (!contextId) {
      reply.code(450).send({  // v2.3.4: Context error
        error: 'ASH_CTX_NOT_FOUND',
        message: 'Missing X-ASH-Context-ID header',
      });
      return;
    }

    // VULN-004 FIX: Validate contextId format before store lookup
    if (contextId.length > MAX_CONTEXT_ID_LENGTH) {
      reply.code(400).send({
        error: 'ASH_MALFORMED_REQUEST',
        message: 'Context ID exceeds maximum length',
      });
      return;
    }
    if (!/^[A-Za-z0-9_.-]+$/.test(contextId)) {
      reply.code(400).send({
        error: 'ASH_MALFORMED_REQUEST',
        message: 'Context ID contains invalid characters',
      });
      return;
    }

    if (!proof) {
      reply.code(483).send({  // v2.3.4: Format error
        error: 'ASH_PROOF_MISSING',
        message: 'Missing X-ASH-Proof header',
      });
      return;
    }

    // VULN-008 FIX: Validate proof format before store lookup to prevent enumeration
    if (proof.length !== SHA256_HEX_LENGTH || !/^[0-9a-fA-F]+$/.test(proof)) {
      reply.code(460).send({  // v2.3.4: Proof error
        error: 'ASH_PROOF_INVALID',
        message: 'Invalid proof format',
      });
      return;
    }

    // BUG-22 FIX: Validate timestamp freshness before verification
    if (timestamp !== '' && maxTimestampAgeSeconds > 0) {
      try {
        ashValidateTimestamp(timestamp, maxTimestampAgeSeconds);
      } catch (e) {
        reply.code(482).send({  // v2.3.4: Format error
          error: 'ASH_TIMESTAMP_INVALID',
          message: e instanceof Error ? e.message : 'Invalid timestamp',
        });
        return;
      }
    }

    // Get and validate context
    const context = await store.get(contextId);

    if (!context) {
      reply.code(450).send({  // v2.3.4: Context error
        error: 'ASH_CTX_NOT_FOUND',
        message: 'Invalid or expired context',
      });
      return;
    }

    if (context.used) {
      reply.code(452).send({  // v2.3.4: Context error
        error: 'ASH_CTX_ALREADY_USED',
        message: 'Context already used (replay detected)',
      });
      return;
    }

    // Use the binding we already calculated for policy lookup
    const actualBinding = binding;

    // Check binding match
    if (context.binding !== actualBinding) {
      // VULN-010 FIX: Use generic error message in production to prevent info disclosure
      const message = process.env.NODE_ENV === 'production'
        ? 'Request binding does not match context'
        : `Binding mismatch: expected ${context.binding}, got ${actualBinding}`;
      reply.code(461).send({  // v2.3.4: Binding error
        error: 'ASH_BINDING_MISMATCH',
        message,
      });
      return;
    }

    // Canonicalize payload
    let canonicalPayload: string;
    const contentType = request.headers['content-type'] ?? '';
    // BUG-LOGIC-005 FIX: Extract MIME type before parameters (e.g., charset)
    const mimeType = (Array.isArray(contentType) ? contentType[0] : contentType).split(';')[0].trim().toLowerCase();

    try {
      // BUG-LOGIC-005 FIX: Use exact MIME type matching instead of substring
      if (mimeType === 'application/json') {
        canonicalPayload = ashCanonicalizeJson(JSON.stringify(request.body));
      } else if (mimeType === 'application/x-www-form-urlencoded') {
        const body = request.body as Record<string, string>;
        const params = new URLSearchParams(body);
        canonicalPayload = ashCanonicalizeUrlencoded(params.toString());
      } else {
        // BUG-LOGIC-006 FIX: For other content types, use empty string
        // Note: This means bodies with other content types are NOT verified.
        canonicalPayload = '';
      }
    } catch (error) {
      reply.code(422).send({
        error: 'ASH_CANONICALIZATION_ERROR',
        message: 'Failed to canonicalize request body',
      });
      return;
    }

    // Verify proof (v2.3 unified or v2.1 standard)
    let verificationPassed = false;

    if (!context.nonce) {
      reply.code(450).send({  // v2.3.4: Context error
        error: 'ASH_CTX_NOT_FOUND',
        message: 'Context missing nonce for verification',
      });
      return;
    }

    if (enableUnified && (scope.length > 0 || chainHash !== '')) {
      // v2.3 unified verification with scoping/chaining
      // BUG-40 FIX: Check for empty timestamp early to provide clear error
      if (timestamp === '') {
        reply.code(482).send({  // v2.3.4: Format error
          error: 'ASH_TIMESTAMP_INVALID',
          message: 'Timestamp is required for unified proof verification with scope/chain headers',
        });
        return;
      }
      // Parse payload for scoping
      // PENTEST-002 FIX: Use consistent mimeType check instead of contentType.includes()
      // This ensures body parsing and canonicalization use the same MIME type check.
      let payload: Record<string, unknown> = {};
      try {
        if (mimeType === 'application/json' && request.body) {
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
          reply.code(473).send({  // v2.3.4: Verification error
            error: 'ASH_SCOPE_MISMATCH',
            message: 'Scope hash verification failed',
          });
          return;
        }
        if (chainHash !== '') {
          reply.code(474).send({  // v2.3.4: Verification error
            error: 'ASH_CHAIN_BROKEN',
            message: 'Chain hash verification failed',
          });
          return;
        }
        reply.code(460).send({  // v2.3.4: Proof error
          error: 'ASH_PROOF_INVALID',
          message: 'Proof verification failed',
        });
        return;
      }
    } else {
      // v2.1+ standard verification
      // BUG-47 FIX: Use ashVerifyProof instead of ashVerifyProofWithFreshness
      // since we already validated timestamp freshness earlier (lines 199-209)
      const bodyHash = ashHashBody(canonicalPayload);
      verificationPassed = ashVerifyProof(
        context.nonce,
        contextId,
        context.binding,
        timestamp,
        bodyHash,
        proof
      );

      if (!verificationPassed) {
        reply.code(460).send({  // v2.3.4: Proof error
          error: 'ASH_PROOF_INVALID',
          message: 'Proof verification failed',
        });
        return;
      }
    }

    // v2.3.4: Verify IP binding if requested
    if (enforceIp) {
      const clientIp = ashGetClientIp({
        headers: request.headers as Record<string, string | string[] | undefined>,
        socket: { remoteAddress: request.ip },
      });
      const contextIp = context.metadata?.ip as string | undefined;
      if (contextIp && contextIp !== clientIp) {
        const message = process.env.NODE_ENV === 'production'
          ? 'Request binding does not match context'
          : 'IP address mismatch';
        reply.code(461).send({  // v2.3.4: Binding error
          error: 'ASH_BINDING_MISMATCH',
          message,
        });
        return;
      }
    }

    // v2.3.4: Verify user binding if requested
    if (enforceUser) {
      let currentUserId: string | number | undefined;
      if (typeof enforceUser === 'function') {
        currentUserId = enforceUser(request);
      } else {
        // Default: look for request.user?.id (common in Fastify auth plugins)
        currentUserId = (request as unknown as { user?: { id?: string | number } }).user?.id;
      }
      const contextUserId = context.metadata?.user_id as string | number | undefined;
      if (contextUserId !== undefined && currentUserId !== contextUserId) {
        const message = process.env.NODE_ENV === 'production'
          ? 'Request binding does not match context'
          : 'User mismatch';
        reply.code(461).send({  // v2.3.4: Binding error
          error: 'ASH_BINDING_MISMATCH',
          message,
        });
        return;
      }
    }

    // Consume context
    const consumed = await store.consume(contextId);
    if (!consumed) {
      reply.code(452).send({  // v2.3.4: Context error
        error: 'ASH_CTX_ALREADY_USED',
        message: 'Context already used (replay detected)',
      });
      return;
    }

    // Attach context and v2.3 info to request
    (request as unknown as { ashContext: typeof context; ashScope: string[]; ashScopePolicy: string[]; ashChainHash: string }).ashContext = context;
    (request as unknown as { ashScope: string[] }).ashScope = scope;
    (request as unknown as { ashScopePolicy: string[] }).ashScopePolicy = policyScope;
    (request as unknown as { ashChainHash: string }).ashChainHash = chainHash;
    } catch (error) {
      // BUG-LOGIC-066 FIX: Catch unexpected errors and return generic ASH error
      // This prevents stack traces from leaking in non-production environments
      if (process.env.NODE_ENV !== 'production') {
        console.error('[ASH] Unexpected error in Fastify middleware:', error);
      }
      reply.code(500).send({
        error: 'ASH_INTERNAL_ERROR',
        message: 'Request verification failed due to internal error',
      });
      return;
    }
  });
};
