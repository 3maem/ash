/**
 * Express.js middleware for ASH verification.
 *
 * Supports ASH v2.3 unified proof features:
 * - Context scoping (selective field protection)
 * - Request chaining (workflow integrity)
 * - Server-side scope policies (ENH-003)
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { AshContextStore, AshMode } from '../index';
import {
  ashBuildProof,
  ashCanonicalizeJson,
  ashCanonicalizeUrlencoded,
  ashNormalizeBinding,
  ashVerifyProof,
  ashHashBody,
  ashVerifyProofUnified,
  ashExtractScopedFields,
} from '../index';
import { getScopePolicy, hasScopePolicy } from '../config/scopePolicies';

/**
 * Express middleware configuration.
 */
export interface AshExpressOptions {
  /** Context store instance */
  store: AshContextStore;
  /** Expected endpoint binding (e.g., "POST /api/update") */
  expectedBinding?: string;
  /** Security mode (default: balanced) */
  mode?: AshMode;
  /** Custom error handler */
  onError?: (error: AshVerifyError, req: Request, res: Response, next: NextFunction) => void;
  /** Skip verification for certain requests */
  skip?: (req: Request) => boolean;
  /** Enable v2.3 unified verification (scoping + chaining) */
  enableUnified?: boolean;
}

/**
 * Verification error types.
 */
export type AshVerifyErrorCode =
  | 'MISSING_CONTEXT_ID'
  | 'MISSING_PROOF'
  | 'INVALID_CONTEXT'
  | 'CONTEXT_EXPIRED'
  | 'CONTEXT_USED'
  | 'BINDING_MISMATCH'
  | 'PROOF_MISMATCH'
  | 'CANONICALIZATION_FAILED'
  | 'SCOPE_MISMATCH'
  | 'CHAIN_BROKEN'
  | 'SCOPE_POLICY_REQUIRED'
  | 'SCOPE_POLICY_VIOLATION';

/**
 * Verification error.
 */
export class AshVerifyError extends Error {
  code: AshVerifyErrorCode;
  statusCode: number;

  constructor(code: AshVerifyErrorCode, message: string, statusCode = 403) {
    super(message);
    this.name = 'AshVerifyError';
    this.code = code;
    this.statusCode = statusCode;
  }
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
 * Default error handler.
 */
function defaultErrorHandler(
  error: AshVerifyError,
  _req: Request,
  res: Response,
  _next: NextFunction
): void {
  res.status(error.statusCode).json({
    error: error.code,
    message: error.message,
  });
}

/**
 * Create ASH verification middleware for Express.
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { AshMemoryStore, ashExpressMiddleware } from '@3maem/ash-node';
 *
 * const app = express();
 * const store = new AshMemoryStore();
 *
 * app.post(
 *   '/api/update',
 *   ashExpressMiddleware({
 *     store,
 *     expectedBinding: 'POST /api/update',
 *   }),
 *   (req, res) => {
 *     // Request is verified
 *     res.json({ success: true });
 *   }
 * );
 *
 * // With v2.3 unified features (scoping + chaining)
 * app.post(
 *   '/api/transfer',
 *   ashExpressMiddleware({
 *     store,
 *     enableUnified: true,  // Enable v2.3 features
 *   }),
 *   (req, res) => {
 *     // Access scope and chain info
 *     const { ashScope, ashChainHash } = req;
 *     res.json({ success: true });
 *   }
 * );
 * ```
 */
export function ashExpressMiddleware(options: AshExpressOptions): RequestHandler {
  const { store, mode = 'balanced', onError = defaultErrorHandler, skip, enableUnified = false } = options;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Check skip condition
      if (skip?.(req)) {
        next();
        return;
      }

      // Get required headers
      const contextId = req.get(HEADERS.CONTEXT_ID);
      const proof = req.get(HEADERS.PROOF);

      // Get optional v2.3 headers
      const timestamp = req.get(HEADERS.TIMESTAMP) ?? '';
      const scopeHeader = req.get(HEADERS.SCOPE) ?? '';
      const scopeHash = req.get(HEADERS.SCOPE_HASH) ?? '';
      const chainHash = req.get(HEADERS.CHAIN_HASH) ?? '';

      // Normalize binding from request (for policy lookup)
      const queryString = req.query ? new URLSearchParams(req.query as Record<string, string>).toString() : '';
      const binding = ashNormalizeBinding(req.method, req.path, queryString);

      // Parse client scope fields
      const clientScope: string[] = scopeHeader
        ? scopeHeader.split(',').map(s => s.trim()).filter(s => s !== '')
        : [];

      // ENH-003: Check server-side scope policy
      const policyScope = getScopePolicy(binding);
      const hasPolicyScope = policyScope.length > 0;

      // Determine effective scope
      let scope = clientScope;

      if (hasPolicyScope) {
        // If server has a policy, client MUST use it
        if (clientScope.length === 0) {
          throw new AshVerifyError(
            'SCOPE_POLICY_REQUIRED',
            `This endpoint requires scope headers per server policy. Required scope: ${policyScope.join(', ')}`
          );
        }

        // Verify client scope matches server policy
        const sortedClientScope = [...clientScope].sort();
        const sortedPolicyScope = [...policyScope].sort();

        if (sortedClientScope.join(',') !== sortedPolicyScope.join(',')) {
          throw new AshVerifyError(
            'SCOPE_POLICY_VIOLATION',
            `Request scope does not match server policy. Expected: ${policyScope.join(', ')}, Received: ${clientScope.join(', ')}`
          );
        }

        scope = policyScope;
      }

      if (!contextId) {
        throw new AshVerifyError('MISSING_CONTEXT_ID', 'Missing X-ASH-Context-ID header');
      }

      if (!proof) {
        throw new AshVerifyError('MISSING_PROOF', 'Missing X-ASH-Proof header');
      }

      // Get and validate context
      const context = await store.get(contextId);

      if (!context) {
        throw new AshVerifyError('INVALID_CONTEXT', 'Invalid or expired context');
      }

      if (context.used) {
        throw new AshVerifyError('CONTEXT_USED', 'Context already used (replay detected)');
      }

      // Use the binding we already calculated for policy lookup
      const actualBinding = binding;
      const expectedBinding = options.expectedBinding ?? actualBinding;

      // Check binding match
      if (context.binding !== expectedBinding) {
        throw new AshVerifyError(
          'BINDING_MISMATCH',
          `Binding mismatch: expected ${context.binding}, got ${expectedBinding}`
        );
      }

      // Canonicalize payload
      let canonicalPayload: string;
      const contentType = req.get('content-type') ?? '';

      if (contentType.includes('application/json')) {
        canonicalPayload = ashCanonicalizeJson(JSON.stringify(req.body));
      } else if (contentType.includes('application/x-www-form-urlencoded')) {
        const params = new URLSearchParams(req.body as Record<string, string>);
        canonicalPayload = ashCanonicalizeUrlencoded(params.toString());
      } else {
        // For other content types, use empty or raw body
        canonicalPayload = '';
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
          throw new AshVerifyError('INVALID_CONTEXT', 'Context missing nonce for unified verification');
        }

        // Parse payload for scoping
        let payload: Record<string, unknown> = {};
        try {
          if (contentType.includes('application/json') && req.body) {
            payload = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
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
            throw new AshVerifyError('SCOPE_MISMATCH', 'Scope hash verification failed');
          }
          if (chainHash !== '') {
            throw new AshVerifyError('CHAIN_BROKEN', 'Chain hash verification failed');
          }
          throw new AshVerifyError('PROOF_MISMATCH', 'Proof verification failed');
        }
      } else {
        // Legacy verification
        if (!ashVerifyProof(expectedProof, proof)) {
          throw new AshVerifyError('PROOF_MISMATCH', 'Proof verification failed');
        }
        verificationPassed = true;
      }

      // Consume context (mark as used)
      const consumed = await store.consume(contextId);
      if (!consumed) {
        throw new AshVerifyError('CONTEXT_USED', 'Context already used (replay detected)');
      }

      // Attach context metadata to request for downstream use
      (req as unknown as { ashContext: typeof context; ashScope: string[]; ashChainHash: string; ashScopePolicy: string[] }).ashContext = context;
      (req as unknown as { ashScope: string[] }).ashScope = scope;
      (req as unknown as { ashScopePolicy: string[] }).ashScopePolicy = policyScope;
      (req as unknown as { ashChainHash: string }).ashChainHash = chainHash;

      next();
    } catch (error) {
      if (error instanceof AshVerifyError) {
        onError(error, req, res, next);
      } else {
        // Unexpected error
        const ashError = new AshVerifyError(
          'CANONICALIZATION_FAILED',
          error instanceof Error ? error.message : 'Verification failed',
          500
        );
        onError(ashError, req, res, next);
      }
    }
  };
}
