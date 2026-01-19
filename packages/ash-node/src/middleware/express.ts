/**
 * Express.js middleware for ASH verification.
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { AshContextStore, AshMode } from '../index';
import {
  ashBuildProof,
  ashCanonicalizeJson,
  ashCanonicalizeUrlencoded,
  ashNormalizeBinding,
  ashVerifyProof,
} from '../index';

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
  | 'CANONICALIZATION_FAILED';

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
 * Header names for ASH protocol.
 */
const HEADERS = {
  CONTEXT_ID: 'x-ash-context-id',
  PROOF: 'x-ash-proof',
  MODE: 'x-ash-mode',
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
 * ```
 */
export function ashExpressMiddleware(options: AshExpressOptions): RequestHandler {
  const { store, mode = 'balanced', onError = defaultErrorHandler, skip } = options;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Check skip condition
      if (skip?.(req)) {
        next();
        return;
      }

      // Get headers
      const contextId = req.get(HEADERS.CONTEXT_ID);
      const proof = req.get(HEADERS.PROOF);

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

      // Normalize binding from request
      const actualBinding = ashNormalizeBinding(req.method, req.path);
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

      // Verify proof
      if (!ashVerifyProof(expectedProof, proof)) {
        throw new AshVerifyError('PROOF_MISMATCH', 'Proof verification failed');
      }

      // Consume context (mark as used)
      const consumed = await store.consume(contextId);
      if (!consumed) {
        throw new AshVerifyError('CONTEXT_USED', 'Context already used (replay detected)');
      }

      // Attach context metadata to request for downstream use
      (req as unknown as { ashContext: typeof context }).ashContext = context;

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
