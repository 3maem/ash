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
  enforceUser?: boolean | ((req: Request) => string | number | undefined);
}

/**
 * Verification error types (per SDK Implementation Reference Section 8).
 */
export type AshVerifyErrorCode =
  | 'ASH_CTX_NOT_FOUND'
  | 'ASH_CTX_EXPIRED'
  | 'ASH_CTX_ALREADY_USED'
  | 'ASH_BINDING_MISMATCH'
  | 'ASH_PROOF_MISSING'
  | 'ASH_PROOF_INVALID'
  | 'ASH_CANONICALIZATION_ERROR'
  | 'ASH_MALFORMED_REQUEST'
  | 'ASH_MODE_VIOLATION'
  | 'ASH_UNSUPPORTED_CONTENT_TYPE'
  | 'ASH_SCOPE_MISMATCH'
  | 'ASH_CHAIN_BROKEN'
  | 'ASH_INTERNAL_ERROR'
  | 'ASH_TIMESTAMP_INVALID'
  | 'ASH_SCOPED_FIELD_MISSING'
  | 'ASH_SCOPE_POLICY_REQUIRED'
  | 'ASH_SCOPE_POLICY_VIOLATION';

/**
 * Get the recommended HTTP status code for an ASH error code.
 *
 * v2.3.4: Uses unique HTTP status codes in the 450-499 range for ASH-specific errors.
 * This enables precise error identification, better monitoring, and targeted retry logic.
 *
 * Error Categories:
 * - 450-459: Context errors
 * - 460-469: Seal/Proof errors
 * - 461, 473-479: Verification/Binding errors
 * - 480-489: Format/Protocol errors
 */
function getHttpStatusForCode(code: AshVerifyErrorCode): number {
  const statusMap: Record<AshVerifyErrorCode, number> = {
    // Context errors (450-459)
    'ASH_CTX_NOT_FOUND': 450,
    'ASH_CTX_EXPIRED': 451,
    'ASH_CTX_ALREADY_USED': 452,
    // Seal/Proof errors (460-469)
    'ASH_PROOF_INVALID': 460,
    // Binding errors (461)
    'ASH_BINDING_MISMATCH': 461,
    'ASH_SCOPE_MISMATCH': 473,
    'ASH_CHAIN_BROKEN': 474,
    'ASH_SCOPE_POLICY_VIOLATION': 475,
    // Format/Protocol errors (480-489)
    'ASH_TIMESTAMP_INVALID': 482,
    'ASH_PROOF_MISSING': 483,
    // Standard HTTP codes (preserved for semantic clarity)
    'ASH_CANONICALIZATION_ERROR': 422,
    'ASH_MALFORMED_REQUEST': 400,
    'ASH_MODE_VIOLATION': 400,
    'ASH_UNSUPPORTED_CONTENT_TYPE': 415,
    'ASH_SCOPED_FIELD_MISSING': 422,
    'ASH_SCOPE_POLICY_REQUIRED': 400,
    'ASH_INTERNAL_ERROR': 500,
  };
  return statusMap[code] ?? 500;
}

/**
 * Verification error.
 */
export class AshVerifyError extends Error {
  code: AshVerifyErrorCode;
  statusCode: number;

  constructor(code: AshVerifyErrorCode, message: string, statusCode?: number) {
    super(message);
    this.name = 'AshVerifyError';
    this.code = code;
    this.statusCode = statusCode ?? getHttpStatusForCode(code);
  }
}

/**
 * Header names for ASH protocol (v2.3 unified).
 * VULN-016 NOTE: HTTP headers are case-insensitive per RFC 7230.
 * Express's req.get() performs case-insensitive lookup, so these
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
  const {
    store,
    // BUG-43 FIX: mode is accepted for API compatibility but not currently used
    // in verification. The context's mode is stored and can be accessed via req.ashContext.mode
    mode: _mode = 'balanced',
    onError = defaultErrorHandler,
    skip,
    enableUnified = false,
    maxTimestampAgeSeconds = DEFAULT_MAX_TIMESTAMP_AGE_SECONDS,
  } = options;

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

      // BUG-26 FIX: Extract raw query string from original URL to preserve order
      // Don't reconstruct from req.query as Object.entries may not preserve order
      let queryString = '';
      const urlParts = req.originalUrl.split('?');
      if (urlParts.length > 1) {
        // Remove fragment if present
        queryString = urlParts[1].split('#')[0];
      }
      const binding = ashNormalizeBinding(req.method, req.path, queryString);

      // Parse client scope fields
      const clientScope: string[] = scopeHeader
        ? scopeHeader.split(',').map(s => s.trim()).filter(s => s !== '')
        : [];

      // BUG-23 FIX: Reject scope headers when unified mode is disabled
      // This prevents clients from thinking they have scope protection when they don't
      if (!enableUnified && (clientScope.length > 0 || scopeHash !== '' || chainHash !== '')) {
        throw new AshVerifyError(
          'ASH_MODE_VIOLATION',
          'Scope/chain headers are not supported without enableUnified=true. ' +
          'Either enable unified mode on the server or remove scope/chain headers from the request.'
        );
      }

      // ENH-003: Check server-side scope policy
      // BUG-44 FIX: Use expectedBinding for policy lookup to match context verification
      const effectiveBinding = options.expectedBinding ?? binding;
      const policyScope = ashGetScopePolicy(effectiveBinding);
      const hasPolicyScope = policyScope.length > 0;

      // BUG-39 FIX: If server has a scope policy but unified mode is disabled,
      // the configuration is invalid. Provide a clear error message.
      // BUG-LOGIC-106 FIX: Use generic message in production to prevent info disclosure
      if (hasPolicyScope && !enableUnified) {
        const message = process.env.NODE_ENV === 'production'
          ? 'Server configuration error: unified mode required for this endpoint'
          : `Server has a scope policy for "${effectiveBinding}" but enableUnified=false. ` +
            'Scope policies require enableUnified=true in middleware options.';
        throw new AshVerifyError('ASH_MODE_VIOLATION', message);
      }

      // Determine effective scope
      let scope = clientScope;

      if (hasPolicyScope) {
        // If server has a policy, client MUST use it
        if (clientScope.length === 0) {
          throw new AshVerifyError(
            'ASH_SCOPE_POLICY_REQUIRED',
            `This endpoint requires scope headers per server policy. Required scope: ${policyScope.join(', ')}`
          );
        }

        // Verify client scope matches server policy
        // BUG-POTENTIAL-001 FIX: Use normalizeScopeFields for consistent byte-wise sorting
        // This matches the sorting used in proof verification (normalizeScopeFields uses Buffer.compare)
        const normalizedClientScope = ashNormalizeScopeFields(clientScope);
        const normalizedPolicyScope = ashNormalizeScopeFields(policyScope);

        // Compare using the same delimiter as proof verification
        if (normalizedClientScope.join(SCOPE_FIELD_DELIMITER) !== normalizedPolicyScope.join(SCOPE_FIELD_DELIMITER)) {
          throw new AshVerifyError(
            'ASH_SCOPE_POLICY_VIOLATION',
            `Request scope does not match server policy. Expected: ${policyScope.join(', ')}, Received: ${clientScope.join(', ')}`
          );
        }

        scope = policyScope;
      }

      if (!contextId) {
        throw new AshVerifyError('ASH_CTX_NOT_FOUND', 'Missing X-ASH-Context-ID header');
      }

      // VULN-004 FIX: Validate contextId format before store lookup
      if (contextId.length > MAX_CONTEXT_ID_LENGTH) {
        throw new AshVerifyError('ASH_MALFORMED_REQUEST', 'Context ID exceeds maximum length');
      }
      if (!/^[A-Za-z0-9_.-]+$/.test(contextId)) {
        throw new AshVerifyError('ASH_MALFORMED_REQUEST', 'Context ID contains invalid characters');
      }

      if (!proof) {
        throw new AshVerifyError('ASH_PROOF_MISSING', 'Missing X-ASH-Proof header');
      }

      // VULN-008 FIX: Validate proof format before store lookup to prevent enumeration
      if (proof.length !== SHA256_HEX_LENGTH || !/^[0-9a-fA-F]+$/.test(proof)) {
        throw new AshVerifyError('ASH_PROOF_INVALID', 'Invalid proof format');
      }

      // BUG-22 FIX: Validate timestamp freshness before verification
      if (timestamp !== '' && maxTimestampAgeSeconds > 0) {
        try {
          ashValidateTimestamp(timestamp, maxTimestampAgeSeconds);
        } catch (e) {
          throw new AshVerifyError(
            'ASH_TIMESTAMP_INVALID',
            e instanceof Error ? e.message : 'Invalid timestamp'
          );
        }
      }

      // Get and validate context
      const context = await store.get(contextId);

      if (!context) {
        throw new AshVerifyError('ASH_CTX_NOT_FOUND', 'Invalid or expired context');
      }

      if (context.used) {
        throw new AshVerifyError('ASH_CTX_ALREADY_USED', 'Context already used (replay detected)');
      }

      // Use the binding we already calculated for policy lookup
      const actualBinding = binding;
      const expectedBinding = options.expectedBinding ?? actualBinding;

      // Check binding match
      if (context.binding !== expectedBinding) {
        // VULN-010 FIX: Use generic error message in production to prevent info disclosure
        const message = process.env.NODE_ENV === 'production'
          ? 'Request binding does not match context'
          : `Binding mismatch: expected ${context.binding}, got ${expectedBinding}`;
        throw new AshVerifyError('ASH_BINDING_MISMATCH', message);
      }

      // Canonicalize payload
      let canonicalPayload: string;
      const contentType = req.get('content-type') ?? '';
      // BUG-LOGIC-005 FIX: Extract MIME type before parameters (e.g., charset)
      // BUG-LOGIC-058 FIX: Handle array Content-Type (consistent with Fastify middleware)
      const mimeType = (Array.isArray(contentType) ? contentType[0] : contentType)
        .split(';')[0].trim().toLowerCase();

      // BUG-LOGIC-126 FIX: Wrap canonicalization in try-catch for specific error (consistent with Fastify)
      try {
        // BUG-LOGIC-005 FIX: Use exact MIME type matching instead of substring
        if (mimeType === 'application/json') {
          canonicalPayload = ashCanonicalizeJson(JSON.stringify(req.body));
        } else if (mimeType === 'application/x-www-form-urlencoded') {
          const params = new URLSearchParams(req.body as Record<string, string>);
          canonicalPayload = ashCanonicalizeUrlencoded(params.toString());
        } else {
          // BUG-LOGIC-006 FIX: For other content types, use empty string
          // Note: This means bodies with other content types are NOT verified.
          // If you need to verify other content types, canonicalize them appropriately.
          canonicalPayload = '';
        }
      } catch {
        throw new AshVerifyError('ASH_CANONICALIZATION_ERROR', 'Failed to canonicalize request body');
      }

      // Verify proof (v2.3 unified or v2.1 standard)
      let verificationPassed = false;

      if (!context.nonce) {
        throw new AshVerifyError('ASH_CTX_NOT_FOUND', 'Context missing nonce for verification');
      }

      if (enableUnified && (scope.length > 0 || chainHash !== '')) {
        // v2.3 unified verification with scoping/chaining
        // BUG-40 FIX: Check for empty timestamp early to provide clear error
        if (timestamp === '') {
          throw new AshVerifyError(
            'ASH_TIMESTAMP_INVALID',
            'Timestamp is required for unified proof verification with scope/chain headers'
          );
        }
        // Parse payload for scoping
        // PENTEST-002 FIX: Use consistent mimeType check instead of contentType.includes()
        // This ensures body parsing and canonicalization use the same MIME type check.
        let payload: Record<string, unknown> = {};
        try {
          if (mimeType === 'application/json' && req.body) {
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
            throw new AshVerifyError('ASH_SCOPE_MISMATCH', 'Scope hash verification failed');
          }
          if (chainHash !== '') {
            throw new AshVerifyError('ASH_CHAIN_BROKEN', 'Chain hash verification failed');
          }
          throw new AshVerifyError('ASH_PROOF_INVALID', 'Proof verification failed');
        }
      } else {
        // v2.1+ standard verification
        // BUG-47 FIX: Use ashVerifyProof instead of ashVerifyProofWithFreshness
        // since we already validated timestamp freshness earlier (lines 283-292)
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
          throw new AshVerifyError('ASH_PROOF_INVALID', 'Proof verification failed');
        }
      }

      // v2.3.4: Verify IP binding if requested
      if (options.enforceIp) {
        const clientIp = ashGetClientIp(req);
        const contextIp = context.metadata?.ip as string | undefined;
        if (contextIp && contextIp !== clientIp) {
          throw new AshVerifyError('ASH_BINDING_MISMATCH', 'IP address mismatch');
        }
      }

      // v2.3.4: Verify user binding if requested
      if (options.enforceUser) {
        let currentUserId: string | number | undefined;
        if (typeof options.enforceUser === 'function') {
          currentUserId = options.enforceUser(req);
        } else {
          // Default: look for req.user?.id (common in Express auth middleware)
          currentUserId = (req as unknown as { user?: { id?: string | number } }).user?.id;
        }
        const contextUserId = context.metadata?.user_id as string | number | undefined;
        if (contextUserId !== undefined && currentUserId !== contextUserId) {
          throw new AshVerifyError('ASH_BINDING_MISMATCH', 'User mismatch');
        }
      }

      // Consume context (mark as used)
      const consumed = await store.consume(contextId);
      if (!consumed) {
        throw new AshVerifyError('ASH_CTX_ALREADY_USED', 'Context already used (replay detected)');
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
        // BUG-016: Unexpected error - don't leak internal details
        // Log full error for debugging but return generic message to client
        if (process.env.NODE_ENV !== 'production') {
          console.error('[ASH] Unexpected verification error:', error);
        }
        // BUG-LOGIC-057 FIX: Use ASH_INTERNAL_ERROR for unexpected exceptions
        // (was incorrectly using ASH_CANONICALIZATION_ERROR which is misleading for DB errors, etc.)
        const ashError = new AshVerifyError(
          'ASH_INTERNAL_ERROR',
          'Request verification failed due to internal error'
        );
        onError(ashError, req, res, next);
      }
    }
  };
}
