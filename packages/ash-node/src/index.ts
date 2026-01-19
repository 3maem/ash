/**
 * ASH Node.js SDK
 *
 * Request integrity and anti-replay protection for Node.js applications.
 *
 * @packageDocumentation
 * @module @3meam/ash-node
 */

import * as wasm from '@3meam/ash-wasm';

// Re-export WASM functions with TypeScript types
export { wasm };

/**
 * ASH security modes.
 */
export type AshMode = 'minimal' | 'balanced' | 'strict';

/**
 * Context options for creating a new ASH context.
 */
export interface AshContextOptions {
  /** Endpoint binding (e.g., "POST /api/update") */
  binding: string;
  /** Time-to-live in milliseconds */
  ttlMs: number;
  /** Security mode */
  mode?: AshMode;
  /** Optional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Stored context data.
 */
export interface AshContext {
  /** Unique context identifier */
  id: string;
  /** Endpoint binding */
  binding: string;
  /** Expiration timestamp (Unix ms) */
  expiresAt: number;
  /** Security mode */
  mode: AshMode;
  /** Whether context has been used */
  used: boolean;
  /** Optional server-generated nonce */
  nonce?: string;
  /** Optional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Verification result.
 */
export interface AshVerifyResult {
  /** Whether verification succeeded */
  valid: boolean;
  /** Error code if verification failed */
  errorCode?: string;
  /** Error message if verification failed */
  errorMessage?: string;
  /** Context metadata (available on success) */
  metadata?: Record<string, unknown>;
}

/**
 * Context store interface.
 * Implement this to use different storage backends (Redis, SQL, etc.)
 */
export interface AshContextStore {
  /** Create a new context and return its ID */
  create(options: AshContextOptions): Promise<AshContext>;
  /** Get context by ID, returns null if not found or expired */
  get(id: string): Promise<AshContext | null>;
  /** Mark context as used (consume it) */
  consume(id: string): Promise<boolean>;
  /** Delete expired contexts */
  cleanup(): Promise<number>;
}

/**
 * Initialize the ASH library.
 * Call this once before using other functions.
 */
export function ashInit(): void {
  wasm.ashInit();
}

/**
 * Canonicalize a JSON string to deterministic form.
 *
 * @param input - JSON string to canonicalize
 * @returns Canonical JSON string
 * @throws Error if input is not valid JSON
 *
 * @example
 * ```typescript
 * const canonical = ashCanonicalizeJson('{"z":1,"a":2}');
 * // => '{"a":2,"z":1}'
 * ```
 */
export function ashCanonicalizeJson(input: string): string {
  return wasm.ashCanonicalizeJson(input);
}

/**
 * Canonicalize URL-encoded form data to deterministic form.
 *
 * @param input - URL-encoded string to canonicalize
 * @returns Canonical URL-encoded string
 *
 * @example
 * ```typescript
 * const canonical = ashCanonicalizeUrlencoded('z=1&a=2');
 * // => 'a=2&z=1'
 * ```
 */
export function ashCanonicalizeUrlencoded(input: string): string {
  return wasm.ashCanonicalizeUrlencoded(input);
}

/**
 * Build a cryptographic proof for request integrity.
 *
 * @param mode - Security mode: "minimal", "balanced", or "strict"
 * @param binding - Endpoint binding: "METHOD /path"
 * @param contextId - Context ID from server
 * @param nonce - Optional nonce for server-assisted mode
 * @param canonicalPayload - Canonicalized payload string
 * @returns Base64URL-encoded proof string
 *
 * @example
 * ```typescript
 * const proof = ashBuildProof(
 *   'balanced',
 *   'POST /api/update',
 *   'ctx_abc123',
 *   null,
 *   '{"name":"John"}'
 * );
 * ```
 */
export function ashBuildProof(
  mode: AshMode,
  binding: string,
  contextId: string,
  nonce: string | null,
  canonicalPayload: string
): string {
  return wasm.ashBuildProof(mode, binding, contextId, nonce ?? undefined, canonicalPayload);
}

/**
 * Verify that two proofs match using constant-time comparison.
 *
 * @param expected - Expected proof (computed by server)
 * @param actual - Actual proof (received from client)
 * @returns true if proofs match, false otherwise
 */
export function ashVerifyProof(expected: string, actual: string): boolean {
  return wasm.ashVerifyProof(expected, actual);
}

/**
 * Normalize a binding string to canonical form.
 *
 * @param method - HTTP method (GET, POST, etc.)
 * @param path - URL path
 * @returns Canonical binding string
 *
 * @example
 * ```typescript
 * const binding = ashNormalizeBinding('post', '/api//test/');
 * // => 'POST /api/test'
 * ```
 */
export function ashNormalizeBinding(method: string, path: string): string {
  return wasm.ashNormalizeBinding(method, path);
}

/**
 * Constant-time comparison of two strings.
 *
 * @param a - First string
 * @param b - Second string
 * @returns true if strings are equal, false otherwise
 */
export function ashTimingSafeEqual(a: string, b: string): boolean {
  return wasm.ashTimingSafeEqual(a, b);
}

/**
 * Get the ASH protocol version.
 *
 * @returns Version string (e.g., "ASHv1")
 */
export function ashVersion(): string {
  return wasm.ashVersion();
}

/**
 * Get the library version.
 *
 * @returns Semantic version string
 */
export function ashLibraryVersion(): string {
  return wasm.ashLibraryVersion();
}

// Export middleware from separate module
export * from './middleware';
export * from './stores';
