/**
 * ASH Node.js SDK
 *
 * Request integrity and anti-replay protection for Node.js applications.
 *
 * v2.3.1 Specification Compliance:
 *   - JCS Canonicalization (RFC 8785): byte-wise key sorting, NFC normalization
 *   - Binding Format: METHOD|PATH|CANONICAL_QUERY (pipe-separated)
 *   - Canonical Query: byte-wise sorting, uppercase percent-encoding
 *   - SHA-256 lowercase hex output
 *   - Constant-time comparison using crypto.timingSafeEqual
 *   - Derived client secret (clientSecret = HMAC(nonce, contextId+binding))
 *   - Context scoping (v2.2) and request chaining (v2.3)
 *
 * @packageDocumentation
 * @module @3maem/ash-node
 */

import * as crypto from 'crypto';
import * as wasm from '@3maem/ash-wasm';

// Re-export WASM functions with TypeScript types
export { wasm };

/**
 * ASH SDK version (library version, not protocol version).
 */
export const ASH_SDK_VERSION = '2.3.1';

/**
 * ASH protocol version prefix (v1.x legacy).
 */
export const ASH_VERSION_PREFIX = 'ASHv1';

/**
 * ASH protocol version prefix (v2.1).
 * Exported for API consistency across SDKs.
 */
export const ASH_VERSION_PREFIX_V21 = 'ASHv2.1';

/**
 * ASH protocol version prefix (v2.3).
 * Supports context scoping and request chaining.
 */
export const ASH_VERSION_PREFIX_V23 = 'ASHv2.3';

/**
 * ASH security modes.
 */
export type AshMode = 'minimal' | 'balanced' | 'strict';

/**
 * Context options for creating a new ASH context.
 */
export interface AshContextOptions {
  binding: string;
  ttlMs: number;
  mode?: AshMode;
  metadata?: Record<string, unknown>;
}

/**
 * Stored context data (v2.1).
 */
export interface AshContext {
  id: string;
  binding: string;
  expiresAt: number;
  mode: AshMode;
  used: boolean;
  nonce?: string;
  clientSecret?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Client-safe context response (v2.1).
 */
export interface AshClientContext {
  contextId: string;
  binding: string;
  mode: AshMode;
  expiresAt: number;
  clientSecret: string;
}

/**
 * Verification result.
 */
export interface AshVerifyResult {
  valid: boolean;
  errorCode?: string;
  errorMessage?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Context store interface.
 */
export interface AshContextStore {
  create(options: AshContextOptions): Promise<AshContext>;
  get(id: string): Promise<AshContext | null>;
  consume(id: string): Promise<boolean>;
  cleanup(): Promise<number>;
}

// =========================================================================
// Native JavaScript Implementations (RFC 8785 JCS Compliant)
// These serve as reference implementations and fallbacks.
// =========================================================================

/**
 * Canonicalize JSON according to RFC 8785 (JCS - JSON Canonicalization Scheme).
 *
 * Rules implemented:
 * 1. Object keys sorted lexicographically (byte-wise using < > comparison, NOT localeCompare)
 * 2. Unicode normalization: NFC (use str.normalize('NFC'))
 * 3. Minimal JSON escaping:
 *    - 0x08 -> \b, 0x09 -> \t, 0x0A -> \n, 0x0C -> \f, 0x0D -> \r
 *    - 0x22 -> \", 0x5C -> \\
 *    - 0x00-0x1F (other control chars) -> \uXXXX (lowercase hex)
 * 4. Numbers: -0 becomes 0, whole floats become integers
 * 5. MUST reject: NaN, Infinity, undefined
 *
 * @param input JSON string to canonicalize
 * @returns Canonical JSON string per RFC 8785
 * @throws Error if input contains NaN, Infinity, or undefined
 */
export function canonicalizeJsonNative(input: string): string {
  const parsed = JSON.parse(input);
  return serializeJcs(parsed);
}

/**
 * Serialize a value to JCS-compliant JSON.
 * @internal
 */
function serializeJcs(value: unknown): string {
  if (value === null) {
    return 'null';
  }

  if (value === undefined) {
    throw new Error('JCS: undefined values are not allowed');
  }

  const type = typeof value;

  if (type === 'boolean') {
    return value ? 'true' : 'false';
  }

  if (type === 'number') {
    const num = value as number;

    // Reject NaN and Infinity
    if (Number.isNaN(num)) {
      throw new Error('JCS: NaN values are not allowed');
    }
    if (!Number.isFinite(num)) {
      throw new Error('JCS: Infinity values are not allowed');
    }

    // Handle -0 -> 0
    if (Object.is(num, -0)) {
      return '0';
    }

    // Use ES6 number serialization (which handles whole floats correctly)
    return String(num);
  }

  if (type === 'string') {
    return serializeJcsString(value as string);
  }

  if (Array.isArray(value)) {
    const items = value.map(item => serializeJcs(item));
    return '[' + items.join(',') + ']';
  }

  if (type === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj);

    // RFC 8785: Sort keys lexicographically using byte-wise comparison
    // JavaScript's < and > operators on strings perform byte-wise comparison
    keys.sort((a, b) => {
      // Normalize to NFC before comparison
      const normA = a.normalize('NFC');
      const normB = b.normalize('NFC');
      if (normA < normB) return -1;
      if (normA > normB) return 1;
      return 0;
    });

    const pairs = keys.map(key => {
      const normalizedKey = key.normalize('NFC');
      return serializeJcsString(normalizedKey) + ':' + serializeJcs(obj[key]);
    });

    return '{' + pairs.join(',') + '}';
  }

  throw new Error(`JCS: Unsupported type: ${type}`);
}

/**
 * Serialize a string with minimal JCS escaping.
 * @internal
 */
function serializeJcsString(str: string): string {
  // Normalize to NFC first
  const normalized = str.normalize('NFC');

  let result = '"';
  for (let i = 0; i < normalized.length; i++) {
    const char = normalized[i];
    const code = normalized.charCodeAt(i);

    // Minimal escaping per RFC 8785
    switch (code) {
      case 0x08: // backspace
        result += '\\b';
        break;
      case 0x09: // tab
        result += '\\t';
        break;
      case 0x0A: // newline
        result += '\\n';
        break;
      case 0x0C: // form feed
        result += '\\f';
        break;
      case 0x0D: // carriage return
        result += '\\r';
        break;
      case 0x22: // double quote
        result += '\\"';
        break;
      case 0x5C: // backslash
        result += '\\\\';
        break;
      default:
        // Other control characters (0x00-0x1F) use \uXXXX (lowercase hex)
        if (code < 0x20) {
          result += '\\u' + code.toString(16).padStart(4, '0');
        } else {
          result += char;
        }
    }
  }
  result += '"';
  return result;
}

/**
 * Canonicalize a URL query string according to ASH v2.3.1 specification.
 *
 * Rules:
 * 1. Remove leading ? if present
 * 2. Strip fragment (#...)
 * 3. Byte-wise sort by key, then by value (use < > comparison, NOT localeCompare)
 * 4. Uppercase percent-encoding hex (A-F not a-f)
 * 5. Preserve empty values (a= stays as a=)
 * 6. + is literal plus, space is %20
 *
 * @param query Query string to canonicalize
 * @returns Canonical query string
 */
export function canonicalQueryNative(query: string): string {
  // Remove leading ?
  let q = query.startsWith('?') ? query.slice(1) : query;

  // Strip fragment
  const fragIndex = q.indexOf('#');
  if (fragIndex !== -1) {
    q = q.slice(0, fragIndex);
  }

  if (q === '') {
    return '';
  }

  // Parse pairs
  const pairs: Array<{ key: string; value: string }> = [];

  for (const pair of q.split('&')) {
    if (pair === '') continue;

    const eqIndex = pair.indexOf('=');
    let key: string;
    let value: string;

    if (eqIndex === -1) {
      key = pair;
      value = '';
    } else {
      key = pair.slice(0, eqIndex);
      value = pair.slice(eqIndex + 1);
    }

    // Normalize percent-encoding to uppercase
    key = normalizePercentEncoding(key);
    value = normalizePercentEncoding(value);

    pairs.push({ key, value });
  }

  // Sort by key, then by value (byte-wise using < >)
  pairs.sort((a, b) => {
    if (a.key < b.key) return -1;
    if (a.key > b.key) return 1;
    if (a.value < b.value) return -1;
    if (a.value > b.value) return 1;
    return 0;
  });

  // Reconstruct, preserving empty values
  return pairs.map(p => p.key + '=' + p.value).join('&');
}

/**
 * Normalize percent-encoding to uppercase hex.
 * @internal
 */
function normalizePercentEncoding(str: string): string {
  return str.replace(/%([0-9a-fA-F]{2})/g, (_, hex) => '%' + hex.toUpperCase());
}

/**
 * Normalize a binding string to canonical form (native implementation).
 *
 * Format: METHOD|PATH|CANONICAL_QUERY
 * - Method MUST be uppercase
 * - Path MUST start with /
 * - Trailing pipe even if query is empty
 *
 * @param method HTTP method
 * @param path URL path
 * @param query Query string (optional)
 * @returns Canonical binding string
 */
export function normalizeBindingNative(method: string, path: string, query: string = ''): string {
  // Uppercase method
  const upperMethod = method.toUpperCase();

  // Ensure path starts with /
  let normalizedPath = path;
  if (!normalizedPath.startsWith('/')) {
    normalizedPath = '/' + normalizedPath;
  }

  // Remove trailing slashes (except for root /)
  if (normalizedPath !== '/' && normalizedPath.endsWith('/')) {
    normalizedPath = normalizedPath.replace(/\/+$/, '');
  }

  // Remove duplicate slashes
  normalizedPath = normalizedPath.replace(/\/+/g, '/');

  // Canonicalize query
  const canonicalQuery = canonicalQueryNative(query);

  // Format: METHOD|PATH|QUERY (trailing pipe even if query empty)
  return `${upperMethod}|${normalizedPath}|${canonicalQuery}`;
}

// =========================================================================
// WASM-backed implementations (primary)
// =========================================================================

export function ashInit(): void {
  wasm.ashInit();
}

export function ashCanonicalizeJson(input: string): string {
  return wasm.ashCanonicalizeJson(input);
}

export function ashCanonicalizeUrlencoded(input: string): string {
  return wasm.ashCanonicalizeUrlencoded(input);
}

/** @deprecated Use ashBuildProofV21 */
export function ashBuildProof(
  mode: AshMode,
  binding: string,
  contextId: string,
  nonce: string | null,
  canonicalPayload: string
): string {
  return wasm.ashBuildProof(mode, binding, contextId, nonce ?? undefined, canonicalPayload);
}

export function ashVerifyProof(expected: string, actual: string): boolean {
  return wasm.ashVerifyProof(expected, actual);
}

/**
 * Canonicalize a URL query string according to ASH specification.
 * Follows the 9 MUST rules for query canonicalization.
 *
 * @param query Query string to canonicalize (with or without leading ?)
 * @returns Canonical query string
 */
export function ashCanonicalizeQuery(query: string): string {
  return wasm.ashCanonicalizeQuery(query);
}

/**
 * Normalize a binding string to canonical form (v2.3.2+ format).
 * Bindings are in the format: "METHOD|PATH|CANONICAL_QUERY"
 *
 * @param method HTTP method (GET, POST, etc.)
 * @param path URL path
 * @param query Query string (empty string if none)
 * @returns Canonical binding string (METHOD|PATH|QUERY)
 */
export function ashNormalizeBinding(method: string, path: string, query: string = ''): string {
  return wasm.ashNormalizeBinding(method, path, query);
}

/**
 * Normalize a binding from a full URL path (including query string).
 *
 * @param method HTTP method (GET, POST, etc.)
 * @param fullPath Full URL path including query string (e.g., "/api/users?page=1")
 * @returns Canonical binding string (METHOD|PATH|QUERY)
 */
export function ashNormalizeBindingFromUrl(method: string, fullPath: string): string {
  return wasm.ashNormalizeBindingFromUrl(method, fullPath);
}

export function ashTimingSafeEqual(a: string, b: string): boolean {
  return wasm.ashTimingSafeEqual(a, b);
}

export function ashVersion(): string {
  return wasm.ashVersion();
}

export function ashLibraryVersion(): string {
  return wasm.ashLibraryVersion();
}

// ASH v2.1 - Derived Client Secret & Cryptographic Proof

export function ashGenerateNonce(bytes: number = 32): string {
  return crypto.randomBytes(bytes).toString('hex');
}

export function ashGenerateContextId(): string {
  return 'ash_' + crypto.randomBytes(16).toString('hex');
}

export function ashDeriveClientSecret(
  nonce: string,
  contextId: string,
  binding: string
): string {
  return crypto.createHmac('sha256', nonce)
    .update(contextId + '|' + binding)
    .digest('hex');
}

export function ashBuildProofV21(
  clientSecret: string,
  timestamp: string,
  binding: string,
  bodyHash: string
): string {
  const message = timestamp + '|' + binding + '|' + bodyHash;
  return crypto.createHmac('sha256', clientSecret)
    .update(message)
    .digest('hex');
}

export function ashVerifyProofV21(
  nonce: string,
  contextId: string,
  binding: string,
  timestamp: string,
  bodyHash: string,
  clientProof: string
): boolean {
  const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
  const expectedProof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);
  try {
    return crypto.timingSafeEqual(
      Buffer.from(expectedProof, 'hex'),
      Buffer.from(clientProof, 'hex')
    );
  } catch {
    return false;
  }
}

export function ashHashBody(canonicalBody: string): string {
  return crypto.createHash('sha256').update(canonicalBody).digest('hex');
}

export function ashContextToClient(context: AshContext): AshClientContext {
  if (!context.clientSecret) {
    throw new Error('Context must have clientSecret for v2.1');
  }
  return {
    contextId: context.id,
    binding: context.binding,
    mode: context.mode,
    expiresAt: context.expiresAt,
    clientSecret: context.clientSecret,
  };
}

export * from './middleware';
export * from './stores';

// =========================================================================
// ASH v2.2 - Context Scoping (Selective Field Protection)
// =========================================================================

/**
 * Scoped proof result.
 */
export interface AshScopedProofResult {
  proof: string;
  scopeHash: string;
}

/**
 * Extract scoped fields from a payload object.
 *
 * @param payload Full payload object
 * @param scope Array of field paths (supports dot notation)
 * @returns Object containing only scoped fields
 */
export function ashExtractScopedFields(
  payload: Record<string, unknown>,
  scope: string[]
): Record<string, unknown> {
  if (scope.length === 0) {
    return payload;
  }

  const result: Record<string, unknown> = {};

  for (const fieldPath of scope) {
    const value = getNestedValue(payload, fieldPath);
    if (value !== undefined) {
      setNestedValue(result, fieldPath, value);
    }
  }

  return result;
}

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const keys = path.split('.');
  let current: unknown = obj;

  for (const key of keys) {
    if (current === null || typeof current !== 'object') {
      return undefined;
    }
    current = (current as Record<string, unknown>)[key];
  }

  return current;
}

function setNestedValue(
  obj: Record<string, unknown>,
  path: string,
  value: unknown
): void {
  const keys = path.split('.');
  let current = obj;

  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i];
    if (!(key in current) || typeof current[key] !== 'object') {
      current[key] = {};
    }
    current = current[key] as Record<string, unknown>;
  }

  current[keys[keys.length - 1]] = value;
}

/**
 * Build v2.2 proof with scoped fields.
 *
 * @param clientSecret Derived client secret
 * @param timestamp Request timestamp (milliseconds)
 * @param binding Request binding
 * @param payload Full payload object
 * @param scope Fields to protect (empty = all)
 * @returns Proof and scope hash
 */
export function ashBuildProofV21Scoped(
  clientSecret: string,
  timestamp: string,
  binding: string,
  payload: Record<string, unknown>,
  scope: string[]
): AshScopedProofResult {
  const scopedPayload = ashExtractScopedFields(payload, scope);
  const canonicalScoped = JSON.stringify(scopedPayload);
  const bodyHash = ashHashBody(canonicalScoped);

  const scopeStr = scope.join(',');
  const scopeHash = ashHashBody(scopeStr);

  const message = timestamp + '|' + binding + '|' + bodyHash + '|' + scopeHash;
  const proof = crypto.createHmac('sha256', clientSecret)
    .update(message)
    .digest('hex');

  return { proof, scopeHash };
}

/**
 * Verify v2.2 proof with scoped fields.
 */
export function ashVerifyProofV21Scoped(
  nonce: string,
  contextId: string,
  binding: string,
  timestamp: string,
  payload: Record<string, unknown>,
  scope: string[],
  scopeHash: string,
  clientProof: string
): boolean {
  // Verify scope hash
  const scopeStr = scope.join(',');
  const expectedScopeHash = ashHashBody(scopeStr);

  try {
    if (!crypto.timingSafeEqual(
      Buffer.from(expectedScopeHash, 'hex'),
      Buffer.from(scopeHash, 'hex')
    )) {
      return false;
    }
  } catch {
    return false;
  }

  const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
  const result = ashBuildProofV21Scoped(clientSecret, timestamp, binding, payload, scope);

  try {
    return crypto.timingSafeEqual(
      Buffer.from(result.proof, 'hex'),
      Buffer.from(clientProof, 'hex')
    );
  } catch {
    return false;
  }
}

/**
 * Hash scoped payload fields.
 */
export function ashHashScopedBody(
  payload: Record<string, unknown>,
  scope: string[]
): string {
  const scopedPayload = ashExtractScopedFields(payload, scope);
  const canonical = JSON.stringify(scopedPayload);
  return ashHashBody(canonical);
}

// =========================================================================
// ASH v2.3 - Unified Proof Functions (Scoping + Chaining)
// =========================================================================

/**
 * Unified proof result.
 */
export interface AshUnifiedProofResult {
  proof: string;
  scopeHash: string;
  chainHash: string;
}

/**
 * Hash a proof for chaining purposes.
 *
 * @param proof Proof to hash
 * @returns SHA-256 hash of the proof (64 hex chars)
 */
export function ashHashProof(proof: string): string {
  return crypto.createHash('sha256').update(proof).digest('hex');
}

/**
 * Build unified v2.3 cryptographic proof with optional scoping and chaining.
 *
 * Formula:
 *   scopeHash  = scope.length > 0 ? SHA256(scope.join(",")) : ""
 *   bodyHash   = SHA256(canonicalize(scopedPayload))
 *   chainHash  = previousProof ? SHA256(previousProof) : ""
 *   proof      = HMAC-SHA256(clientSecret, timestamp|binding|bodyHash|scopeHash|chainHash)
 *
 * @param clientSecret Derived client secret
 * @param timestamp Request timestamp (milliseconds)
 * @param binding Request binding
 * @param payload Full payload object
 * @param scope Fields to protect (empty = full payload)
 * @param previousProof Previous proof in chain (null/undefined = no chaining)
 * @returns Unified proof result with proof, scopeHash, and chainHash
 */
export function ashBuildProofUnified(
  clientSecret: string,
  timestamp: string,
  binding: string,
  payload: Record<string, unknown>,
  scope: string[] = [],
  previousProof?: string | null
): AshUnifiedProofResult {
  // Extract and hash scoped payload
  const scopedPayload = ashExtractScopedFields(payload, scope);
  const canonicalScoped = JSON.stringify(scopedPayload);
  const bodyHash = ashHashBody(canonicalScoped);

  // Compute scope hash (empty string if no scope)
  const scopeHash = scope.length > 0 ? ashHashBody(scope.join(',')) : '';

  // Compute chain hash (empty string if no previous proof)
  const chainHash = (previousProof && previousProof !== '')
    ? ashHashProof(previousProof)
    : '';

  // Build proof message: timestamp|binding|bodyHash|scopeHash|chainHash
  const message = `${timestamp}|${binding}|${bodyHash}|${scopeHash}|${chainHash}`;
  const proof = crypto.createHmac('sha256', clientSecret)
    .update(message)
    .digest('hex');

  return { proof, scopeHash, chainHash };
}

/**
 * Verify unified v2.3 proof with optional scoping and chaining.
 *
 * @param nonce Server-side secret nonce
 * @param contextId Context identifier
 * @param binding Request binding
 * @param timestamp Request timestamp
 * @param payload Full payload object
 * @param clientProof Proof received from client
 * @param scope Fields that were protected (empty = full payload)
 * @param scopeHash Scope hash from client (empty if no scoping)
 * @param previousProof Previous proof in chain (null if no chaining)
 * @param chainHash Chain hash from client (empty if no chaining)
 * @returns true if proof is valid
 */
export function ashVerifyProofUnified(
  nonce: string,
  contextId: string,
  binding: string,
  timestamp: string,
  payload: Record<string, unknown>,
  clientProof: string,
  scope: string[] = [],
  scopeHash: string = '',
  previousProof?: string | null,
  chainHash: string = ''
): boolean {
  // Validate scope hash if scoping is used
  if (scope.length > 0) {
    const expectedScopeHash = ashHashBody(scope.join(','));
    try {
      if (!crypto.timingSafeEqual(
        Buffer.from(expectedScopeHash, 'hex'),
        Buffer.from(scopeHash, 'hex')
      )) {
        return false;
      }
    } catch {
      return false;
    }
  }

  // Validate chain hash if chaining is used
  if (previousProof && previousProof !== '') {
    const expectedChainHash = ashHashProof(previousProof);
    try {
      if (!crypto.timingSafeEqual(
        Buffer.from(expectedChainHash, 'hex'),
        Buffer.from(chainHash, 'hex')
      )) {
        return false;
      }
    } catch {
      return false;
    }
  }

  // Derive client secret and compute expected proof
  const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
  const result = ashBuildProofUnified(
    clientSecret,
    timestamp,
    binding,
    payload,
    scope,
    previousProof
  );

  try {
    return crypto.timingSafeEqual(
      Buffer.from(result.proof, 'hex'),
      Buffer.from(clientProof, 'hex')
    );
  } catch {
    return false;
  }
}

// =========================================================================
// ASH Namespace Object (v2.3.1)
// Provides proper namespace consistency: ash.canon.*, ash.utils.*, etc.
// =========================================================================

/**
 * Canonicalization namespace.
 * Contains all JCS and query canonicalization functions.
 */
export const ashCanon = {
  /**
   * Canonicalize JSON according to RFC 8785 (JCS).
   * - Object keys sorted lexicographically (byte-wise using < > comparison)
   * - Unicode normalization: NFC
   * - Minimal JSON escaping
   * - Rejects NaN, Infinity, undefined
   */
  json: ashCanonicalizeJson,

  /**
   * Native JavaScript implementation of JCS canonicalization.
   * Use for testing or as fallback when WASM is unavailable.
   */
  jsonNative: canonicalizeJsonNative,

  /**
   * Canonicalize URL-encoded form data.
   * Parameters sorted by key, then by value (byte-wise).
   */
  urlencoded: ashCanonicalizeUrlencoded,

  /**
   * Canonicalize a URL query string.
   * - Remove leading ? if present
   * - Strip fragment (#)
   * - Byte-wise sort by key, then by value
   * - Uppercase percent-encoding hex (A-F not a-f)
   * - Preserve empty values (a= stays as a=)
   * - + is literal plus, space is %20
   */
  query: ashCanonicalizeQuery,

  /**
   * Native JavaScript implementation of query canonicalization.
   * Use for testing or as fallback when WASM is unavailable.
   */
  queryNative: canonicalQueryNative,
};

/**
 * Utility namespace.
 * Contains helper functions for hashing, timing-safe comparison, etc.
 */
export const ashUtils = {
  /**
   * Timing-safe string comparison.
   * Uses crypto.timingSafeEqual internally.
   */
  timingSafeEqual: ashTimingSafeEqual,

  /**
   * Hash a body/payload using SHA-256.
   * Returns lowercase hex (64 characters).
   */
  hashBody: ashHashBody,

  /**
   * Hash a proof for chaining purposes.
   * Returns SHA-256 lowercase hex (64 characters).
   */
  hashProof: ashHashProof,

  /**
   * Generate a cryptographically secure nonce.
   * Returns hex-encoded random bytes.
   */
  generateNonce: ashGenerateNonce,

  /**
   * Generate a unique context ID.
   * Format: ash_<32 hex chars>
   */
  generateContextId: ashGenerateContextId,

  /**
   * Extract scoped fields from a payload.
   * Supports dot notation for nested fields.
   */
  extractScopedFields: ashExtractScopedFields,

  /**
   * Hash scoped payload fields.
   */
  hashScopedBody: ashHashScopedBody,
};

/**
 * Binding namespace.
 * Contains functions for normalizing request bindings.
 */
export const ashBinding = {
  /**
   * Normalize a binding string to canonical form.
   * Format: METHOD|PATH|CANONICAL_QUERY
   * - Method MUST be uppercase
   * - Path MUST start with /
   * - Trailing pipe even if query is empty
   */
  normalize: ashNormalizeBinding,

  /**
   * Native JavaScript implementation of binding normalization.
   * Use for testing or as fallback when WASM is unavailable.
   */
  normalizeNative: normalizeBindingNative,

  /**
   * Normalize a binding from a full URL path.
   * Parses query string from the path automatically.
   */
  normalizeFromUrl: ashNormalizeBindingFromUrl,
};

/**
 * Proof namespace.
 * Contains proof generation and verification functions.
 */
export const ashProof = {
  /**
   * Build legacy proof (pre-v2.1).
   * @deprecated Use buildV21 or buildUnified instead.
   */
  build: ashBuildProof,

  /**
   * Verify legacy proof (pre-v2.1).
   * @deprecated Use verifyV21 or verifyUnified instead.
   */
  verify: ashVerifyProof,

  /**
   * Build v2.1 proof with derived client secret.
   */
  buildV21: ashBuildProofV21,

  /**
   * Verify v2.1 proof.
   * Uses constant-time comparison internally.
   */
  verifyV21: ashVerifyProofV21,

  /**
   * Build v2.1 proof with context scoping.
   */
  buildV21Scoped: ashBuildProofV21Scoped,

  /**
   * Verify v2.1 proof with context scoping.
   * Uses constant-time comparison internally.
   */
  verifyV21Scoped: ashVerifyProofV21Scoped,

  /**
   * Build unified v2.3 proof with optional scoping and chaining.
   */
  buildUnified: ashBuildProofUnified,

  /**
   * Verify unified v2.3 proof.
   * Uses constant-time comparison internally.
   */
  verifyUnified: ashVerifyProofUnified,

  /**
   * Derive client secret from nonce, contextId, and binding.
   */
  deriveClientSecret: ashDeriveClientSecret,
};

/**
 * Context namespace.
 * Contains context-related functions.
 */
export const ashContext = {
  /**
   * Convert server context to client-safe context.
   * Strips sensitive fields (nonce) and adds clientSecret.
   */
  toClient: ashContextToClient,
};

/**
 * ASH namespace object for proper namespace consistency.
 *
 * Usage:
 *   ash.canon.json(input)
 *   ash.canon.query(input)
 *   ash.utils.hashBody(payload)
 *   ash.utils.timingSafeEqual(a, b)
 *   ash.binding.normalize(method, path, query)
 *   ash.proof.buildUnified(...)
 *   ash.proof.verifyUnified(...)
 *
 * @example
 * ```typescript
 * import { ash } from '@3maem/ash-node';
 *
 * // Canonicalize JSON
 * const canonical = ash.canon.json('{"b":2,"a":1}');
 *
 * // Normalize binding
 * const binding = ash.binding.normalize('POST', '/api/users', 'sort=name&page=1');
 *
 * // Build proof
 * const { proof } = ash.proof.buildUnified(clientSecret, timestamp, binding, payload);
 * ```
 */
export const ash = {
  // Version info
  VERSION: ASH_SDK_VERSION,
  VERSION_PREFIX: ASH_VERSION_PREFIX,
  VERSION_PREFIX_V21: ASH_VERSION_PREFIX_V21,
  VERSION_PREFIX_V23: ASH_VERSION_PREFIX_V23,

  // Core functions
  init: ashInit,
  version: ashVersion,
  libraryVersion: ashLibraryVersion,

  // Namespaced modules (v2.3.1 structure)
  canon: ashCanon,
  utils: ashUtils,
  binding: ashBinding,
  proof: ashProof,
  context: ashContext,

  // Legacy flat access (deprecated, use namespaced versions)
  /** @deprecated Use ash.canon.json */
  canonicalizeJson: ashCanonicalizeJson,
  /** @deprecated Use ash.canon.urlencoded */
  canonicalizeUrlencoded: ashCanonicalizeUrlencoded,
  /** @deprecated Use ash.canon.query */
  canonicalizeQuery: ashCanonicalizeQuery,
  /** @deprecated Use ash.binding.normalize */
  normalizeBinding: ashNormalizeBinding,
  /** @deprecated Use ash.binding.normalizeFromUrl */
  normalizeBindingFromUrl: ashNormalizeBindingFromUrl,
  /** @deprecated Use ash.proof.build */
  buildProof: ashBuildProof,
  /** @deprecated Use ash.proof.verify */
  verifyProof: ashVerifyProof,
  /** @deprecated Use ash.utils.timingSafeEqual */
  timingSafeEqual: ashTimingSafeEqual,
  /** @deprecated Use ash.utils.generateNonce */
  generateNonce: ashGenerateNonce,
  /** @deprecated Use ash.utils.generateContextId */
  generateContextId: ashGenerateContextId,
  /** @deprecated Use ash.proof.deriveClientSecret */
  deriveClientSecret: ashDeriveClientSecret,
  /** @deprecated Use ash.proof.buildV21 */
  buildProofV21: ashBuildProofV21,
  /** @deprecated Use ash.proof.verifyV21 */
  verifyProofV21: ashVerifyProofV21,
  /** @deprecated Use ash.utils.hashBody */
  hashBody: ashHashBody,
  /** @deprecated Use ash.context.toClient */
  contextToClient: ashContextToClient,
  /** @deprecated Use ash.utils.extractScopedFields */
  extractScopedFields: ashExtractScopedFields,
  /** @deprecated Use ash.proof.buildV21Scoped */
  buildProofV21Scoped: ashBuildProofV21Scoped,
  /** @deprecated Use ash.proof.verifyV21Scoped */
  verifyProofV21Scoped: ashVerifyProofV21Scoped,
  /** @deprecated Use ash.utils.hashScopedBody */
  hashScopedBody: ashHashScopedBody,
  /** @deprecated Use ash.utils.hashProof */
  hashProof: ashHashProof,
  /** @deprecated Use ash.proof.buildUnified */
  buildProofUnified: ashBuildProofUnified,
  /** @deprecated Use ash.proof.verifyUnified */
  verifyProofUnified: ashVerifyProofUnified,
};

// =========================================================================
// ENH-003: Server-Side Scope Policies
// =========================================================================

export {
  registerScopePolicy,
  registerScopePolicies,
  getScopePolicy,
  hasScopePolicy,
  getAllScopePolicies,
  clearScopePolicies,
} from './config/scopePolicies';

export type { ScopePolicyConfig } from './config/scopePolicies';
