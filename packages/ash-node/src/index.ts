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
import * as fs from 'fs';
import * as path from 'path';
import * as url from 'url';
import * as wasm from '@3maem/ash-wasm';

// Re-export WASM functions with TypeScript types
export { wasm };

/**
 * ASH SDK version (library version, not protocol version).
 */
export const ASH_SDK_VERSION = '2.3.4';

/**
 * Scope field delimiter for hashing (using U+001F unit separator to avoid collision).
 * BUG-002: Prevents collision when field names contain commas.
 * Must match Rust ash-core SCOPE_FIELD_DELIMITER.
 */
export const SCOPE_FIELD_DELIMITER = '\x1F';

// =========================================================================
// Security Limits (v2.3.4)
// =========================================================================

/**
 * Minimum bytes for nonce generation.
 */
export const MIN_NONCE_BYTES = 16;

/**
 * Minimum hex characters in nonce (32 hex = 16 bytes).
 */
export const MIN_NONCE_HEX_CHARS = 32;

/**
 * SEC-NONCE-001: Maximum nonce length.
 */
export const MAX_NONCE_LENGTH = 128;

/**
 * SEC-CTX-001: Maximum context_id length.
 */
export const MAX_CONTEXT_ID_LENGTH = 256;

/**
 * SEC-AUDIT-004: Maximum binding length (8KB).
 */
export const MAX_BINDING_LENGTH = 8192;

/**
 * SEC-SCOPE-001: Maximum individual scope field name length.
 */
export const MAX_SCOPE_FIELD_NAME_LENGTH = 64;

/**
 * SEC-SCOPE-001: Maximum total scope string length.
 */
export const MAX_TOTAL_SCOPE_LENGTH = 4096;

/**
 * BUG-018: Maximum number of scope fields.
 */
export const MAX_SCOPE_FIELDS = 100;

/**
 * SEC-011: Maximum array index in scope paths.
 */
export const MAX_ARRAY_INDEX = 10000;

/**
 * BUG-036: Maximum total array elements that can be allocated.
 */
export const MAX_TOTAL_ARRAY_ALLOCATION = 10000;

/**
 * SEC-019: Maximum dot-separated path depth in scope paths.
 */
export const MAX_SCOPE_PATH_DEPTH = 32;

/**
 * VULN-001: Maximum JSON nesting depth.
 */
export const MAX_RECURSION_DEPTH = 64;

/**
 * VULN-002: Maximum payload size (10MB).
 */
export const MAX_PAYLOAD_SIZE = 10485760;

/**
 * Expected length of SHA-256 hex output.
 */
export const SHA256_HEX_LENGTH = 64;

/**
 * Timing-safe comparison: bytes per comparison chunk.
 */
export const CHUNK_SIZE = 256;

/**
 * BUG-030/BUG-037: Fixed number of iterations for timing-safe comparison.
 */
export const FIXED_ITERATIONS = 8;

/**
 * Total bytes compared in timing-safe comparison (256 * 8).
 */
export const FIXED_WORK_SIZE = 2048;

// =========================================================================
// Configuration (v2.3.4)
// =========================================================================

/**
 * ASH Configuration interface.
 */
export interface AshConfig {
  trustProxy: boolean;
  trustedProxies: string[];
  rateLimitWindow: number;
  rateLimitMax: number;
  timestampTolerance: number;
}

let cachedConfig: AshConfig | null = null;

/**
 * Load configuration from environment variables.
 * v2.3.4: Added support for proxy and rate limiting configuration.
 *
 * @returns AshConfig object with environment-based settings
 */
export function ashLoadConfig(): AshConfig {
  if (cachedConfig) {
    return cachedConfig;
  }

  cachedConfig = {
    trustProxy: process.env.ASH_TRUST_PROXY === 'true',
    trustedProxies: process.env.ASH_TRUSTED_PROXIES?.split(',').map(s => s.trim()).filter(Boolean) ?? [],
    rateLimitWindow: parseInt(process.env.ASH_RATE_LIMIT_WINDOW ?? '60', 10),
    rateLimitMax: parseInt(process.env.ASH_RATE_LIMIT_MAX ?? '10', 10),
    timestampTolerance: parseInt(process.env.ASH_TIMESTAMP_TOLERANCE ?? '30', 10),
  };

  return cachedConfig;
}

/**
 * Get client IP address with proxy support.
 * v2.3.4: Added X-Forwarded-For handling for deployments behind proxies/CDNs.
 *
 * @param req - HTTP request object (Express/Node.js)
 * @returns Client IP address
 */
export function ashGetClientIp(req?: { headers?: { [key: string]: string | string[] | undefined }; socket?: { remoteAddress?: string } }): string {
  const config = ashLoadConfig();

  // If not trusting proxies, use direct connection IP
  if (!config.trustProxy) {
    return req?.socket?.remoteAddress ?? 'unknown';
  }

  // Check for X-Forwarded-For header
  const forwardedFor = req?.headers?.['x-forwarded-for'];
  if (forwardedFor) {
    const ips = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor;
    const clientIp = ips.split(',')[0].trim();
    // Basic IP validation (IPv4 or IPv6)
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(clientIp) || /^[0-9a-fA-F:]+$/.test(clientIp)) {
      return clientIp;
    }
  }

  // Check for X-Real-IP header
  const realIp = req?.headers?.['x-real-ip'];
  if (realIp && !Array.isArray(realIp)) {
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(realIp) || /^[0-9a-fA-F:]+$/.test(realIp)) {
      return realIp;
    }
  }

  // Fall back to direct connection IP
  return req?.socket?.remoteAddress ?? 'unknown';
}

/**
 * Normalize scope fields by sorting and deduplicating.
 * BUG-023: Ensures deterministic scope hash across all SDKs.
 * BUG-42 FIX: Uses byte-wise comparison for cross-SDK compatibility with Rust.
 *
 * @param scope Array of field paths
 * @returns Sorted and deduplicated scope array
 */
export function ashNormalizeScopeFields(scope: string[]): string[] {
  // Deduplicate using Set, then sort using byte-wise comparison
  // BUG-42 FIX: JavaScript's default sort uses UTF-16 code units, which differs
  // from Rust's byte-wise sort for non-ASCII strings. Use Buffer comparison.
  return [...new Set(scope)].sort((a, b) => {
    const bufA = Buffer.from(a, 'utf8');
    const bufB = Buffer.from(b, 'utf8');
    return bufA.compare(bufB);
  });
}

/**
 * Validate scope fields for security limits.
 * SEC-SCOPE-001: Enforces length limits on scope fields.
 * BUG-018: Uses byte length for proper Unicode handling.
 *
 * @param scope Array of field paths
 * @throws Error if validation fails
 */
export function ashValidateScopeFields(scope: string[]): void {
  // BUG-018: Validate scope array length
  if (scope.length > MAX_SCOPE_FIELDS) {
    throw new Error(`Scope exceeds maximum of ${MAX_SCOPE_FIELDS} fields`);
  }

  let totalByteLength = 0;

  for (const field of scope) {
    // Validate field not empty
    if (field.length === 0) {
      throw new Error('Scope field names cannot be empty');
    }

    // BUG-018: Use byte length for proper Unicode handling
    const fieldByteLength = Buffer.byteLength(field, 'utf8');

    // SEC-SCOPE-001: Validate individual field byte length
    if (fieldByteLength > MAX_SCOPE_FIELD_NAME_LENGTH) {
      throw new Error(`Scope field name exceeds maximum length of ${MAX_SCOPE_FIELD_NAME_LENGTH} bytes`);
    }

    // Validate field doesn't contain delimiter
    if (field.includes(SCOPE_FIELD_DELIMITER)) {
      throw new Error('Scope field contains reserved delimiter character (U+001F)');
    }

    // Accumulate total byte length
    totalByteLength += fieldByteLength;
  }

  // Add delimiter lengths (scope.length - 1 delimiters, each delimiter is 1 byte)
  if (scope.length > 1) {
    totalByteLength += scope.length - 1;
  }

  // SEC-SCOPE-001: Validate total scope byte length
  if (totalByteLength > MAX_TOTAL_SCOPE_LENGTH) {
    throw new Error(`Total scope length exceeds maximum of ${MAX_TOTAL_SCOPE_LENGTH} bytes`);
  }
}

/**
 * Join scope fields with the proper delimiter after normalization.
 * BUG-002, BUG-023: Uses unit separator and normalizes for cross-SDK compatibility.
 * SEC-SCOPE-001: Validates scope field lengths.
 * BUG-46 FIX: Validates count after deduplication.
 *
 * @param scope Array of field paths
 * @returns Joined scope string
 * @throws Error if validation fails
 */
export function ashJoinScopeFields(scope: string[]): string {
  // BUG-46 FIX: Normalize first (deduplicate), then validate the deduplicated result
  // This allows 200 fields with 150 duplicates to pass if deduplicated result has <100 fields
  const normalized = ashNormalizeScopeFields(scope);
  // SEC-SCOPE-001: Validate scope fields after deduplication
  ashValidateScopeFields(normalized);
  return normalized.join(SCOPE_FIELD_DELIMITER);
}

/**
 * ASH protocol version prefix (current version per SDK Implementation Reference).
 * Per spec Section 1.2: ASH_VERSION_PREFIX = "ASHv2.1"
 */
export const ASH_VERSION_PREFIX = 'ASHv2.1';

/**
 * ASH protocol version prefix (v1.x legacy).
 * @deprecated Use ASH_VERSION_PREFIX for current version
 */
export const ASH_VERSION_PREFIX_V1 = 'ASHv1';

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
 *
 * INFO-002 SECURITY NOTE: Rate Limiting Not Built-In (By Design)
 *
 * The SDK intentionally does NOT include rate limiting because:
 * 1. Rate limiting strategies vary by application (per-IP, per-user, per-API-key)
 * 2. Distributed rate limiting requires external infrastructure (Redis, etc.)
 * 3. API gateways/load balancers typically handle this more efficiently
 *
 * VULN-012 SECURITY NOTE: Without rate limiting, attackers could create
 * millions of contexts to exhaust storage (DoS attack).
 *
 * REQUIRED MITIGATIONS (implement at application level):
 * 1. API Gateway Rate Limiting:
 *    - Use nginx limit_req, AWS API Gateway throttling, or similar
 *    - Limit context creation endpoint to ~100 req/min per IP
 *
 * 2. Application-Level Rate Limiting:
 *    ```typescript
 *    import rateLimit from 'express-rate-limit';
 *    app.use('/api/context', rateLimit({ windowMs: 60000, max: 100 }));
 *    ```
 *
 * 3. Short TTLs:
 *    - Use minimal TTLs (30-60 seconds) to auto-expire unused contexts
 *    - Run cleanup() periodically (default: every 60 seconds in MemoryStore)
 *
 * 4. Storage Limits:
 *    - For Redis: Set maxmemory with eviction policy
 *    - For SQL: Monitor table size and add alerts
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
 * 6. VULN-002: Validates payload size <= MAX_PAYLOAD_SIZE (10MB)
 * 7. VULN-001: Validates nesting depth <= MAX_RECURSION_DEPTH (64)
 *
 * @param input JSON string to canonicalize
 * @returns Canonical JSON string per RFC 8785
 * @throws Error if input contains NaN, Infinity, undefined, or exceeds limits
 */
export function ashCanonicalizeJsonNative(input: string): string {
  // VULN-002: Validate payload size
  if (Buffer.byteLength(input, 'utf8') > MAX_PAYLOAD_SIZE) {
    throw new Error(`Payload size exceeds maximum of ${MAX_PAYLOAD_SIZE} bytes (10MB)`);
  }

  const parsed = JSON.parse(input);
  return serializeJcs(parsed, 0);
}

/**
 * Canonicalize an already-parsed JSON value with size checking.
 * BUG-044: Use this for Values from untrusted sources that have already been parsed.
 *
 * This function estimates the output size and validates it doesn't exceed limits.
 * Use ashCanonicalizeJsonNative() for string input which validates input size.
 *
 * @param value Already-parsed JSON value
 * @returns Canonical JSON string per RFC 8785
 * @throws Error if value contains NaN, Infinity, undefined, or exceeds limits
 */
export function ashCanonicalizeJsonValueNative(value: unknown): string {
  // Serialize first to check size (can't estimate accurately without serializing)
  const result = serializeJcs(value, 0);

  // VULN-002 / BUG-044: Validate output size
  if (Buffer.byteLength(result, 'utf8') > MAX_PAYLOAD_SIZE) {
    throw new Error(`Canonicalized payload size exceeds maximum of ${MAX_PAYLOAD_SIZE} bytes (10MB)`);
  }

  return result;
}

/**
 * Serialize a value to JCS-compliant JSON.
 * VULN-001: Validates nesting depth.
 * @internal
 */
function serializeJcs(value: unknown, depth: number): string {
  // VULN-001: Check recursion depth
  if (depth > MAX_RECURSION_DEPTH) {
    throw new Error(`JSON nesting depth exceeds maximum of ${MAX_RECURSION_DEPTH}`);
  }

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
    const items = value.map(item => serializeJcs(item, depth + 1));
    return '[' + items.join(',') + ']';
  }

  if (type === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj);

    // RFC 8785: Sort keys lexicographically using byte-wise comparison
    // BUG-LOGIC-002 FIX: JavaScript's < and > operators compare UTF-16 code units,
    // NOT bytes. Use Buffer.compare for true byte-wise sorting per RFC 8785.
    keys.sort((a, b) => {
      // Normalize to NFC first, then compare as UTF-8 bytes
      const normA = a.normalize('NFC');
      const normB = b.normalize('NFC');
      const bufA = Buffer.from(normA, 'utf8');
      const bufB = Buffer.from(normB, 'utf8');
      return bufA.compare(bufB);
    });

    const pairs = keys.map(key => {
      const normalizedKey = key.normalize('NFC');
      return serializeJcsString(normalizedKey) + ':' + serializeJcs(obj[key], depth + 1);
    });

    return '{' + pairs.join(',') + '}';
  }

  // BUG-27 FIX: Provide specific error message for BigInt
  if (type === 'bigint') {
    throw new Error(
      'JCS: BigInt values are not supported. Convert to string or number before canonicalization. ' +
      'Example: Use Number(bigintValue) for small values or bigintValue.toString() for large values.'
    );
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
 * BUG-043 FIX: Whitespace-only query strings treated as empty.
 *
 * @param query Query string to canonicalize
 * @returns Canonical query string
 */
export function ashCanonicalizeQueryNative(query: string): string {
  // Remove leading ?
  let q = query.startsWith('?') ? query.slice(1) : query;

  // Strip fragment
  const fragIndex = q.indexOf('#');
  if (fragIndex !== -1) {
    q = q.slice(0, fragIndex);
  }

  // BUG-043 FIX: Trim whitespace and treat whitespace-only as empty
  q = q.trim();

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

  // Sort by key, then by value (byte-wise using Buffer.compare)
  // PENTEST-001 FIX: JavaScript's < > operators compare UTF-16 code units, not bytes.
  // Use Buffer.compare for true byte-wise sorting to match Rust SDK behavior.
  pairs.sort((a, b) => {
    const keyCompare = Buffer.from(a.key, 'utf8').compare(Buffer.from(b.key, 'utf8'));
    if (keyCompare !== 0) return keyCompare;
    return Buffer.from(a.value, 'utf8').compare(Buffer.from(b.value, 'utf8'));
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
 * Native implementation of URL-encoded body canonicalization.
 * URL-encoded form bodies treat + as literal plus (not space), so + must be encoded as %2B.
 * BUG-LOGIC-128 FIX: Provides fallback for WASM failures.
 *
 * @param input URL-encoded string to canonicalize
 * @returns Canonical URL-encoded string
 */
export function ashCanonicalizeUrlencodedNative(input: string): string {
  // URL-encoded bodies: + is literal plus, must be encoded as %2B
  // First encode + as %2B, then run through query canonicalization
  const withEncodedPlus = input.replace(/\+/g, '%2B');
  return ashCanonicalizeQueryNative(withEncodedPlus.startsWith('?') ? withEncodedPlus.slice(1) : withEncodedPlus);
}

/**
 * Normalize a binding string to canonical form (native implementation).
 *
 * Format: METHOD|PATH|CANONICAL_QUERY
 * - Method MUST be uppercase
 * - Path MUST start with /
 * - Trailing pipe even if query is empty
 *
 * BUG-035 FIX: Resolves . and .. segments in path.
 * BUG-042 FIX: Rejects non-ASCII method names.
 *
 * @param method HTTP method
 * @param path URL path
 * @param query Query string (optional)
 * @returns Canonical binding string
 */
export function ashNormalizeBindingNative(method: string, path: string, query: string = ''): string {
  // BUG-042 FIX: Reject non-ASCII method names
  if (!/^[A-Z]+$/i.test(method)) {
    throw new Error('Method must contain only ASCII alphabetic characters');
  }

  // Uppercase method
  const upperMethod = method.toUpperCase();

  // BUG-027 FIX: Reject path containing encoded query delimiter (%3F = '?')
  // This prevents bypass attacks where the query is hidden in the path
  if (/%3[Ff]/.test(path)) {
    throw new Error('Path contains encoded query delimiter (%3F). Use separate query parameter.');
  }

  // Ensure path starts with /
  let normalizedPath = path;
  if (!normalizedPath.startsWith('/')) {
    normalizedPath = '/' + normalizedPath;
  }

  // Remove duplicate slashes
  normalizedPath = normalizedPath.replace(/\/+/g, '/');

  // BUG-035 FIX: Resolve . and .. segments
  const segments = normalizedPath.split('/');
  const resolvedSegments: string[] = [];

  for (const segment of segments) {
    if (segment === '' || segment === '.') {
      // Skip empty segments and current directory
      continue;
    } else if (segment === '..') {
      // Go up one level, but can't go above root
      if (resolvedSegments.length > 0) {
        resolvedSegments.pop();
      }
    } else {
      resolvedSegments.push(segment);
    }
  }

  // Reconstruct path
  normalizedPath = '/' + resolvedSegments.join('/');

  // Remove trailing slashes (except for root /)
  if (normalizedPath !== '/' && normalizedPath.endsWith('/')) {
    normalizedPath = normalizedPath.replace(/\/+$/, '');
  }

  // Canonicalize query
  const canonicalQuery = ashCanonicalizeQueryNative(query);

  // Format: METHOD|PATH|QUERY (trailing pipe even if query empty)
  return `${upperMethod}|${normalizedPath}|${canonicalQuery}`;
}

// =========================================================================
// WASM-backed implementations (primary) with native fallback
// BUG-LOGIC-128 FIX: All WASM functions now have try-catch with fallback
// =========================================================================

/**
 * Track if WASM has been initialized successfully.
 * Used to avoid repeated failed initialization attempts.
 */
let wasmInitialized = false;
let wasmInitFailed = false;

/**
 * Initialize the ASH WASM module.
 *
 * For NodeJS targets, wasm-pack auto-loads the WASM binary synchronously,
 * so we just need to call the ASH-specific init to set up panic hooks.
 */
export function ashInit(): void {
  if (wasmInitialized) {
    return; // Already initialized
  }
  if (wasmInitFailed) {
    return; // Don't retry if already failed
  }

  try {
    // For NodeJS targets, wasm-pack auto-loads the WASM binary.
    // Just call ashInit to set up panic hooks and verify WASM works.
    wasm.ashInit();

    // Verify WASM is working by calling a simple function
    const version = wasm.ashVersion();
    if (!version) {
      throw new Error('WASM ashVersion returned empty');
    }

    wasmInitialized = true;
  } catch (error) {
    wasmInitFailed = true;
    // WASM init failure is not critical - native fallbacks will be used
    if (process.env.NODE_ENV !== 'production') {
      console.warn('[ASH] WASM initialization failed, using native implementations');
    }
  }
}

/**
 * BUG-LOGIC-128 FIX: Canonicalize JSON with WASM, fallback to native on error.
 */
export function ashCanonicalizeJson(input: string): string {
  if (!wasmInitFailed) {
    try {
      return wasm.ashCanonicalizeJson(input);
    } catch {
      // Fall through to native implementation
    }
  }
  return ashCanonicalizeJsonNative(input);
}

/**
 * Canonicalize URL-encoded form data to deterministic form.
 * BUG-LOGIC-128 FIX: Falls back to native implementation on WASM error.
 * BUG-LOGIC-130 FIX: WASM now correctly treats + as literal plus (%2B).
 */
export function ashCanonicalizeUrlencoded(input: string): string {
  if (!wasmInitFailed) {
    try {
      return wasm.ashCanonicalizeUrlencoded(input);
    } catch {
      // Fall through to native implementation
    }
  }
  return ashCanonicalizeUrlencodedNative(input);
}


/**
 * Canonicalize a URL query string according to ASH specification.
 * Follows the 9 MUST rules for query canonicalization.
 * BUG-LOGIC-128 FIX: Falls back to native implementation on WASM error.
 *
 * @param query Query string to canonicalize (with or without leading ?)
 * @returns Canonical query string
 */
export function ashCanonicalizeQuery(query: string): string {
  if (!wasmInitFailed) {
    try {
      return wasm.ashCanonicalizeQuery(query);
    } catch {
      // Fall through to native implementation
    }
  }
  return ashCanonicalizeQueryNative(query);
}

/**
 * Normalize a binding string to canonical form (v2.3.2+ format).
 * Bindings are in the format: "METHOD|PATH|CANONICAL_QUERY"
 * BUG-LOGIC-128 FIX: Falls back to native implementation on WASM error.
 *
 * @param method HTTP method (GET, POST, etc.)
 * @param path URL path
 * @param query Query string (empty string if none)
 * @returns Canonical binding string (METHOD|PATH|QUERY)
 */
export function ashNormalizeBinding(method: string, path: string, query: string = ''): string {
  if (!wasmInitFailed) {
    try {
      return wasm.ashNormalizeBinding(method, path, query);
    } catch {
      // Fall through to native implementation
    }
  }
  return ashNormalizeBindingNative(method, path, query);
}

/**
 * Normalize a binding from a full URL path (including query string).
 * BUG-LOGIC-128 FIX: Falls back to native implementation on WASM error.
 *
 * @param method HTTP method (GET, POST, etc.)
 * @param fullPath Full URL path including query string (e.g., "/api/users?page=1")
 * @returns Canonical binding string (METHOD|PATH|QUERY)
 */
export function ashNormalizeBindingFromUrl(method: string, fullPath: string): string {
  if (!wasmInitFailed) {
    try {
      return wasm.ashNormalizeBindingFromUrl(method, fullPath);
    } catch {
      // Fall through to native implementation
    }
  }
  // Parse the fullPath to extract path and query
  const queryIndex = fullPath.indexOf('?');
  if (queryIndex === -1) {
    return ashNormalizeBindingNative(method, fullPath, '');
  }
  const path = fullPath.substring(0, queryIndex);
  const query = fullPath.substring(queryIndex + 1);
  return ashNormalizeBindingNative(method, path, query);
}

/**
 * BUG-LOGIC-128 FIX: Timing-safe comparison with WASM, fallback to native.
 */
export function ashTimingSafeEqual(a: string, b: string): boolean {
  if (!wasmInitFailed) {
    try {
      return wasm.ashTimingSafeEqual(a, b);
    } catch {
      // Fall through to native implementation
    }
  }
  // Native fallback using crypto.timingSafeEqual
  if (a.length !== b.length) {
    return false;
  }
  try {
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    return false;
  }
}

/**
 * BUG-LOGIC-128 FIX: Version with WASM, fallback to constant.
 */
export function ashVersion(): string {
  if (!wasmInitFailed) {
    try {
      return wasm.ashVersion();
    } catch {
      // Fall through to constant
    }
  }
  return ASH_VERSION_PREFIX; // ASHv2.1
}

/**
 * BUG-LOGIC-128 FIX: Library version with WASM, fallback to constant.
 */
export function ashLibraryVersion(): string {
  if (!wasmInitFailed) {
    try {
      return wasm.ashLibraryVersion();
    } catch {
      // Fall through to constant
    }
  }
  return ASH_SDK_VERSION;
}

// ASH v2.1 - Derived Client Secret & Cryptographic Proof

export function ashGenerateNonce(bytes: number = 32): string {
  // Validate minimum bytes per spec
  if (bytes < MIN_NONCE_BYTES) {
    throw new Error(`Nonce must be at least ${MIN_NONCE_BYTES} bytes (${MIN_NONCE_HEX_CHARS} hex characters)`);
  }
  // BUG-41 FIX: Validate maximum bytes to prevent OOM attacks
  // MAX_NONCE_LENGTH is hex chars, so max bytes is MAX_NONCE_LENGTH / 2
  const maxBytes = MAX_NONCE_LENGTH / 2;
  if (bytes > maxBytes) {
    throw new Error(`Nonce cannot exceed ${maxBytes} bytes (${MAX_NONCE_LENGTH} hex characters)`);
  }
  return crypto.randomBytes(bytes).toString('hex');
}

export function ashGenerateContextId(): string {
  return 'ash_' + crypto.randomBytes(16).toString('hex');
}

/**
 * Generate a unique context ID with 256-bit entropy.
 * Matches Rust SDK: ash_generate_context_id_256
 *
 * @returns Context ID in format "ash_" + 64 hex chars (256 bits)
 */
export function ashGenerateContextId256(): string {
  return 'ash_' + crypto.randomBytes(32).toString('hex');
}

/**
 * Validate nonce for security limits.
 * SEC-NONCE-001: Enforces length limits and hex-only validation.
 *
 * @param nonce The nonce to validate
 * @throws Error if validation fails
 */
function validateNonce(nonce: string): void {
  // Validate minimum length
  if (nonce.length < MIN_NONCE_HEX_CHARS) {
    throw new Error(`Nonce must be at least ${MIN_NONCE_HEX_CHARS} hex characters (16 bytes) for adequate entropy`);
  }

  // SEC-NONCE-001: Validate maximum length
  if (nonce.length > MAX_NONCE_LENGTH) {
    throw new Error(`Nonce exceeds maximum length of ${MAX_NONCE_LENGTH} characters`);
  }

  // Validate hex-only
  if (!/^[0-9a-fA-F]+$/.test(nonce)) {
    throw new Error('Nonce must contain only hexadecimal characters (0-9, a-f, A-F)');
  }
}

/**
 * Validate context_id for security limits.
 * SEC-CTX-001: Enforces length limits and charset validation.
 *
 * @param contextId The context_id to validate
 * @throws Error if validation fails
 */
function validateContextId(contextId: string): void {
  // Validate not empty
  if (contextId.length === 0) {
    throw new Error('context_id cannot be empty');
  }

  // SEC-CTX-001: Validate maximum length
  if (contextId.length > MAX_CONTEXT_ID_LENGTH) {
    throw new Error(`context_id exceeds maximum length of ${MAX_CONTEXT_ID_LENGTH} characters`);
  }

  // SEC-CTX-001: Validate charset (only ASCII alphanumeric + underscore + hyphen + dot)
  if (!/^[A-Za-z0-9_.-]+$/.test(contextId)) {
    throw new Error('context_id must contain only ASCII alphanumeric characters, underscore, hyphen, or dot');
  }

  // SEC-015: Explicit pipe character check (delimiter collision risk)
  // Per SDK Implementation Reference Section 2.2 item 4: "redundant after #3, but explicit check recommended"
  if (contextId.includes('|')) {
    throw new Error("context_id must not contain '|' character (delimiter collision risk)");
  }
}

/**
 * Validate binding for security limits.
 * SEC-AUDIT-004: Enforces length limits.
 *
 * @param binding The binding to validate
 * @param allowEmpty Whether empty bindings are allowed
 * @throws Error if validation fails
 */
function validateBinding(binding: string, allowEmpty: boolean = false): void {
  // Validate not empty (if required)
  if (!allowEmpty && binding.length === 0) {
    throw new Error('binding cannot be empty');
  }

  // SEC-AUDIT-004: Validate maximum length
  if (binding.length > MAX_BINDING_LENGTH) {
    throw new Error(`binding exceeds maximum length of ${MAX_BINDING_LENGTH} bytes`);
  }

  // BUG-LOGIC-111 FIX: Warn about binding format (METHOD|PATH|QUERY)
  // A properly normalized binding contains pipe delimiters
  // We warn in development but don't reject for backward compatibility
  if (binding !== '' && !binding.includes('|') && process.env.NODE_ENV !== 'production') {
    console.warn(
      '[ASH] Warning: binding should be in format METHOD|PATH|QUERY. ' +
      'Use ashNormalizeBinding() to create properly formatted bindings.'
    );
  }
}

/**
 * Derive client secret from nonce, contextId, and binding.
 * SEC-CTX-001, SEC-NONCE-001: Validates inputs for security.
 */
export function ashDeriveClientSecret(
  nonce: string,
  contextId: string,
  binding: string
): string {
  // Validate inputs
  validateNonce(nonce);
  validateContextId(contextId);
  validateBinding(binding);

  return crypto.createHmac('sha256', nonce)
    .update(contextId + '|' + binding)
    .digest('hex');
}

/**
 * Validate body hash format.
 * Must be exactly 64 hex characters (SHA-256 output).
 * BUG-35 FIX: Normalizes to lowercase for consistent comparison.
 *
 * @param bodyHash The body hash to validate
 * @returns The normalized (lowercase) body hash
 * @throws Error if validation fails
 */
function validateBodyHash(bodyHash: string): string {
  if (bodyHash.length !== SHA256_HEX_LENGTH) {
    throw new Error(`body_hash must be ${SHA256_HEX_LENGTH} hex characters (SHA-256), got ${bodyHash.length}`);
  }

  if (!/^[0-9a-fA-F]+$/.test(bodyHash)) {
    throw new Error('body_hash must contain only hexadecimal characters (0-9, a-f, A-F)');
  }

  // BUG-35 FIX: Normalize to lowercase for consistent comparison
  // ashHashBody produces lowercase, so we normalize input to match
  return bodyHash.toLowerCase();
}

/**
 * Validate proof format.
 * Must be exactly 64 hex characters (HMAC-SHA256 output).
 * BUG-31 FIX: Added dedicated validation for proofs.
 *
 * @param proof The proof to validate
 * @returns The normalized (lowercase) proof
 * @throws Error if validation fails
 */
function validateProofFormat(proof: string): string {
  if (proof.length !== SHA256_HEX_LENGTH) {
    throw new Error(`proof must be ${SHA256_HEX_LENGTH} hex characters (HMAC-SHA256), got ${proof.length}`);
  }

  if (!/^[0-9a-fA-F]+$/.test(proof)) {
    throw new Error('proof must contain only hexadecimal characters (0-9, a-f, A-F)');
  }

  // Normalize to lowercase for consistent comparison
  return proof.toLowerCase();
}

/**
 * SEC-018: Maximum reasonable timestamp (year 3000 in Unix seconds).
 * Prevents integer overflow and unreasonable future timestamps.
 */
export const MAX_TIMESTAMP = 32503680000;

/**
 * Validate timestamp format (per SDK Implementation Reference Section 6.1).
 * Must be non-empty, digits only, no leading zeros, within reasonable range.
 * VULN-003 FIX: Also validates against MAX_SAFE_INTEGER to prevent precision loss.
 *
 * @param timestamp The timestamp to validate
 * @returns The parsed timestamp as a number
 * @throws Error if validation fails
 */
export function ashValidateTimestampFormat(timestamp: string): number {
  if (timestamp.length === 0) {
    throw new Error('Timestamp cannot be empty');
  }

  if (!/^[0-9]+$/.test(timestamp)) {
    throw new Error('Timestamp must contain only digits (0-9)');
  }

  // Check for leading zeros (except "0" itself)
  if (timestamp.length > 1 && timestamp.startsWith('0')) {
    throw new Error('Timestamp must not have leading zeros');
  }

  // VULN-003 FIX: Check string length before parsing to prevent precision loss
  // MAX_SAFE_INTEGER is 9007199254740991 (16 digits)
  // Any timestamp with more than 16 digits would lose precision
  if (timestamp.length > 16) {
    throw new Error('Timestamp exceeds maximum safe integer value');
  }

  // Parse as integer
  const tsNum = parseInt(timestamp, 10);
  if (isNaN(tsNum)) {
    throw new Error('Timestamp must be a valid integer');
  }

  // VULN-003 FIX: Verify the parsed number matches the original string
  // This catches cases where precision was lost during parsing
  if (tsNum.toString() !== timestamp) {
    throw new Error('Timestamp value exceeds safe integer precision');
  }

  // VULN-003 FIX: Explicit check against MAX_SAFE_INTEGER
  if (tsNum > Number.MAX_SAFE_INTEGER) {
    throw new Error('Timestamp exceeds maximum safe integer value');
  }

  // SEC-018: Check maximum timestamp to prevent overflow
  if (tsNum > MAX_TIMESTAMP) {
    throw new Error('Timestamp exceeds maximum allowed value');
  }

  // BUG-LOGIC-013 NOTE: Timestamp "0" passes format validation intentionally.
  // Freshness validation (ashValidateTimestamp) will reject old timestamps.
  // Format validation only checks format, not semantic validity.

  return tsNum;
}

// Internal alias for backwards compatibility
const validateTimestamp = ashValidateTimestampFormat;

/**
 * Default maximum timestamp age in seconds.
 */
export const DEFAULT_MAX_TIMESTAMP_AGE_SECONDS = 300; // 5 minutes

/**
 * Default clock skew allowance in seconds.
 *
 * VULN-009 SECURITY NOTE: Combined with maxAgeSeconds, this creates a window
 * of (maxAgeSeconds + clockSkewSeconds) during which a captured proof could
 * potentially be replayed if the context is not properly consumed.
 *
 * With defaults: 300 + 60 = 360 seconds (6 minutes) total window.
 *
 * Mitigations:
 * 1. Context consumption is atomic - replays are rejected
 * 2. Reduce clockSkewSeconds if your infrastructure has synchronized clocks
 * 3. Use shorter maxAgeSeconds for sensitive operations
 */
export const DEFAULT_CLOCK_SKEW_SECONDS = 60; // 1 minute

/**
 * Validate timestamp freshness (not expired and not too far in future).
 * Matches Rust SDK: ash_validate_timestamp
 *
 * @param timestamp The timestamp string to validate
 * @param maxAgeSeconds Maximum age in seconds (how old the timestamp can be)
 * @param clockSkewSeconds Allowed clock skew in seconds (how far in future is allowed)
 * @returns true if timestamp is valid
 * @throws Error if timestamp is expired or too far in future
 */
export function ashValidateTimestamp(
  timestamp: string,
  maxAgeSeconds: number = DEFAULT_MAX_TIMESTAMP_AGE_SECONDS,
  clockSkewSeconds: number = DEFAULT_CLOCK_SKEW_SECONDS
): boolean {
  // BUG-LOGIC-053 FIX: Validate parameters are non-negative
  // BUG-LOGIC-068 FIX: Also validate for Infinity/NaN to prevent bypass
  // BUG-LOGIC-104 FIX: Add upper bound to prevent unreasonable values
  const MAX_CLOCK_SKEW_SECONDS = 86400; // 24 hours
  const MAX_AGE_SECONDS = 31536000; // 1 year

  if (!Number.isFinite(maxAgeSeconds) || maxAgeSeconds < 0) {
    throw new Error('maxAgeSeconds must be a non-negative finite number');
  }
  if (maxAgeSeconds > MAX_AGE_SECONDS) {
    throw new Error(`maxAgeSeconds must not exceed ${MAX_AGE_SECONDS} seconds (1 year)`);
  }
  if (!Number.isFinite(clockSkewSeconds) || clockSkewSeconds < 0) {
    throw new Error('clockSkewSeconds must be a non-negative finite number');
  }
  if (clockSkewSeconds > MAX_CLOCK_SKEW_SECONDS) {
    throw new Error(`clockSkewSeconds must not exceed ${MAX_CLOCK_SKEW_SECONDS} seconds (24 hours)`);
  }

  // First validate format
  const ts = validateTimestamp(timestamp);

  // Get current time in seconds
  const now = Math.floor(Date.now() / 1000);

  // Check if timestamp is in the future (beyond clock skew allowance)
  if (ts > now + clockSkewSeconds) {
    throw new Error('Timestamp is in the future');
  }

  // Check if timestamp has expired
  if (now > ts && (now - ts) > maxAgeSeconds) {
    throw new Error('Timestamp has expired');
  }

  return true;
}

/** @deprecated Use ashValidateTimestamp instead */
export const validateTimestampFreshness = ashValidateTimestamp;

/**
 * Build v2.1+ HMAC-SHA256 proof.
 * Validates all inputs for security.
 */
export function ashBuildProof(
  clientSecret: string,
  timestamp: string,
  binding: string,
  bodyHash: string
): string {
  // Validate inputs
  if (clientSecret.length === 0) {
    throw new Error('client_secret cannot be empty');
  }
  validateTimestamp(timestamp);
  validateBinding(binding);
  // BUG-35 FIX: Use normalized (lowercase) body hash
  const normalizedBodyHash = validateBodyHash(bodyHash);

  const message = timestamp + '|' + binding + '|' + normalizedBodyHash;
  return crypto.createHmac('sha256', clientSecret)
    .update(message)
    .digest('hex');
}

/** @deprecated Use ashBuildProof instead */
export const ashBuildProofV21 = ashBuildProof;

/** Alias for ashBuildProof (HMAC-SHA256 proof construction) */
export const ashBuildProofHmac = ashBuildProof;

/**
 * Detailed verification result for debugging.
 * BUG-019: Provides error details without exposing secrets.
 */
export interface AshVerifyDetailedResult {
  valid: boolean;
  errorCode?: 'INVALID_TIMESTAMP' | 'INVALID_NONCE' | 'INVALID_CONTEXT_ID' | 'INVALID_BINDING' | 'INVALID_BODY_HASH' | 'INVALID_PROOF_FORMAT' | 'PROOF_MISMATCH';
  errorMessage?: string;
}

/**
 * Verify v2.1+ HMAC-SHA256 proof with detailed error reporting.
 * BUG-019: Returns error details for debugging without exposing secrets.
 * Uses constant-time comparison.
 */
export function ashVerifyProofDetailed(
  nonce: string,
  contextId: string,
  binding: string,
  timestamp: string,
  bodyHash: string,
  clientProof: string
): AshVerifyDetailedResult {
  try {
    // Validate timestamp format first
    validateTimestamp(timestamp);
  } catch (e) {
    return {
      valid: false,
      errorCode: 'INVALID_TIMESTAMP',
      errorMessage: e instanceof Error ? e.message : 'Invalid timestamp',
    };
  }

  try {
    validateNonce(nonce);
  } catch (e) {
    return {
      valid: false,
      errorCode: 'INVALID_NONCE',
      errorMessage: e instanceof Error ? e.message : 'Invalid nonce',
    };
  }

  try {
    validateContextId(contextId);
  } catch (e) {
    return {
      valid: false,
      errorCode: 'INVALID_CONTEXT_ID',
      errorMessage: e instanceof Error ? e.message : 'Invalid context_id',
    };
  }

  try {
    validateBinding(binding);
  } catch (e) {
    return {
      valid: false,
      errorCode: 'INVALID_BINDING',
      errorMessage: e instanceof Error ? e.message : 'Invalid binding',
    };
  }

  try {
    validateBodyHash(bodyHash);
  } catch (e) {
    return {
      valid: false,
      errorCode: 'INVALID_BODY_HASH',
      errorMessage: e instanceof Error ? e.message : 'Invalid body_hash',
    };
  }

  // Validate proof format (including null/undefined check)
  if (!clientProof || typeof clientProof !== 'string' || clientProof.length !== SHA256_HEX_LENGTH || !/^[0-9a-fA-F]+$/.test(clientProof)) {
    return {
      valid: false,
      errorCode: 'INVALID_PROOF_FORMAT',
      errorMessage: `Proof must be ${SHA256_HEX_LENGTH} hex characters`,
    };
  }

  try {
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
    const expectedProof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

    const valid = crypto.timingSafeEqual(
      Buffer.from(expectedProof, 'hex'),
      Buffer.from(clientProof, 'hex')
    );

    if (!valid) {
      return {
        valid: false,
        errorCode: 'PROOF_MISMATCH',
        errorMessage: 'Proof does not match expected value',
      };
    }

    return { valid: true };
  } catch {
    return {
      valid: false,
      errorCode: 'PROOF_MISMATCH',
      errorMessage: 'Proof verification failed',
    };
  }
}

/**
 * Verify v2.1+ HMAC-SHA256 proof.
 * Uses constant-time comparison.
 */
export function ashVerifyProof(
  nonce: string,
  contextId: string,
  binding: string,
  timestamp: string,
  bodyHash: string,
  clientProof: string
): boolean {
  return ashVerifyProofDetailed(nonce, contextId, binding, timestamp, bodyHash, clientProof).valid;
}

/** @deprecated Use ashVerifyProof instead */
export const ashVerifyProofV21 = ashVerifyProof;

/**
 * Verify v2.1+ HMAC-SHA256 proof with timestamp freshness check.
 * Matches Rust SDK: ash_verify_proof_with_freshness
 *
 * @param nonce Server nonce
 * @param contextId Context ID
 * @param binding Request binding
 * @param timestamp Request timestamp (Unix seconds)
 * @param bodyHash SHA-256 hash of canonical body
 * @param clientProof Proof from client
 * @param maxAgeSeconds Maximum age of timestamp in seconds
 * @returns true if proof is valid and timestamp is fresh
 */
export function ashVerifyProofWithFreshness(
  nonce: string,
  contextId: string,
  binding: string,
  timestamp: string,
  bodyHash: string,
  clientProof: string,
  maxAgeSeconds: number = DEFAULT_MAX_TIMESTAMP_AGE_SECONDS
): boolean {
  // First validate timestamp freshness
  try {
    ashValidateTimestamp(timestamp, maxAgeSeconds);
  } catch {
    return false;
  }

  // Then verify proof
  return ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, clientProof);
}

export function ashHashBody(canonicalBody: string): string {
  return crypto.createHash('sha256').update(canonicalBody).digest('hex');
}

export function ashContextToClient(context: AshContext): AshClientContext {
  // BUG-LOGIC-112 FIX: Validate required fields for v2.1
  if (!context.clientSecret) {
    throw new Error('Context must have clientSecret for v2.1');
  }
  if (!context.nonce) {
    throw new Error('Context must have nonce for v2.1 verification');
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
 * BUG-036: Tracks total array allocation to prevent DoS.
 * SEC-019: Validates path depth limits.
 * SEC-011: Validates array index limits.
 * Matches Rust SDK: ash_extract_scoped_fields
 *
 * INFO-004 LIMITATION: Numeric string keys vs array indices
 * Scope paths with all-digit segments (e.g., "items.0") are treated as array indices.
 * If the original payload has an object with numeric string keys like {"items": {"0": "value"}},
 * the extracted result will have array structure {"items": ["value"]} instead.
 * This is consistent across SDKs - use non-numeric keys for object properties if structure
 * preservation is critical.
 *
 * @param payload Full payload object
 * @param scope Array of field paths (supports dot notation)
 * @returns Object containing only scoped fields
 */
export function ashExtractScopedFields(
  payload: Record<string, unknown>,
  scope: string[]
): Record<string, unknown> {
  // BUG-LOGIC-105 FIX: Validate payload is a plain object
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('payload must be a plain object');
  }

  if (scope.length === 0) {
    return payload;
  }

  const result: Record<string, unknown> = {};
  // BUG-036: Track total array allocation
  const allocCtx: AllocationContext = { totalAllocated: 0 };

  for (const fieldPath of scope) {
    const value = getNestedValue(payload, fieldPath);
    if (value !== undefined) {
      setNestedValue(result, fieldPath, value, allocCtx);
    }
  }

  return result;
}

/**
 * Extract scoped fields from a payload object (strict mode).
 * Throws error if any scoped field is missing from payload.
 * Matches Rust SDK: ash_extract_scoped_fields_strict
 *
 * @param payload Full payload object
 * @param scope Array of field paths (supports dot notation)
 * @returns Object containing only scoped fields
 * @throws Error if any scoped field is missing
 */
export function ashExtractScopedFieldsStrict(
  payload: Record<string, unknown>,
  scope: string[]
): Record<string, unknown> {
  // BUG-LOGIC-105 FIX: Validate payload is a plain object
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('payload must be a plain object');
  }

  if (scope.length === 0) {
    return payload;
  }

  const result: Record<string, unknown> = {};
  // BUG-036: Track total array allocation
  const allocCtx: AllocationContext = { totalAllocated: 0 };

  for (const fieldPath of scope) {
    const value = getNestedValue(payload, fieldPath);
    if (value === undefined) {
      // BUG-LOGIC-083 FIX: Use generic error message to prevent field enumeration attacks
      // Don't reveal which specific field is missing to avoid information disclosure
      throw new Error('One or more required scoped fields are missing from payload');
    }
    setNestedValue(result, fieldPath, value, allocCtx);
  }

  return result;
}

/**
 * BUG-37/38 FIX: Dangerous property names that could cause prototype pollution.
 * These keys must be blocked in scope paths to prevent attacks.
 */
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Parse a scope path into keys, handling bracket notation.
 * SEC-019: Validates path depth limit.
 * SEC-011: Validates array index limits.
 * BUG-28: Rejects leading zeros in array indices.
 * BUG-30: Rejects empty paths.
 * BUG-37: Blocks prototype pollution via dangerous keys.
 * @internal
 */
function parseScopePath(path: string): string[] {
  // BUG-30 FIX: Reject empty paths
  if (path === '') {
    throw new Error('Scope path cannot be empty');
  }

  // BUG-LOGIC-009 FIX: Reject whitespace-only paths
  if (path.trim() === '') {
    throw new Error('Scope path cannot be whitespace-only');
  }

  const keys = path.split('.').flatMap(key => {
    // BUG-37 FIX: Block prototype pollution via dangerous keys
    if (DANGEROUS_KEYS.has(key)) {
      throw new Error(`Scope path contains dangerous key: "${key}"`);
    }
    // Handle bracket notation: items[0] -> ['items', '0']
    // Also handle multi-dimensional: matrix[0][1] -> ['matrix', '0', '1']
    const parts: string[] = [];
    let remaining = key;

    // First extract the base key (before any brackets)
    const baseMatch = remaining.match(/^([^[]+)/);
    if (baseMatch) {
      // BUG-30 FIX: Reject empty key segments
      if (baseMatch[1] === '') {
        throw new Error('Scope path contains empty segment');
      }
      // BUG-37 FIX: Block prototype pollution via dangerous keys in bracket base
      if (DANGEROUS_KEYS.has(baseMatch[1])) {
        throw new Error(`Scope path contains dangerous key: "${baseMatch[1]}"`);
      }
      parts.push(baseMatch[1]);
      remaining = remaining.slice(baseMatch[1].length);
    }

    // BUG-28 FIX: If there are brackets, validate them strictly
    if (remaining.includes('[')) {
      // Check for invalid bracket formats (leading zeros, non-numeric, etc.)
      // First, check if the entire remaining string is valid bracket notation
      const invalidBracketMatch = remaining.match(/\[(\d+)\]/g);
      if (invalidBracketMatch) {
        for (const bracket of invalidBracketMatch) {
          const indexStr = bracket.slice(1, -1); // Remove [ and ]
          // BUG-28: Reject leading zeros (except for just "0")
          if (indexStr.length > 1 && indexStr.startsWith('0')) {
            throw new Error(`Invalid array index: "${indexStr}" has leading zeros`);
          }
        }
      }

      // Now extract valid indices
      const bracketRegex = /\[(0|[1-9]\d*)\]/g;
      let match;
      let lastIndex = 0;
      while ((match = bracketRegex.exec(remaining)) !== null) {
        // Check for invalid characters between valid brackets
        if (match.index > lastIndex) {
          const between = remaining.slice(lastIndex, match.index);
          if (between !== '') {
            throw new Error(`Invalid scope path: unexpected characters "${between}" in bracket notation`);
          }
        }
        lastIndex = bracketRegex.lastIndex;

        const index = parseInt(match[1], 10);
        // SEC-011: Validate array index limit
        // BUG-LOGIC-004 FIX: Use >= to prevent off-by-one (allocation is index+1)
        if (index >= MAX_ARRAY_INDEX) {
          throw new Error(`Array index ${index} exceeds maximum of ${MAX_ARRAY_INDEX - 1}`);
        }
        parts.push(match[1]);
      }

      // Check for trailing invalid content after brackets
      if (lastIndex < remaining.length) {
        const trailing = remaining.slice(lastIndex);
        if (trailing !== '') {
          throw new Error(`Invalid scope path: unexpected content "${trailing}" after brackets`);
        }
      }
    }

    return parts.length > 0 ? parts : [key];
  });

  // SEC-019: Validate path depth limit
  if (keys.length > MAX_SCOPE_PATH_DEPTH) {
    throw new Error(`Scope path depth ${keys.length} exceeds maximum of ${MAX_SCOPE_PATH_DEPTH}`);
  }

  return keys;
}

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  // BUG-010: Support array index notation like "items[0]" or "items.0"
  // SEC-019, SEC-011: Validate path depth and array indices
  // BUG-38: parseScopePath now blocks dangerous keys like __proto__
  const keys = parseScopePath(path);

  let current: unknown = obj;

  for (const key of keys) {
    if (current === null || typeof current !== 'object') {
      return undefined;
    }
    // Handle array access with numeric string keys
    if (Array.isArray(current)) {
      const index = parseInt(key, 10);
      if (isNaN(index) || index < 0 || index >= current.length) {
        return undefined;
      }
      current = current[index];
    } else {
      // BUG-38 FIX: Only access own properties, not inherited ones
      const rec = current as Record<string, unknown>;
      if (!Object.prototype.hasOwnProperty.call(rec, key)) {
        return undefined;
      }
      current = rec[key];
    }
  }

  return current;
}

/**
 * Context for tracking array allocations during scoped field extraction.
 * BUG-036: Prevents excessive array allocation.
 * @internal
 */
interface AllocationContext {
  totalAllocated: number;
}

function setNestedValue(
  obj: Record<string, unknown>,
  path: string,
  value: unknown,
  allocCtx?: AllocationContext
): void {
  // BUG-011: Support array index notation and create arrays when needed
  // SEC-019, SEC-011: Validate path depth and array indices
  // BUG-37: parseScopePath now blocks dangerous keys like __proto__
  const keys = parseScopePath(path);

  let current: Record<string, unknown> | unknown[] = obj;

  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i];
    const nextKey = keys[i + 1];
    const nextIsArrayIndex = /^\d+$/.test(nextKey);

    if (Array.isArray(current)) {
      const index = parseInt(key, 10);
      if (current[index] === undefined || current[index] === null || typeof current[index] !== 'object') {
        if (nextIsArrayIndex) {
          const arraySize = parseInt(nextKey, 10) + 1;
          // BUG-036: Track allocation
          // BUG-LOGIC-103 FIX: Check BEFORE adding to prevent exceeding limit
          if (allocCtx) {
            if (allocCtx.totalAllocated + arraySize > MAX_TOTAL_ARRAY_ALLOCATION) {
              throw new Error(`Total array allocation would exceed maximum of ${MAX_TOTAL_ARRAY_ALLOCATION}`);
            }
            allocCtx.totalAllocated += arraySize;
          }
          current[index] = [];
        } else {
          current[index] = {};
        }
      }
      current = current[index] as Record<string, unknown> | unknown[];
    } else {
      const rec = current as Record<string, unknown>;
      // BUG-37 FIX: Use hasOwnProperty instead of 'in' to avoid prototype chain
      if (!Object.prototype.hasOwnProperty.call(rec, key) || rec[key] === null || typeof rec[key] !== 'object') {
        if (nextIsArrayIndex) {
          const arraySize = parseInt(nextKey, 10) + 1;
          // BUG-036: Track allocation
          // BUG-LOGIC-103 FIX: Check BEFORE adding to prevent exceeding limit
          if (allocCtx) {
            if (allocCtx.totalAllocated + arraySize > MAX_TOTAL_ARRAY_ALLOCATION) {
              throw new Error(`Total array allocation would exceed maximum of ${MAX_TOTAL_ARRAY_ALLOCATION}`);
            }
            allocCtx.totalAllocated += arraySize;
          }
          rec[key] = [];
        } else {
          rec[key] = {};
        }
      }
      current = rec[key] as Record<string, unknown> | unknown[];
    }
  }

  const lastKey = keys[keys.length - 1];
  if (Array.isArray(current)) {
    const index = parseInt(lastKey, 10);
    current[index] = value;
  } else {
    (current as Record<string, unknown>)[lastKey] = value;
  }
}

/**
 * Build scoped proof with selective field protection.
 *
 * @param clientSecret Derived client secret
 * @param timestamp Request timestamp (milliseconds)
 * @param binding Request binding
 * @param payload Full payload object
 * @param scope Fields to protect (empty = all)
 * @returns Proof and scope hash
 */
export function ashBuildProofScoped(
  clientSecret: string,
  timestamp: string,
  binding: string,
  payload: Record<string, unknown>,
  scope: string[]
): AshScopedProofResult {
  // BUG-046: Validate inputs (matching ashBuildProof)
  if (clientSecret.length === 0) {
    throw new Error('client_secret cannot be empty');
  }
  validateTimestamp(timestamp);
  validateBinding(binding);

  // BUG-023: Normalize scope for deterministic ordering
  const normalizedScope = ashNormalizeScopeFields(scope);
  const scopedPayload = ashExtractScopedFields(payload, normalizedScope);
  const canonicalScoped = ashCanonicalizeJsonNative(JSON.stringify(scopedPayload));
  const bodyHash = ashHashBody(canonicalScoped);

  // BUG-002, BUG-023: Use unit separator and normalized scope
  const scopeStr = ashJoinScopeFields(scope);
  const scopeHash = ashHashBody(scopeStr);

  const message = timestamp + '|' + binding + '|' + bodyHash + '|' + scopeHash;
  const proof = crypto.createHmac('sha256', clientSecret)
    .update(message)
    .digest('hex');

  return { proof, scopeHash };
}

/** @deprecated Use ashBuildProofScoped instead */
export const ashBuildProofV21Scoped = ashBuildProofScoped;

/**
 * Verify scoped proof with selective field protection.
 * Uses constant-time comparison.
 * BUG-31 FIX: Validates proof and hash formats before comparison.
 */
export function ashVerifyProofScoped(
  nonce: string,
  contextId: string,
  binding: string,
  timestamp: string,
  payload: Record<string, unknown>,
  scope: string[],
  scopeHash: string,
  clientProof: string
): boolean {
  // BUG-31 FIX: Validate proof format before any processing
  let normalizedProof: string;
  try {
    normalizedProof = validateProofFormat(clientProof);
  } catch {
    return false;
  }

  // SEC-013: Validate consistency - scopeHash must be empty when scope is empty
  if (scope.length === 0 && scopeHash !== '') {
    return false;
  }

  // BUG-LOGIC-007 FIX: Symmetric check - scopeHash must be provided when scope is not empty
  if (scope.length > 0 && scopeHash === '') {
    return false;
  }

  // BUG-002, BUG-023: Verify scope hash with unit separator and normalization
  if (scope.length > 0) {
    // VULN-006 FIX: Use constant-time validation for scope hash
    const scopeStr = ashJoinScopeFields(scope);
    const expectedScopeHash = ashHashBody(scopeStr);

    // VULN-006 FIX: Normalize input for constant-time comparison
    let normalizedScopeHash: string;
    if (scopeHash.length === SHA256_HEX_LENGTH && /^[0-9a-fA-F]+$/.test(scopeHash)) {
      normalizedScopeHash = scopeHash.toLowerCase();
    } else {
      // Use dummy hash for constant-time comparison
      normalizedScopeHash = '0'.repeat(SHA256_HEX_LENGTH);
    }

    try {
      if (!crypto.timingSafeEqual(
        Buffer.from(expectedScopeHash, 'hex'),
        Buffer.from(normalizedScopeHash, 'hex')
      )) {
        return false;
      }
    } catch {
      return false;
    }
  }

  const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
  const result = ashBuildProofScoped(clientSecret, timestamp, binding, payload, scope);

  try {
    return crypto.timingSafeEqual(
      Buffer.from(result.proof, 'hex'),
      Buffer.from(normalizedProof, 'hex')
    );
  } catch {
    return false;
  }
}

/** @deprecated Use ashVerifyProofScoped instead */
export const ashVerifyProofV21Scoped = ashVerifyProofScoped;

/**
 * Hash scoped payload fields.
 * BUG-012: Normalizes scope for deterministic ordering.
 * Matches Rust SDK: ash_hash_scoped_body
 */
export function ashHashScopedBody(
  payload: Record<string, unknown>,
  scope: string[]
): string {
  // BUG-012: Normalize scope for deterministic ordering
  const normalizedScope = ashNormalizeScopeFields(scope);
  const scopedPayload = ashExtractScopedFields(payload, normalizedScope);
  const canonical = ashCanonicalizeJsonNative(JSON.stringify(scopedPayload));
  return ashHashBody(canonical);
}

/**
 * Hash scoped payload fields (strict mode).
 * Throws error if any scoped field is missing from payload.
 * Matches Rust SDK: ash_hash_scoped_body_strict
 */
export function ashHashScopedBodyStrict(
  payload: Record<string, unknown>,
  scope: string[]
): string {
  // BUG-012: Normalize scope for deterministic ordering
  const normalizedScope = ashNormalizeScopeFields(scope);
  const scopedPayload = ashExtractScopedFieldsStrict(payload, normalizedScope);
  const canonical = ashCanonicalizeJsonNative(JSON.stringify(scopedPayload));
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
 * BUG-029 FIX: Rejects empty proof strings.
 *
 * @param proof Proof to hash
 * @returns SHA-256 hash of the proof (64 hex chars)
 * @throws Error if proof is empty
 */
export function ashHashProof(proof: string): string {
  // BUG-029 FIX: Reject empty proofs to prevent ambiguous chain starts
  if (proof === '') {
    throw new Error('Proof cannot be empty for chain hashing');
  }
  return crypto.createHash('sha256').update(proof).digest('hex');
}

/**
 * Compute scope hash per SDK Implementation Reference Section 5.2.
 * Returns empty string if scope is empty.
 * Validates, normalizes, and joins scope with unit separator before hashing.
 *
 * @param scope Array of field paths
 * @returns SHA-256 hash of joined scope (64 hex chars) or empty string
 */
export function ashHashScope(scope: string[]): string {
  if (scope.length === 0) {
    return '';
  }
  // Validate and join with unit separator (also normalizes)
  const joined = ashJoinScopeFields(scope);
  return ashHashBody(joined);
}

/**
 * Build unified v2.3 cryptographic proof with optional scoping and chaining.
 *
 * Formula:
 *   scopeHash  = scope.length > 0 ? SHA256(sorted(scope).join("\x1F")) : ""
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
  // BUG-046: Validate inputs (matching ashBuildProof)
  if (clientSecret.length === 0) {
    throw new Error('client_secret cannot be empty');
  }
  validateTimestamp(timestamp);
  validateBinding(binding);

  // BUG-023: Normalize scope for deterministic ordering
  const normalizedScope = ashNormalizeScopeFields(scope);

  // Extract and hash scoped payload
  const scopedPayload = ashExtractScopedFields(payload, normalizedScope);
  const canonicalScoped = ashCanonicalizeJsonNative(JSON.stringify(scopedPayload));
  const bodyHash = ashHashBody(canonicalScoped);

  // BUG-002, BUG-023: Compute scope hash with unit separator and normalization
  const scopeHash = scope.length > 0 ? ashHashBody(ashJoinScopeFields(scope)) : '';

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
 * BUG-31 FIX: Validates proof format before comparison.
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
  // BUG-31 FIX: Validate proof format before any processing
  let normalizedProof: string;
  try {
    normalizedProof = validateProofFormat(clientProof);
  } catch {
    return false;
  }

  // SEC-013: Validate consistency - scopeHash must be empty when scope is empty
  if (scope.length === 0 && scopeHash !== '') {
    return false;
  }

  // BUG-LOGIC-007 FIX: Symmetric check - scopeHash must be provided when scope is not empty
  if (scope.length > 0 && scopeHash === '') {
    return false;
  }

  // BUG-002, BUG-023: Validate scope hash with unit separator and normalization
  if (scope.length > 0) {
    // VULN-006 FIX: Use constant-time validation for all checks
    // First compute expected hash (constant time operation)
    const expectedScopeHash = ashHashBody(ashJoinScopeFields(scope));

    // VULN-006 FIX: Normalize input to fixed length for constant-time comparison
    // If format is invalid, use a dummy value for comparison to avoid timing leak
    let normalizedScopeHash: string;
    if (scopeHash.length === SHA256_HEX_LENGTH && /^[0-9a-fA-F]+$/.test(scopeHash)) {
      normalizedScopeHash = scopeHash.toLowerCase();
    } else {
      // Use a dummy hash that will never match - comparison still happens
      normalizedScopeHash = '0'.repeat(SHA256_HEX_LENGTH);
    }

    try {
      if (!crypto.timingSafeEqual(
        Buffer.from(expectedScopeHash, 'hex'),
        Buffer.from(normalizedScopeHash, 'hex')
      )) {
        return false;
      }
    } catch {
      return false;
    }
  }

  // SEC-013: Validate consistency - chainHash must be empty when previousProof is absent
  if ((!previousProof || previousProof === '') && chainHash !== '') {
    return false;
  }

  // Validate chain hash if chaining is used
  if (previousProof && previousProof !== '') {
    // VULN-006 FIX: Use constant-time validation for chain hash
    const expectedChainHash = ashHashProof(previousProof);

    // VULN-006 FIX: Normalize input for constant-time comparison
    let normalizedChainHash: string;
    if (chainHash.length === SHA256_HEX_LENGTH && /^[0-9a-fA-F]+$/.test(chainHash)) {
      normalizedChainHash = chainHash.toLowerCase();
    } else {
      // Use dummy hash for constant-time comparison
      normalizedChainHash = '0'.repeat(SHA256_HEX_LENGTH);
    }

    try {
      if (!crypto.timingSafeEqual(
        Buffer.from(expectedChainHash, 'hex'),
        Buffer.from(normalizedChainHash, 'hex')
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
      Buffer.from(normalizedProof, 'hex')
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
  jsonNative: ashCanonicalizeJsonNative,

  /**
   * Canonicalize an already-parsed JSON value with size checking.
   * BUG-044: Use this for Values from untrusted sources.
   */
  jsonValueNative: ashCanonicalizeJsonValueNative,

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
  queryNative: ashCanonicalizeQueryNative,
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
   * Hash scope array per SDK Implementation Reference Section 5.2.
   * Returns empty string if scope is empty.
   */
  hashScope: ashHashScope,

  /**
   * Generate a cryptographically secure nonce.
   * Returns hex-encoded random bytes.
   */
  generateNonce: ashGenerateNonce,

  /**
   * Generate a unique context ID (128-bit).
   * Format: ash_<32 hex chars>
   */
  generateContextId: ashGenerateContextId,

  /**
   * Generate a unique context ID (256-bit).
   * Format: ash_<64 hex chars>
   */
  generateContextId256: ashGenerateContextId256,

  /**
   * Extract scoped fields from a payload.
   * Supports dot notation for nested fields.
   */
  extractScopedFields: ashExtractScopedFields,

  /**
   * Extract scoped fields from a payload (strict mode).
   * Throws if any scoped field is missing.
   */
  extractScopedFieldsStrict: ashExtractScopedFieldsStrict,

  /**
   * Hash scoped payload fields.
   */
  hashScopedBody: ashHashScopedBody,

  /**
   * Hash scoped payload fields (strict mode).
   * Throws if any scoped field is missing.
   */
  hashScopedBodyStrict: ashHashScopedBodyStrict,

  /**
   * Validate timestamp format (digits only, no leading zeros, within range).
   * Per SDK Implementation Reference Section 6.1.
   */
  validateTimestampFormat: ashValidateTimestampFormat,

  /**
   * Validate timestamp freshness (not expired and not too far in future).
   * Matches Rust SDK: ash_validate_timestamp
   */
  validateTimestamp: ashValidateTimestamp,

  /** @deprecated Use validateTimestamp instead */
  validateTimestampFreshness: ashValidateTimestamp,

  /**
   * Normalize scope fields (sort and deduplicate).
   */
  normalizeScopeFields: ashNormalizeScopeFields,

  /**
   * Validate scope fields for security limits.
   */
  validateScopeFields: ashValidateScopeFields,

  /**
   * Join scope fields with the proper delimiter.
   */
  joinScopeFields: ashJoinScopeFields,
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
  normalizeNative: ashNormalizeBindingNative,

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
   * Build HMAC-SHA256 proof.
   */
  build: ashBuildProof,

  /**
   * Verify HMAC-SHA256 proof.
   * Uses constant-time comparison internally.
   */
  verify: ashVerifyProof,

  /**
   * Verify HMAC-SHA256 proof with timestamp freshness check.
   * Matches Rust SDK: ash_verify_proof_with_freshness
   */
  verifyWithFreshness: ashVerifyProofWithFreshness,

  /**
   * Verify HMAC-SHA256 proof with detailed error reporting.
   * BUG-019: Returns error details for debugging.
   */
  verifyDetailed: ashVerifyProofDetailed,

  /**
   * Build scoped proof with selective field protection.
   */
  buildScoped: ashBuildProofScoped,

  /**
   * Verify scoped proof with selective field protection.
   * Uses constant-time comparison internally.
   */
  verifyScoped: ashVerifyProofScoped,

  /**
   * Build unified proof with optional scoping and chaining.
   */
  buildUnified: ashBuildProofUnified,

  /**
   * Verify unified proof with optional scoping and chaining.
   * Uses constant-time comparison internally.
   */
  verifyUnified: ashVerifyProofUnified,

  /**
   * Derive client secret from nonce, contextId, and binding.
   */
  deriveClientSecret: ashDeriveClientSecret,

  // Deprecated aliases for backwards compatibility
  /** @deprecated Use build instead */
  buildV21: ashBuildProof,
  /** @deprecated Use verify instead */
  verifyV21: ashVerifyProof,
  /** @deprecated Use buildScoped instead */
  buildV21Scoped: ashBuildProofScoped,
  /** @deprecated Use verifyScoped instead */
  verifyV21Scoped: ashVerifyProofScoped,
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
  /** @deprecated Use ash.proof.build */
  buildProofV21: ashBuildProofV21,
  /** @deprecated Use ash.proof.verify */
  verifyProofV21: ashVerifyProofV21,
  /** @deprecated Use ash.utils.hashBody */
  hashBody: ashHashBody,
  /** @deprecated Use ash.context.toClient */
  contextToClient: ashContextToClient,
  /** @deprecated Use ash.utils.extractScopedFields */
  extractScopedFields: ashExtractScopedFields,
  /** @deprecated Use ash.proof.buildScoped */
  buildProofScoped: ashBuildProofScoped,
  /** @deprecated Use ash.proof.buildScoped */
  buildProofV21Scoped: ashBuildProofV21Scoped,
  /** @deprecated Use ash.proof.verifyScoped */
  verifyProofScoped: ashVerifyProofScoped,
  /** @deprecated Use ash.proof.verifyScoped */
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
  ashRegisterScopePolicy,
  ashRegisterScopePolicies,
  ashGetScopePolicy,
  ashHasScopePolicy,
  ashGetAllScopePolicies,
  ashClearScopePolicies,
  // Deprecated aliases
  registerScopePolicy,
  registerScopePolicies,
  getScopePolicy,
  hasScopePolicy,
  getAllScopePolicies,
  clearScopePolicies,
} from './config/scopePolicies';

export type { ScopePolicyConfig } from './config/scopePolicies';

// =========================================================================
// Secure Memory Utilities
// =========================================================================

export {
  ashSecureZeroBuffer,
  ashSecureZeroUint8Array,
  SecureBuffer,
  SecureString,
  withSecureBuffer,
  withSecureString,
  ashSecureDeriveClientSecret,
  UNSAFE_BUFFER_ACCESS,
  // Deprecated aliases
  secureZeroBuffer,
  secureZeroUint8Array,
  secureDeriveClientSecret,
} from './utils';

// =========================================================================
// Additional ASH Utility Functions
// =========================================================================

/**
 * Check if a mode string is a valid ASH security mode.
 *
 * @param mode The mode string to validate
 * @returns true if the mode is valid
 */
export function ashIsValidMode(mode: string): mode is AshMode {
  return mode === 'minimal' || mode === 'balanced' || mode === 'strict';
}

/**
 * Encode a string or buffer to base64url format.
 * Base64url uses URL-safe characters: - instead of +, _ instead of /.
 *
 * @param input String or Buffer to encode
 * @returns Base64url-encoded string
 */
export function ashBase64UrlEncode(input: string | Buffer): string {
  const buffer = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  return buffer.toString('base64url');
}

/**
 * Decode a base64url-encoded string.
 *
 * @param input Base64url-encoded string
 * @returns Decoded string
 */
export function ashBase64UrlDecode(input: string): string {
  return Buffer.from(input, 'base64url').toString('utf8');
}

/**
 * Decode a base64url-encoded string to a Buffer.
 *
 * @param input Base64url-encoded string
 * @returns Decoded Buffer
 */
export function ashBase64UrlDecodeToBuffer(input: string): Buffer {
  return Buffer.from(input, 'base64url');
}

// =========================================================================
// Deprecated Aliases for Backward Compatibility
// These aliases maintain backward compatibility with previous API versions.
// =========================================================================

/** @deprecated Use ashNormalizeScopeFields instead */
export const normalizeScopeFields = ashNormalizeScopeFields;

/** @deprecated Use ashValidateScopeFields instead */
export const validateScopeFields = ashValidateScopeFields;

/** @deprecated Use ashJoinScopeFields instead */
export const joinScopeFields = ashJoinScopeFields;

/** @deprecated Use ashHashBody instead */
export const hashBody = ashHashBody;

/** @deprecated Use ashHashProof instead */
export const hashProof = ashHashProof;

/** @deprecated Use ashHashScopedBody instead */
export const hashScopedBody = ashHashScopedBody;

/** @deprecated Use ashBuildProof instead */
export const buildProof = ashBuildProof;

/** @deprecated Use ashBuildProofHmac instead */
export const buildProofV21 = ashBuildProofHmac;

/** @deprecated Use ashVerifyProof instead */
export const verifyProofV21 = ashVerifyProof;

/** @deprecated Use ashBuildProofScoped instead */
export const buildProofV21Scoped = ashBuildProofScoped;

/** @deprecated Use ashVerifyProofScoped instead */
export const verifyProofV21Scoped = ashVerifyProofScoped;

/** @deprecated Use ashBuildProofUnified instead */
export const buildProofUnified = ashBuildProofUnified;

/** @deprecated Use ashVerifyProofUnified instead */
export const verifyProofUnified = ashVerifyProofUnified;

/** @deprecated Use ashDeriveClientSecret instead */
export const deriveClientSecret = ashDeriveClientSecret;

/** @deprecated Use ashGenerateNonce instead */
export const generateNonce = ashGenerateNonce;

/** @deprecated Use ashGenerateContextId instead */
export const generateContextId = ashGenerateContextId;

/** @deprecated Use ashCanonicalizeJson instead */
export const canonicalizeJson = ashCanonicalizeJson;

/** @deprecated Use ashCanonicalizeQuery instead */
export const canonicalizeQuery = ashCanonicalizeQuery;

/** @deprecated Use ashCanonicalizeUrlencoded instead */
export const canonicalizeUrlencoded = ashCanonicalizeUrlencoded;

/** @deprecated Use ashNormalizeBinding instead */
export const normalizeBinding = ashNormalizeBinding;

/** @deprecated Use ashTimingSafeEqual instead */
export const timingSafeEqual = ashTimingSafeEqual;

/** @deprecated Use ashExtractScopedFields instead */
export const extractScopedFields = ashExtractScopedFields;

/** @deprecated Use ashIsValidMode instead */
export const isValidMode = ashIsValidMode;

/** @deprecated Use ashBase64UrlEncode instead */
export const base64UrlEncode = ashBase64UrlEncode;

/** @deprecated Use ashBase64UrlDecode instead */
export const base64UrlDecode = ashBase64UrlDecode;

/** @deprecated Use ashCanonicalizeJsonNative instead */
export const canonicalizeJsonNative = ashCanonicalizeJsonNative;

/** @deprecated Use ashCanonicalizeJsonValueNative instead */
export const canonicalizeJsonValueNative = ashCanonicalizeJsonValueNative;

/** @deprecated Use ashCanonicalizeQueryNative instead */
export const canonicalQueryNative = ashCanonicalizeQueryNative;

/** @deprecated Use ashCanonicalizeUrlencodedNative instead */
export const canonicalizeUrlencodedNative = ashCanonicalizeUrlencodedNative;

/** @deprecated Use ashNormalizeBindingNative instead */
export const normalizeBindingNative = ashNormalizeBindingNative;
