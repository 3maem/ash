/**
 * ASH Secure Memory Utilities
 *
 * Provides secure handling of sensitive data with automatic memory clearing.
 * Prevents secrets from lingering in memory after use.
 *
 * Security Properties:
 * - Zeros buffer memory on clear/dispose
 * - Prevents accidental string conversion
 * - Works with try/finally or using patterns
 */

import * as crypto from 'crypto';

/**
 * INFO-003 FIX: Symbol key for unsafe buffer access.
 * Using a Symbol prevents accidental use of getUnsafe() - callers must
 * explicitly import and use this symbol, making unsafe access intentional.
 */
export const UNSAFE_BUFFER_ACCESS = Symbol.for('ash.secureBuffer.unsafeAccess');

/**
 * Securely zero out a Buffer's memory.
 *
 * Uses crypto.randomFill followed by zero fill to ensure
 * the data is thoroughly overwritten.
 *
 * @param buffer - Buffer to clear
 */
export function ashSecureZeroBuffer(buffer: Buffer): void {
  // First overwrite with random data to prevent recovery
  crypto.randomFillSync(buffer);
  // Then zero out
  buffer.fill(0);
}

/**
 * Securely zero out a Uint8Array's memory.
 *
 * @param array - Uint8Array to clear
 */
export function ashSecureZeroUint8Array(array: Uint8Array): void {
  // Overwrite with random data
  crypto.randomFillSync(array);
  // Then zero out
  array.fill(0);
}

/**
 * A secure container for sensitive byte data that can be
 * explicitly cleared from memory.
 *
 * @example
 * ```typescript
 * const secret = new SecureBuffer(Buffer.from(sensitiveData));
 * try {
 *   const result = crypto.createHmac('sha256', secret.get()).update(message).digest();
 * } finally {
 *   secret.clear();
 * }
 * ```
 *
 * @example Using with async/await
 * ```typescript
 * const secret = new SecureBuffer(32); // Random 32 bytes
 * try {
 *   await useSecret(secret.get());
 * } finally {
 *   secret.clear();
 * }
 * ```
 */
export class SecureBuffer {
  private _data: Buffer;
  private _cleared: boolean = false;

  /**
   * Create a new SecureBuffer.
   *
   * @param data - Initial data (Buffer, hex string, or length for random)
   */
  constructor(data: Buffer | string | number) {
    if (typeof data === 'number') {
      // BUG-LOGIC-116 FIX: Validate number parameter before crypto.randomBytes
      if (!Number.isInteger(data) || data < 0) {
        throw new TypeError('Number must be a non-negative integer');
      }
      if (data > 2147483647) {
        throw new TypeError('Number exceeds maximum safe buffer size');
      }
      // Generate random secure bytes
      this._data = crypto.randomBytes(data);
    } else if (typeof data === 'string') {
      // BUG-LOGIC-052 FIX: Validate hex string before conversion
      // Buffer.from(str, 'hex') silently skips invalid characters, creating partial buffers
      if (!/^[0-9a-fA-F]*$/.test(data)) {
        throw new TypeError('String must be a valid hexadecimal string (0-9, a-f, A-F only)');
      }
      if (data.length % 2 !== 0) {
        throw new TypeError('Hex string must have even length (each byte is 2 hex characters)');
      }
      // BUG-LOGIC-122 FIX: Validate hex string length to prevent large buffer allocation
      // Max 2GB buffer = 4 billion hex chars, but use same limit as number path for consistency
      const MAX_HEX_LENGTH = 2147483647 * 2; // 2 hex chars per byte
      if (data.length > MAX_HEX_LENGTH) {
        throw new TypeError('Hex string exceeds maximum safe buffer size');
      }
      this._data = Buffer.from(data, 'hex');
    } else if (Buffer.isBuffer(data)) {
      // Copy the buffer
      this._data = Buffer.alloc(data.length);
      data.copy(this._data);
    } else {
      throw new TypeError(`Unsupported data type: ${typeof data}`);
    }
  }

  /**
   * Get the buffer data.
   * VULN-013 FIX: Returns a copy to prevent external modification.
   * @throws Error if already cleared
   */
  get(): Buffer {
    if (this._cleared) {
      throw new Error('SecureBuffer has been cleared');
    }
    // VULN-013 FIX: Return a copy to prevent external mutation
    return Buffer.from(this._data);
  }

  /**
   * Get a reference to the internal buffer for performance-critical operations.
   * WARNING: Modifying this buffer will affect the internal state.
   * Use get() for a safe copy.
   *
   * INFO-003 FIX: Access via Symbol to prevent accidental use.
   * Callers must explicitly use: secureBuffer[UNSAFE_BUFFER_ACCESS]()
   *
   * @throws Error if already cleared
   * @internal
   */
  [UNSAFE_BUFFER_ACCESS](): Buffer {
    if (this._cleared) {
      throw new Error('SecureBuffer has been cleared');
    }
    return this._data;
  }

  /**
   * @deprecated Use Symbol access: buffer[UNSAFE_BUFFER_ACCESS]()
   * Kept for backwards compatibility but marked deprecated.
   * @internal
   */
  getUnsafe(): Buffer {
    return this[UNSAFE_BUFFER_ACCESS]();
  }

  /**
   * Get the data as a hex string.
   * @throws Error if already cleared
   */
  toHex(): string {
    if (this._cleared) {
      throw new Error('SecureBuffer has been cleared');
    }
    return this._data.toString('hex');
  }

  /**
   * Get the length of the buffer.
   */
  get length(): number {
    if (this._cleared) {
      return 0;
    }
    return this._data.length;
  }

  /**
   * Check if the buffer has been cleared.
   */
  get isCleared(): boolean {
    return this._cleared;
  }

  /**
   * Securely clear the buffer memory.
   */
  clear(): void {
    if (!this._cleared) {
      ashSecureZeroBuffer(this._data);
      this._cleared = true;
    }
  }

  /**
   * String representation (does not expose data).
   */
  toString(): string {
    if (this._cleared) {
      return 'SecureBuffer(<cleared>)';
    }
    return `SecureBuffer(<${this._data.length} bytes>)`;
  }

  /**
   * Inspect representation for console.log.
   */
  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}

/**
 * A secure container for sensitive string data (like client secrets)
 * that can be explicitly cleared from memory.
 *
 * @example
 * ```typescript
 * const secret = new SecureString(clientSecret);
 * try {
 *   const proof = buildProofV21(secret.get(), timestamp, binding, bodyHash);
 * } finally {
 *   secret.clear();
 * }
 * ```
 */
export class SecureString {
  private _data: Buffer;
  private _cleared: boolean = false;

  /**
   * Create a new SecureString.
   *
   * @param data - String data to protect
   */
  constructor(data: string) {
    // Store as buffer for secure clearing
    this._data = Buffer.from(data, 'utf8');
  }

  /**
   * Get the string.
   * @throws Error if already cleared
   */
  get(): string {
    if (this._cleared) {
      throw new Error('SecureString has been cleared');
    }
    return this._data.toString('utf8');
  }

  /**
   * Get the byte length of the string (UTF-8 encoded).
   * INFO-005 NOTE: Returns byte count, not character count.
   * For multi-byte UTF-8 characters, this may differ from string.length.
   * Example: "café" has 4 characters but 5 bytes (é is 2 bytes in UTF-8).
   */
  get length(): number {
    if (this._cleared) {
      return 0;
    }
    return this._data.length;
  }

  /**
   * Check if the string has been cleared.
   */
  get isCleared(): boolean {
    return this._cleared;
  }

  /**
   * Securely clear the memory.
   */
  clear(): void {
    if (!this._cleared) {
      ashSecureZeroBuffer(this._data);
      this._cleared = true;
    }
  }

  /**
   * String representation (does not expose data).
   */
  toString(): string {
    if (this._cleared) {
      return 'SecureString(<cleared>)';
    }
    return `SecureString(<${this._data.length} bytes>)`;
  }

  /**
   * Inspect representation for console.log.
   */
  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}

/**
 * Execute a function with a secure buffer that is automatically cleared afterward.
 *
 * @example
 * ```typescript
 * const result = await withSecureBuffer(secretKey, async (key) => {
 *   return crypto.createHmac('sha256', key).update(message).digest('hex');
 * });
 * // secretKey buffer is now cleared
 * ```
 *
 * @param data - Data to wrap in SecureBuffer
 * @param fn - Function to execute with the secure buffer
 * @returns Result of the function
 */
export async function withSecureBuffer<T>(
  data: Buffer | string | number,
  fn: (buffer: Buffer) => T | Promise<T>
): Promise<T> {
  const secure = new SecureBuffer(data);
  try {
    return await fn(secure.get());
  } finally {
    secure.clear();
  }
}

/**
 * Execute a function with a secure string that is automatically cleared afterward.
 *
 * @example
 * ```typescript
 * const proof = await withSecureString(clientSecret, async (secret) => {
 *   return buildProofV21(secret, timestamp, binding, bodyHash);
 * });
 * // clientSecret is now cleared
 * ```
 *
 * @param data - String to wrap in SecureString
 * @param fn - Function to execute with the secure string
 * @returns Result of the function
 */
export async function withSecureString<T>(
  data: string,
  fn: (str: string) => T | Promise<T>
): Promise<T> {
  const secure = new SecureString(data);
  try {
    return await fn(secure.get());
  } finally {
    secure.clear();
  }
}

// Security constants (matching index.ts)
const MIN_NONCE_HEX_CHARS = 32;
const MAX_NONCE_LENGTH = 128;
const MAX_CONTEXT_ID_LENGTH = 256;
const MAX_BINDING_LENGTH = 8192;

/**
 * Derive client secret with secure memory handling.
 *
 * Returns a SecureString that should be cleared after use.
 * BUG-014: Validates inputs matching ashDeriveClientSecret.
 *
 * @example
 * ```typescript
 * const secret = ashSecureDeriveClientSecret(nonce, contextId, binding);
 * try {
 *   const proof = buildProofV21(secret.get(), timestamp, binding, bodyHash);
 * } finally {
 *   secret.clear();
 * }
 * ```
 *
 * @param nonce - Server nonce (hex string or SecureBuffer)
 * @param contextId - Context identifier
 * @param binding - Request binding
 * @returns SecureString containing the derived client secret
 * @throws Error if validation fails
 */
export function ashSecureDeriveClientSecret(
  nonce: string | SecureBuffer,
  contextId: string,
  binding: string
): SecureString {
  const nonceStr = typeof nonce === 'string' ? nonce : nonce.toHex();

  // BUG-014: Validate nonce
  if (nonceStr.length < MIN_NONCE_HEX_CHARS) {
    throw new Error(`Nonce must be at least ${MIN_NONCE_HEX_CHARS} hex characters (16 bytes) for adequate entropy`);
  }
  if (nonceStr.length > MAX_NONCE_LENGTH) {
    throw new Error(`Nonce exceeds maximum length of ${MAX_NONCE_LENGTH} characters`);
  }
  if (!/^[0-9a-fA-F]+$/.test(nonceStr)) {
    throw new Error('Nonce must contain only hexadecimal characters (0-9, a-f, A-F)');
  }

  // BUG-014: Validate contextId
  if (contextId.length === 0) {
    throw new Error('context_id cannot be empty');
  }
  if (contextId.length > MAX_CONTEXT_ID_LENGTH) {
    throw new Error(`context_id exceeds maximum length of ${MAX_CONTEXT_ID_LENGTH} characters`);
  }
  if (!/^[A-Za-z0-9_.-]+$/.test(contextId)) {
    throw new Error('context_id must contain only ASCII alphanumeric characters, underscore, hyphen, or dot');
  }

  // BUG-014: Validate binding
  if (binding.length === 0) {
    throw new Error('binding cannot be empty');
  }
  if (binding.length > MAX_BINDING_LENGTH) {
    throw new Error(`binding exceeds maximum length of ${MAX_BINDING_LENGTH} bytes`);
  }

  const message = `${contextId}|${binding}`;

  // BUG-21 FIX: Use nonce as raw string (matching ashDeriveClientSecret)
  // NOT as hex-decoded bytes. The nonce is used as the HMAC key directly.
  const secret = crypto
    .createHmac('sha256', nonceStr)
    .update(message)
    .digest('hex');

  return new SecureString(secret);
}

// =========================================================================
// Deprecated Aliases for Backward Compatibility
// =========================================================================

/** @deprecated Use ashSecureZeroBuffer instead */
export const secureZeroBuffer = ashSecureZeroBuffer;

/** @deprecated Use ashSecureZeroUint8Array instead */
export const secureZeroUint8Array = ashSecureZeroUint8Array;

/** @deprecated Use ashSecureDeriveClientSecret instead */
export const secureDeriveClientSecret = ashSecureDeriveClientSecret;
