/**
 * ASH Node.js SDK
 *
 * Request integrity and anti-replay protection for Node.js applications.
 *
 * v2.1.0 SECURITY IMPROVEMENT:
 *   - Derived client secret (clientSecret = HMAC(nonce, contextId+binding))
 *   - Client-side proof generation using clientSecret
 *   - Cryptographic binding between context and request body
 *   - Nonce NEVER leaves server (clientSecret is derived, one-way)
 *
 * @packageDocumentation
 * @module @3maem/ash-node
 */

import * as crypto from 'crypto';
import * as wasm from '@3maem/ash-wasm';

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

export function ashNormalizeBinding(method: string, path: string): string {
  return wasm.ashNormalizeBinding(method, path);
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
  if (\!context.clientSecret) {
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
