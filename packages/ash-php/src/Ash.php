<?php

declare(strict_types=1);

namespace Ash;

use Ash\Core\AshMode;
use Ash\Core\BuildProofInput;
use Ash\Core\Canonicalize;
use Ash\Core\Compare;
use Ash\Core\Proof;

/**
 * ASH - Authenticity & Stateless Hardening Protocol.
 *
 * A cryptographic protocol for tamper-proof, replay-resistant API requests.
 *
 * v2.1.0 SECURITY IMPROVEMENT:
 *   - Derived client secret (clientSecret = HMAC(nonce, contextId+binding))
 *   - Client-side proof generation using clientSecret
 *   - Cryptographic binding between context and request body
 *   - Nonce NEVER leaves server (clientSecret is derived, one-way)
 *
 * Example (v2.1):
 *     use Ash\Ash;
 *
 *     // Server: Create context and derive clientSecret
 *     $nonce = Ash::generateNonce();
 *     $contextId = Ash::generateContextId();
 *     $clientSecret = Ash::deriveClientSecret($nonce, $contextId, 'POST /login');
 *     // Send contextId + clientSecret to client (NOT the nonce!)
 *
 *     // Client: Build proof
 *     $bodyHash = Ash::hashBody($canonicalBody);
 *     $proof = Ash::buildProofV21($clientSecret, $timestamp, $binding, $bodyHash);
 *
 *     // Server: Verify proof
 *     $valid = Ash::verifyProofV21($nonce, $contextId, $binding, $timestamp, $bodyHash, $proof);
 */
final class Ash
{
    public const VERSION = '2.3.1';

    /**
     * Canonicalize a JSON value to a deterministic string.
     *
     * @param mixed $value The value to canonicalize
     * @return string Canonical JSON string
     * @throws Core\Exceptions\CanonicalizationException If value contains unsupported types
     */
    public static function canonicalizeJson(mixed $value): string
    {
        return Canonicalize::json($value);
    }

    /**
     * Canonicalize URL-encoded form data.
     *
     * @param string|array<string, string|array<string>> $inputData URL-encoded string or dict
     * @return string Canonical URL-encoded string
     * @throws Core\Exceptions\CanonicalizationException If input cannot be parsed
     */
    public static function canonicalizeUrlEncoded(string|array $inputData): string
    {
        return Canonicalize::urlEncoded($inputData);
    }

    /**
     * Normalize a binding string.
     *
     * @param string $method HTTP method
     * @param string $path Request path
     * @return string Normalized binding string
     */
    public static function normalizeBinding(string $method, string $path): string
    {
        return Canonicalize::normalizeBinding($method, $path);
    }

    /**
     * Build a deterministic proof from the given inputs.
     *
     * @param BuildProofInput $input Proof input parameters
     * @return string Base64URL encoded proof string
     */
    public static function buildProof(BuildProofInput $input): string
    {
        return Proof::build($input);
    }

    /**
     * Perform a timing-safe string comparison.
     *
     * @param string $known The known string
     * @param string $userInput The user-provided string to compare
     * @return bool True if strings are equal, false otherwise
     */
    public static function timingSafeCompare(string $known, string $userInput): bool
    {
        return Compare::timingSafe($known, $userInput);
    }

    /**
     * Encode bytes as Base64URL (no padding).
     *
     * @param string $data The data to encode
     * @return string Base64URL encoded string
     */
    public static function base64UrlEncode(string $data): string
    {
        return Proof::base64UrlEncode($data);
    }

    /**
     * Decode a Base64URL string to bytes.
     *
     * @param string $input The Base64URL string to decode
     * @return string Decoded bytes
     */
    public static function base64UrlDecode(string $input): string
    {
        return Proof::base64UrlDecode($input);
    }

    // =========================================================================
    // ASH v2.1 - Derived Client Secret & Cryptographic Proof
    // =========================================================================

    /**
     * Generate a cryptographically secure random nonce.
     *
     * @param int $bytes Number of bytes (default 32)
     * @return string Hex-encoded nonce (64 chars for 32 bytes)
     */
    public static function generateNonce(int $bytes = 32): string
    {
        return Proof::generateNonce($bytes);
    }

    /**
     * Generate a unique context ID.
     *
     * @return string Context ID with "ash_" prefix
     */
    public static function generateContextId(): string
    {
        return Proof::generateContextId();
    }

    /**
     * Derive client secret from server nonce (v2.1).
     *
     * SECURITY: The nonce MUST stay server-side only.
     * The derived clientSecret is safe to send to the client.
     *
     * @param string $nonce Server-side secret nonce
     * @param string $contextId Context identifier
     * @param string $binding Request binding (e.g., "POST /login")
     * @return string Derived client secret (64 hex chars)
     */
    public static function deriveClientSecret(string $nonce, string $contextId, string $binding): string
    {
        return Proof::deriveClientSecret($nonce, $contextId, $binding);
    }

    /**
     * Build v2.1 cryptographic proof (client-side).
     *
     * @param string $clientSecret Derived client secret
     * @param string $timestamp Request timestamp (milliseconds)
     * @param string $binding Request binding
     * @param string $bodyHash SHA-256 hash of canonical request body
     * @return string Proof (64 hex chars)
     */
    public static function buildProofV21(
        string $clientSecret,
        string $timestamp,
        string $binding,
        string $bodyHash
    ): string {
        return Proof::buildV21($clientSecret, $timestamp, $binding, $bodyHash);
    }

    /**
     * Verify v2.1 proof (server-side).
     *
     * @param string $nonce Server-side secret nonce
     * @param string $contextId Context identifier
     * @param string $binding Request binding
     * @param string $timestamp Request timestamp
     * @param string $bodyHash SHA-256 hash of canonical body
     * @param string $clientProof Proof received from client
     * @return bool True if proof is valid
     */
    public static function verifyProofV21(
        string $nonce,
        string $contextId,
        string $binding,
        string $timestamp,
        string $bodyHash,
        string $clientProof
    ): bool {
        return Proof::verifyV21($nonce, $contextId, $binding, $timestamp, $bodyHash, $clientProof);
    }

    /**
     * Compute SHA-256 hash of canonical body.
     *
     * @param string $canonicalBody Canonicalized request body
     * @return string SHA-256 hash (64 hex chars)
     */
    public static function hashBody(string $canonicalBody): string
    {
        return Proof::hashBody($canonicalBody);
    }
}
