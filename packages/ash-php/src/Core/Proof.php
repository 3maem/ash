<?php

declare(strict_types=1);

namespace Ash\Core;

/**
 * ASH Protocol Proof Generation.
 *
 * Deterministic hash-based integrity proof.
 * Same inputs MUST produce identical proof across all implementations.
 *
 * v2.1.0: Added derived client secret and HMAC-based proof for
 *         cryptographic binding between context and request.
 */
final class Proof
{
    /**
     * ASH protocol version prefix.
     */
    private const VERSION_PREFIX = 'ASHv1';

    /**
     * ASH v2.1 protocol version prefix.
     */
    private const VERSION_PREFIX_V21 = 'ASHv2.1';

    /**
     * Build a deterministic proof from the given inputs (v1.x legacy).
     *
     * Proof structure (from ASH-Spec-v1.0):
     *     proof = SHA256(
     *       "ASHv1" + "\n" +
     *       mode + "\n" +
     *       binding + "\n" +
     *       contextId + "\n" +
     *       (nonce? + "\n" : "") +
     *       canonicalPayload
     *     )
     *
     * Output: Base64URL encoded (no padding)
     *
     * @param BuildProofInput $input Proof input parameters
     * @return string Base64URL encoded proof string
     * @deprecated Use buildV21() for new implementations
     */
    public static function build(BuildProofInput $input): string
    {
        // Build the proof input string
        $proofInput = self::VERSION_PREFIX . "\n"
            . $input->mode->value . "\n"
            . $input->binding . "\n"
            . $input->contextId . "\n";

        // Add nonce if present (server-assisted mode)
        if ($input->nonce !== null && $input->nonce !== '') {
            $proofInput .= $input->nonce . "\n";
        }

        // Add canonical payload
        $proofInput .= $input->canonicalPayload;

        // Compute SHA-256 hash
        $hashBytes = hash('sha256', $proofInput, true);

        // Encode as Base64URL (no padding)
        return self::base64UrlEncode($hashBytes);
    }

    // =========================================================================
    // ASH v2.1 - Derived Client Secret & HMAC Proof
    // =========================================================================

    /**
     * Derive client secret from server nonce (v2.1).
     *
     * SECURITY PROPERTIES:
     * - One-way: Cannot derive nonce from clientSecret (HMAC is irreversible)
     * - Context-bound: Unique per contextId + binding combination
     * - Safe to expose: Client can use it but cannot forge other contexts
     *
     * Formula: clientSecret = HMAC-SHA256(nonce, contextId + "|" + binding)
     *
     * @param string $nonce Server-side secret nonce (32 bytes hex)
     * @param string $contextId Context identifier
     * @param string $binding Request binding (e.g., "POST /login")
     * @return string Derived client secret (64 hex chars)
     */
    public static function deriveClientSecret(string $nonce, string $contextId, string $binding): string
    {
        return hash_hmac('sha256', $contextId . '|' . $binding, $nonce);
    }

    /**
     * Build v2.1 cryptographic proof using client secret.
     *
     * The client computes this proof to demonstrate:
     * 1. They possess the clientSecret (received from context creation)
     * 2. The request body hasn't been tampered with
     * 3. The timestamp is recent (prevents replay)
     *
     * Formula: proof = HMAC-SHA256(clientSecret, timestamp + "|" + binding + "|" + bodyHash)
     *
     * @param string $clientSecret Derived client secret
     * @param string $timestamp Request timestamp (milliseconds)
     * @param string $binding Request binding
     * @param string $bodyHash SHA-256 hash of canonical request body
     * @return string Proof (64 hex chars)
     */
    public static function buildV21(
        string $clientSecret,
        string $timestamp,
        string $binding,
        string $bodyHash
    ): string {
        $message = $timestamp . '|' . $binding . '|' . $bodyHash;
        return hash_hmac('sha256', $message, $clientSecret);
    }

    /**
     * Verify v2.1 proof using stored nonce (server-side).
     *
     * @param string $nonce Server-side secret nonce
     * @param string $contextId Context identifier
     * @param string $binding Request binding
     * @param string $timestamp Request timestamp
     * @param string $bodyHash SHA-256 hash of canonical body
     * @param string $clientProof Proof received from client
     * @return bool True if proof is valid
     */
    public static function verifyV21(
        string $nonce,
        string $contextId,
        string $binding,
        string $timestamp,
        string $bodyHash,
        string $clientProof
    ): bool {
        // Derive the same client secret server-side
        $clientSecret = self::deriveClientSecret($nonce, $contextId, $binding);

        // Compute expected proof
        $expectedProof = self::buildV21($clientSecret, $timestamp, $binding, $bodyHash);

        // Constant-time comparison to prevent timing attacks
        return Compare::timingSafe($expectedProof, $clientProof);
    }

    /**
     * Compute SHA-256 hash of canonical body.
     *
     * @param string $canonicalBody Canonicalized request body
     * @return string SHA-256 hash (64 hex chars)
     */
    public static function hashBody(string $canonicalBody): string
    {
        return hash('sha256', $canonicalBody);
    }

    // =========================================================================
    // Base64URL Encoding/Decoding
    // =========================================================================

    /**
     * Encode bytes as Base64URL (no padding).
     *
     * RFC 4648 Section 5: Base 64 Encoding with URL and Filename Safe Alphabet
     */
    public static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Decode a Base64URL string to bytes.
     *
     * Handles both padded and unpadded input.
     */
    public static function base64UrlDecode(string $input): string
    {
        // Add padding if needed
        $padLength = (4 - strlen($input) % 4) % 4;
        $input .= str_repeat('=', $padLength);
        $decoded = base64_decode(strtr($input, '-_', '+/'), true);
        if ($decoded === false) {
            return '';
        }
        return $decoded;
    }

    /**
     * Generate a cryptographically secure random nonce.
     *
     * @param int $bytes Number of bytes (default 32)
     * @return string Hex-encoded nonce
     */
    public static function generateNonce(int $bytes = 32): string
    {
        return bin2hex(random_bytes($bytes));
    }

    /**
     * Generate a unique context ID.
     *
     * @return string Context ID with "ash_" prefix
     */
    public static function generateContextId(): string
    {
        return 'ash_' . bin2hex(random_bytes(16));
    }

    // =========================================================================
    // ASH v2.2 - Context Scoping (Selective Field Protection)
    // =========================================================================

    /**
     * Extract scoped fields from a payload array.
     *
     * @param array<string, mixed> $payload Full payload array
     * @param array<string> $scope Fields to extract (empty = all)
     * @return array<string, mixed> Extracted fields
     */
    public static function extractScopedFields(array $payload, array $scope): array
    {
        if (empty($scope)) {
            return $payload;
        }

        $result = [];
        foreach ($scope as $fieldPath) {
            $value = self::getNestedValue($payload, $fieldPath);
            if ($value !== null) {
                self::setNestedValue($result, $fieldPath, $value);
            }
        }
        return $result;
    }

    private static function getNestedValue(array $array, string $path): mixed
    {
        $keys = explode('.', $path);
        $current = $array;

        foreach ($keys as $key) {
            if (!is_array($current) || !array_key_exists($key, $current)) {
                return null;
            }
            $current = $current[$key];
        }

        return $current;
    }

    private static function setNestedValue(array &$array, string $path, mixed $value): void
    {
        $keys = explode('.', $path);
        $current = &$array;

        foreach ($keys as $i => $key) {
            if ($i === count($keys) - 1) {
                $current[$key] = $value;
            } else {
                if (!isset($current[$key]) || !is_array($current[$key])) {
                    $current[$key] = [];
                }
                $current = &$current[$key];
            }
        }
    }

    /**
     * Build v2.2 proof with scoped fields.
     */
    public static function buildV21Scoped(
        string $clientSecret,
        string $timestamp,
        string $binding,
        array $payload,
        array $scope
    ): array {
        $scopedPayload = self::extractScopedFields($payload, $scope);
        $canonicalScoped = json_encode($scopedPayload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $bodyHash = self::hashBody($canonicalScoped);

        $scopeStr = implode(',', $scope);
        $scopeHash = self::hashBody($scopeStr);

        $message = $timestamp . '|' . $binding . '|' . $bodyHash . '|' . $scopeHash;
        $proof = hash_hmac('sha256', $message, $clientSecret);

        return ['proof' => $proof, 'scopeHash' => $scopeHash];
    }

    /**
     * Verify v2.2 proof with scoped fields.
     */
    public static function verifyV21Scoped(
        string $nonce,
        string $contextId,
        string $binding,
        string $timestamp,
        array $payload,
        array $scope,
        string $scopeHash,
        string $clientProof
    ): bool {
        $scopeStr = implode(',', $scope);
        $expectedScopeHash = self::hashBody($scopeStr);
        if (!Compare::timingSafe($expectedScopeHash, $scopeHash)) {
            return false;
        }

        $clientSecret = self::deriveClientSecret($nonce, $contextId, $binding);
        $result = self::buildV21Scoped($clientSecret, $timestamp, $binding, $payload, $scope);

        return Compare::timingSafe($result['proof'], $clientProof);
    }

    /**
     * Hash scoped payload fields.
     */
    public static function hashScopedBody(array $payload, array $scope): string
    {
        $scopedPayload = self::extractScopedFields($payload, $scope);
        $canonical = json_encode($scopedPayload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        return self::hashBody($canonical);
    }
}
