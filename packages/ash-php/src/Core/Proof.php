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
     * ASH protocol version prefix (legacy v1.x).
     */
    public const VERSION_PREFIX = 'ASHv1';

    /**
     * ASH v2.1 protocol version prefix.
     */
    public const VERSION_PREFIX_V21 = 'ASHv2.1';

    /**
     * Scope field delimiter for hashing (using U+001F unit separator to avoid collision).
     * BUG-002: Prevents collision when field names contain commas.
     * Must match Rust ash-core SCOPE_FIELD_DELIMITER.
     */
    public const SCOPE_FIELD_DELIMITER = "\x1F";

    // =========================================================================
    // Security Constants (Must match Rust ash-core)
    // =========================================================================

    /**
     * Minimum hex characters for nonce in derive_client_secret.
     * SEC-014: Ensures adequate entropy (32 hex chars = 16 bytes = 128 bits).
     */
    public const MIN_NONCE_HEX_CHARS = 32;

    /**
     * Maximum nonce length.
     * SEC-NONCE-001: Limits nonce beyond minimum entropy requirement.
     */
    public const MAX_NONCE_LENGTH = 128;

    /**
     * Maximum context_id length.
     * SEC-CTX-001: Limits context_id to reasonable size for headers and storage.
     */
    public const MAX_CONTEXT_ID_LENGTH = 256;

    /**
     * Maximum binding length.
     * SEC-AUDIT-004: Prevents DoS via extremely long bindings.
     */
    public const MAX_BINDING_LENGTH = 8192; // 8KB

    /**
     * Normalize scope fields by sorting and deduplicating.
     * BUG-023: Ensures deterministic scope hash across all SDKs.
     *
     * @param array<string> $scope Array of field paths
     * @return array<string> Sorted and deduplicated scope array
     */
    public static function ashNormalizeScopeFields(array $scope): array
    {
        if (empty($scope)) {
            return $scope;
        }
        // Deduplicate and sort
        $unique = array_unique($scope);
        sort($unique, SORT_STRING);
        return array_values($unique);
    }

    /**
     * @deprecated Use ashNormalizeScopeFields() instead
     */
    public static function normalizeScopeFields(array $scope): array
    {
        return self::ashNormalizeScopeFields($scope);
    }

    /**
     * Join scope fields with the proper delimiter after normalization.
     * BUG-002, BUG-023: Uses unit separator and normalizes for cross-SDK compatibility.
     *
     * @param array<string> $scope Array of field paths
     * @return string Joined scope string
     */
    public static function ashJoinScopeFields(array $scope): string
    {
        $normalized = self::ashNormalizeScopeFields($scope);
        return implode(self::SCOPE_FIELD_DELIMITER, $normalized);
    }

    /**
     * @deprecated Use ashJoinScopeFields() instead
     */
    public static function joinScopeFields(array $scope): string
    {
        return self::ashJoinScopeFields($scope);
    }

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
     * @deprecated Use ashBuildProofHmac() for new implementations
     */
    public static function ashBuildProof(BuildProofInput $input): string
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
        return self::ashBase64UrlEncode($hashBytes);
    }

    /**
     * @deprecated Use ashBuildProof() instead
     */
    public static function build(BuildProofInput $input): string
    {
        return self::ashBuildProof($input);
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
     * @param string $nonce Server-side secret nonce (minimum 32 hex chars for adequate entropy)
     * @param string $contextId Context identifier (alphanumeric, underscore, hyphen, dot only)
     * @param string $binding Request binding (e.g., "POST|/login|")
     * @return string Derived client secret (64 hex chars)
     * @throws Exceptions\ValidationException If any input fails validation
     */
    public static function ashDeriveClientSecret(string $nonce, string $contextId, string $binding): string
    {
        // SEC-014: Validate nonce has sufficient entropy
        if (strlen($nonce) < self::MIN_NONCE_HEX_CHARS) {
            throw new Exceptions\ValidationException(sprintf(
                'nonce must be at least %d hex characters (%d bytes) for adequate entropy',
                self::MIN_NONCE_HEX_CHARS,
                self::MIN_NONCE_HEX_CHARS / 2
            ));
        }

        // SEC-NONCE-001: Validate nonce doesn't exceed maximum length
        if (strlen($nonce) > self::MAX_NONCE_LENGTH) {
            throw new Exceptions\ValidationException(sprintf(
                'nonce exceeds maximum length of %d characters',
                self::MAX_NONCE_LENGTH
            ));
        }

        // BUG-004: Validate nonce is valid hexadecimal
        if (!ctype_xdigit($nonce)) {
            throw new Exceptions\ValidationException(
                'nonce must contain only hexadecimal characters (0-9, a-f, A-F)'
            );
        }

        // BUG-041: Validate contextId is not empty
        if ($contextId === '') {
            throw new Exceptions\ValidationException('context_id cannot be empty');
        }

        // SEC-CTX-001: Validate contextId doesn't exceed maximum length
        if (strlen($contextId) > self::MAX_CONTEXT_ID_LENGTH) {
            throw new Exceptions\ValidationException(sprintf(
                'context_id exceeds maximum length of %d characters',
                self::MAX_CONTEXT_ID_LENGTH
            ));
        }

        // SEC-CTX-001: Validate contextId contains only allowed characters (A-Z a-z 0-9 _ - .)
        if (!preg_match('/^[A-Za-z0-9_.\-]+$/', $contextId)) {
            throw new Exceptions\ValidationException(
                'context_id must contain only ASCII alphanumeric characters, underscore, hyphen, or dot'
            );
        }

        // SEC-AUDIT-004: Validate binding length to prevent memory exhaustion
        if (strlen($binding) > self::MAX_BINDING_LENGTH) {
            throw new Exceptions\ValidationException(sprintf(
                'binding exceeds maximum length of %d bytes',
                self::MAX_BINDING_LENGTH
            ));
        }

        return hash_hmac('sha256', $contextId . '|' . $binding, $nonce);
    }

    /**
     * @deprecated Use ashDeriveClientSecret() instead
     */
    public static function deriveClientSecret(string $nonce, string $contextId, string $binding): string
    {
        return self::ashDeriveClientSecret($nonce, $contextId, $binding);
    }

    /**
     * Build HMAC-based cryptographic proof using client secret.
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
    public static function ashBuildProofHmac(
        string $clientSecret,
        string $timestamp,
        string $binding,
        string $bodyHash
    ): string {
        $message = $timestamp . '|' . $binding . '|' . $bodyHash;
        return hash_hmac('sha256', $message, $clientSecret);
    }

    /**
     * @deprecated Use ashBuildProofHmac() instead
     */
    public static function buildV21(
        string $clientSecret,
        string $timestamp,
        string $binding,
        string $bodyHash
    ): string {
        return self::ashBuildProofHmac($clientSecret, $timestamp, $binding, $bodyHash);
    }

    /**
     * Verify proof using stored nonce (server-side).
     *
     * @param string $nonce Server-side secret nonce
     * @param string $contextId Context identifier
     * @param string $binding Request binding
     * @param string $timestamp Request timestamp
     * @param string $bodyHash SHA-256 hash of canonical body
     * @param string $clientProof Proof received from client
     * @return bool True if proof is valid
     */
    public static function ashVerifyProof(
        string $nonce,
        string $contextId,
        string $binding,
        string $timestamp,
        string $bodyHash,
        string $clientProof
    ): bool {
        // Derive the same client secret server-side
        $clientSecret = self::ashDeriveClientSecret($nonce, $contextId, $binding);

        // Compute expected proof
        $expectedProof = self::ashBuildProofHmac($clientSecret, $timestamp, $binding, $bodyHash);

        // Constant-time comparison to prevent timing attacks
        return Compare::ashTimingSafeEqual($expectedProof, $clientProof);
    }

    /**
     * @deprecated Use ashVerifyProof() instead
     */
    public static function verifyV21(
        string $nonce,
        string $contextId,
        string $binding,
        string $timestamp,
        string $bodyHash,
        string $clientProof
    ): bool {
        return self::ashVerifyProof($nonce, $contextId, $binding, $timestamp, $bodyHash, $clientProof);
    }

    /**
     * Compute SHA-256 hash of canonical body.
     *
     * @param string $canonicalBody Canonicalized request body
     * @return string SHA-256 hash (64 hex chars)
     */
    public static function ashHashBody(string $canonicalBody): string
    {
        return hash('sha256', $canonicalBody);
    }

    /**
     * @deprecated Use ashHashBody() instead
     */
    public static function hashBody(string $canonicalBody): string
    {
        return self::ashHashBody($canonicalBody);
    }

    // =========================================================================
    // Base64URL Encoding/Decoding
    // =========================================================================

    /**
     * Encode bytes as Base64URL (no padding).
     *
     * RFC 4648 Section 5: Base 64 Encoding with URL and Filename Safe Alphabet
     */
    public static function ashBase64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * @deprecated Use ashBase64UrlEncode() instead
     */
    public static function base64UrlEncode(string $data): string
    {
        return self::ashBase64UrlEncode($data);
    }

    /**
     * Decode a Base64URL string to bytes.
     *
     * Handles both padded and unpadded input.
     */
    public static function ashBase64UrlDecode(string $input): string
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
     * @deprecated Use ashBase64UrlDecode() instead
     */
    public static function base64UrlDecode(string $input): string
    {
        return self::ashBase64UrlDecode($input);
    }

    /**
     * Generate a cryptographically secure random nonce.
     *
     * @param int<1, max> $bytes Number of bytes (default 32)
     * @return string Hex-encoded nonce
     */
    public static function ashGenerateNonce(int $bytes = 32): string
    {
        if ($bytes < 1) {
            $bytes = 32;
        }
        return bin2hex(random_bytes($bytes));
    }

    /**
     * @deprecated Use ashGenerateNonce() instead
     */
    public static function generateNonce(int $bytes = 32): string
    {
        return self::ashGenerateNonce($bytes);
    }

    /**
     * Generate a unique context ID.
     *
     * @return string Context ID with "ash_" prefix
     */
    public static function ashGenerateContextId(): string
    {
        return 'ash_' . bin2hex(random_bytes(16));
    }

    /**
     * @deprecated Use ashGenerateContextId() instead
     */
    public static function generateContextId(): string
    {
        return self::ashGenerateContextId();
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
    public static function ashExtractScopedFields(array $payload, array $scope): array
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

    /**
     * @deprecated Use ashExtractScopedFields() instead
     */
    public static function extractScopedFields(array $payload, array $scope): array
    {
        return self::ashExtractScopedFields($payload, $scope);
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
     * Build proof with scoped fields.
     */
    public static function ashBuildProofScoped(
        string $clientSecret,
        string $timestamp,
        string $binding,
        array $payload,
        array $scope
    ): array {
        // BUG-023: Normalize scope for deterministic ordering
        $normalizedScope = self::ashNormalizeScopeFields($scope);
        $scopedPayload = self::ashExtractScopedFields($payload, $normalizedScope);
        $canonicalScoped = Canonicalize::ashCanonicalizeJson($scopedPayload);
        $bodyHash = self::ashHashBody($canonicalScoped);

        // BUG-002, BUG-023: Use unit separator and normalized scope
        $scopeStr = self::ashJoinScopeFields($scope);
        $scopeHash = self::ashHashBody($scopeStr);

        $message = $timestamp . '|' . $binding . '|' . $bodyHash . '|' . $scopeHash;
        $proof = hash_hmac('sha256', $message, $clientSecret);

        return ['proof' => $proof, 'scopeHash' => $scopeHash];
    }

    /**
     * @deprecated Use ashBuildProofScoped() instead
     */
    public static function buildV21Scoped(
        string $clientSecret,
        string $timestamp,
        string $binding,
        array $payload,
        array $scope
    ): array {
        return self::ashBuildProofScoped($clientSecret, $timestamp, $binding, $payload, $scope);
    }

    /**
     * Verify proof with scoped fields.
     */
    public static function ashVerifyProofScoped(
        string $nonce,
        string $contextId,
        string $binding,
        string $timestamp,
        array $payload,
        array $scope,
        string $scopeHash,
        string $clientProof
    ): bool {
        // BUG-002, BUG-023: Verify scope hash with unit separator and normalization
        $scopeStr = self::ashJoinScopeFields($scope);
        $expectedScopeHash = self::ashHashBody($scopeStr);
        if (!Compare::ashTimingSafeEqual($expectedScopeHash, $scopeHash)) {
            return false;
        }

        $clientSecret = self::ashDeriveClientSecret($nonce, $contextId, $binding);
        $result = self::ashBuildProofScoped($clientSecret, $timestamp, $binding, $payload, $scope);

        return Compare::ashTimingSafeEqual($result['proof'], $clientProof);
    }

    /**
     * @deprecated Use ashVerifyProofScoped() instead
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
        return self::ashVerifyProofScoped($nonce, $contextId, $binding, $timestamp, $payload, $scope, $scopeHash, $clientProof);
    }

    /**
     * Hash scoped payload fields.
     */
    public static function ashHashScopedBody(array $payload, array $scope): string
    {
        $scopedPayload = self::ashExtractScopedFields($payload, $scope);
        $canonical = Canonicalize::ashCanonicalizeJson($scopedPayload);
        return self::ashHashBody($canonical);
    }

    /**
     * @deprecated Use ashHashScopedBody() instead
     */
    public static function hashScopedBody(array $payload, array $scope): string
    {
        return self::ashHashScopedBody($payload, $scope);
    }

    // =========================================================================
    // ASH v2.3 - Unified Proof Functions (Scoping + Chaining)
    // =========================================================================

    /**
     * Hash a proof for chaining purposes.
     *
     * @param string $proof Proof to hash
     * @return string SHA-256 hash of the proof (64 hex chars)
     */
    public static function ashHashProof(string $proof): string
    {
        return hash('sha256', $proof);
    }

    /**
     * @deprecated Use ashHashProof() instead
     */
    public static function hashProof(string $proof): string
    {
        return self::ashHashProof($proof);
    }

    /**
     * Build unified cryptographic proof with optional scoping and chaining.
     *
     * @param string $clientSecret Derived client secret
     * @param string $timestamp Request timestamp (milliseconds)
     * @param string $binding Request binding
     * @param array<string, mixed> $payload Full payload array
     * @param array<string> $scope Fields to protect (empty = full payload)
     * @param string|null $previousProof Previous proof in chain (null = no chaining)
     * @return array{proof: string, scopeHash: string, chainHash: string}
     */
    public static function ashBuildProofUnified(
        string $clientSecret,
        string $timestamp,
        string $binding,
        array $payload,
        array $scope = [],
        ?string $previousProof = null
    ): array {
        // BUG-023: Normalize scope for deterministic ordering
        $normalizedScope = self::ashNormalizeScopeFields($scope);
        $scopedPayload = self::ashExtractScopedFields($payload, $normalizedScope);
        $canonicalScoped = Canonicalize::ashCanonicalizeJson($scopedPayload);
        $bodyHash = self::ashHashBody($canonicalScoped);

        // BUG-002, BUG-023: Use unit separator and normalized scope
        $scopeHash = empty($scope) ? '' : self::ashHashBody(self::ashJoinScopeFields($scope));
        $chainHash = ($previousProof !== null && $previousProof !== '')
            ? self::ashHashProof($previousProof)
            : '';

        $message = $timestamp . '|' . $binding . '|' . $bodyHash . '|' . $scopeHash . '|' . $chainHash;
        $proof = hash_hmac('sha256', $message, $clientSecret);

        return [
            'proof' => $proof,
            'scopeHash' => $scopeHash,
            'chainHash' => $chainHash,
        ];
    }

    /**
     * @deprecated Use ashBuildProofUnified() instead
     */
    public static function buildUnified(
        string $clientSecret,
        string $timestamp,
        string $binding,
        array $payload,
        array $scope = [],
        ?string $previousProof = null
    ): array {
        return self::ashBuildProofUnified($clientSecret, $timestamp, $binding, $payload, $scope, $previousProof);
    }

    /**
     * Verify unified proof with optional scoping and chaining.
     *
     * @param string $nonce Server-side secret nonce
     * @param string $contextId Context identifier
     * @param string $binding Request binding
     * @param string $timestamp Request timestamp
     * @param array<string, mixed> $payload Full payload array
     * @param string $clientProof Proof received from client
     * @param array<string> $scope Fields that were protected (empty = full payload)
     * @param string $scopeHash Scope hash from client (empty if no scoping)
     * @param string|null $previousProof Previous proof in chain (null if no chaining)
     * @param string $chainHash Chain hash from client (empty if no chaining)
     * @return bool True if proof is valid
     */
    public static function ashVerifyProofUnified(
        string $nonce,
        string $contextId,
        string $binding,
        string $timestamp,
        array $payload,
        string $clientProof,
        array $scope = [],
        string $scopeHash = '',
        ?string $previousProof = null,
        string $chainHash = ''
    ): bool {
        // SEC-013: Validate consistency - scopeHash must be empty when scope is empty
        if (empty($scope) && $scopeHash !== '') {
            return false;
        }

        // BUG-002, BUG-023: Verify scope hash with unit separator and normalization
        if (!empty($scope)) {
            $expectedScopeHash = self::ashHashBody(self::ashJoinScopeFields($scope));
            if (!Compare::ashTimingSafeEqual($expectedScopeHash, $scopeHash)) {
                return false;
            }
        }

        // SEC-013: Validate consistency - chainHash must be empty when previousProof is absent
        if (($previousProof === null || $previousProof === '') && $chainHash !== '') {
            return false;
        }

        if ($previousProof !== null && $previousProof !== '') {
            $expectedChainHash = self::ashHashProof($previousProof);
            if (!Compare::ashTimingSafeEqual($expectedChainHash, $chainHash)) {
                return false;
            }
        }

        $clientSecret = self::ashDeriveClientSecret($nonce, $contextId, $binding);
        $result = self::ashBuildProofUnified($clientSecret, $timestamp, $binding, $payload, $scope, $previousProof);

        return Compare::ashTimingSafeEqual($result['proof'], $clientProof);
    }

    /**
     * @deprecated Use ashVerifyProofUnified() instead
     */
    public static function verifyUnified(
        string $nonce,
        string $contextId,
        string $binding,
        string $timestamp,
        array $payload,
        string $clientProof,
        array $scope = [],
        string $scopeHash = '',
        ?string $previousProof = null,
        string $chainHash = ''
    ): bool {
        return self::ashVerifyProofUnified($nonce, $contextId, $binding, $timestamp, $payload, $clientProof, $scope, $scopeHash, $previousProof, $chainHash);
    }
}
