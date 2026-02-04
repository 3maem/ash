<?php

declare(strict_types=1);

namespace Ash;

use Ash\Core;
use Ash\Core\AshMode;
use Ash\Core\BuildProofInput;
use Ash\Core\Canonicalize;
use Ash\Core\Compare;
use Ash\Core\Proof;
use Ash\Store;

/**
 * ASH - Authenticity & Stateless Hardening Protocol.
 *
 * A cryptographic protocol for tamper-proof, replay-resistant API requests.
 *
 * SECURITY FEATURES:
 *   - Derived client secret (clientSecret = HMAC(nonce, contextId+binding))
 *   - Client-side proof generation using clientSecret
 *   - Cryptographic binding between context and request body
 *   - Nonce NEVER leaves server (clientSecret is derived, one-way)
 *
 * Example:
 *     use Ash\Ash;
 *
 *     // Server: Create context and derive clientSecret
 *     $nonce = Ash::ashGenerateNonce();
 *     $contextId = Ash::ashGenerateContextId();
 *     $clientSecret = Ash::ashDeriveClientSecret($nonce, $contextId, 'POST /login');
 *     // Send contextId + clientSecret to client (NOT the nonce!)
 *
 *     // Client: Build proof
 *     $bodyHash = Ash::ashHashBody($canonicalBody);
 *     $proof = Ash::ashBuildProofHmac($clientSecret, $timestamp, $binding, $bodyHash);
 *
 *     // Server: Verify proof
 *     $valid = Ash::ashVerifyProof($nonce, $contextId, $binding, $timestamp, $bodyHash, $proof);
 */
final class Ash
{
    public const VERSION = '2.3.4';

    private ?Store\ContextStoreInterface $store = null;

    // Configuration cache
    private static ?array $config = null;

    /**
     * Create a new Ash instance with a context store.
     *
     * @param Store\ContextStoreInterface|null $store Context store (optional for static-only usage)
     */
    public function __construct(?Store\ContextStoreInterface $store = null)
    {
        $this->store = $store;
    }

    /**
     * Load configuration from environment variables.
     *
     * @return array<string, mixed> Configuration values
     */
    public static function loadConfig(): array
    {
        if (self::$config === null) {
            self::$config = [
                'trust_proxy' => filter_var($_ENV['ASH_TRUST_PROXY'] ?? false, FILTER_VALIDATE_BOOL),
                'trusted_proxies' => array_filter(explode(',', $_ENV['ASH_TRUSTED_PROXIES'] ?? '')),
                'rate_limit_window' => (int)($_ENV['ASH_RATE_LIMIT_WINDOW'] ?? 60),
                'rate_limit_max' => (int)($_ENV['ASH_RATE_LIMIT_MAX'] ?? 10),
                'timestamp_tolerance' => (int)($_ENV['ASH_TIMESTAMP_TOLERANCE'] ?? 30),
            ];
        }
        return self::$config;
    }

    /**
     * Get client IP address with proxy support.
     *
     * @return string Client IP address
     */
    public static function getClientIp(): string
    {
        $config = self::loadConfig();

        // If not trusting proxies, use direct connection IP
        if (!$config['trust_proxy']) {
            return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        }

        // Check for X-Forwarded-For header
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $clientIp = trim($ips[0]);

            // Validate IP format
            if (filter_var($clientIp, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $clientIp;
            }
        }

        // Check for X-Real-IP header
        if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
            $clientIp = $_SERVER['HTTP_X_REAL_IP'];
            if (filter_var($clientIp, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $clientIp;
            }
        }

        // Fall back to REMOTE_ADDR
        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }

    /**
     * Normalize binding (instance method for middleware compatibility).
     *
     * @param string $method HTTP method
     * @param string $path Request path
     * @param string $query Query string (optional)
     * @return string Normalized binding string
     */
    public function ashNormalizeBinding(string $method, string $path, string $query = ''): string
    {
        return Canonicalize::ashNormalizeBinding($method, $path, $query);
    }

    /**
     * Verify a request (instance method for middleware compatibility).
     *
     * @param string $contextId Context identifier
     * @param string $proof Client-provided proof
     * @param string $binding Normalized binding
     * @param string $payload Request body
     * @param string $contentType Content-Type header
     * @param array<string, mixed> $options Optional verification options (scope, scopeHash, chainHash)
     * @return AshVerifyResult Verification result
     */
    public function ashVerify(
        string $contextId,
        string $proof,
        string $binding,
        string $payload,
        string $contentType,
        array $options = []
    ): AshVerifyResult {
        if ($this->store === null) {
            return new AshVerifyResult(
                valid: false,
                errorCode: Core\AshErrorCode::InternalError,
                errorMessage: 'No context store configured',
            );
        }

        // Get context from store
        $context = $this->store->get($contextId);
        if ($context === null) {
            return new AshVerifyResult(
                valid: false,
                errorCode: Core\AshErrorCode::CtxNotFound,
                errorMessage: 'Context not found or expired',
            );
        }

        // Check if already used
        if ($context->used) {
            return new AshVerifyResult(
                valid: false,
                errorCode: Core\AshErrorCode::CtxUsed,
                errorMessage: 'Context already used',
            );
        }

        // Canonicalize payload based on content type
        $canonicalPayload = $this->canonicalizePayload($payload, $contentType);

        // Get timestamp from options or use current time
        $timestamp = $options['timestamp'] ?? (string)(int)(microtime(true) * 1000);

        // Get scope and chain options
        $scope = $options['scope'] ?? [];
        $scopeHash = $options['scopeHash'] ?? '';
        $chainHash = $options['chainHash'] ?? '';
        $previousProof = $options['previousProof'] ?? null;

        // Build expected proof using v2.1 if we have a nonce
        if ($context->nonce !== null) {
            $bodyHash = Proof::ashHashBody($canonicalPayload);

            // Verify using v2.3 unified if scope or chain is present
            if (!empty($scope) || !empty($chainHash)) {
                $payloadArray = json_decode($payload, true) ?: [];
                $valid = Proof::ashVerifyProofUnified(
                    $context->nonce,
                    $contextId,
                    $binding,
                    $timestamp,
                    $payloadArray,
                    $proof,
                    $scope,
                    $scopeHash,
                    $previousProof,
                    $chainHash
                );
            } else {
                $valid = Proof::ashVerifyProof(
                    $context->nonce,
                    $contextId,
                    $binding,
                    $timestamp,
                    $bodyHash,
                    $proof
                );
            }

            if (!$valid) {
                return new AshVerifyResult(
                    valid: false,
                    errorCode: Core\AshErrorCode::ProofInvalid,
                    errorMessage: 'Invalid proof',
                );
            }
        }

        // Consume context
        if (!$this->store->consume($contextId)) {
            return new AshVerifyResult(
                valid: false,
                errorCode: Core\AshErrorCode::CtxUsed,
                errorMessage: 'Failed to consume context',
            );
        }

        return new AshVerifyResult(
            valid: true,
            metadata: $context->metadata,
        );
    }

    /**
     * Canonicalize payload based on content type.
     */
    private function canonicalizePayload(string $payload, string $contentType): string
    {
        if ($payload === '') {
            return '';
        }

        $contentType = strtolower(trim(explode(';', $contentType)[0]));

        if ($contentType === 'application/json' || str_ends_with($contentType, '+json')) {
            $decoded = json_decode($payload, true);
            if ($decoded !== null || $payload === 'null') {
                return Canonicalize::ashCanonicalizeJson($decoded);
            }
        }

        if ($contentType === 'application/x-www-form-urlencoded') {
            return Canonicalize::ashCanonicalizeUrlEncoded($payload);
        }

        return $payload;
    }

    /**
     * Create a new context.
     *
     * @param string $binding Endpoint binding
     * @param int $ttlMs Time-to-live in milliseconds
     * @param Core\AshMode $mode Security mode
     * @param array<string, mixed> $metadata Optional metadata
     * @return AshContext Created context
     * @throws Core\Exceptions\AshException If no store configured
     */
    public function createContext(
        string $binding,
        int $ttlMs = 300000,
        Core\AshMode $mode = Core\AshMode::Strict,
        array $metadata = []
    ): AshContext {
        if ($this->store === null) {
            throw new Core\Exceptions\AshException(
                Core\AshErrorCode::InternalError,
                'No context store configured'
            );
        }

        return $this->store->create($binding, $ttlMs, $mode, $metadata);
    }

    /**
     * Canonicalize a JSON value to a deterministic string.
     *
     * @param mixed $value The value to canonicalize
     * @return string Canonical JSON string
     * @throws Core\Exceptions\CanonicalizationException If value contains unsupported types
     */
    public static function ashCanonicalizeJson(mixed $value): string
    {
        return Canonicalize::ashCanonicalizeJson($value);
    }

    /**
     * @deprecated Use ashCanonicalizeJson() instead
     */
    public static function canonicalizeJson(mixed $value): string
    {
        return self::ashCanonicalizeJson($value);
    }

    /**
     * Canonicalize URL-encoded form data.
     *
     * @param string|array<string, string|array<string>> $inputData URL-encoded string or dict
     * @return string Canonical URL-encoded string
     * @throws Core\Exceptions\CanonicalizationException If input cannot be parsed
     */
    public static function ashCanonicalizeUrlEncoded(string|array $inputData): string
    {
        return Canonicalize::ashCanonicalizeUrlEncoded($inputData);
    }

    /**
     * @deprecated Use ashCanonicalizeUrlEncoded() instead
     */
    public static function canonicalizeUrlEncoded(string|array $inputData): string
    {
        return self::ashCanonicalizeUrlEncoded($inputData);
    }

    /**
     * Normalize a binding string.
     *
     * @param string $method HTTP method
     * @param string $path Request path
     * @return string Normalized binding string
     */
    public static function ashNormalizeBindingStatic(string $method, string $path): string
    {
        return Canonicalize::ashNormalizeBinding($method, $path);
    }

    /**
     * @deprecated Use ashNormalizeBindingStatic() instead
     */
    public static function normalizeBinding(string $method, string $path): string
    {
        return self::ashNormalizeBindingStatic($method, $path);
    }

    /**
     * Build a deterministic proof from the given inputs.
     *
     * @param BuildProofInput $input Proof input parameters
     * @return string Base64URL encoded proof string
     * @deprecated Use ashBuildProofHmac() for new implementations
     */
    public static function ashBuildProof(BuildProofInput $input): string
    {
        return Proof::ashBuildProof($input);
    }

    /**
     * @deprecated Use ashBuildProof() instead
     */
    public static function buildProof(BuildProofInput $input): string
    {
        return self::ashBuildProof($input);
    }

    /**
     * Perform a timing-safe string comparison.
     *
     * @param string $known The known string
     * @param string $userInput The user-provided string to compare
     * @return bool True if strings are equal, false otherwise
     */
    public static function ashTimingSafeEqual(string $known, string $userInput): bool
    {
        return Compare::ashTimingSafeEqual($known, $userInput);
    }

    /**
     * @deprecated Use ashTimingSafeEqual() instead
     */
    public static function timingSafeCompare(string $known, string $userInput): bool
    {
        return self::ashTimingSafeEqual($known, $userInput);
    }

    /**
     * Encode bytes as Base64URL (no padding).
     *
     * @param string $data The data to encode
     * @return string Base64URL encoded string
     */
    public static function ashBase64UrlEncode(string $data): string
    {
        return Proof::ashBase64UrlEncode($data);
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
     * @param string $input The Base64URL string to decode
     * @return string Decoded bytes
     */
    public static function ashBase64UrlDecode(string $input): string
    {
        return Proof::ashBase64UrlDecode($input);
    }

    /**
     * @deprecated Use ashBase64UrlDecode() instead
     */
    public static function base64UrlDecode(string $input): string
    {
        return self::ashBase64UrlDecode($input);
    }

    // =========================================================================
    // ASH - Derived Client Secret & Cryptographic Proof
    // =========================================================================

    /**
     * Generate a cryptographically secure random nonce.
     *
     * @param int $bytes Number of bytes (default 32)
     * @return string Hex-encoded nonce (64 chars for 32 bytes)
     */
    public static function ashGenerateNonce(int $bytes = 32): string
    {
        return Proof::ashGenerateNonce($bytes);
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
        return Proof::ashGenerateContextId();
    }

    /**
     * @deprecated Use ashGenerateContextId() instead
     */
    public static function generateContextId(): string
    {
        return self::ashGenerateContextId();
    }

    /**
     * Derive client secret from server nonce.
     *
     * SECURITY: The nonce MUST stay server-side only.
     * The derived clientSecret is safe to send to the client.
     *
     * @param string $nonce Server-side secret nonce
     * @param string $contextId Context identifier
     * @param string $binding Request binding (e.g., "POST /login")
     * @return string Derived client secret (64 hex chars)
     */
    public static function ashDeriveClientSecret(string $nonce, string $contextId, string $binding): string
    {
        return Proof::ashDeriveClientSecret($nonce, $contextId, $binding);
    }

    /**
     * @deprecated Use ashDeriveClientSecret() instead
     */
    public static function deriveClientSecret(string $nonce, string $contextId, string $binding): string
    {
        return self::ashDeriveClientSecret($nonce, $contextId, $binding);
    }

    /**
     * Build HMAC-based cryptographic proof (client-side).
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
        return Proof::ashBuildProofHmac($clientSecret, $timestamp, $binding, $bodyHash);
    }

    /**
     * @deprecated Use ashBuildProofHmac() instead
     */
    public static function buildProofV21(
        string $clientSecret,
        string $timestamp,
        string $binding,
        string $bodyHash
    ): string {
        return self::ashBuildProofHmac($clientSecret, $timestamp, $binding, $bodyHash);
    }

    /**
     * Verify proof (server-side).
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
        return Proof::ashVerifyProof($nonce, $contextId, $binding, $timestamp, $bodyHash, $clientProof);
    }

    /**
     * @deprecated Use ashVerifyProof() instead
     */
    public static function verifyProofV21(
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
        return Proof::ashHashBody($canonicalBody);
    }

    /**
     * @deprecated Use ashHashBody() instead
     */
    public static function hashBody(string $canonicalBody): string
    {
        return self::ashHashBody($canonicalBody);
    }
}
