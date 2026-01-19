<?php

declare(strict_types=1);

namespace Ash;

use Ash\Canonicalize\JsonCanonicalizer;
use Ash\Canonicalize\UrlencodedCanonicalizer;
use Ash\Proof\ProofBuilder;
use Ash\Store\ContextStoreInterface;

/**
 * ASH PHP SDK
 *
 * Request integrity and anti-replay protection for PHP applications.
 *
 * @package Ash
 */
final class Ash
{
    private const VERSION = 'ASHv1';
    private const LIBRARY_VERSION = '1.0.0';

    private ContextStoreInterface $store;
    private AshMode $defaultMode;

    /**
     * Create a new ASH instance.
     *
     * @param ContextStoreInterface $store Context store implementation
     * @param AshMode $defaultMode Default security mode
     */
    public function __construct(
        ContextStoreInterface $store,
        AshMode $defaultMode = AshMode::Balanced
    ) {
        $this->store = $store;
        $this->defaultMode = $defaultMode;
    }

    /**
     * Issue a new context for a request.
     *
     * @param string $binding Endpoint binding (e.g., "POST /api/update")
     * @param int $ttlMs Time-to-live in milliseconds
     * @param AshMode|null $mode Security mode (uses default if null)
     * @param array<string, mixed> $metadata Optional metadata
     * @return AshContext The created context
     */
    public function ashIssueContext(
        string $binding,
        int $ttlMs,
        ?AshMode $mode = null,
        array $metadata = []
    ): AshContext {
        return $this->store->create(
            $binding,
            $ttlMs,
            $mode ?? $this->defaultMode,
            $metadata
        );
    }

    /**
     * Verify a request against its context and proof.
     *
     * @param string $contextId Context ID from request header
     * @param string $proof Proof from request header
     * @param string $binding Actual request binding
     * @param string $payload Request payload (raw body)
     * @param string $contentType Content-Type header
     * @return AshVerifyResult Verification result
     */
    public function ashVerify(
        string $contextId,
        string $proof,
        string $binding,
        string $payload,
        string $contentType
    ): AshVerifyResult {
        // Get context
        $context = $this->store->get($contextId);

        if ($context === null) {
            return AshVerifyResult::failure(
                AshErrorCode::InvalidContext,
                'Invalid or expired context'
            );
        }

        // Check if already used
        if ($context->used) {
            return AshVerifyResult::failure(
                AshErrorCode::ReplayDetected,
                'Context already used (replay detected)'
            );
        }

        // Check binding
        if ($context->binding !== $binding) {
            return AshVerifyResult::failure(
                AshErrorCode::EndpointMismatch,
                "Binding mismatch: expected {$context->binding}, got {$binding}"
            );
        }

        // Canonicalize payload
        try {
            $canonicalPayload = $this->ashCanonicalize($payload, $contentType);
        } catch (\Exception $e) {
            return AshVerifyResult::failure(
                AshErrorCode::CanonicalizationFailed,
                'Failed to canonicalize payload: ' . $e->getMessage()
            );
        }

        // Build expected proof
        $expectedProof = $this->ashBuildProof(
            $context->mode,
            $context->binding,
            $contextId,
            $context->nonce,
            $canonicalPayload
        );

        // Constant-time comparison
        if (!$this->ashTimingSafeEqual($expectedProof, $proof)) {
            return AshVerifyResult::failure(
                AshErrorCode::IntegrityFailed,
                'Proof verification failed'
            );
        }

        // Consume context
        if (!$this->store->consume($contextId)) {
            return AshVerifyResult::failure(
                AshErrorCode::ReplayDetected,
                'Context already used (replay detected)'
            );
        }

        return AshVerifyResult::success($context->metadata);
    }

    /**
     * Canonicalize a payload based on content type.
     *
     * @param string $payload Raw payload
     * @param string $contentType Content-Type header
     * @return string Canonical payload
     */
    public function ashCanonicalize(string $payload, string $contentType): string
    {
        if (str_contains($contentType, 'application/json')) {
            return $this->ashCanonicalizeJson($payload);
        }

        if (str_contains($contentType, 'application/x-www-form-urlencoded')) {
            return $this->ashCanonicalizeUrlencoded($payload);
        }

        // For other content types, return as-is
        return $payload;
    }

    /**
     * Canonicalize JSON to deterministic form.
     *
     * @param string $json JSON string
     * @return string Canonical JSON string
     */
    public function ashCanonicalizeJson(string $json): string
    {
        return JsonCanonicalizer::canonicalize($json);
    }

    /**
     * Canonicalize URL-encoded data to deterministic form.
     *
     * @param string $urlencoded URL-encoded string
     * @return string Canonical URL-encoded string
     */
    public function ashCanonicalizeUrlencoded(string $urlencoded): string
    {
        return UrlencodedCanonicalizer::canonicalize($urlencoded);
    }

    /**
     * Build a cryptographic proof.
     *
     * @param AshMode $mode Security mode
     * @param string $binding Endpoint binding
     * @param string $contextId Context ID
     * @param string|null $nonce Optional nonce
     * @param string $canonicalPayload Canonicalized payload
     * @return string Base64URL-encoded proof
     */
    public function ashBuildProof(
        AshMode $mode,
        string $binding,
        string $contextId,
        ?string $nonce,
        string $canonicalPayload
    ): string {
        return ProofBuilder::build($mode, $binding, $contextId, $nonce, $canonicalPayload);
    }

    /**
     * Normalize a binding string.
     *
     * @param string $method HTTP method
     * @param string $path URL path
     * @return string Canonical binding
     */
    public function ashNormalizeBinding(string $method, string $path): string
    {
        // Uppercase method
        $method = strtoupper($method);

        // Remove query string
        $path = strtok($path, '?') ?: $path;

        // Ensure path starts with /
        if (!str_starts_with($path, '/')) {
            $path = '/' . $path;
        }

        // Collapse duplicate slashes
        $path = preg_replace('#/+#', '/', $path) ?? $path;

        // Remove trailing slash (except for root)
        if ($path !== '/') {
            $path = rtrim($path, '/');
        }

        return "{$method} {$path}";
    }

    /**
     * Constant-time string comparison.
     *
     * @param string $expected Expected value
     * @param string $actual Actual value
     * @return bool True if equal
     */
    public function ashTimingSafeEqual(string $expected, string $actual): bool
    {
        return hash_equals($expected, $actual);
    }

    /**
     * Get the ASH protocol version.
     *
     * @return string Version string
     */
    public function ashVersion(): string
    {
        return self::VERSION;
    }

    /**
     * Get the library version.
     *
     * @return string Semantic version
     */
    public function ashLibraryVersion(): string
    {
        return self::LIBRARY_VERSION;
    }

    /**
     * Get the context store.
     *
     * @return ContextStoreInterface
     */
    public function getStore(): ContextStoreInterface
    {
        return $this->store;
    }
}
