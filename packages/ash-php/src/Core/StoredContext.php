<?php

declare(strict_types=1);

namespace Ash\Core;

/**
 * Context as stored on server.
 *
 * v2.1.0: Added clientSecret for cryptographic proof binding
 */
final class StoredContext
{
    /**
     * @param string $contextId Unique context identifier (CSPRNG)
     * @param string $binding Canonical binding: 'METHOD /path'
     * @param AshMode $mode Security mode
     * @param int $issuedAt Timestamp when context was issued (ms epoch)
     * @param int $expiresAt Timestamp when context expires (ms epoch)
     * @param string|null $nonce Server-side secret nonce (NEVER expose to client)
     * @param string|null $clientSecret v2.1: Derived secret for client (safe to expose)
     * @param string|null $fingerprint Device fingerprint hash
     * @param string|null $ipAddress Client IP address for binding
     * @param int|null $userId User ID for binding
     * @param int|null $consumedAt Timestamp when context was consumed (null if not consumed)
     */
    public function __construct(
        public readonly string $contextId,
        public readonly string $binding,
        public readonly AshMode $mode,
        public readonly int $issuedAt,
        public readonly int $expiresAt,
        public readonly ?string $nonce = null,
        public readonly ?string $clientSecret = null,
        public readonly ?string $fingerprint = null,
        public readonly ?string $ipAddress = null,
        public readonly ?int $userId = null,
        public readonly ?int $consumedAt = null,
    ) {
    }

    /**
     * Check if context has expired.
     */
    public function isExpired(): bool
    {
        return $this->expiresAt < (int)(microtime(true) * 1000);
    }

    /**
     * Check if context has been consumed.
     */
    public function isConsumed(): bool
    {
        return $this->consumedAt !== null;
    }

    /**
     * Convert to client-safe array (v2.1).
     * SECURITY: nonce is NEVER included, only clientSecret.
     */
    public function toClientArray(): array
    {
        return [
            'contextId' => $this->contextId,
            'binding' => $this->binding,
            'mode' => $this->mode->value,
            'expiresAt' => $this->expiresAt,
            'clientSecret' => $this->clientSecret, // v2.1: Derived secret for proof
            // NOTE: nonce is NEVER included - stays server-side only
        ];
    }
}
