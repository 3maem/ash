<?php

declare(strict_types=1);

namespace Ash\Core;

/**
 * Context as stored on server.
 */
final class StoredContext
{
    /**
     * @param string $contextId Unique context identifier (CSPRNG)
     * @param string $binding Canonical binding: 'METHOD /path'
     * @param AshMode $mode Security mode
     * @param int $issuedAt Timestamp when context was issued (ms epoch)
     * @param int $expiresAt Timestamp when context expires (ms epoch)
     * @param string|null $nonce Optional nonce for server-assisted mode
     * @param int|null $consumedAt Timestamp when context was consumed (null if not consumed)
     */
    public function __construct(
        public readonly string $contextId,
        public readonly string $binding,
        public readonly AshMode $mode,
        public readonly int $issuedAt,
        public readonly int $expiresAt,
        public readonly ?string $nonce = null,
        public readonly ?int $consumedAt = null,
    ) {
    }
}
