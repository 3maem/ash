<?php

declare(strict_types=1);

namespace Ash\Core;

/**
 * Public context info returned to client.
 */
final class ContextPublicInfo
{
    /**
     * @param string $contextId Opaque context ID
     * @param int $expiresAt Expiration timestamp (ms epoch)
     * @param AshMode $mode Security mode
     * @param string|null $nonce Optional nonce (if server-assisted mode)
     */
    public function __construct(
        public readonly string $contextId,
        public readonly int $expiresAt,
        public readonly AshMode $mode,
        public readonly ?string $nonce = null,
    ) {
    }
}
