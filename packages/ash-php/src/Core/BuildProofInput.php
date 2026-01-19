<?php

declare(strict_types=1);

namespace Ash\Core;

/**
 * Input for building a proof.
 */
final class BuildProofInput
{
    /**
     * @param AshMode $mode ASH mode
     * @param string $binding Canonical binding: 'METHOD /path'
     * @param string $contextId Server-issued context ID
     * @param string $canonicalPayload Canonicalized payload string
     * @param string|null $nonce Optional server-issued nonce
     */
    public function __construct(
        public readonly AshMode $mode,
        public readonly string $binding,
        public readonly string $contextId,
        public readonly string $canonicalPayload,
        public readonly ?string $nonce = null,
    ) {
    }
}
