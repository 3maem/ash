<?php

declare(strict_types=1);

namespace Ash\Store;

use Ash\AshContext;
use Ash\AshMode;

/**
 * Interface for ASH context storage backends.
 */
interface ContextStoreInterface
{
    /**
     * Create a new context.
     *
     * @param string $binding Endpoint binding
     * @param int $ttlMs Time-to-live in milliseconds
     * @param AshMode $mode Security mode
     * @param array<string, mixed> $metadata Optional metadata
     * @return AshContext Created context
     */
    public function create(
        string $binding,
        int $ttlMs,
        AshMode $mode,
        array $metadata = []
    ): AshContext;

    /**
     * Get a context by ID.
     *
     * @param string $id Context ID
     * @return AshContext|null Context or null if not found/expired
     */
    public function get(string $id): ?AshContext;

    /**
     * Consume a context (mark as used).
     *
     * @param string $id Context ID
     * @return bool True if consumed, false if not found or already used
     */
    public function consume(string $id): bool;

    /**
     * Clean up expired contexts.
     *
     * @return int Number of contexts removed
     */
    public function cleanup(): int;
}
