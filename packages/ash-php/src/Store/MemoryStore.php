<?php

declare(strict_types=1);

namespace Ash\Store;

use Ash\AshContext;
use Ash\AshMode;

/**
 * In-memory context store.
 *
 * Suitable for development and single-process deployments.
 * For production, use Redis or database store.
 */
final class MemoryStore implements ContextStoreInterface
{
    /** @var array<string, AshContext> */
    private array $contexts = [];

    /**
     * Create a new context.
     */
    public function create(
        string $binding,
        int $ttlMs,
        AshMode $mode,
        array $metadata = []
    ): AshContext {
        $id = 'ctx_' . bin2hex(random_bytes(16));
        $nonce = $mode === AshMode::Strict ? bin2hex(random_bytes(16)) : null;

        $context = new AshContext(
            id: $id,
            binding: $binding,
            expiresAt: $this->getTimestampMs() + $ttlMs,
            mode: $mode,
            used: false,
            nonce: $nonce,
            metadata: $metadata,
        );

        $this->contexts[$id] = $context;

        return $context;
    }

    /**
     * Get a context by ID.
     */
    public function get(string $id): ?AshContext
    {
        $context = $this->contexts[$id] ?? null;

        if ($context === null) {
            return null;
        }

        // Check expiration
        if ($context->isExpired()) {
            unset($this->contexts[$id]);
            return null;
        }

        return $context;
    }

    /**
     * Consume a context.
     */
    public function consume(string $id): bool
    {
        $context = $this->get($id);

        if ($context === null) {
            return false;
        }

        if ($context->used) {
            return false;
        }

        // Mark as used (create new instance since properties are readonly)
        $this->contexts[$id] = new AshContext(
            id: $context->id,
            binding: $context->binding,
            expiresAt: $context->expiresAt,
            mode: $context->mode,
            used: true,
            nonce: $context->nonce,
            metadata: $context->metadata,
        );

        return true;
    }

    /**
     * Clean up expired contexts.
     */
    public function cleanup(): int
    {
        $now = $this->getTimestampMs();
        $removed = 0;

        foreach ($this->contexts as $id => $context) {
            if ($now > $context->expiresAt) {
                unset($this->contexts[$id]);
                $removed++;
            }
        }

        return $removed;
    }

    /**
     * Get the number of active contexts.
     */
    public function count(): int
    {
        return count($this->contexts);
    }

    /**
     * Clear all contexts.
     */
    public function clear(): void
    {
        $this->contexts = [];
    }

    /**
     * Get current timestamp in milliseconds.
     */
    private function getTimestampMs(): int
    {
        return (int)(microtime(true) * 1000);
    }
}
