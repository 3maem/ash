<?php

declare(strict_types=1);

namespace Ash\Store;

use Ash\AshContext;
use Ash\AshMode;

/**
 * Redis context store.
 *
 * Production-ready store for distributed deployments.
 * Requires a Redis client (Predis or PhpRedis).
 */
final class RedisStore implements ContextStoreInterface
{
    private object $redis;
    private string $keyPrefix;

    /**
     * Create a new Redis store.
     *
     * @param object $redis Redis client (Predis\Client or \Redis)
     * @param string $keyPrefix Key prefix for context keys
     */
    public function __construct(object $redis, string $keyPrefix = 'ash:ctx:')
    {
        $this->redis = $redis;
        $this->keyPrefix = $keyPrefix;
    }

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

        // Store with TTL (add 1 second buffer)
        $ttlSeconds = (int)ceil($ttlMs / 1000) + 1;

        $this->redis->setex(
            $this->key($id),
            $ttlSeconds,
            json_encode($context->toArray())
        );

        return $context;
    }

    /**
     * Get a context by ID.
     */
    public function get(string $id): ?AshContext
    {
        $data = $this->redis->get($this->key($id));

        if ($data === null || $data === false) {
            return null;
        }

        $context = AshContext::fromArray(json_decode($data, true));

        // Double-check expiration
        if ($context->isExpired()) {
            $this->redis->del($this->key($id));
            return null;
        }

        return $context;
    }

    /**
     * Consume a context atomically.
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

        // Mark as used
        $updated = new AshContext(
            id: $context->id,
            binding: $context->binding,
            expiresAt: $context->expiresAt,
            mode: $context->mode,
            used: true,
            nonce: $context->nonce,
            metadata: $context->metadata,
        );

        // Calculate remaining TTL
        $remainingMs = $context->expiresAt - $this->getTimestampMs();
        $remainingSeconds = max(1, (int)ceil($remainingMs / 1000));

        $this->redis->setex(
            $this->key($id),
            $remainingSeconds,
            json_encode($updated->toArray())
        );

        return true;
    }

    /**
     * Cleanup is handled by Redis TTL.
     */
    public function cleanup(): int
    {
        return 0;
    }

    /**
     * Generate Redis key for context ID.
     */
    private function key(string $id): string
    {
        return $this->keyPrefix . $id;
    }

    /**
     * Get current timestamp in milliseconds.
     */
    private function getTimestampMs(): int
    {
        return (int)(microtime(true) * 1000);
    }
}
