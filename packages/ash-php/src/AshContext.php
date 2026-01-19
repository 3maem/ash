<?php

declare(strict_types=1);

namespace Ash;

/**
 * ASH context representing a one-time use token.
 */
final class AshContext
{
    /**
     * Create a new context.
     *
     * @param string $id Unique context identifier
     * @param string $binding Endpoint binding
     * @param int $expiresAt Expiration timestamp (Unix ms)
     * @param AshMode $mode Security mode
     * @param bool $used Whether context has been used
     * @param string|null $nonce Server-generated nonce (strict mode)
     * @param array<string, mixed> $metadata Optional metadata
     */
    public function __construct(
        public readonly string $id,
        public readonly string $binding,
        public readonly int $expiresAt,
        public readonly AshMode $mode,
        public bool $used = false,
        public readonly ?string $nonce = null,
        public readonly array $metadata = [],
    ) {
    }

    /**
     * Check if context has expired.
     *
     * @return bool True if expired
     */
    public function isExpired(): bool
    {
        return $this->getTimestampMs() > $this->expiresAt;
    }

    /**
     * Get current timestamp in milliseconds.
     *
     * @return int Unix timestamp in milliseconds
     */
    private function getTimestampMs(): int
    {
        return (int)(microtime(true) * 1000);
    }

    /**
     * Convert to array for serialization.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'binding' => $this->binding,
            'expiresAt' => $this->expiresAt,
            'mode' => $this->mode->value,
            'used' => $this->used,
            'nonce' => $this->nonce,
            'metadata' => $this->metadata,
        ];
    }

    /**
     * Create from array.
     *
     * @param array<string, mixed> $data
     * @return self
     */
    public static function fromArray(array $data): self
    {
        return new self(
            id: $data['id'],
            binding: $data['binding'],
            expiresAt: $data['expiresAt'],
            mode: AshMode::from($data['mode']),
            used: $data['used'] ?? false,
            nonce: $data['nonce'] ?? null,
            metadata: $data['metadata'] ?? [],
        );
    }
}
