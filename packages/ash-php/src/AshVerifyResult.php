<?php

declare(strict_types=1);

namespace Ash;

/**
 * Result of ASH verification.
 */
final class AshVerifyResult
{
    /**
     * Create a new verification result.
     *
     * @param bool $valid Whether verification succeeded
     * @param AshErrorCode|null $errorCode Error code if failed
     * @param string|null $errorMessage Error message if failed
     * @param array<string, mixed> $metadata Context metadata (on success)
     */
    public function __construct(
        public readonly bool $valid,
        public readonly ?AshErrorCode $errorCode = null,
        public readonly ?string $errorMessage = null,
        public readonly array $metadata = [],
    ) {
    }

    /**
     * Create a successful result.
     *
     * @param array<string, mixed> $metadata Context metadata
     * @return self
     */
    public static function success(array $metadata = []): self
    {
        return new self(
            valid: true,
            metadata: $metadata,
        );
    }

    /**
     * Create a failed result.
     *
     * @param AshErrorCode $code Error code
     * @param string $message Error message
     * @return self
     */
    public static function failure(AshErrorCode $code, string $message): self
    {
        return new self(
            valid: false,
            errorCode: $code,
            errorMessage: $message,
        );
    }
}
