<?php

declare(strict_types=1);

namespace Ash;

/**
 * ASH security modes.
 */
enum AshMode: string
{
    /**
     * Minimal mode - basic integrity protection.
     * Suitable for low-risk operations.
     */
    case Minimal = 'minimal';

    /**
     * Balanced mode - recommended for most operations.
     * Good balance of security and performance.
     */
    case Balanced = 'balanced';

    /**
     * Strict mode - maximum security with server nonce.
     * Recommended for sensitive operations.
     */
    case Strict = 'strict';
}
