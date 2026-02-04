<?php

declare(strict_types=1);

namespace Ash\Core;

/**
 * Timing-safe comparison utilities.
 */
final class Compare
{
    /**
     * Perform a timing-safe string comparison.
     *
     * Uses PHP's built-in hash_equals which is constant-time.
     *
     * @param string $known The known string
     * @param string $userInput The user-provided string to compare
     * @return bool True if strings are equal, false otherwise
     */
    public static function ashTimingSafeEqual(string $known, string $userInput): bool
    {
        return hash_equals($known, $userInput);
    }

    /**
     * @deprecated Use ashTimingSafeEqual() instead
     */
    public static function timingSafe(string $known, string $userInput): bool
    {
        return self::ashTimingSafeEqual($known, $userInput);
    }
}
