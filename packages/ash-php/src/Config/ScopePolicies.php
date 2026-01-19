<?php

declare(strict_types=1);

namespace Ash\Config;

/**
 * Server-side scope policy registry.
 *
 * Allows servers to define which fields must be protected for each route,
 * without requiring client-side scope management.
 *
 * @example
 * // Register policies at application boot
 * ScopePolicies::register('POST|/api/transfer|', ['amount', 'recipient']);
 * ScopePolicies::register('POST|/api/payment|', ['amount', 'card_last4']);
 * ScopePolicies::register('PUT|/api/users/*|', ['role', 'permissions']);
 *
 * // Later, get policy for a binding
 * $scope = ScopePolicies::get('POST|/api/transfer|');
 * // Returns: ['amount', 'recipient']
 */
final class ScopePolicies
{
    /**
     * @var array<string, string[]> Registered scope policies
     */
    private static array $policies = [];

    /**
     * Register a scope policy for a binding pattern.
     *
     * @param string $binding The binding pattern (supports * wildcards)
     * @param string[] $fields The fields that must be protected
     *
     * @example
     * ScopePolicies::register('POST|/api/transfer|', ['amount', 'recipient']);
     * ScopePolicies::register('PUT|/api/users/*|', ['role', 'permissions']);
     */
    public static function register(string $binding, array $fields): void
    {
        self::$policies[$binding] = $fields;
    }

    /**
     * Register multiple scope policies at once.
     *
     * @param array<string, string[]> $policies Map of binding => fields
     *
     * @example
     * ScopePolicies::registerMany([
     *     'POST|/api/transfer|' => ['amount', 'recipient'],
     *     'POST|/api/payment|' => ['amount', 'card_last4'],
     * ]);
     */
    public static function registerMany(array $policies): void
    {
        foreach ($policies as $binding => $fields) {
            self::$policies[$binding] = $fields;
        }
    }

    /**
     * Get the scope policy for a binding.
     *
     * Returns empty array if no policy is defined (full payload protection).
     *
     * @param string $binding The normalized binding string
     * @return string[] The fields that must be protected
     */
    public static function get(string $binding): array
    {
        // Exact match first
        if (isset(self::$policies[$binding])) {
            return self::$policies[$binding];
        }

        // Wildcard pattern match
        foreach (self::$policies as $pattern => $fields) {
            if (self::matchesPattern($binding, $pattern)) {
                return $fields;
            }
        }

        // Default: no scoping (full payload protection)
        return [];
    }

    /**
     * Check if a binding has a scope policy defined.
     *
     * @param string $binding The normalized binding string
     * @return bool True if a policy exists
     */
    public static function has(string $binding): bool
    {
        if (isset(self::$policies[$binding])) {
            return true;
        }

        foreach (self::$policies as $pattern => $fields) {
            if (self::matchesPattern($binding, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get all registered policies.
     *
     * @return array<string, string[]>
     */
    public static function all(): array
    {
        return self::$policies;
    }

    /**
     * Clear all registered policies.
     *
     * Useful for testing.
     */
    public static function clear(): void
    {
        self::$policies = [];
    }

    /**
     * Check if a binding matches a pattern with wildcards.
     *
     * Supports:
     * - * for single path segment wildcard
     * - ** for multi-segment wildcard
     *
     * @param string $binding The actual binding
     * @param string $pattern The pattern to match against
     * @return bool True if matches
     */
    private static function matchesPattern(string $binding, string $pattern): bool
    {
        // If no wildcards, must be exact match
        if (!str_contains($pattern, '*')) {
            return $binding === $pattern;
        }

        // Convert pattern to regex
        $regex = preg_quote($pattern, '/');

        // Replace ** first (multi-segment)
        $regex = str_replace('\\*\\*', '.*', $regex);

        // Replace * (single segment - not containing | or /)
        $regex = str_replace('\\*', '[^|/]*', $regex);

        return preg_match('/^' . $regex . '$/', $binding) === 1;
    }
}
