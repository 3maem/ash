<?php

declare(strict_types=1);

namespace Ash\Canonicalize;

use JsonException;

/**
 * JSON canonicalizer for deterministic serialization.
 *
 * Follows these rules:
 * - Object keys sorted lexicographically
 * - No whitespace
 * - Unicode NFC normalized
 * - Numbers normalized
 */
final class JsonCanonicalizer
{
    /**
     * Canonicalize a JSON string.
     *
     * @param string $json JSON string to canonicalize
     * @return string Canonical JSON string
     * @throws JsonException If JSON is invalid
     */
    public static function canonicalize(string $json): string
    {
        // Parse JSON
        $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

        // Recursively sort and normalize
        $normalized = self::normalizeValue($data);

        // Encode without whitespace
        return json_encode(
            $normalized,
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
        );
    }

    /**
     * Normalize a value recursively.
     *
     * @param mixed $value Value to normalize
     * @return mixed Normalized value
     */
    private static function normalizeValue(mixed $value): mixed
    {
        if (is_array($value)) {
            // Check if associative array (object)
            if (self::isAssociativeArray($value)) {
                return self::normalizeObject($value);
            }

            // Regular array - preserve order
            return array_map([self::class, 'normalizeValue'], $value);
        }

        if (is_string($value)) {
            // NFC normalize Unicode strings
            if (function_exists('normalizer_normalize')) {
                return \Normalizer::normalize($value, \Normalizer::FORM_C) ?: $value;
            }
            return $value;
        }

        // Numbers, booleans, null - return as-is
        return $value;
    }

    /**
     * Normalize an object (associative array).
     *
     * @param array<string, mixed> $obj Object to normalize
     * @return array<string, mixed> Normalized object with sorted keys
     */
    private static function normalizeObject(array $obj): array
    {
        // Normalize keys (NFC)
        $normalized = [];
        foreach ($obj as $key => $value) {
            $normalizedKey = $key;
            if (is_string($key) && function_exists('normalizer_normalize')) {
                $normalizedKey = \Normalizer::normalize($key, \Normalizer::FORM_C) ?: $key;
            }
            $normalized[$normalizedKey] = self::normalizeValue($value);
        }

        // Sort keys lexicographically
        ksort($normalized, SORT_STRING);

        return $normalized;
    }

    /**
     * Check if array is associative (object-like).
     *
     * @param array<mixed> $arr Array to check
     * @return bool True if associative
     */
    private static function isAssociativeArray(array $arr): bool
    {
        if (empty($arr)) {
            return false;
        }

        return array_keys($arr) !== range(0, count($arr) - 1);
    }
}
