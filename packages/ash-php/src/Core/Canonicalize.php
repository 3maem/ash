<?php

declare(strict_types=1);

namespace Ash\Core;

use Ash\Core\Exceptions\CanonicalizationException;
use Normalizer;

/**
 * ASH Protocol Canonicalization Engine.
 *
 * Deterministic canonicalization for JSON and URL-encoded payloads.
 * Same input MUST produce identical output across all implementations.
 */
final class Canonicalize
{
    /**
     * Canonicalize a JSON value to a deterministic string.
     *
     * Rules (from ASH-Spec-v1.0):
     * - JSON minified (no whitespace)
     * - Object keys sorted lexicographically (ascending)
     * - Arrays preserve order
     * - Unicode normalization: NFC
     * - Numbers: no scientific notation, remove trailing zeros, -0 becomes 0
     * - Unsupported values REJECT: NaN, Infinity, resource types
     *
     * @param mixed $value The value to canonicalize
     * @return string Canonical JSON string
     * @throws CanonicalizationException If value contains unsupported types
     */
    public static function json(mixed $value): string
    {
        $canonicalized = self::canonicalizeValue($value);
        return self::buildCanonicalJson($canonicalized);
    }

    /**
     * Canonicalize URL-encoded form data.
     *
     * Rules (from ASH-Spec-v1.0):
     * - Parse into key-value pairs
     * - Percent-decode consistently
     * - Sort keys lexicographically
     * - For duplicate keys: preserve value order per key
     * - Output format: k1=v1&k1=v2&k2=v3
     * - Unicode NFC applies after decoding
     *
     * @param string|array<string, string|array<string>> $inputData URL-encoded string or dict
     * @return string Canonical URL-encoded string
     * @throws CanonicalizationException If input cannot be parsed
     */
    public static function urlEncoded(string|array $inputData): string
    {
        if (is_string($inputData)) {
            $pairs = self::parseUrlEncoded($inputData);
        } else {
            $pairs = self::objectToPairs($inputData);
        }

        // Normalize all keys and values with NFC
        $normalizedPairs = [];
        foreach ($pairs as [$key, $value]) {
            $normalizedKey = Normalizer::normalize($key, Normalizer::FORM_C);
            $normalizedValue = Normalizer::normalize($value, Normalizer::FORM_C);
            if ($normalizedKey === false || $normalizedValue === false) {
                throw new CanonicalizationException('Failed to normalize Unicode');
            }
            $normalizedPairs[] = [$normalizedKey, $normalizedValue];
        }

        // Sort by key (stable sort preserves value order for same keys)
        usort($normalizedPairs, fn($a, $b) => strcmp($a[0], $b[0]));

        // Encode and join
        $parts = [];
        foreach ($normalizedPairs as [$key, $value]) {
            $parts[] = rawurlencode($key) . '=' . rawurlencode($value);
        }

        return implode('&', $parts);
    }

    /**
     * Canonicalize a URL query string according to ASH specification.
     *
     * 9 MUST Rules:
     * 1. MUST parse query string after ? (or use full string if no ?)
     * 2. MUST split on & to get key=value pairs
     * 3. MUST handle keys without values (treat as empty string)
     * 4. MUST percent-decode all keys and values
     * 5. MUST apply Unicode NFC normalization
     * 6. MUST sort pairs by key lexicographically (byte order)
     * 7. MUST preserve order of duplicate keys
     * 8. MUST re-encode with uppercase hex (%XX)
     * 9. MUST join with & separator
     *
     * @param string $query Query string (with or without leading ?)
     * @return string Canonical query string
     */
    public static function canonicalizeQuery(string $query): string
    {
        // Rule 1: Remove leading ? if present
        if (str_starts_with($query, '?')) {
            $query = substr($query, 1);
        }

        if ($query === '') {
            return '';
        }

        // Rule 2 & 3: Parse pairs
        $pairs = self::parseUrlEncoded($query);

        // Rule 4 & 5: Normalize with NFC (already done in parseUrlEncoded via urldecode)
        $normalizedPairs = [];
        foreach ($pairs as [$key, $value]) {
            $normalizedKey = Normalizer::normalize($key, Normalizer::FORM_C);
            $normalizedValue = Normalizer::normalize($value, Normalizer::FORM_C);
            if ($normalizedKey === false || $normalizedValue === false) {
                throw new CanonicalizationException('Failed to normalize Unicode');
            }
            $normalizedPairs[] = [$normalizedKey, $normalizedValue];
        }

        // Rule 6 & 7: Sort by key (stable sort preserves value order for same keys)
        usort($normalizedPairs, fn($a, $b) => strcmp($a[0], $b[0]));

        // Rule 8 & 9: Re-encode and join
        $parts = [];
        foreach ($normalizedPairs as [$key, $value]) {
            $parts[] = rawurlencode($key) . '=' . rawurlencode($value);
        }

        return implode('&', $parts);
    }

    /**
     * Normalize a binding string to canonical form (v2.3.2+ format).
     *
     * Format: METHOD|PATH|CANONICAL_QUERY
     *
     * Rules:
     * - Method uppercased
     * - Path must start with /
     * - Duplicate slashes collapsed
     * - Trailing slash removed (except for root)
     * - Query string canonicalized
     * - Parts joined with | (pipe)
     *
     * @param string $method HTTP method
     * @param string $path Request path
     * @param string $query Query string (empty string if none)
     * @return string Canonical binding string (METHOD|PATH|QUERY)
     */
    public static function normalizeBinding(string $method, string $path, string $query = ''): string
    {
        $normalizedMethod = strtoupper($method);

        // Remove fragment (#...) first
        $fragmentIndex = strpos($path, '#');
        $normalizedPath = $fragmentIndex !== false ? substr($path, 0, $fragmentIndex) : $path;

        // Extract path without query string (in case path contains ?)
        $queryIndex = strpos($normalizedPath, '?');
        $normalizedPath = $queryIndex !== false ? substr($normalizedPath, 0, $queryIndex) : $normalizedPath;

        // Ensure path starts with /
        if (!str_starts_with($normalizedPath, '/')) {
            $normalizedPath = '/' . $normalizedPath;
        }

        // Collapse duplicate slashes
        $normalizedPath = (string) preg_replace('#/+#', '/', $normalizedPath);

        // Remove trailing slash (except for root)
        if (strlen($normalizedPath) > 1 && str_ends_with($normalizedPath, '/')) {
            $normalizedPath = substr($normalizedPath, 0, -1);
        }

        // Canonicalize query string
        $canonicalQuery = $query !== '' ? self::canonicalizeQuery($query) : '';

        // v2.3.2 format: METHOD|PATH|CANONICAL_QUERY
        return "{$normalizedMethod}|{$normalizedPath}|{$canonicalQuery}";
    }

    /**
     * Normalize a binding from a full URL path (including query string).
     *
     * @param string $method HTTP method
     * @param string $fullPath Full URL path including query string (e.g., "/api/users?page=1")
     * @return string Canonical binding string (METHOD|PATH|QUERY)
     */
    public static function normalizeBindingFromUrl(string $method, string $fullPath): string
    {
        $queryIndex = strpos($fullPath, '?');
        if ($queryIndex !== false) {
            $path = substr($fullPath, 0, $queryIndex);
            $query = substr($fullPath, $queryIndex + 1);
        } else {
            $path = $fullPath;
            $query = '';
        }

        return self::normalizeBinding($method, $path, $query);
    }

    /**
     * Build canonical JSON string manually to ensure key ordering.
     */
    private static function buildCanonicalJson(mixed $value): string
    {
        if ($value === null) {
            return 'null';
        }

        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        if (is_string($value)) {
            return self::jsonEscapeString($value);
        }

        if (is_int($value) || is_float($value)) {
            // Handle -0
            if ($value == 0) {
                return '0';
            }
            // Convert to int if whole number
            if (is_float($value) && $value == (int) $value) {
                return (string) (int) $value;
            }
            return (string) $value;
        }

        if (is_array($value)) {
            // Check if it's an associative array (object) or sequential array
            if (self::isAssociativeArray($value)) {
                $sortedKeys = array_keys($value);
                sort($sortedKeys, SORT_STRING);
                $pairs = [];
                foreach ($sortedKeys as $key) {
                    $pairs[] = self::jsonEscapeString((string) $key) . ':' . self::buildCanonicalJson($value[$key]);
                }
                return '{' . implode(',', $pairs) . '}';
            } else {
                $items = [];
                foreach ($value as $item) {
                    $items[] = self::buildCanonicalJson($item);
                }
                return '[' . implode(',', $items) . ']';
            }
        }

        throw new CanonicalizationException('Cannot serialize type: ' . gettype($value));
    }

    /**
     * Escape a string for JSON output.
     */
    private static function jsonEscapeString(string $s): string
    {
        $result = '"';
        $length = mb_strlen($s, 'UTF-8');
        for ($i = 0; $i < $length; $i++) {
            $char = mb_substr($s, $i, 1, 'UTF-8');
            switch ($char) {
                case '"':
                    $result .= '\\"';
                    break;
                case '\\':
                    $result .= '\\\\';
                    break;
                case "\n":
                    $result .= '\\n';
                    break;
                case "\r":
                    $result .= '\\r';
                    break;
                case "\t":
                    $result .= '\\t';
                    break;
                default:
                    $ord = mb_ord($char, 'UTF-8');
                    if ($ord !== false && $ord < 0x20) {
                        $result .= sprintf('\\u%04x', $ord);
                    } else {
                        $result .= $char;
                    }
            }
        }
        $result .= '"';
        return $result;
    }

    /**
     * Recursively canonicalize a value.
     */
    private static function canonicalizeValue(mixed $value): mixed
    {
        if ($value === null) {
            return null;
        }

        if (is_bool($value)) {
            return $value;
        }

        if (is_string($value)) {
            // Apply NFC normalization to strings
            $normalized = Normalizer::normalize($value, Normalizer::FORM_C);
            if ($normalized === false) {
                throw new CanonicalizationException('Failed to normalize Unicode string');
            }
            return $normalized;
        }

        if (is_int($value)) {
            return $value;
        }

        if (is_float($value)) {
            return self::canonicalizeNumber($value);
        }

        if (is_array($value)) {
            if (self::isAssociativeArray($value)) {
                $sortedKeys = array_keys($value);
                sort($sortedKeys, SORT_STRING);
                $result = [];
                foreach ($sortedKeys as $key) {
                    $val = $value[$key];
                    if ($val !== null) {
                        $normalizedKey = Normalizer::normalize((string) $key, Normalizer::FORM_C);
                        if ($normalizedKey === false) {
                            throw new CanonicalizationException('Failed to normalize Unicode key');
                        }
                        $result[$normalizedKey] = self::canonicalizeValue($val);
                    }
                }
                return $result;
            } else {
                return array_map([self::class, 'canonicalizeValue'], $value);
            }
        }

        throw new CanonicalizationException('Unsupported type: ' . gettype($value));
    }

    /**
     * Canonicalize a number according to ASH spec.
     *
     * Rules:
     * - No scientific notation
     * - Remove trailing zeros
     * - -0 becomes 0
     * - Reject NaN and Infinity
     */
    private static function canonicalizeNumber(float $num): int|float
    {
        if (is_nan($num)) {
            throw new CanonicalizationException('NaN values are not allowed');
        }

        if (is_infinite($num)) {
            throw new CanonicalizationException('Infinity values are not allowed');
        }

        // Convert -0 to 0
        if ($num == 0) {
            return 0;
        }

        // Convert to int if whole number
        if ($num == (int) $num) {
            return (int) $num;
        }

        return $num;
    }

    /**
     * Parse URL-encoded string into key-value pairs.
     *
     * Handles + as space (per application/x-www-form-urlencoded spec).
     * Skips empty parts from && or leading/trailing &.
     *
     * @return array<array{0: string, 1: string}>
     */
    private static function parseUrlEncoded(string $inputStr): array
    {
        if ($inputStr === '') {
            return [];
        }

        $pairs = [];
        $parts = explode('&', $inputStr);

        foreach ($parts as $part) {
            if ($part === '') {
                continue;
            }

            $eqIndex = strpos($part, '=');
            if ($eqIndex === false) {
                $key = urldecode(str_replace('+', ' ', $part));
                if ($key !== '') {
                    $pairs[] = [$key, ''];
                }
            } else {
                $key = urldecode(str_replace('+', ' ', substr($part, 0, $eqIndex)));
                $value = urldecode(str_replace('+', ' ', substr($part, $eqIndex + 1)));
                if ($key !== '') {
                    $pairs[] = [$key, $value];
                }
            }
        }

        return $pairs;
    }

    /**
     * Convert object to key-value pairs, preserving array order.
     *
     * @param array<string, string|array<string>> $obj
     * @return array<array{0: string, 1: string}>
     */
    private static function objectToPairs(array $obj): array
    {
        $pairs = [];

        foreach ($obj as $key => $value) {
            if (is_array($value)) {
                foreach ($value as $v) {
                    $pairs[] = [(string) $key, (string) $v];
                }
            } else {
                $pairs[] = [(string) $key, (string) $value];
            }
        }

        return $pairs;
    }

    /**
     * Check if an array is associative (object-like) or sequential.
     *
     * @param array<mixed> $arr
     */
    private static function isAssociativeArray(array $arr): bool
    {
        if ($arr === []) {
            return false;
        }
        return array_keys($arr) !== range(0, count($arr) - 1);
    }
}
