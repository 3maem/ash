<?php

declare(strict_types=1);

namespace Ash\Canonicalize;

/**
 * URL-encoded data canonicalizer.
 *
 * Follows these rules:
 * - Parameters sorted by key
 * - Values percent-encoded consistently
 * - Unicode NFC normalized
 */
final class UrlencodedCanonicalizer
{
    /**
     * Canonicalize URL-encoded data.
     *
     * @param string $data URL-encoded string
     * @return string Canonical URL-encoded string
     */
    public static function canonicalize(string $data): string
    {
        if ($data === '') {
            return '';
        }

        // Parse into key-value pairs
        $pairs = [];
        parse_str($data, $parsed);

        // Flatten and collect all pairs (handling arrays)
        self::flattenParams($parsed, '', $pairs);

        // Sort by key
        usort($pairs, function (array $a, array $b): int {
            return strcmp($a[0], $b[0]);
        });

        // Encode consistently with uppercase hex (ASH spec requirement)
        $encoded = [];
        foreach ($pairs as [$key, $value]) {
            // NFC normalize if available
            if (function_exists('normalizer_normalize')) {
                $key = \Normalizer::normalize($key, \Normalizer::FORM_C) ?: $key;
                $value = \Normalizer::normalize($value, \Normalizer::FORM_C) ?: $value;
            }

            // Percent-encode with rawurlencode (RFC 3986) and convert to uppercase hex
            $encoded[] = self::uppercasePercentEncode($key) . '=' . self::uppercasePercentEncode($value);
        }

        return implode('&', $encoded);
    }

    /**
     * Percent-encode a string with uppercase hex digits (RFC 3986 + ASH spec).
     *
     * @param string $value String to encode
     * @return string Percent-encoded string with uppercase hex
     */
    private static function uppercasePercentEncode(string $value): string
    {
        $encoded = rawurlencode($value);

        // Convert lowercase hex in percent-encoding to uppercase
        return preg_replace_callback(
            '/%[0-9a-f]{2}/i',
            fn(array $matches): string => strtoupper($matches[0]),
            $encoded
        ) ?? $encoded;
    }

    /**
     * Flatten nested parameters into key-value pairs.
     *
     * @param array<mixed>|string $params Parameters
     * @param string $prefix Key prefix
     * @param array<array{0: string, 1: string}> $result Result accumulator
     */
    private static function flattenParams(
        array|string $params,
        string $prefix,
        array &$result
    ): void {
        if (is_string($params)) {
            $result[] = [$prefix, $params];
            return;
        }

        foreach ($params as $key => $value) {
            $fullKey = $prefix === '' ? (string)$key : "{$prefix}[{$key}]";

            if (is_array($value)) {
                self::flattenParams($value, $fullKey, $result);
            } else {
                $result[] = [$fullKey, (string)$value];
            }
        }
    }
}
