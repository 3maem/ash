<?php

declare(strict_types=1);

namespace Ash;

use Ash\Core\AshMode;
use Ash\Core\BuildProofInput;
use Ash\Core\Canonicalize;
use Ash\Core\Compare;
use Ash\Core\Proof;

/**
 * ASH - Authenticity & Stateless Hardening Protocol.
 *
 * A cryptographic protocol for tamper-proof, replay-resistant API requests.
 *
 * Example:
 *     use Ash\Ash;
 *     use Ash\Core\AshMode;
 *     use Ash\Core\BuildProofInput;
 *
 *     // Canonicalize JSON payload
 *     $canonical = Ash::canonicalizeJson(['key' => 'value']);
 *
 *     // Build proof
 *     $input = new BuildProofInput(
 *         mode: AshMode::Balanced,
 *         binding: 'POST /api/update',
 *         contextId: 'ctx_abc123',
 *         canonicalPayload: $canonical
 *     );
 *     $proof = Ash::buildProof($input);
 */
final class Ash
{
    public const VERSION = '1.0.0';

    /**
     * Canonicalize a JSON value to a deterministic string.
     *
     * @param mixed $value The value to canonicalize
     * @return string Canonical JSON string
     * @throws Core\Exceptions\CanonicalizationException If value contains unsupported types
     */
    public static function canonicalizeJson(mixed $value): string
    {
        return Canonicalize::json($value);
    }

    /**
     * Canonicalize URL-encoded form data.
     *
     * @param string|array<string, string|array<string>> $inputData URL-encoded string or dict
     * @return string Canonical URL-encoded string
     * @throws Core\Exceptions\CanonicalizationException If input cannot be parsed
     */
    public static function canonicalizeUrlEncoded(string|array $inputData): string
    {
        return Canonicalize::urlEncoded($inputData);
    }

    /**
     * Normalize a binding string.
     *
     * @param string $method HTTP method
     * @param string $path Request path
     * @return string Normalized binding string
     */
    public static function normalizeBinding(string $method, string $path): string
    {
        return Canonicalize::normalizeBinding($method, $path);
    }

    /**
     * Build a deterministic proof from the given inputs.
     *
     * @param BuildProofInput $input Proof input parameters
     * @return string Base64URL encoded proof string
     */
    public static function buildProof(BuildProofInput $input): string
    {
        return Proof::build($input);
    }

    /**
     * Perform a timing-safe string comparison.
     *
     * @param string $known The known string
     * @param string $userInput The user-provided string to compare
     * @return bool True if strings are equal, false otherwise
     */
    public static function timingSafeCompare(string $known, string $userInput): bool
    {
        return Compare::timingSafe($known, $userInput);
    }

    /**
     * Encode bytes as Base64URL (no padding).
     *
     * @param string $data The data to encode
     * @return string Base64URL encoded string
     */
    public static function base64UrlEncode(string $data): string
    {
        return Proof::base64UrlEncode($data);
    }

    /**
     * Decode a Base64URL string to bytes.
     *
     * @param string $input The Base64URL string to decode
     * @return string Decoded bytes
     */
    public static function base64UrlDecode(string $input): string
    {
        return Proof::base64UrlDecode($input);
    }
}
