<?php

declare(strict_types=1);

namespace Ash\Core;

/**
 * ASH Protocol Proof Generation.
 *
 * Deterministic hash-based integrity proof.
 * Same inputs MUST produce identical proof across all implementations.
 */
final class Proof
{
    /**
     * ASH protocol version prefix.
     */
    private const VERSION_PREFIX = 'ASHv1';

    /**
     * Build a deterministic proof from the given inputs.
     *
     * Proof structure (from ASH-Spec-v1.0):
     *     proof = SHA256(
     *       "ASHv1" + "\n" +
     *       mode + "\n" +
     *       binding + "\n" +
     *       contextId + "\n" +
     *       (nonce? + "\n" : "") +
     *       canonicalPayload
     *     )
     *
     * Output: Base64URL encoded (no padding)
     *
     * @param BuildProofInput $input Proof input parameters
     * @return string Base64URL encoded proof string
     */
    public static function build(BuildProofInput $input): string
    {
        // Build the proof input string
        $proofInput = self::VERSION_PREFIX . "\n"
            . $input->mode->value . "\n"
            . $input->binding . "\n"
            . $input->contextId . "\n";

        // Add nonce if present (server-assisted mode)
        if ($input->nonce !== null && $input->nonce !== '') {
            $proofInput .= $input->nonce . "\n";
        }

        // Add canonical payload
        $proofInput .= $input->canonicalPayload;

        // Compute SHA-256 hash
        $hashBytes = hash('sha256', $proofInput, true);

        // Encode as Base64URL (no padding)
        return self::base64UrlEncode($hashBytes);
    }

    /**
     * Encode bytes as Base64URL (no padding).
     *
     * RFC 4648 Section 5: Base 64 Encoding with URL and Filename Safe Alphabet
     */
    public static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Decode a Base64URL string to bytes.
     *
     * Handles both padded and unpadded input.
     */
    public static function base64UrlDecode(string $input): string
    {
        // Add padding if needed
        $padLength = (4 - strlen($input) % 4) % 4;
        $input .= str_repeat('=', $padLength);
        $decoded = base64_decode(strtr($input, '-_', '+/'), true);
        if ($decoded === false) {
            return '';
        }
        return $decoded;
    }
}
