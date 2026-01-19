<?php

declare(strict_types=1);

namespace Ash\Proof;

use Ash\AshMode;

/**
 * Proof builder for ASH.
 */
final class ProofBuilder
{
    private const VERSION = 'ASHv1';

    /**
     * Build a cryptographic proof.
     *
     * The proof is computed as:
     * proof = BASE64URL(SHA256(
     *   "ASHv1\n" +
     *   mode + "\n" +
     *   binding + "\n" +
     *   contextId + "\n" +
     *   (nonce + "\n" if present) +
     *   canonicalPayload
     * ))
     *
     * @param AshMode $mode Security mode
     * @param string $binding Endpoint binding
     * @param string $contextId Context ID
     * @param string|null $nonce Optional nonce
     * @param string $canonicalPayload Canonicalized payload
     * @return string Base64URL-encoded proof
     */
    public static function build(
        AshMode $mode,
        string $binding,
        string $contextId,
        ?string $nonce,
        string $canonicalPayload
    ): string {
        // Build the proof input string
        $input = self::VERSION . "\n";
        $input .= $mode->value . "\n";
        $input .= $binding . "\n";
        $input .= $contextId . "\n";

        if ($nonce !== null) {
            $input .= $nonce . "\n";
        }

        $input .= $canonicalPayload;

        // Compute SHA-256 hash
        $hash = hash('sha256', $input, true);

        // Encode as Base64URL without padding
        return self::base64UrlEncode($hash);
    }

    /**
     * Encode data as Base64URL (no padding).
     *
     * @param string $data Raw binary data
     * @return string Base64URL-encoded string
     */
    private static function base64UrlEncode(string $data): string
    {
        $base64 = base64_encode($data);
        $base64Url = strtr($base64, '+/', '-_');
        return rtrim($base64Url, '=');
    }
}
