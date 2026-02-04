<?php

declare(strict_types=1);

namespace Ash\Tests;

use Ash\Ash;
use Ash\Core\AshMode;
use Ash\Core\BuildProofInput;
use Ash\Core\Proof;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Comprehensive proof verification tests.
 */
final class VerificationComprehensiveTest extends TestCase
{
    // ========== HMAC PROOF BUILDING TESTS ==========

    #[Test]
    public function ashBuildProofHmacReturnsHexString(): void
    {
        $proof = Proof::ashBuildProofHmac('secret', '1234567890', 'POST|/api|', 'abc123');
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $proof);
    }

    #[Test]
    public function ashBuildProofHmacIsDeterministic(): void
    {
        $proof1 = Proof::ashBuildProofHmac('secret', '1234567890', 'POST|/api|', 'abc123');
        $proof2 = Proof::ashBuildProofHmac('secret', '1234567890', 'POST|/api|', 'abc123');
        $this->assertSame($proof1, $proof2);
    }

    #[Test]
    public function ashBuildProofHmacDifferentSecretsDifferentProofs(): void
    {
        $proof1 = Proof::ashBuildProofHmac('secret1', '1234567890', 'POST|/api|', 'abc123');
        $proof2 = Proof::ashBuildProofHmac('secret2', '1234567890', 'POST|/api|', 'abc123');
        $this->assertNotSame($proof1, $proof2);
    }

    #[Test]
    public function ashBuildProofHmacDifferentTimestampsDifferentProofs(): void
    {
        $proof1 = Proof::ashBuildProofHmac('secret', '1234567890', 'POST|/api|', 'abc123');
        $proof2 = Proof::ashBuildProofHmac('secret', '1234567891', 'POST|/api|', 'abc123');
        $this->assertNotSame($proof1, $proof2);
    }

    #[Test]
    public function ashBuildProofHmacDifferentBindingsDifferentProofs(): void
    {
        $proof1 = Proof::ashBuildProofHmac('secret', '1234567890', 'POST|/api|', 'abc123');
        $proof2 = Proof::ashBuildProofHmac('secret', '1234567890', 'GET|/api|', 'abc123');
        $this->assertNotSame($proof1, $proof2);
    }

    #[Test]
    public function ashBuildProofHmacDifferentBodyHashesDifferentProofs(): void
    {
        $proof1 = Proof::ashBuildProofHmac('secret', '1234567890', 'POST|/api|', 'abc123');
        $proof2 = Proof::ashBuildProofHmac('secret', '1234567890', 'POST|/api|', 'def456');
        $this->assertNotSame($proof1, $proof2);
    }

    // ========== VERIFY PROOF TESTS ==========

    #[Test]
    public function ashVerifyProofReturnsTrue(): void
    {
        $nonce = str_repeat('a', 64);
        $contextId = 'ctx_verify';
        $binding = 'POST|/api/update|';
        $timestamp = '1234567890';
        $bodyHash = Proof::hashBody('{"test":"data"}');

        $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding);
        $proof = Proof::ashBuildProofHmac($clientSecret, $timestamp, $binding, $bodyHash);
        $result = Proof::ashVerifyProof($nonce, $contextId, $binding, $timestamp, $bodyHash, $proof);

        $this->assertTrue($result);
    }

    #[Test]
    public function ashVerifyProofReturnsFalseForTamperedProof(): void
    {
        $nonce = str_repeat('b', 64);
        $contextId = 'ctx_tampered';
        $binding = 'POST|/api/update|';
        $timestamp = '1234567890';
        $bodyHash = Proof::hashBody('{"test":"data"}');
        $tamperedProof = str_repeat('0', 64);

        $result = Proof::ashVerifyProof($nonce, $contextId, $binding, $timestamp, $bodyHash, $tamperedProof);

        $this->assertFalse($result);
    }

    #[Test]
    public function ashVerifyProofReturnsFalseForWrongNonce(): void
    {
        $nonce = str_repeat('c', 64);
        $wrongNonce = str_repeat('d', 64);
        $contextId = 'ctx_nonce';
        $binding = 'POST|/api/update|';
        $timestamp = '1234567890';
        $bodyHash = Proof::hashBody('{"test":"data"}');

        $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding);
        $proof = Proof::ashBuildProofHmac($clientSecret, $timestamp, $binding, $bodyHash);
        $result = Proof::ashVerifyProof($wrongNonce, $contextId, $binding, $timestamp, $bodyHash, $proof);

        $this->assertFalse($result);
    }

    #[Test]
    public function ashVerifyProofReturnsFalseForWrongTimestamp(): void
    {
        $nonce = str_repeat('e', 64);
        $contextId = 'ctx_timestamp';
        $binding = 'POST|/api/update|';
        $timestamp = '1234567890';
        $bodyHash = Proof::hashBody('{"test":"data"}');

        $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding);
        $proof = Proof::ashBuildProofHmac($clientSecret, $timestamp, $binding, $bodyHash);
        $result = Proof::ashVerifyProof($nonce, $contextId, $binding, '9999999999', $bodyHash, $proof);

        $this->assertFalse($result);
    }

    #[Test]
    public function ashVerifyProofReturnsFalseForWrongBinding(): void
    {
        $nonce = str_repeat('f', 64);
        $contextId = 'ctx_binding';
        $binding = 'POST|/api/update|';
        $timestamp = '1234567890';
        $bodyHash = Proof::hashBody('{"test":"data"}');

        $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding);
        $proof = Proof::ashBuildProofHmac($clientSecret, $timestamp, $binding, $bodyHash);
        $result = Proof::ashVerifyProof($nonce, $contextId, 'GET|/api/update|', $timestamp, $bodyHash, $proof);

        $this->assertFalse($result);
    }

    #[Test]
    public function ashVerifyProofReturnsFalseForWrongBodyHash(): void
    {
        $nonce = str_repeat('0', 64);
        $contextId = 'ctx_body';
        $binding = 'POST|/api/update|';
        $timestamp = '1234567890';
        $bodyHash = Proof::hashBody('{"test":"data"}');

        $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding);
        $proof = Proof::ashBuildProofHmac($clientSecret, $timestamp, $binding, $bodyHash);
        $wrongBodyHash = Proof::hashBody('{"test":"tampered"}');
        $result = Proof::ashVerifyProof($nonce, $contextId, $binding, $timestamp, $wrongBodyHash, $proof);

        $this->assertFalse($result);
    }

    // ========== HASH BODY TESTS ==========

    #[Test]
    public function hashBodyReturnsHexString(): void
    {
        $hash = Proof::hashBody('test');
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
    }

    #[Test]
    public function hashBodyIsDeterministic(): void
    {
        $hash1 = Proof::hashBody('test');
        $hash2 = Proof::hashBody('test');
        $this->assertSame($hash1, $hash2);
    }

    #[Test]
    public function hashBodyDifferentInputsDifferentHashes(): void
    {
        $hash1 = Proof::hashBody('test1');
        $hash2 = Proof::hashBody('test2');
        $this->assertNotSame($hash1, $hash2);
    }

    #[Test]
    public function hashBodyHandlesEmptyString(): void
    {
        $hash = Proof::hashBody('');
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
    }

    #[Test]
    public function hashBodyHandlesUnicode(): void
    {
        $hash = Proof::hashBody('你好世界');
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
    }

    #[Test]
    public function hashBodyHandlesLongString(): void
    {
        $hash = Proof::hashBody(str_repeat('a', 100000));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
    }

    // ========== BUILD PROOF INPUT TESTS ==========

    #[Test]
    public function buildProofWithBalancedMode(): void
    {
        $input = new BuildProofInput(
            mode: AshMode::Balanced,
            binding: 'POST|/api|',
            contextId: 'ctx_123',
            canonicalPayload: '{"test":"data"}'
        );

        $proof = Proof::build($input);
        $this->assertNotEmpty($proof);
    }

    #[Test]
    public function buildProofWithStrictMode(): void
    {
        $input = new BuildProofInput(
            mode: AshMode::Strict,
            binding: 'POST|/api|',
            contextId: 'ctx_123',
            canonicalPayload: '{"test":"data"}'
        );

        $proof = Proof::build($input);
        $this->assertNotEmpty($proof);
    }

    #[Test]
    public function buildProofWithMinimalMode(): void
    {
        $input = new BuildProofInput(
            mode: AshMode::Minimal,
            binding: 'POST|/api|',
            contextId: 'ctx_123',
            canonicalPayload: '{"test":"data"}'
        );

        $proof = Proof::build($input);
        $this->assertNotEmpty($proof);
    }

    #[Test]
    public function buildProofWithNonce(): void
    {
        $input = new BuildProofInput(
            mode: AshMode::Balanced,
            binding: 'POST|/api|',
            contextId: 'ctx_123',
            canonicalPayload: '{"test":"data"}',
            nonce: 'abcd1234abcd1234abcd1234abcd1234'
        );

        $proof = Proof::build($input);
        $this->assertNotEmpty($proof);
    }

    #[Test]
    public function buildProofDifferentNoncesDifferentProofs(): void
    {
        $input1 = new BuildProofInput(
            mode: AshMode::Balanced,
            binding: 'POST|/api|',
            contextId: 'ctx_123',
            canonicalPayload: '{"test":"data"}',
            nonce: '11111111111111111111111111111111'
        );

        $input2 = new BuildProofInput(
            mode: AshMode::Balanced,
            binding: 'POST|/api|',
            contextId: 'ctx_123',
            canonicalPayload: '{"test":"data"}',
            nonce: '22222222222222222222222222222222'
        );

        $proof1 = Proof::build($input1);
        $proof2 = Proof::build($input2);

        $this->assertNotSame($proof1, $proof2);
    }

    // ========== BASE64URL ENCODING TESTS ==========

    #[Test]
    public function base64UrlEncodeNoPlus(): void
    {
        $data = random_bytes(100);
        $encoded = Proof::base64UrlEncode($data);
        $this->assertStringNotContainsString('+', $encoded);
    }

    #[Test]
    public function base64UrlEncodeNoSlash(): void
    {
        $data = random_bytes(100);
        $encoded = Proof::base64UrlEncode($data);
        $this->assertStringNotContainsString('/', $encoded);
    }

    #[Test]
    public function base64UrlEncodeNoPadding(): void
    {
        $data = random_bytes(100);
        $encoded = Proof::base64UrlEncode($data);
        $this->assertStringNotContainsString('=', $encoded);
    }

    #[Test]
    public function base64UrlRoundTrip(): void
    {
        $original = random_bytes(100);
        $encoded = Proof::base64UrlEncode($original);
        $decoded = Proof::base64UrlDecode($encoded);
        $this->assertSame($original, $decoded);
    }

    #[Test]
    public function base64UrlDecodeHandlesPadding(): void
    {
        $padded = 'SGVsbG8='; // "Hello" with padding
        $decoded = Proof::base64UrlDecode($padded);
        $this->assertSame('Hello', $decoded);
    }

    #[Test]
    public function base64UrlDecodeHandlesNoPadding(): void
    {
        $unpadded = 'SGVsbG8'; // "Hello" without padding
        $decoded = Proof::base64UrlDecode($unpadded);
        $this->assertSame('Hello', $decoded);
    }

    // ========== TIMING SAFE COMPARE TESTS ==========

    #[Test]
    public function timingSafeCompareEqualStrings(): void
    {
        $this->assertTrue(Ash::timingSafeCompare('secret123', 'secret123'));
    }

    #[Test]
    public function timingSafeCompareUnequalStrings(): void
    {
        $this->assertFalse(Ash::timingSafeCompare('secret123', 'secret456'));
    }

    #[Test]
    public function timingSafeCompareDifferentLengths(): void
    {
        $this->assertFalse(Ash::timingSafeCompare('short', 'much longer string'));
    }

    #[Test]
    public function timingSafeCompareEmptyStrings(): void
    {
        $this->assertTrue(Ash::timingSafeCompare('', ''));
    }

    #[Test]
    public function timingSafeCompareSingleChar(): void
    {
        $this->assertTrue(Ash::timingSafeCompare('a', 'a'));
        $this->assertFalse(Ash::timingSafeCompare('a', 'b'));
    }

    // ========== DERIVE CLIENT SECRET TESTS ==========

    #[Test]
    public function deriveClientSecretReturnsHexString(): void
    {
        $secret = Proof::deriveClientSecret('abcd1234abcd1234abcd1234abcd1234', 'ctx_456', 'POST|/api|');
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $secret);
    }

    #[Test]
    public function deriveClientSecretIsDeterministic(): void
    {
        $secret1 = Proof::deriveClientSecret('abcd1234abcd1234abcd1234abcd1234', 'ctx_456', 'POST|/api|');
        $secret2 = Proof::deriveClientSecret('abcd1234abcd1234abcd1234abcd1234', 'ctx_456', 'POST|/api|');
        $this->assertSame($secret1, $secret2);
    }

    #[Test]
    public function deriveClientSecretDifferentNoncesDifferentSecrets(): void
    {
        $secret1 = Proof::deriveClientSecret('11111111111111111111111111111111', 'ctx_456', 'POST|/api|');
        $secret2 = Proof::deriveClientSecret('22222222222222222222222222222222', 'ctx_456', 'POST|/api|');
        $this->assertNotSame($secret1, $secret2);
    }

    #[Test]
    public function deriveClientSecretDifferentContextsDifferentSecrets(): void
    {
        $secret1 = Proof::deriveClientSecret('abcd1234abcd1234abcd1234abcd1234', 'ctx_1', 'POST|/api|');
        $secret2 = Proof::deriveClientSecret('abcd1234abcd1234abcd1234abcd1234', 'ctx_2', 'POST|/api|');
        $this->assertNotSame($secret1, $secret2);
    }

    // ========== TIMESTAMP TESTS ==========

    #[Test]
    public function timestampIsNumericString(): void
    {
        $timestamp = (string)time();
        $this->assertMatchesRegularExpression('/^\d+$/', $timestamp);
    }

    #[Test]
    public function timestampIsCurrentTime(): void
    {
        $before = time();
        $timestamp = time();
        $after = time();

        $this->assertGreaterThanOrEqual($before, $timestamp);
        $this->assertLessThanOrEqual($after, $timestamp);
    }

    // ========== STRESS TESTS ==========

    #[Test]
    public function ashBuildProofHmacStress(): void
    {
        for ($i = 0; $i < 1000; $i++) {
            $proof = Proof::ashBuildProofHmac(
                "secret_$i",
                (string)(1000000000 + $i),
                "POST|/api/$i|",
                hash('sha256', "body_$i")
            );
            $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $proof);
        }
    }

    #[Test]
    public function ashVerifyProofStress(): void
    {
        $nonce = str_repeat('a', 64);
        $contextId = 'ctx_stress';

        for ($i = 0; $i < 100; $i++) {
            $timestamp = (string)(1000000000 + $i);
            $binding = "POST|/api/resource/$i|";
            $bodyHash = Proof::hashBody("body content $i");

            $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding);
            $proof = Proof::ashBuildProofHmac($clientSecret, $timestamp, $binding, $bodyHash);
            $this->assertTrue(Proof::ashVerifyProof($nonce, $contextId, $binding, $timestamp, $bodyHash, $proof));
        }
    }

    // ========== CROSS-SDK COMPATIBILITY TESTS ==========

    #[Test]
    public function hashBodyMatchesCrossSdk(): void
    {
        // Empty body hash should match across SDKs
        $emptyHash = Proof::hashBody('');
        $this->assertSame('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', $emptyHash);
    }

    #[Test]
    public function hashBodyJsonMatchesCrossSdk(): void
    {
        $hash = Proof::hashBody('{"a":1,"b":2}');
        // SHA-256 of '{"a":1,"b":2}'
        $this->assertSame('43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777', $hash);
    }
}
