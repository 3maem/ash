<?php

declare(strict_types=1);

namespace Ash\Tests;

use Ash\Ash;
use Ash\Core\Compare;
use Ash\Core\Proof;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Comprehensive cryptographic property tests.
 */
final class CryptoPropertiesTest extends TestCase
{
    // ========== HMAC SECURITY PROPERTIES ==========

    #[Test]
    public function hmacProducesFixedLengthOutput(): void
    {
        $lengths = [1, 10, 100, 1000, 10000];

        foreach ($lengths as $len) {
            $proof = Proof::ashBuildProofHmac(
                str_repeat('s', $len),
                '1234567890',
                'POST|/api|',
                str_repeat('a', 64)
            );
            $this->assertSame(64, strlen($proof)); // SHA-256 hex = 64 chars
        }
    }

    #[Test]
    public function hmacIsNotReversible(): void
    {
        $proof = Proof::ashBuildProofHmac('secret', '1234567890', 'POST|/api|', 'abc123');

        // The proof should not contain any of the inputs
        $this->assertStringNotContainsString('secret', $proof);
        $this->assertStringNotContainsString('1234567890', $proof);
        $this->assertStringNotContainsString('POST', $proof);
    }

    #[Test]
    public function smallInputChangeProducesDifferentOutput(): void
    {
        $proof1 = Proof::ashBuildProofHmac('secret', '1234567890', 'POST|/api|', 'abc123');
        $proof2 = Proof::ashBuildProofHmac('secret', '1234567891', 'POST|/api|', 'abc123'); // One char diff

        $this->assertNotSame($proof1, $proof2);

        // Count differing characters
        $diffCount = 0;
        for ($i = 0; $i < strlen($proof1); $i++) {
            if ($proof1[$i] !== $proof2[$i]) {
                $diffCount++;
            }
        }

        // Should have significant difference (avalanche effect)
        $this->assertGreaterThan(20, $diffCount);
    }

    #[Test]
    public function emptySecretStillProducesOutput(): void
    {
        $proof = Proof::ashBuildProofHmac('', '1234567890', 'POST|/api|', 'abc123');
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $proof);
    }

    #[Test]
    public function veryLongSecretWorks(): void
    {
        $longSecret = str_repeat('a', 100000);
        $proof = Proof::ashBuildProofHmac($longSecret, '1234567890', 'POST|/api|', 'abc123');
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $proof);
    }

    #[Test]
    public function unicodeSecretWorks(): void
    {
        $proof = Proof::ashBuildProofHmac('密码🔐', '1234567890', 'POST|/api|', 'abc123');
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $proof);
    }

    // ========== SHA-256 HASH PROPERTIES ==========

    #[Test]
    public function sha256ProducesCorrectLength(): void
    {
        $hash = Proof::hashBody('test');
        $this->assertSame(64, strlen($hash));
    }

    #[Test]
    public function sha256ProducesLowercaseHex(): void
    {
        $hash = Proof::hashBody('test');
        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $hash);
    }

    #[Test]
    public function sha256EmptyInputKnownValue(): void
    {
        $hash = Proof::hashBody('');
        // SHA-256 of empty string is well-known
        $this->assertSame('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', $hash);
    }

    #[Test]
    public function sha256KnownTestVector(): void
    {
        $hash = Proof::hashBody('hello');
        // SHA-256 of "hello"
        $this->assertSame('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', $hash);
    }

    #[Test]
    public function sha256CollisionResistance(): void
    {
        $hashes = [];

        for ($i = 0; $i < 1000; $i++) {
            $hashes[] = Proof::hashBody("input_$i");
        }

        $unique = array_unique($hashes);
        $this->assertCount(1000, $unique); // All should be unique
    }

    #[Test]
    public function sha256Determinism(): void
    {
        $input = 'determinism test';
        $hashes = [];

        for ($i = 0; $i < 100; $i++) {
            $hashes[] = Proof::hashBody($input);
        }

        $unique = array_unique($hashes);
        $this->assertCount(1, $unique); // All should be identical
    }

    // ========== TIMING SAFE COMPARISON PROPERTIES ==========

    #[Test]
    public function timingSafeCompareIdenticalStrings(): void
    {
        $str = 'secret_value_12345';
        $this->assertTrue(Compare::timingSafe($str, $str));
    }

    #[Test]
    public function timingSafeCompareEqualStrings(): void
    {
        $str1 = 'secret_value_12345';
        $str2 = 'secret_value_12345';
        $this->assertTrue(Compare::timingSafe($str1, $str2));
    }

    #[Test]
    public function timingSafeCompareUnequalStrings(): void
    {
        $str1 = 'secret_value_12345';
        $str2 = 'secret_value_12346';
        $this->assertFalse(Compare::timingSafe($str1, $str2));
    }

    #[Test]
    public function timingSafeCompareFirstCharDifferent(): void
    {
        $str1 = 'abcdefghij';
        $str2 = 'xbcdefghij';
        $this->assertFalse(Compare::timingSafe($str1, $str2));
    }

    #[Test]
    public function timingSafeCompareLastCharDifferent(): void
    {
        $str1 = 'abcdefghij';
        $str2 = 'abcdefghix';
        $this->assertFalse(Compare::timingSafe($str1, $str2));
    }

    #[Test]
    public function timingSafeCompareMiddleCharDifferent(): void
    {
        $str1 = 'abcdefghij';
        $str2 = 'abcdXfghij';
        $this->assertFalse(Compare::timingSafe($str1, $str2));
    }

    #[Test]
    public function timingSafeCompareDifferentLengths(): void
    {
        $this->assertFalse(Compare::timingSafe('short', 'longerstring'));
    }

    #[Test]
    public function timingSafeCompareEmptyStrings(): void
    {
        $this->assertTrue(Compare::timingSafe('', ''));
    }

    #[Test]
    public function timingSafeCompareOneEmpty(): void
    {
        $this->assertFalse(Compare::timingSafe('', 'notempty'));
        $this->assertFalse(Compare::timingSafe('notempty', ''));
    }

    #[Test]
    public function timingSafeCompareBinaryData(): void
    {
        $bin1 = "\x00\x01\x02\x03";
        $bin2 = "\x00\x01\x02\x03";
        $this->assertTrue(Compare::timingSafe($bin1, $bin2));
    }

    #[Test]
    public function timingSafeCompareBinaryDataDifferent(): void
    {
        $bin1 = "\x00\x01\x02\x03";
        $bin2 = "\x00\x01\x02\x04";
        $this->assertFalse(Compare::timingSafe($bin1, $bin2));
    }

    // ========== BASE64URL ENCODING PROPERTIES ==========

    #[Test]
    public function base64UrlEncodingIsUrlSafe(): void
    {
        // Test with data that would produce + and / in standard base64
        $data = "\xfb\xff\xfe";
        $encoded = Proof::base64UrlEncode($data);

        $this->assertStringNotContainsString('+', $encoded);
        $this->assertStringNotContainsString('/', $encoded);
    }

    #[Test]
    public function base64UrlEncodingHasNoPadding(): void
    {
        for ($len = 1; $len <= 10; $len++) {
            $data = str_repeat('a', $len);
            $encoded = Proof::base64UrlEncode($data);
            $this->assertStringNotContainsString('=', $encoded);
        }
    }

    #[Test]
    public function base64UrlRoundTripPreservesData(): void
    {
        $testData = [
            '',
            'a',
            'ab',
            'abc',
            'abcd',
            str_repeat('x', 100),
            "\x00\x01\x02\xff\xfe\xfd",
            '你好世界',
            '🔐🔑',
        ];

        foreach ($testData as $original) {
            $encoded = Proof::base64UrlEncode($original);
            $decoded = Proof::base64UrlDecode($encoded);
            $this->assertSame($original, $decoded);
        }
    }

    #[Test]
    public function base64UrlDecodingHandlesStandardBase64(): void
    {
        // Standard base64 with padding
        $standard = base64_encode('Hello World');
        $decoded = Proof::base64UrlDecode($standard);
        $this->assertSame('Hello World', $decoded);
    }

    // ========== CLIENT SECRET DERIVATION PROPERTIES ==========

    #[Test]
    public function clientSecretDerivationIsOneWay(): void
    {
        $secret = Proof::deriveClientSecret('abcd1234abcd1234abcd1234abcd1234', 'ctx_456', 'POST|/api|');

        // Secret should not contain inputs
        $this->assertStringNotContainsString('abcd1234abcd1234abcd1234abcd1234', $secret);
        $this->assertStringNotContainsString('ctx_456', $secret);
    }

    #[Test]
    public function clientSecretHasCorrectLength(): void
    {
        $secret = Proof::deriveClientSecret('abcd1234abcd1234abcd1234abcd1234', 'ctx', 'POST|/api|');
        $this->assertSame(64, strlen($secret)); // SHA-256 hex
    }

    #[Test]
    public function clientSecretIsDeterministic(): void
    {
        $secret1 = Proof::deriveClientSecret('abcd1234abcd1234abcd1234abcd1234', 'ctx', 'POST|/api|');
        $secret2 = Proof::deriveClientSecret('abcd1234abcd1234abcd1234abcd1234', 'ctx', 'POST|/api|');
        $this->assertSame($secret1, $secret2);
    }

    #[Test]
    public function clientSecretDifferentInputsDifferentSecrets(): void
    {
        $secrets = [];

        for ($i = 0; $i < 100; $i++) {
            $secrets[] = Proof::deriveClientSecret(sprintf('%032x', $i) . sprintf('%032x', $i + 1000), sprintf('%032x', $i) . sprintf('%032x', $i + 2000), 'POST|/api|');
        }

        $unique = array_unique($secrets);
        $this->assertCount(100, $unique);
    }

    // ========== ENTROPY TESTS ==========

    #[Test]
    public function proofHasGoodDistribution(): void
    {
        $charCounts = array_fill_keys(str_split('0123456789abcdef'), 0);

        for ($i = 0; $i < 100; $i++) {
            $proof = Proof::ashBuildProofHmac(
                "secret_$i",
                (string)(1000000000 + $i),
                "POST|/api/$i|",
                "body_$i"
            );

            foreach (str_split($proof) as $char) {
                $charCounts[$char]++;
            }
        }

        // Each hex char should appear roughly equally (6400 chars total / 16 = 400 per char)
        // Allow for variance but check for reasonable distribution
        foreach ($charCounts as $char => $count) {
            $this->assertGreaterThan(200, $count, "Character $char appears too infrequently");
            $this->assertLessThan(600, $count, "Character $char appears too frequently");
        }
    }

    // ========== NONCE GENERATION TESTS ==========

    #[Test]
    public function generateNonceReturnsHexString(): void
    {
        $nonce = Ash::generateNonce();
        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $nonce);
    }

    #[Test]
    public function generateNonceHasMinimumLength(): void
    {
        $nonce = Ash::generateNonce();
        $this->assertGreaterThanOrEqual(32, strlen($nonce)); // 16 bytes = 32 hex chars minimum
    }

    #[Test]
    public function generateNonceIsUnique(): void
    {
        $nonces = [];

        for ($i = 0; $i < 1000; $i++) {
            $nonces[] = Ash::generateNonce();
        }

        $unique = array_unique($nonces);
        $this->assertCount(1000, $unique);
    }

    // ========== CONTEXT ID GENERATION TESTS ==========

    #[Test]
    public function generateContextIdReturnsString(): void
    {
        $contextId = Ash::generateContextId();
        $this->assertIsString($contextId);
        $this->assertNotEmpty($contextId);
    }

    #[Test]
    public function generateContextIdIsUnique(): void
    {
        $ids = [];

        for ($i = 0; $i < 1000; $i++) {
            $ids[] = Ash::generateContextId();
        }

        $unique = array_unique($ids);
        $this->assertCount(1000, $unique);
    }

    // ========== STRESS TESTS ==========

    #[Test]
    public function hmacStressTest(): void
    {
        for ($i = 0; $i < 1000; $i++) {
            $proof = Proof::ashBuildProofHmac(
                bin2hex(random_bytes(32)),
                (string)time(),
                'POST|/api/stress|',
                bin2hex(random_bytes(32))
            );
            $this->assertSame(64, strlen($proof));
        }
    }

    #[Test]
    public function hashStressTest(): void
    {
        for ($i = 0; $i < 1000; $i++) {
            $hash = Proof::hashBody(bin2hex(random_bytes(100)));
            $this->assertSame(64, strlen($hash));
        }
    }

    #[Test]
    public function timingSafeStressTest(): void
    {
        for ($i = 0; $i < 1000; $i++) {
            $str = bin2hex(random_bytes(32));
            $this->assertTrue(Compare::timingSafe($str, $str));
        }
    }
}
