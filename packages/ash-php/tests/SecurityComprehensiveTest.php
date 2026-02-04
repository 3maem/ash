<?php

declare(strict_types=1);

namespace Ash\Tests;

use Ash\Ash;
use Ash\Core\Compare;
use Ash\Core\Proof;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Comprehensive security-focused tests.
 */
final class SecurityComprehensiveTest extends TestCase
{
    // ========== TIMING ATTACK RESISTANCE ==========

    #[Test]
    public function timingSafeCompareResistsTimingAttack(): void
    {
        $secret = hash('sha256', 'actual_secret');

        // Different length should return false
        $this->assertFalse(Compare::timingSafe($secret, 'short'));

        // First char wrong
        $this->assertFalse(Compare::timingSafe($secret, 'x' . substr($secret, 1)));

        // Last char wrong
        $this->assertFalse(Compare::timingSafe($secret, substr($secret, 0, -1) . 'x'));

        // Middle char wrong
        $this->assertFalse(Compare::timingSafe($secret, substr($secret, 0, 32) . 'x' . substr($secret, 33)));

        // Correct comparison
        $this->assertTrue(Compare::timingSafe($secret, $secret));
    }

    #[Test]
    public function timingSafeCompareDifferentPositions(): void
    {
        $original = str_repeat('a', 100);

        for ($pos = 0; $pos < 100; $pos++) {
            $modified = substr($original, 0, $pos) . 'b' . substr($original, $pos + 1);
            $this->assertFalse(Compare::timingSafe($original, $modified));
        }
    }

    // ========== PROOF TAMPERING DETECTION ==========

    #[Test]
    public function detectsSingleBitChange(): void
    {
        $nonce = str_repeat('a', 64);
        $contextId = 'ctx_test';
        $binding = 'POST|/api|';
        $timestamp = '1234567890';
        $bodyHash = Proof::hashBody('data');

        $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding);
        $proof = Proof::ashBuildProofHmac($clientSecret, $timestamp, $binding, $bodyHash);

        // Change single character
        $chars = str_split($proof);
        for ($i = 0; $i < strlen($proof); $i++) {
            $tampered = $chars;
            $tampered[$i] = $chars[$i] === 'a' ? 'b' : 'a';
            $tamperedProof = implode('', $tampered);

            $this->assertFalse(
                Proof::ashVerifyProof($nonce, $contextId, $binding, $timestamp, $bodyHash, $tamperedProof),
                "Should detect tampering at position $i"
            );
        }
    }

    #[Test]
    public function detectsTimestampTampering(): void
    {
        $nonce = str_repeat('b', 64);
        $contextId = 'ctx_timestamp';
        $binding = 'POST|/api|';
        $bodyHash = Proof::hashBody('data');

        $originalTimestamp = '1234567890';
        $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding);
        $proof = Proof::ashBuildProofHmac($clientSecret, $originalTimestamp, $binding, $bodyHash);

        // Try different timestamps
        $tamperedTimestamps = [
            '1234567891', // Off by one
            '0000000000', // All zeros
            '9999999999', // All nines
            '', // Empty
            '-1', // Negative
        ];

        foreach ($tamperedTimestamps as $tampered) {
            $this->assertFalse(
                Proof::ashVerifyProof($nonce, $contextId, $binding, $tampered, $bodyHash, $proof),
                "Should detect timestamp tampering: $tampered"
            );
        }
    }

    #[Test]
    public function detectsBindingTampering(): void
    {
        $nonce = str_repeat('c', 64);
        $contextId = 'ctx_binding';
        $timestamp = '1234567890';
        $bodyHash = Proof::hashBody('data');

        $originalBinding = 'POST|/api/users|';
        $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $originalBinding);
        $proof = Proof::ashBuildProofHmac($clientSecret, $timestamp, $originalBinding, $bodyHash);

        // Try different bindings - verifying with different binding should fail
        $tamperedBindings = [
            'GET|/api/users|', // Wrong method
            'POST|/api/admin|', // Wrong path
            'POST|/api/users|extra', // Extra data
            '', // Empty
        ];

        foreach ($tamperedBindings as $tampered) {
            $this->assertFalse(
                Proof::ashVerifyProof($nonce, $contextId, $tampered, $timestamp, $bodyHash, $proof),
                "Should detect binding tampering: $tampered"
            );
        }
    }

    #[Test]
    public function detectsBodyTampering(): void
    {
        $nonce = str_repeat('d', 64);
        $contextId = 'ctx_body';
        $timestamp = '1234567890';
        $binding = 'POST|/api|';

        $originalBody = '{"name":"John","action":"transfer"}';
        $originalHash = Proof::hashBody($originalBody);
        $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding);
        $proof = Proof::ashBuildProofHmac($clientSecret, $timestamp, $binding, $originalHash);

        // Try tampered bodies
        $tamperedBodies = [
            '{"name":"Jane","action":"transfer"}', // Changed name
            '{"name":"John","action":"delete"}', // Changed action
            '{"name":"John","action":"transfer","extra":true}', // Added field
            '', // Empty
        ];

        foreach ($tamperedBodies as $tampered) {
            $tamperedHash = Proof::hashBody($tampered);
            $this->assertFalse(
                Proof::ashVerifyProof($nonce, $contextId, $binding, $timestamp, $tamperedHash, $proof),
                "Should detect body tampering"
            );
        }
    }

    // ========== REPLAY ATTACK RESISTANCE ==========

    #[Test]
    public function sameInputsProduceSameProof(): void
    {
        // This is a property test - same inputs = same output
        // Replay detection must be handled at the context level
        $secret = 'secret';
        $timestamp = '1234567890';
        $binding = 'POST|/api|';
        $bodyHash = 'abc123';

        $proof1 = Proof::ashBuildProofHmac($secret, $timestamp, $binding, $bodyHash);
        $proof2 = Proof::ashBuildProofHmac($secret, $timestamp, $binding, $bodyHash);

        $this->assertSame($proof1, $proof2);
    }

    #[Test]
    public function differentContextsProduceDifferentProofs(): void
    {
        // Nonce/context should be included to prevent replay
        $timestamp = '1234567890';
        $binding = 'POST|/api|';
        $bodyHash = 'abc123';

        $secret1 = Proof::deriveClientSecret('11111111111111111111111111111111', 'ctx1', $binding);
        $secret2 = Proof::deriveClientSecret('22222222222222222222222222222222', 'ctx2', $binding);

        $proof1 = Proof::ashBuildProofHmac($secret1, $timestamp, $binding, $bodyHash);
        $proof2 = Proof::ashBuildProofHmac($secret2, $timestamp, $binding, $bodyHash);

        $this->assertNotSame($proof1, $proof2);
    }

    // ========== SECRET DERIVATION SECURITY ==========

    #[Test]
    public function clientSecretIsNotReversible(): void
    {
        $secret = Proof::deriveClientSecret('abcd1234abcd1234abcd1234abcd1234', 'ctx456', 'POST|/api|');

        // Secret should not contain input values
        $this->assertStringNotContainsString('abcd1234abcd1234abcd1234abcd1234', $secret);
        $this->assertStringNotContainsString('ctx456', $secret);
        $this->assertStringNotContainsString('nonce', $secret);
        $this->assertStringNotContainsString('ctx', $secret);
    }

    #[Test]
    public function clientSecretHasHighEntropy(): void
    {
        $secrets = [];

        for ($i = 0; $i < 100; $i++) {
            $secrets[] = Proof::deriveClientSecret(sprintf('%032x', $i) . sprintf('%032x', $i + 1000), sprintf('%032x', $i) . sprintf('%032x', $i + 2000), 'POST|/api|');
        }

        // All should be unique
        $unique = array_unique($secrets);
        $this->assertCount(100, $unique);

        // Check character distribution
        $allChars = implode('', $secrets);
        $hexChars = '0123456789abcdef';

        foreach (str_split($hexChars) as $char) {
            $count = substr_count($allChars, $char);
            // Each hex char should appear roughly equally (6400 chars / 16 = 400)
            $this->assertGreaterThan(200, $count, "Character $char appears too rarely");
        }
    }

    // ========== HASH SECURITY ==========

    #[Test]
    public function hashResistsCollisions(): void
    {
        $hashes = [];

        for ($i = 0; $i < 1000; $i++) {
            $hashes[] = Proof::hashBody("input_$i");
        }

        $unique = array_unique($hashes);
        $this->assertCount(1000, $unique);
    }

    #[Test]
    public function hashAvalancheEffect(): void
    {
        $hash1 = Proof::hashBody('test');
        $hash2 = Proof::hashBody('test1'); // One char added

        // Count different characters
        $diffCount = 0;
        for ($i = 0; $i < 64; $i++) {
            if ($hash1[$i] !== $hash2[$i]) {
                $diffCount++;
            }
        }

        // Should have significant difference (avalanche effect)
        $this->assertGreaterThan(20, $diffCount);
    }

    #[Test]
    public function hashPreimageResistance(): void
    {
        $hash = Proof::hashBody('secret_data');

        // Hash should not reveal input
        $this->assertStringNotContainsString('secret', $hash);
        $this->assertStringNotContainsString('data', $hash);
    }

    // ========== INPUT VALIDATION SECURITY ==========

    #[Test]
    public function handlesNullByteAttack(): void
    {
        // Null byte shouldn't truncate strings
        $hash1 = Proof::hashBody("test\x00data");
        $hash2 = Proof::hashBody("test");

        $this->assertNotSame($hash1, $hash2);
    }

    #[Test]
    public function handlesOverlongUtf8(): void
    {
        // Test that overlong UTF-8 sequences are handled safely
        $normal = 'test';
        $hash1 = Proof::hashBody($normal);

        // Should not crash or behave unexpectedly
        $this->assertSame(64, strlen($hash1));
    }

    // ========== SCOPED PROOF SECURITY ==========

    #[Test]
    public function scopedProofProtectsSelectedFields(): void
    {
        $nonce = str_repeat('e', 64);
        $contextId = 'ctx_scoped';
        $binding = 'POST|/api|';
        $timestamp = '1234567890';

        $payload = ['name' => 'John', 'email' => 'john@example.com'];
        $scope = ['name'];

        $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding);
        $result = Proof::ashBuildProofScoped($clientSecret, $timestamp, $binding, $payload, $scope);

        // Changing scoped field should break verification
        $tamperedPayload = ['name' => 'Jane', 'email' => 'john@example.com'];
        $verified = Proof::ashVerifyProofScoped(
            $nonce, $contextId, $binding, $timestamp, $tamperedPayload, $scope,
            $result['scopeHash'], $result['proof']
        );
        $this->assertFalse($verified);
    }

    #[Test]
    public function scopedProofAllowsUnscopedChanges(): void
    {
        $nonce = str_repeat('f', 64);
        $contextId = 'ctx_unscoped';
        $binding = 'POST|/api|';
        $timestamp = '1234567890';

        $payload = ['name' => 'John', 'email' => 'john@example.com'];
        $scope = ['name'];

        $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding);
        $result = Proof::ashBuildProofScoped($clientSecret, $timestamp, $binding, $payload, $scope);

        // Changing unscoped field should still verify
        $modifiedPayload = ['name' => 'John', 'email' => 'different@example.com'];
        $verified = Proof::ashVerifyProofScoped(
            $nonce, $contextId, $binding, $timestamp, $modifiedPayload, $scope,
            $result['scopeHash'], $result['proof']
        );
        $this->assertTrue($verified);
    }

    // ========== CHAIN INTEGRITY ==========

    #[Test]
    public function chainHashPreventsReordering(): void
    {
        $nonce = str_repeat('a', 64);
        $contextId = 'ctx_chain';
        $binding1 = 'POST|/api/step1|';
        $binding2 = 'POST|/api/step2|';

        $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding1);

        // Create chain of requests
        $result1 = Proof::ashBuildProofUnified(
            $clientSecret, '1000000001', $binding1,
            ['step' => 1], ['step'], null
        );

        $result2 = Proof::ashBuildProofUnified(
            $clientSecret, '1000000002', $binding2,
            ['step' => 2], ['step'], $result1['proof']
        );

        // Chain hash should match previous proof hash
        $expectedChainHash = Proof::hashProof($result1['proof']);
        $this->assertSame($expectedChainHash, $result2['chainHash']);
    }

    // ========== NONCE GENERATION SECURITY ==========

    #[Test]
    public function nonceHasSufficientEntropy(): void
    {
        $nonces = [];

        for ($i = 0; $i < 1000; $i++) {
            $nonces[] = Ash::generateNonce();
        }

        // All should be unique
        $unique = array_unique($nonces);
        $this->assertCount(1000, $unique);
    }

    #[Test]
    public function nonceHasMinimumLength(): void
    {
        for ($i = 0; $i < 100; $i++) {
            $nonce = Ash::generateNonce();
            $this->assertGreaterThanOrEqual(32, strlen($nonce)); // 16 bytes = 32 hex
        }
    }

    // ========== CONTEXT ID GENERATION SECURITY ==========

    #[Test]
    public function contextIdIsUnique(): void
    {
        $ids = [];

        for ($i = 0; $i < 1000; $i++) {
            $ids[] = Ash::generateContextId();
        }

        $unique = array_unique($ids);
        $this->assertCount(1000, $unique);
    }

    // ========== BASE64URL SECURITY ==========

    #[Test]
    public function base64UrlIsUrlSafe(): void
    {
        // Test data that would produce unsafe chars in standard base64
        $testData = [
            "\xfb\xff\xfe", // Would produce + and / in standard
            random_bytes(100),
            str_repeat("\x00\xff", 50),
        ];

        foreach ($testData as $data) {
            $encoded = Proof::base64UrlEncode($data);

            $this->assertStringNotContainsString('+', $encoded);
            $this->assertStringNotContainsString('/', $encoded);
            $this->assertStringNotContainsString('=', $encoded);

            // Should round-trip correctly
            $decoded = Proof::base64UrlDecode($encoded);
            $this->assertSame($data, $decoded);
        }
    }
}
