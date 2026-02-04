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
 * Comprehensive type and interface tests.
 */
final class TypesComprehensiveTest extends TestCase
{
    // ========== ASH MODE TESTS ==========

    #[Test]
    public function ashModeStrictValue(): void
    {
        $this->assertSame('strict', AshMode::Strict->value);
    }

    #[Test]
    public function ashModeBalancedValue(): void
    {
        $this->assertSame('balanced', AshMode::Balanced->value);
    }

    #[Test]
    public function ashModeMinimalValue(): void
    {
        $this->assertSame('minimal', AshMode::Minimal->value);
    }

    #[Test]
    public function ashModeEnumCases(): void
    {
        $cases = AshMode::cases();
        $this->assertCount(3, $cases);
    }

    #[Test]
    public function ashModeFromString(): void
    {
        $this->assertSame(AshMode::Strict, AshMode::from('strict'));
        $this->assertSame(AshMode::Balanced, AshMode::from('balanced'));
        $this->assertSame(AshMode::Minimal, AshMode::from('minimal'));
    }

    #[Test]
    public function ashModeTryFromValid(): void
    {
        $this->assertSame(AshMode::Strict, AshMode::tryFrom('strict'));
        $this->assertSame(AshMode::Balanced, AshMode::tryFrom('balanced'));
        $this->assertSame(AshMode::Minimal, AshMode::tryFrom('minimal'));
    }

    #[Test]
    public function ashModeTryFromInvalid(): void
    {
        $this->assertNull(AshMode::tryFrom('invalid'));
        $this->assertNull(AshMode::tryFrom(''));
        $this->assertNull(AshMode::tryFrom('STRICT')); // Case sensitive
    }

    // ========== BUILD PROOF INPUT TESTS ==========

    #[Test]
    public function buildProofInputRequiredFields(): void
    {
        $input = new BuildProofInput(
            mode: AshMode::Balanced,
            binding: 'POST|/api|',
            contextId: 'ctx_123',
            canonicalPayload: '{"test":"data"}'
        );

        $this->assertSame(AshMode::Balanced, $input->mode);
        $this->assertSame('POST|/api|', $input->binding);
        $this->assertSame('ctx_123', $input->contextId);
        $this->assertSame('{"test":"data"}', $input->canonicalPayload);
    }

    #[Test]
    public function buildProofInputOptionalNonce(): void
    {
        $input = new BuildProofInput(
            mode: AshMode::Balanced,
            binding: 'POST|/api|',
            contextId: 'ctx_123',
            canonicalPayload: '{}',
            nonce: 'abcd1234abcd1234abcd1234abcd1234'
        );

        $this->assertSame('abcd1234abcd1234abcd1234abcd1234', $input->nonce);
    }

    #[Test]
    public function buildProofInputNonceDefaultNull(): void
    {
        $input = new BuildProofInput(
            mode: AshMode::Balanced,
            binding: 'POST|/api|',
            contextId: 'ctx_123',
            canonicalPayload: '{}'
        );

        $this->assertNull($input->nonce);
    }

    #[Test]
    public function buildProofInputAllModes(): void
    {
        foreach (AshMode::cases() as $mode) {
            $input = new BuildProofInput(
                mode: $mode,
                binding: 'POST|/api|',
                contextId: 'ctx_123',
                canonicalPayload: '{}'
            );

            $this->assertSame($mode, $input->mode);
        }
    }

    // ========== ASH FACADE TESTS ==========

    #[Test]
    public function ashVersionConstant(): void
    {
        $this->assertIsString(Ash::VERSION);
        $this->assertMatchesRegularExpression('/^\d+\.\d+\.\d+$/', Ash::VERSION);
    }

    #[Test]
    public function ashCanonicalizeJsonMethod(): void
    {
        $result = Ash::canonicalizeJson(['b' => 2, 'a' => 1]);
        $this->assertSame('{"a":1,"b":2}', $result);
    }

    #[Test]
    public function ashCanonicalizeUrlEncodedMethod(): void
    {
        $result = Ash::canonicalizeUrlEncoded('b=2&a=1');
        $this->assertSame('a=1&b=2', $result);
    }

    #[Test]
    public function ashNormalizeBindingMethod(): void
    {
        $result = Ash::normalizeBinding('post', '/api/update');
        $this->assertSame('POST|/api/update|', $result);
    }

    #[Test]
    public function ashBuildProofMethod(): void
    {
        $input = new BuildProofInput(
            mode: AshMode::Balanced,
            binding: 'POST|/api|',
            contextId: 'ctx_123',
            canonicalPayload: '{}'
        );

        $proof = Ash::buildProof($input);
        $this->assertNotEmpty($proof);
    }

    #[Test]
    public function ashTimingSafeCompareMethod(): void
    {
        $this->assertTrue(Ash::timingSafeCompare('test', 'test'));
        $this->assertFalse(Ash::timingSafeCompare('test', 'other'));
    }

    #[Test]
    public function ashBase64UrlEncodeMethod(): void
    {
        $encoded = Ash::base64UrlEncode('hello');
        $this->assertStringNotContainsString('+', $encoded);
        $this->assertStringNotContainsString('/', $encoded);
        $this->assertStringNotContainsString('=', $encoded);
    }

    #[Test]
    public function ashBase64UrlDecodeMethod(): void
    {
        $encoded = Ash::base64UrlEncode('hello');
        $decoded = Ash::base64UrlDecode($encoded);
        $this->assertSame('hello', $decoded);
    }

    #[Test]
    public function ashGenerateNonceMethod(): void
    {
        $nonce = Ash::generateNonce();
        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $nonce);
        $this->assertGreaterThanOrEqual(32, strlen($nonce));
    }

    #[Test]
    public function ashGenerateContextIdMethod(): void
    {
        $contextId = Ash::generateContextId();
        $this->assertIsString($contextId);
        $this->assertNotEmpty($contextId);
    }

    // ========== PROOF CLASS TESTS ==========

    #[Test]
    public function proofBuildMethod(): void
    {
        $input = new BuildProofInput(
            mode: AshMode::Balanced,
            binding: 'POST|/api|',
            contextId: 'ctx_123',
            canonicalPayload: '{}'
        );

        $proof = Proof::build($input);
        $this->assertNotEmpty($proof);
    }

    #[Test]
    public function proofAshBuildProofHmacMethod(): void
    {
        $proof = Proof::ashBuildProofHmac('secret', '1234567890', 'POST|/api|', 'abc123');
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $proof);
    }

    #[Test]
    public function proofAshVerifyProofMethod(): void
    {
        $nonce = str_repeat('a', 64);
        $contextId = 'ctx_test';
        $binding = 'POST|/api|';
        $timestamp = '1234567890';
        $bodyHash = Proof::hashBody('test');

        $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding);
        $proof = Proof::ashBuildProofHmac($clientSecret, $timestamp, $binding, $bodyHash);
        $result = Proof::ashVerifyProof($nonce, $contextId, $binding, $timestamp, $bodyHash, $proof);

        $this->assertTrue($result);
    }

    #[Test]
    public function proofHashBodyMethod(): void
    {
        $hash = Proof::hashBody('test');
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
    }

    #[Test]
    public function proofDeriveClientSecretMethod(): void
    {
        $secret = Proof::deriveClientSecret('abcd1234abcd1234abcd1234abcd1234', 'ctx', 'POST|/api|');
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $secret);
    }

    #[Test]
    public function proofBase64UrlEncodeMethod(): void
    {
        $encoded = Proof::base64UrlEncode('test');
        $this->assertIsString($encoded);
    }

    #[Test]
    public function proofBase64UrlDecodeMethod(): void
    {
        $encoded = Proof::base64UrlEncode('test');
        $decoded = Proof::base64UrlDecode($encoded);
        $this->assertSame('test', $decoded);
    }

    #[Test]
    public function timestampIsNumericString(): void
    {
        $timestamp = (string)time();
        $this->assertMatchesRegularExpression('/^\d+$/', $timestamp);
    }

    // ========== SCOPED PROOF METHODS ==========

    #[Test]
    public function proofExtractScopedFieldsMethod(): void
    {
        $payload = ['name' => 'John', 'email' => 'john@example.com'];
        $scope = ['name'];

        $extracted = Proof::extractScopedFields($payload, $scope);

        $this->assertArrayHasKey('name', $extracted);
        $this->assertArrayNotHasKey('email', $extracted);
    }

    #[Test]
    public function proofJoinScopeFieldsMethod(): void
    {
        $hash = Proof::hashBody(Proof::joinScopeFields(['field1', 'field2']));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
    }

    #[Test]
    public function proofHashScopedBodyMethod(): void
    {
        $hash = Proof::hashScopedBody(['name' => 'John'], ['name']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
    }

    #[Test]
    public function proofAshBuildProofScopedMethod(): void
    {
        $result = Proof::ashBuildProofScoped(
            'secret',
            '1234567890',
            'POST|/api|',
            ['name' => 'John'],
            ['name']
        );

        $this->assertArrayHasKey('proof', $result);
        $this->assertArrayHasKey('scopeHash', $result);
    }

    #[Test]
    public function proofAshVerifyProofScopedMethod(): void
    {
        $nonce = str_repeat('a', 64);
        $contextId = 'ctx_verify';
        $binding = 'POST|/api|';
        $timestamp = '1234567890';
        $payload = ['name' => 'John'];
        $scope = ['name'];

        $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding);
        $result = Proof::ashBuildProofScoped($clientSecret, $timestamp, $binding, $payload, $scope);
        $verified = Proof::ashVerifyProofScoped(
            $nonce,
            $contextId,
            $binding,
            $timestamp,
            $payload,
            $scope,
            $result['scopeHash'],
            $result['proof']
        );

        $this->assertTrue($verified);
    }

    #[Test]
    public function proofNormalizeScopeFieldsMethod(): void
    {
        $normalized = Proof::normalizeScopeFields(['z', 'a', 'm']);
        $this->assertSame(['a', 'm', 'z'], $normalized);
    }

    // ========== UNIFIED PROOF METHODS ==========

    #[Test]
    public function proofHashProofMethod(): void
    {
        $hash = Proof::hashProof('abc123');
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
    }

    #[Test]
    public function proofBuildUnifiedMethod(): void
    {
        $result = Proof::ashBuildProofUnified(
            'secret',
            '1234567890',
            'POST|/api|',
            ['name' => 'John'],
            ['name'],
            null
        );

        $this->assertArrayHasKey('proof', $result);
        $this->assertArrayHasKey('scopeHash', $result);
        $this->assertArrayHasKey('chainHash', $result);
    }

    #[Test]
    public function proofVerifyUnifiedMethod(): void
    {
        $nonce = str_repeat('b', 64);
        $contextId = 'ctx_unified';
        $binding = 'POST|/api|';
        $timestamp = '1234567890';
        $payload = ['name' => 'John'];
        $scope = ['name'];

        $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding);
        $result = Proof::ashBuildProofUnified($clientSecret, $timestamp, $binding, $payload, $scope, null);
        $verified = Proof::ashVerifyProofUnified(
            $nonce,
            $contextId,
            $binding,
            $timestamp,
            $payload,
            $result['proof'],
            $scope,
            $result['scopeHash'],
            null,
            $result['chainHash']
        );

        $this->assertTrue($verified);
    }

    // ========== RETURN TYPE TESTS ==========

    #[Test]
    public function proofBuildReturnsString(): void
    {
        $input = new BuildProofInput(
            mode: AshMode::Balanced,
            binding: 'POST|/api|',
            contextId: 'ctx_123',
            canonicalPayload: '{}'
        );

        $proof = Proof::build($input);
        $this->assertIsString($proof);
    }

    #[Test]
    public function proofAshVerifyProofReturnsBool(): void
    {
        $result = Proof::ashVerifyProof(str_repeat('a', 64), 'ctx', 'binding', '123', 'hash', str_repeat('0', 64));
        $this->assertIsBool($result);
    }

    #[Test]
    public function proofHashBodyReturnsString(): void
    {
        $hash = Proof::hashBody('test');
        $this->assertIsString($hash);
    }

    #[Test]
    public function proofAshBuildProofScopedReturnsArray(): void
    {
        $result = Proof::ashBuildProofScoped('secret', '123', 'binding', ['a' => 1], ['a']);
        $this->assertIsArray($result);
    }

    #[Test]
    public function proofBuildUnifiedReturnsArray(): void
    {
        $result = Proof::ashBuildProofUnified('secret', '123', 'binding', ['a' => 1], ['a'], null);
        $this->assertIsArray($result);
    }

    // ========== DETERMINISM TESTS ==========

    #[Test]
    public function allMethodsDeterministic(): void
    {
        // Test that all methods produce consistent results
        for ($i = 0; $i < 10; $i++) {
            $this->assertSame(
                Proof::hashBody('test'),
                Proof::hashBody('test')
            );

            $this->assertSame(
                Proof::ashBuildProofHmac('s', 't', 'b', 'h'),
                Proof::ashBuildProofHmac('s', 't', 'b', 'h')
            );

            $this->assertSame(
                Proof::deriveClientSecret('abcd1234abcd1234abcd1234abcd1234', 'ctx', 'binding'),
                Proof::deriveClientSecret('abcd1234abcd1234abcd1234abcd1234', 'ctx', 'binding')
            );
        }
    }
}
