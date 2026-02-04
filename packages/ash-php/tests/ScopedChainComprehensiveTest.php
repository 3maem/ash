<?php

declare(strict_types=1);

namespace Ash\Tests;

use Ash\Core\Proof;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Comprehensive scoped and chained proof tests (v2.2/v2.3 features).
 */
final class ScopedChainComprehensiveTest extends TestCase
{
    // ========== SCOPED FIELD EXTRACTION TESTS ==========

    #[Test]
    public function extractScopedFieldsSingleField(): void
    {
        $payload = ['name' => 'John', 'email' => 'john@example.com', 'age' => 30];
        $scope = ['name'];

        $extracted = Proof::extractScopedFields($payload, $scope);

        $this->assertSame(['name' => 'John'], $extracted);
    }

    #[Test]
    public function extractScopedFieldsMultipleFields(): void
    {
        $payload = ['name' => 'John', 'email' => 'john@example.com', 'age' => 30];
        $scope = ['name', 'email'];

        $extracted = Proof::extractScopedFields($payload, $scope);

        $this->assertSame(['name' => 'John', 'email' => 'john@example.com'], $extracted);
    }

    #[Test]
    public function extractScopedFieldsPreservesOrder(): void
    {
        $payload = ['z' => 26, 'a' => 1, 'm' => 13];
        $scope = ['a', 'z'];

        $extracted = Proof::extractScopedFields($payload, $scope);

        $this->assertArrayHasKey('a', $extracted);
        $this->assertArrayHasKey('z', $extracted);
    }

    #[Test]
    public function extractScopedFieldsNestedField(): void
    {
        $payload = ['user' => ['name' => 'John', 'email' => 'john@example.com']];
        $scope = ['user.name'];

        $extracted = Proof::extractScopedFields($payload, $scope);

        $this->assertSame(['user' => ['name' => 'John']], $extracted);
    }

    #[Test]
    public function extractScopedFieldsDeeplyNested(): void
    {
        $payload = ['a' => ['b' => ['c' => ['d' => 'value']]]];
        $scope = ['a.b.c.d'];

        $extracted = Proof::extractScopedFields($payload, $scope);

        $this->assertSame(['a' => ['b' => ['c' => ['d' => 'value']]]], $extracted);
    }

    #[Test]
    public function extractScopedFieldsArrayIndex(): void
    {
        $payload = ['items' => ['first', 'second', 'third']];
        $scope = ['items.0'];

        $extracted = Proof::extractScopedFields($payload, $scope);

        $this->assertSame(['items' => ['first']], $extracted);
    }

    #[Test]
    public function extractScopedFieldsMultipleArrayIndices(): void
    {
        $payload = ['items' => ['a', 'b', 'c', 'd']];
        $scope = ['items.0', 'items.2'];

        $extracted = Proof::extractScopedFields($payload, $scope);

        $this->assertArrayHasKey('items', $extracted);
        $this->assertSame('a', $extracted['items'][0]);
        $this->assertSame('c', $extracted['items'][2]);
    }

    #[Test]
    public function extractScopedFieldsNestedArrayObject(): void
    {
        $payload = ['users' => [['name' => 'John'], ['name' => 'Jane']]];
        $scope = ['users.0.name'];

        $extracted = Proof::extractScopedFields($payload, $scope);

        $this->assertSame('John', $extracted['users'][0]['name']);
    }

    #[Test]
    public function extractScopedFieldsEmptyScope(): void
    {
        $payload = ['name' => 'John'];
        $scope = [];

        $extracted = Proof::extractScopedFields($payload, $scope);

        // Empty scope returns full payload per library behavior
        $this->assertSame($payload, $extracted);
    }

    #[Test]
    public function extractScopedFieldsMissingField(): void
    {
        $payload = ['name' => 'John'];
        $scope = ['email'];

        $extracted = Proof::extractScopedFields($payload, $scope);

        $this->assertArrayNotHasKey('email', $extracted);
    }

    #[Test]
    public function extractScopedFieldsWithNullValue(): void
    {
        $payload = ['name' => null, 'email' => 'john@example.com'];
        $scope = ['name'];

        $extracted = Proof::extractScopedFields($payload, $scope);

        // Library skips null values
        $this->assertArrayNotHasKey('name', $extracted);
    }

    // ========== SCOPE HASH TESTS ==========

    #[Test]
    public function hashScopeReturnsHex(): void
    {
        $hash = Proof::hashBody(Proof::joinScopeFields(['field1', 'field2']));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
    }

    #[Test]
    public function hashScopeIsDeterministic(): void
    {
        $hash1 = Proof::hashBody(Proof::joinScopeFields(['field1', 'field2']));
        $hash2 = Proof::hashBody(Proof::joinScopeFields(['field1', 'field2']));
        $this->assertSame($hash1, $hash2);
    }

    #[Test]
    public function hashScopeDifferentFieldsDifferentHashes(): void
    {
        $hash1 = Proof::hashBody(Proof::joinScopeFields(['field1']));
        $hash2 = Proof::hashBody(Proof::joinScopeFields(['field2']));
        $this->assertNotSame($hash1, $hash2);
    }

    #[Test]
    public function hashScopeOrderMatters(): void
    {
        // After normalization, order should be consistent
        $hash1 = Proof::hashBody(Proof::joinScopeFields(['a', 'b']));
        $hash2 = Proof::hashBody(Proof::joinScopeFields(['b', 'a']));
        // After normalization they should be the same
        $this->assertSame($hash1, $hash2);
    }

    #[Test]
    public function hashScopeEmptyArray(): void
    {
        $hash = Proof::hashBody(Proof::joinScopeFields([]));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
    }

    // ========== SCOPED BODY HASH TESTS ==========

    #[Test]
    public function hashScopedBodyReturnsHex(): void
    {
        $payload = ['name' => 'John', 'email' => 'john@example.com'];
        $scope = ['name'];

        $hash = Proof::hashScopedBody($payload, $scope);

        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
    }

    #[Test]
    public function hashScopedBodyIsDeterministic(): void
    {
        $payload = ['name' => 'John'];
        $scope = ['name'];

        $hash1 = Proof::hashScopedBody($payload, $scope);
        $hash2 = Proof::hashScopedBody($payload, $scope);

        $this->assertSame($hash1, $hash2);
    }

    #[Test]
    public function hashScopedBodyDifferentScopesDifferentHashes(): void
    {
        $payload = ['name' => 'John', 'email' => 'john@example.com'];

        $hash1 = Proof::hashScopedBody($payload, ['name']);
        $hash2 = Proof::hashScopedBody($payload, ['email']);

        $this->assertNotSame($hash1, $hash2);
    }

    #[Test]
    public function hashScopedBodyDifferentValuesDifferentHashes(): void
    {
        $payload1 = ['name' => 'John'];
        $payload2 = ['name' => 'Jane'];
        $scope = ['name'];

        $hash1 = Proof::hashScopedBody($payload1, $scope);
        $hash2 = Proof::hashScopedBody($payload2, $scope);

        $this->assertNotSame($hash1, $hash2);
    }

    // ========== BUILD SCOPED PROOF TESTS ==========

    #[Test]
    public function buildScopedProofReturnsResult(): void
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
    public function buildScopedProofProofIsHex(): void
    {
        $result = Proof::ashBuildProofScoped(
            'secret',
            '1234567890',
            'POST|/api|',
            ['name' => 'John'],
            ['name']
        );

        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $result['proof']);
    }

    #[Test]
    public function buildScopedProofScopeHashIsHex(): void
    {
        $result = Proof::ashBuildProofScoped(
            'secret',
            '1234567890',
            'POST|/api|',
            ['name' => 'John'],
            ['name']
        );

        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $result['scopeHash']);
    }

    #[Test]
    public function buildScopedProofIsDeterministic(): void
    {
        $args = [
            'secret',
            '1234567890',
            'POST|/api|',
            ['name' => 'John'],
            ['name']
        ];

        $result1 = Proof::ashBuildProofScoped(...$args);
        $result2 = Proof::ashBuildProofScoped(...$args);

        $this->assertSame($result1['proof'], $result2['proof']);
        $this->assertSame($result1['scopeHash'], $result2['scopeHash']);
    }

    // ========== VERIFY SCOPED PROOF TESTS ==========

    #[Test]
    public function verifyScopedProofReturnsTrue(): void
    {
        $nonce = str_repeat('a', 64);
        $contextId = 'ctx_scoped';
        $binding = 'POST|/api|';
        $timestamp = '1234567890';
        $payload = ['name' => 'John', 'email' => 'john@example.com'];
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
    public function verifyScopedProofReturnsFalseForTamperedPayload(): void
    {
        $nonce = str_repeat('b', 64);
        $contextId = 'ctx_tampered';
        $binding = 'POST|/api|';
        $timestamp = '1234567890';
        $payload = ['name' => 'John'];
        $scope = ['name'];

        $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding);
        $result = Proof::ashBuildProofScoped($clientSecret, $timestamp, $binding, $payload, $scope);

        $tamperedPayload = ['name' => 'Jane'];
        $verified = Proof::ashVerifyProofScoped(
            $nonce,
            $contextId,
            $binding,
            $timestamp,
            $tamperedPayload,
            $scope,
            $result['scopeHash'],
            $result['proof']
        );

        $this->assertFalse($verified);
    }

    #[Test]
    public function verifyScopedProofAllowsUnscopedFieldChanges(): void
    {
        $nonce = str_repeat('c', 64);
        $contextId = 'ctx_unscoped';
        $binding = 'POST|/api|';
        $timestamp = '1234567890';
        $payload = ['name' => 'John', 'email' => 'john@example.com'];
        $scope = ['name']; // Only protecting name

        $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding);
        $result = Proof::ashBuildProofScoped($clientSecret, $timestamp, $binding, $payload, $scope);

        // Change unscoped field (email)
        $modifiedPayload = ['name' => 'John', 'email' => 'different@example.com'];
        $verified = Proof::ashVerifyProofScoped(
            $nonce,
            $contextId,
            $binding,
            $timestamp,
            $modifiedPayload,
            $scope,
            $result['scopeHash'],
            $result['proof']
        );

        $this->assertTrue($verified);
    }

    // ========== CHAIN HASH TESTS ==========

    #[Test]
    public function hashProofReturnsHex(): void
    {
        $hash = Proof::hashProof('abc123def456');
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
    }

    #[Test]
    public function hashProofIsDeterministic(): void
    {
        $hash1 = Proof::hashProof('proof123');
        $hash2 = Proof::hashProof('proof123');
        $this->assertSame($hash1, $hash2);
    }

    #[Test]
    public function hashProofDifferentProofsDifferentHashes(): void
    {
        $hash1 = Proof::hashProof('proof1');
        $hash2 = Proof::hashProof('proof2');
        $this->assertNotSame($hash1, $hash2);
    }

    // ========== BUILD UNIFIED PROOF TESTS ==========

    #[Test]
    public function buildUnifiedProofReturnsResult(): void
    {
        $result = Proof::ashBuildProofUnified(
            'secret',
            '1234567890',
            'POST|/api|',
            ['name' => 'John'],
            ['name'],
            null // No previous proof
        );

        $this->assertArrayHasKey('proof', $result);
        $this->assertArrayHasKey('scopeHash', $result);
        $this->assertArrayHasKey('chainHash', $result);
    }

    #[Test]
    public function buildUnifiedProofWithChaining(): void
    {
        // First request
        $result1 = Proof::ashBuildProofUnified(
            'secret',
            '1234567890',
            'POST|/api/step1|',
            ['step' => 1],
            ['step'],
            null
        );

        // Second request, chained to first
        $result2 = Proof::ashBuildProofUnified(
            'secret',
            '1234567891',
            'POST|/api/step2|',
            ['step' => 2],
            ['step'],
            $result1['proof']
        );

        $this->assertNotEmpty($result2['chainHash']);
        $this->assertNotSame($result1['proof'], $result2['proof']);
    }

    #[Test]
    public function buildUnifiedProofChainHashMatchesPreviousProofHash(): void
    {
        $result1 = Proof::ashBuildProofUnified(
            'secret',
            '1234567890',
            'POST|/api/step1|',
            ['step' => 1],
            ['step'],
            null
        );

        $result2 = Proof::ashBuildProofUnified(
            'secret',
            '1234567891',
            'POST|/api/step2|',
            ['step' => 2],
            ['step'],
            $result1['proof']
        );

        $expectedChainHash = Proof::hashProof($result1['proof']);
        $this->assertSame($expectedChainHash, $result2['chainHash']);
    }

    // ========== VERIFY UNIFIED PROOF TESTS ==========

    #[Test]
    public function verifyUnifiedProofReturnsTrue(): void
    {
        $nonce = str_repeat('d', 64);
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

    #[Test]
    public function verifyUnifiedProofWithChaining(): void
    {
        $nonce = str_repeat('e', 64);
        $contextId = 'ctx_chain';
        $binding1 = 'POST|/api/step1|';
        $binding2 = 'POST|/api/step2|';

        // First request
        $clientSecret1 = Proof::deriveClientSecret($nonce, $contextId, $binding1);
        $result1 = Proof::ashBuildProofUnified(
            $clientSecret1,
            '1234567890',
            $binding1,
            ['step' => 1],
            ['step'],
            null
        );

        // Verify first
        $verified1 = Proof::ashVerifyProofUnified(
            $nonce,
            $contextId,
            $binding1,
            '1234567890',
            ['step' => 1],
            $result1['proof'],
            ['step'],
            $result1['scopeHash'],
            null,
            $result1['chainHash']
        );
        $this->assertTrue($verified1);

        // Second request, chained
        $clientSecret2 = Proof::deriveClientSecret($nonce, $contextId, $binding2);
        $result2 = Proof::ashBuildProofUnified(
            $clientSecret2,
            '1234567891',
            $binding2,
            ['step' => 2],
            ['step'],
            $result1['proof']
        );

        // Verify second with chain hash
        $verified2 = Proof::ashVerifyProofUnified(
            $nonce,
            $contextId,
            $binding2,
            '1234567891',
            ['step' => 2],
            $result2['proof'],
            ['step'],
            $result2['scopeHash'],
            $result1['proof'],
            $result2['chainHash']
        );
        $this->assertTrue($verified2);
    }

    // ========== NORMALIZE SCOPE FIELDS TESTS ==========

    #[Test]
    public function normalizeScopeFieldsSortsAlphabetically(): void
    {
        $normalized = Proof::normalizeScopeFields(['z', 'a', 'm']);
        $this->assertSame(['a', 'm', 'z'], $normalized);
    }

    #[Test]
    public function normalizeScopeFieldsRemovesDuplicates(): void
    {
        $normalized = Proof::normalizeScopeFields(['a', 'a', 'b']);
        $this->assertSame(['a', 'b'], $normalized);
    }

    #[Test]
    public function normalizeScopeFieldsPreservesWhitespace(): void
    {
        // Library preserves field names as-is (no trimming)
        $normalized = Proof::normalizeScopeFields(['  a  ', ' b']);
        // Sorted by string comparison: '  a  ' (space+space+a) < ' b' (space+b)
        $this->assertSame(['  a  ', ' b'], $normalized);
    }

    #[Test]
    public function normalizeScopeFieldsHandlesEmpty(): void
    {
        $normalized = Proof::normalizeScopeFields([]);
        $this->assertSame([], $normalized);
    }

    // ========== STRESS TESTS ==========

    #[Test]
    public function scopedProofStress(): void
    {
        $nonce = str_repeat('f', 64);
        $contextId = 'ctx_stress';

        for ($i = 0; $i < 100; $i++) {
            $payload = ['field' => "value_$i"];
            $scope = ['field'];
            $binding = "POST|/api/$i|";
            $timestamp = (string)(1000000000 + $i);

            $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding);
            $result = Proof::ashBuildProofScoped(
                $clientSecret,
                $timestamp,
                $binding,
                $payload,
                $scope
            );

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
    }

    #[Test]
    public function unifiedProofChainStress(): void
    {
        $secret = 'chain-secret';
        $previousProof = null;

        for ($i = 0; $i < 50; $i++) {
            $result = Proof::ashBuildProofUnified(
                $secret,
                (string)(1000000000 + $i),
                "POST|/api/step$i|",
                ['step' => $i],
                ['step'],
                $previousProof
            );

            $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $result['proof']);
            $previousProof = $result['proof'];
        }
    }
}
