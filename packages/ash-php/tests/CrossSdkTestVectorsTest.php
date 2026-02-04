<?php

declare(strict_types=1);

namespace Ash\Tests;

use Ash\Core\Canonicalize;
use Ash\Core\Compare;
use Ash\Core\Proof;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Cross-SDK Test Vectors for ASH v2.3.2
 *
 * These test vectors MUST produce identical results across all SDK implementations.
 * Any SDK that fails these tests is not compliant with the ASH specification.
 */
final class CrossSdkTestVectorsTest extends TestCase
{
    // ========================================================================
    // FIXED TEST VECTORS - DO NOT MODIFY
    // These values are used across all SDK implementations
    // ========================================================================

    private const TEST_NONCE = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    private const TEST_CONTEXT_ID = 'ash_test_ctx_12345';
    private const TEST_BINDING = 'POST|/api/transfer|';
    private const TEST_TIMESTAMP = '1704067200000'; // 2024-01-01 00:00:00 UTC in ms

    // ========================================================================
    // JSON Canonicalization Tests (RFC 8785 JCS)
    // ========================================================================

    #[Test]
    public function jsonCanonicalizeSimpleObject(): void
    {
        $input = ['z' => 1, 'a' => 2, 'm' => 3];
        $expected = '{"a":2,"m":3,"z":1}';
        $this->assertSame($expected, Canonicalize::json($input));
    }

    #[Test]
    public function jsonCanonicalizeNestedObject(): void
    {
        $input = ['outer' => ['z' => 1, 'a' => 2], 'inner' => ['b' => 2, 'a' => 1]];
        $expected = '{"inner":{"a":1,"b":2},"outer":{"a":2,"z":1}}';
        $this->assertSame($expected, Canonicalize::json($input));
    }

    #[Test]
    public function jsonCanonicalizeArrayPreservesOrder(): void
    {
        $input = ['arr' => [3, 1, 2]];
        $expected = '{"arr":[3,1,2]}';
        $this->assertSame($expected, Canonicalize::json($input));
    }

    #[Test]
    public function jsonCanonicalizeEmptyValues(): void
    {
        $this->assertSame('null', Canonicalize::json(null));
        $this->assertSame('true', Canonicalize::json(true));
        $this->assertSame('false', Canonicalize::json(false));
        $this->assertSame('[]', Canonicalize::json([])); // PHP [] is an empty array
        $this->assertSame('""', Canonicalize::json(''));
    }

    // ========================================================================
    // Query String Canonicalization Tests
    // ========================================================================

    #[Test]
    public function queryCanonicalizesSorted(): void
    {
        $result = Canonicalize::canonicalizeQuery('z=1&a=2&m=3');
        $this->assertSame('a=2&m=3&z=1', $result);
    }

    #[Test]
    public function queryCanonicalizeStripsLeadingQuestionMark(): void
    {
        $result = Canonicalize::canonicalizeQuery('?a=1&b=2');
        $this->assertSame('a=1&b=2', $result);
    }

    #[Test]
    public function queryCanonicalizeUppercaseHex(): void
    {
        $result = Canonicalize::canonicalizeQuery('a=%2f&b=%2F');
        $this->assertSame('a=%2F&b=%2F', $result);
    }

    #[Test]
    public function queryCanonicalizePreservesEmptyValues(): void
    {
        $result = Canonicalize::canonicalizeQuery('a=&b=1');
        $this->assertSame('a=&b=1', $result);
    }

    #[Test]
    public function queryCanonicalizesDuplicateKeysByValue(): void
    {
        // Per ASH spec: sort by key first, then by value for duplicate keys
        $result = Canonicalize::canonicalizeQuery('a=z&a=a&a=m');
        $this->assertSame('a=a&a=m&a=z', $result);
    }

    // ========================================================================
    // URL-Encoded Canonicalization Tests
    // ========================================================================

    #[Test]
    public function urlEncodedCanonicalizeSorted(): void
    {
        $result = Canonicalize::urlEncoded('b=2&a=1');
        $this->assertSame('a=1&b=2', $result);
    }

    #[Test]
    public function urlEncodedCanonicalizePlusAsLiteral(): void
    {
        // ASH protocol treats + as literal plus, not space
        $result = Canonicalize::urlEncoded('a=hello+world');
        $this->assertSame('a=hello%2Bworld', $result);
    }

    #[Test]
    public function urlEncodedCanonicalizeUppercaseHex(): void
    {
        $result = Canonicalize::urlEncoded('a=hello%2fworld');
        $this->assertSame('a=hello%2Fworld', $result);
    }

    // ========================================================================
    // Binding Normalization Tests (v2.3.1+ format: METHOD|PATH|QUERY)
    // ========================================================================

    #[Test]
    public function bindingNormalizeSimple(): void
    {
        $result = Canonicalize::normalizeBinding('POST', '/api/test');
        $this->assertSame('POST|/api/test|', $result);
    }

    #[Test]
    public function bindingNormalizeLowercaseMethod(): void
    {
        $result = Canonicalize::normalizeBinding('post', '/api/test');
        $this->assertSame('POST|/api/test|', $result);
    }

    #[Test]
    public function bindingNormalizeWithQuery(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/api/users', 'page=1&sort=name');
        $this->assertSame('GET|/api/users|page=1&sort=name', $result);
    }

    #[Test]
    public function bindingNormalizeQuerySorted(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/api/users', 'z=1&a=2');
        $this->assertSame('GET|/api/users|a=2&z=1', $result);
    }

    #[Test]
    public function bindingNormalizeCollapseSlashes(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/api//test///path');
        $this->assertSame('GET|/api/test/path|', $result);
    }

    #[Test]
    public function bindingNormalizeRemoveTrailingSlash(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/api/test/');
        $this->assertSame('GET|/api/test|', $result);
    }

    #[Test]
    public function bindingNormalizePreserveRoot(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/');
        $this->assertSame('GET|/|', $result);
    }

    #[Test]
    public function bindingNormalizeAddLeadingSlash(): void
    {
        $result = Canonicalize::normalizeBinding('GET', 'api/test');
        $this->assertSame('GET|/api/test|', $result);
    }

    #[Test]
    public function bindingNormalizeStripFragment(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/api/test#section');
        $this->assertSame('GET|/api/test|', $result);
    }

    // ========================================================================
    // Hash Body Tests (SHA-256 lowercase hex)
    // ========================================================================

    #[Test]
    public function hashBodyKnownValue(): void
    {
        $result = Proof::hashBody('test');
        $this->assertSame('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', $result);
    }

    #[Test]
    public function hashBodyEmpty(): void
    {
        $result = Proof::hashBody('');
        $this->assertSame('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', $result);
    }

    #[Test]
    public function hashBodyFormat(): void
    {
        $result = Proof::hashBody('{"amount":100,"recipient":"user123"}');
        $this->assertSame(64, strlen($result));
        $this->assertSame($result, strtolower($result));
    }

    // ========================================================================
    // Client Secret Derivation Tests (v2.1)
    // ========================================================================

    #[Test]
    public function deriveClientSecretDeterministic(): void
    {
        $secret1 = Proof::deriveClientSecret(self::TEST_NONCE, self::TEST_CONTEXT_ID, self::TEST_BINDING);
        $secret2 = Proof::deriveClientSecret(self::TEST_NONCE, self::TEST_CONTEXT_ID, self::TEST_BINDING);
        $this->assertSame($secret1, $secret2);
    }

    #[Test]
    public function deriveClientSecretFormat(): void
    {
        $secret = Proof::deriveClientSecret(self::TEST_NONCE, self::TEST_CONTEXT_ID, self::TEST_BINDING);
        $this->assertSame(64, strlen($secret));
        $this->assertSame($secret, strtolower($secret));
    }

    #[Test]
    public function deriveClientSecretDifferentInputs(): void
    {
        $secret1 = Proof::deriveClientSecret(self::TEST_NONCE, 'ctx_a', self::TEST_BINDING);
        $secret2 = Proof::deriveClientSecret(self::TEST_NONCE, 'ctx_b', self::TEST_BINDING);
        $this->assertNotSame($secret1, $secret2);
    }

    // ========================================================================
    // v2.1 Proof Tests
    // ========================================================================

    #[Test]
    public function ashBuildProofHmacDeterministic(): void
    {
        $clientSecret = Proof::deriveClientSecret(self::TEST_NONCE, self::TEST_CONTEXT_ID, self::TEST_BINDING);
        $bodyHash = Proof::hashBody('{"amount":100}');

        $proof1 = Proof::ashBuildProofHmac($clientSecret, self::TEST_TIMESTAMP, self::TEST_BINDING, $bodyHash);
        $proof2 = Proof::ashBuildProofHmac($clientSecret, self::TEST_TIMESTAMP, self::TEST_BINDING, $bodyHash);

        $this->assertSame($proof1, $proof2);
    }

    #[Test]
    public function ashBuildProofHmacFormat(): void
    {
        $clientSecret = Proof::deriveClientSecret(self::TEST_NONCE, self::TEST_CONTEXT_ID, self::TEST_BINDING);
        $bodyHash = Proof::hashBody('{"amount":100}');

        $proof = Proof::ashBuildProofHmac($clientSecret, self::TEST_TIMESTAMP, self::TEST_BINDING, $bodyHash);

        $this->assertSame(64, strlen($proof));
        $this->assertSame($proof, strtolower($proof));
    }

    #[Test]
    public function ashVerifyProofValid(): void
    {
        $clientSecret = Proof::deriveClientSecret(self::TEST_NONCE, self::TEST_CONTEXT_ID, self::TEST_BINDING);
        $bodyHash = Proof::hashBody('{"amount":100}');
        $proof = Proof::ashBuildProofHmac($clientSecret, self::TEST_TIMESTAMP, self::TEST_BINDING, $bodyHash);

        $valid = Proof::ashVerifyProof(
            self::TEST_NONCE,
            self::TEST_CONTEXT_ID,
            self::TEST_BINDING,
            self::TEST_TIMESTAMP,
            $bodyHash,
            $proof
        );

        $this->assertTrue($valid);
    }

    #[Test]
    public function ashVerifyProofInvalidProof(): void
    {
        $bodyHash = Proof::hashBody('{"amount":100}');
        $wrongProof = str_repeat('0', 64);

        $valid = Proof::ashVerifyProof(
            self::TEST_NONCE,
            self::TEST_CONTEXT_ID,
            self::TEST_BINDING,
            self::TEST_TIMESTAMP,
            $bodyHash,
            $wrongProof
        );

        $this->assertFalse($valid);
    }

    #[Test]
    public function ashVerifyProofWrongBody(): void
    {
        $clientSecret = Proof::deriveClientSecret(self::TEST_NONCE, self::TEST_CONTEXT_ID, self::TEST_BINDING);
        $bodyHash1 = Proof::hashBody('{"amount":100}');
        $bodyHash2 = Proof::hashBody('{"amount":200}');
        $proof = Proof::ashBuildProofHmac($clientSecret, self::TEST_TIMESTAMP, self::TEST_BINDING, $bodyHash1);

        $valid = Proof::ashVerifyProof(
            self::TEST_NONCE,
            self::TEST_CONTEXT_ID,
            self::TEST_BINDING,
            self::TEST_TIMESTAMP,
            $bodyHash2,
            $proof
        );

        $this->assertFalse($valid);
    }

    // ========================================================================
    // v2.3 Unified Proof Tests (with Scoping and Chaining)
    // ========================================================================

    #[Test]
    public function buildProofUnifiedBasicNoScopeNoChain(): void
    {
        $clientSecret = Proof::deriveClientSecret(self::TEST_NONCE, self::TEST_CONTEXT_ID, self::TEST_BINDING);
        $payload = ['amount' => 100, 'note' => 'test'];

        $result = Proof::ashBuildProofUnified($clientSecret, self::TEST_TIMESTAMP, self::TEST_BINDING, $payload);

        $this->assertSame(64, strlen($result['proof']));
        $this->assertSame('', $result['scopeHash']);
        $this->assertSame('', $result['chainHash']);

        // Verify
        $valid = Proof::ashVerifyProofUnified(
            self::TEST_NONCE,
            self::TEST_CONTEXT_ID,
            self::TEST_BINDING,
            self::TEST_TIMESTAMP,
            $payload,
            $result['proof']
        );
        $this->assertTrue($valid);
    }

    #[Test]
    public function buildProofUnifiedWithScope(): void
    {
        $clientSecret = Proof::deriveClientSecret(self::TEST_NONCE, self::TEST_CONTEXT_ID, self::TEST_BINDING);
        $payload = ['amount' => 100, 'note' => 'test', 'recipient' => 'user123'];
        $scope = ['amount', 'recipient'];

        $result = Proof::ashBuildProofUnified($clientSecret, self::TEST_TIMESTAMP, self::TEST_BINDING, $payload, $scope);

        $this->assertNotSame('', $result['scopeHash']);
        $this->assertSame('', $result['chainHash']);

        // Verify
        $valid = Proof::ashVerifyProofUnified(
            self::TEST_NONCE,
            self::TEST_CONTEXT_ID,
            self::TEST_BINDING,
            self::TEST_TIMESTAMP,
            $payload,
            $result['proof'],
            $scope,
            $result['scopeHash']
        );
        $this->assertTrue($valid);
    }

    #[Test]
    public function buildProofUnifiedWithChain(): void
    {
        $binding = 'POST|/api/confirm|';
        $clientSecret = Proof::deriveClientSecret(self::TEST_NONCE, self::TEST_CONTEXT_ID, $binding);
        $payload = ['confirmed' => true];
        $previousProof = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';

        $result = Proof::ashBuildProofUnified($clientSecret, self::TEST_TIMESTAMP, $binding, $payload, [], $previousProof);

        $this->assertSame('', $result['scopeHash']);
        $this->assertNotSame('', $result['chainHash']);
        $this->assertSame(Proof::hashProof($previousProof), $result['chainHash']);

        // Verify
        $valid = Proof::ashVerifyProofUnified(
            self::TEST_NONCE,
            self::TEST_CONTEXT_ID,
            $binding,
            self::TEST_TIMESTAMP,
            $payload,
            $result['proof'],
            [],
            '',
            $previousProof,
            $result['chainHash']
        );
        $this->assertTrue($valid);
    }

    // ========================================================================
    // Scoped Field Extraction Tests (ENH-003)
    // ========================================================================

    #[Test]
    public function extractScopedFieldsSimple(): void
    {
        $payload = ['amount' => 100, 'note' => 'test', 'recipient' => 'user123'];
        $scope = ['amount', 'recipient'];

        $result = Proof::extractScopedFields($payload, $scope);

        $this->assertSame(100, $result['amount']);
        $this->assertSame('user123', $result['recipient']);
        $this->assertArrayNotHasKey('note', $result);
    }

    #[Test]
    public function extractScopedFieldsNested(): void
    {
        $payload = ['user' => ['name' => 'John', 'email' => 'john@example.com'], 'amount' => 100];
        $scope = ['user.name', 'amount'];

        $result = Proof::extractScopedFields($payload, $scope);

        $this->assertSame(100, $result['amount']);
        $this->assertSame('John', $result['user']['name']);
        $this->assertArrayNotHasKey('email', $result['user']);
    }

    #[Test]
    public function extractScopedFieldsEmptyScope(): void
    {
        $payload = ['amount' => 100, 'note' => 'test'];
        $scope = [];

        $result = Proof::extractScopedFields($payload, $scope);

        $this->assertSame($payload, $result);
    }

    // ========================================================================
    // Hash Proof Tests (for Chaining)
    // ========================================================================

    #[Test]
    public function hashProofDeterministic(): void
    {
        $proof = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';
        $hash1 = Proof::hashProof($proof);
        $hash2 = Proof::hashProof($proof);
        $this->assertSame($hash1, $hash2);
    }

    #[Test]
    public function hashProofFormat(): void
    {
        $proof = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';
        $hash = Proof::hashProof($proof);
        $this->assertSame(64, strlen($hash));
        $this->assertSame($hash, strtolower($hash));
    }

    // ========================================================================
    // Timing-Safe Comparison Tests
    // ========================================================================

    #[Test]
    public function timingSafeEqual(): void
    {
        $this->assertTrue(Compare::timingSafe('hello', 'hello'));
        $this->assertTrue(Compare::timingSafe('', ''));
    }

    #[Test]
    public function timingSafeNotEqual(): void
    {
        $this->assertFalse(Compare::timingSafe('hello', 'world'));
        $this->assertFalse(Compare::timingSafe('hello', 'hello!'));
        $this->assertFalse(Compare::timingSafe('hello', ''));
    }

    // ========================================================================
    // Fixed Test Vectors
    // ========================================================================

    #[Test]
    public function fixedVectorClientSecret(): void
    {
        $nonce = str_repeat('a', 64);
        $contextId = 'ash_fixed_test_001';
        $binding = 'POST|/api/test|';

        $secret = Proof::deriveClientSecret($nonce, $contextId, $binding);

        $this->assertSame(64, strlen($secret));
        $secret2 = Proof::deriveClientSecret($nonce, $contextId, $binding);
        $this->assertSame($secret, $secret2);
    }

    #[Test]
    public function fixedVectorBodyHash(): void
    {
        $payload = ['amount' => 100, 'recipient' => 'user123'];
        $canonical = Canonicalize::json($payload);
        $hash = Proof::hashBody($canonical);

        $this->assertSame('{"amount":100,"recipient":"user123"}', $canonical);
        $this->assertSame(64, strlen($hash));
    }
}
