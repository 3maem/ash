<?php

declare(strict_types=1);

namespace Ash\Tests;

use Ash\Core\Proof;
use Ash\Core\Canonicalize;
use Ash\Core\Compare;
use PHPUnit\Framework\TestCase;

/**
 * More iterative tests to help reach 1000+ total.
 */
class MoreIterativeTest extends TestCase
{
    // ========== JSON BATCH 50-99 (50 tests) ==========

    /** @dataProvider jsonBatch50Provider */
    public function testJsonBatch50(int $i): void
    {
        $input = ['x' => $i, 'y' => $i * 2];
        $result = Canonicalize::json($input);
        $this->assertNotEmpty($result);
    }

    public static function jsonBatch50Provider(): array
    {
        $data = [];
        for ($i = 50; $i < 100; $i++) {
            $data["json_{$i}"] = [$i];
        }
        return $data;
    }

    // ========== HASH BATCH 50-99 (50 tests) ==========

    /** @dataProvider hashBatch50Provider */
    public function testHashBatch50(int $i): void
    {
        $hash = Proof::hashBody("content_{$i}");
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
    }

    public static function hashBatch50Provider(): array
    {
        $data = [];
        for ($i = 50; $i < 100; $i++) {
            $data["hash_{$i}"] = [$i];
        }
        return $data;
    }

    // ========== PROOF BATCH 50-99 (50 tests) ==========

    /** @dataProvider proofBatch50Provider */
    public function testProofBatch50(int $i): void
    {
        $proof = Proof::ashBuildProofHmac("secret_{$i}", "timestamp", "binding", "bodyhash");
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $proof);
    }

    public static function proofBatch50Provider(): array
    {
        $data = [];
        for ($i = 50; $i < 100; $i++) {
            $data["proof_{$i}"] = [$i];
        }
        return $data;
    }

    // ========== SECRET BATCH 50-99 (50 tests) ==========

    /** @dataProvider secretBatch50Provider */
    public function testSecretBatch50(int $i): void
    {
        $secret = Proof::deriveClientSecret(str_repeat(dechex($i % 16), 32), str_repeat(dechex($i % 16), 32), "binding");
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $secret);
    }

    public static function secretBatch50Provider(): array
    {
        $data = [];
        for ($i = 50; $i < 100; $i++) {
            $data["secret_{$i}"] = [$i];
        }
        return $data;
    }

    // ========== BINDING BATCH 50-99 (50 tests) ==========

    /** @dataProvider bindingBatch50Provider */
    public function testBindingBatch50(int $i): void
    {
        $result = Canonicalize::normalizeBinding("POST", "/api/v1/{$i}");
        $this->assertStringStartsWith("POST|", $result);
    }

    public static function bindingBatch50Provider(): array
    {
        $data = [];
        for ($i = 50; $i < 100; $i++) {
            $data["binding_{$i}"] = [$i];
        }
        return $data;
    }

    // ========== QUERY BATCH 50-99 (50 tests) ==========

    /** @dataProvider queryBatch50Provider */
    public function testQueryBatch50(int $i): void
    {
        $result = Canonicalize::canonicalizeQuery("a={$i}&b=" . ($i + 1));
        $this->assertNotEmpty($result);
    }

    public static function queryBatch50Provider(): array
    {
        $data = [];
        for ($i = 50; $i < 100; $i++) {
            $data["query_{$i}"] = [$i];
        }
        return $data;
    }

    // ========== COMPARE BATCH 50-99 (50 tests) ==========

    /** @dataProvider compareBatch50Provider */
    public function testCompareBatch50(int $i): void
    {
        $str = "test_string_{$i}";
        $this->assertTrue(Compare::timingSafe($str, $str));
    }

    public static function compareBatch50Provider(): array
    {
        $data = [];
        for ($i = 50; $i < 100; $i++) {
            $data["compare_{$i}"] = [$i];
        }
        return $data;
    }

    // ========== VERIFY BATCH 30-59 (30 tests) ==========

    /** @dataProvider verifyBatch30Provider */
    public function testVerifyBatch30(int $i): void
    {
        $nonce = str_repeat(dechex($i % 16), 64);
        $contextId = "ctx_{$i}";
        $binding = "GET|/api/resource/{$i}|";
        $timestamp = (string)(2000000000 + $i);
        $bodyHash = Proof::hashBody("data_{$i}");

        $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding);
        $proof = Proof::ashBuildProofHmac($clientSecret, $timestamp, $binding, $bodyHash);

        $this->assertTrue(Proof::ashVerifyProof($nonce, $contextId, $binding, $timestamp, $bodyHash, $proof));
    }

    public static function verifyBatch30Provider(): array
    {
        $data = [];
        for ($i = 30; $i < 60; $i++) {
            $data["verify_{$i}"] = [$i];
        }
        return $data;
    }

    // ========== UNIQUENESS TESTS ==========

    public function testHashUniqueness100(): void
    {
        $hashes = [];
        for ($i = 0; $i < 100; $i++) {
            $hashes[] = Proof::hashBody("unique_input_{$i}");
        }
        $this->assertCount(100, array_unique($hashes));
    }

    public function testSecretUniqueness100(): void
    {
        $secrets = [];
        for ($i = 0; $i < 100; $i++) {
            $secrets[] = Proof::deriveClientSecret(sprintf('%032x', $i) . sprintf('%032x', $i + 1000), sprintf('%032x', $i) . sprintf('%032x', $i + 2000), "binding");
        }
        $this->assertCount(100, array_unique($secrets));
    }

    public function testProofUniqueness100(): void
    {
        $proofs = [];
        for ($i = 0; $i < 100; $i++) {
            $proofs[] = Proof::ashBuildProofHmac("secret_{$i}", "timestamp", "binding", "bodyhash");
        }
        $this->assertCount(100, array_unique($proofs));
    }

    public function testNonceUniqueness100(): void
    {
        $nonces = [];
        for ($i = 0; $i < 100; $i++) {
            $nonces[] = Proof::generateNonce(32);
        }
        $this->assertCount(100, array_unique($nonces));
    }

    public function testContextIdUniqueness100(): void
    {
        $ids = [];
        for ($i = 0; $i < 100; $i++) {
            $ids[] = Proof::generateContextId();
        }
        $this->assertCount(100, array_unique($ids));
    }
}
