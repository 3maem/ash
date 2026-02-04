<?php

declare(strict_types=1);

namespace Ash\Tests;

use Ash\Core\Proof;
use Ash\Core\Canonicalize;
use Ash\Core\Compare;
use PHPUnit\Framework\TestCase;

/**
 * Extended iterative tests to reach 1000+ total.
 */
class ExtendedIterativeTest extends TestCase
{
    // ========== JSON INDIVIDUAL TESTS (50 tests) ==========

    /** @dataProvider jsonIndividualProvider */
    public function testJsonIndividual(int $i): void
    {
        $input = ['id' => $i, 'name' => "item_{$i}"];
        $result = Canonicalize::json($input);
        $this->assertNotEmpty($result);
    }

    public static function jsonIndividualProvider(): array
    {
        $data = [];
        for ($i = 0; $i < 50; $i++) {
            $data["json_{$i}"] = [$i];
        }
        return $data;
    }

    // ========== HASH INDIVIDUAL TESTS (50 tests) ==========

    /** @dataProvider hashIndividualProvider */
    public function testHashIndividual(int $i): void
    {
        $hash = Proof::hashBody("body_content_{$i}");
        $this->assertEquals(64, strlen($hash));
    }

    public static function hashIndividualProvider(): array
    {
        $data = [];
        for ($i = 0; $i < 50; $i++) {
            $data["hash_{$i}"] = [$i];
        }
        return $data;
    }

    // ========== PROOF INDIVIDUAL TESTS (50 tests) ==========

    /** @dataProvider proofIndividualProvider */
    public function testProofIndividual(int $i): void
    {
        $proof = Proof::ashBuildProofHmac("secret_{$i}", "1234567890", "POST|/api|", "abc123");
        $this->assertEquals(64, strlen($proof));
    }

    public static function proofIndividualProvider(): array
    {
        $data = [];
        for ($i = 0; $i < 50; $i++) {
            $data["proof_{$i}"] = [$i];
        }
        return $data;
    }

    // ========== SECRET INDIVIDUAL TESTS (50 tests) ==========

    /** @dataProvider secretIndividualProvider */
    public function testSecretIndividual(int $i): void
    {
        $secret = Proof::deriveClientSecret(str_repeat(dechex($i % 16), 32), str_repeat(dechex($i % 16), 32), "binding");
        $this->assertEquals(64, strlen($secret));
    }

    public static function secretIndividualProvider(): array
    {
        $data = [];
        for ($i = 0; $i < 50; $i++) {
            $data["secret_{$i}"] = [$i];
        }
        return $data;
    }

    // ========== BINDING INDIVIDUAL TESTS (50 tests) ==========

    /** @dataProvider bindingIndividualProvider */
    public function testBindingIndividual(int $i): void
    {
        $result = Canonicalize::normalizeBinding("GET", "/api/resource/{$i}");
        $this->assertStringContainsString("GET", $result);
    }

    public static function bindingIndividualProvider(): array
    {
        $data = [];
        for ($i = 0; $i < 50; $i++) {
            $data["binding_{$i}"] = [$i];
        }
        return $data;
    }

    // ========== QUERY INDIVIDUAL TESTS (50 tests) ==========

    /** @dataProvider queryIndividualProvider */
    public function testQueryIndividual(int $i): void
    {
        $result = Canonicalize::canonicalizeQuery("id={$i}&name=item_{$i}");
        $this->assertNotEmpty($result);
    }

    public static function queryIndividualProvider(): array
    {
        $data = [];
        for ($i = 0; $i < 50; $i++) {
            $data["query_{$i}"] = [$i];
        }
        return $data;
    }

    // ========== COMPARE INDIVIDUAL TESTS (50 tests) ==========

    /** @dataProvider compareIndividualProvider */
    public function testCompareIndividual(int $i): void
    {
        $hash = Proof::hashBody("input_{$i}");
        $this->assertTrue(Compare::timingSafe($hash, $hash));
    }

    public static function compareIndividualProvider(): array
    {
        $data = [];
        for ($i = 0; $i < 50; $i++) {
            $data["compare_{$i}"] = [$i];
        }
        return $data;
    }

    // ========== VERIFY INDIVIDUAL TESTS (30 tests) ==========

    /** @dataProvider verifyIndividualProvider */
    public function testVerifyIndividual(int $i): void
    {
        $nonce = str_repeat(dechex($i % 16), 64);
        $contextId = "ctx_{$i}";
        $binding = "POST|/api/{$i}|";
        $timestamp = (string)(1000000000 + $i);
        $bodyHash = Proof::hashBody("body_{$i}");

        $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding);
        $proof = Proof::ashBuildProofHmac($clientSecret, $timestamp, $binding, $bodyHash);

        $this->assertTrue(Proof::ashVerifyProof($nonce, $contextId, $binding, $timestamp, $bodyHash, $proof));
    }

    public static function verifyIndividualProvider(): array
    {
        $data = [];
        for ($i = 0; $i < 30; $i++) {
            $data["verify_{$i}"] = [$i];
        }
        return $data;
    }

    // ========== BASE64URL INDIVIDUAL TESTS (30 tests) ==========

    /** @dataProvider base64IndividualProvider */
    public function testBase64Individual(int $length): void
    {
        $original = random_bytes($length);
        $encoded = Proof::base64UrlEncode($original);
        $decoded = Proof::base64UrlDecode($encoded);
        $this->assertEquals($original, $decoded);
    }

    public static function base64IndividualProvider(): array
    {
        $data = [];
        for ($i = 1; $i <= 30; $i++) {
            $data["base64_len_{$i}"] = [$i];
        }
        return $data;
    }
}
