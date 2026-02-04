<?php

declare(strict_types=1);

namespace Ash\Tests;

use Ash\Ash;
use Ash\Core\AshMode;
use Ash\Core\BuildProofInput;
use Ash\Core\Canonicalize;
use Ash\Core\Compare;
use Ash\Core\Proof;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Comprehensive stress and performance tests.
 */
final class StressComprehensiveTest extends TestCase
{
    // ========== JSON CANONICALIZATION STRESS ==========

    #[Test]
    public function jsonCanonicalizeStress1000(): void
    {
        for ($i = 0; $i < 1000; $i++) {
            $input = ['key' => $i, 'nested' => ['value' => $i * 2]];
            $result = Canonicalize::json($input);
            $this->assertIsString($result);
        }
    }

    #[Test]
    public function jsonCanonicalizeDeepNesting(): void
    {
        for ($depth = 1; $depth <= 50; $depth++) {
            $input = [];
            $current = &$input;
            for ($i = 0; $i < $depth; $i++) {
                $current['level'] = [];
                $current = &$current['level'];
            }
            $current['value'] = 'deep';

            $result = Canonicalize::json($input);
            $this->assertStringContainsString('"value":"deep"', $result);
        }
    }

    #[Test]
    public function jsonCanonicalizeWideObject(): void
    {
        for ($width = 10; $width <= 500; $width += 10) {
            $input = [];
            for ($i = 0; $i < $width; $i++) {
                $input["key_$i"] = $i;
            }
            $result = Canonicalize::json($input);
            $this->assertIsString($result);
        }
    }

    #[Test]
    public function jsonCanonicalizeLongStrings(): void
    {
        $lengths = [100, 1000, 5000, 10000];

        foreach ($lengths as $len) {
            $input = ['data' => str_repeat('a', $len)];
            $result = Canonicalize::json($input);
            $this->assertStringContainsString(str_repeat('a', $len), $result);
        }
    }

    #[Test]
    public function jsonCanonicalizeUnicodeStress(): void
    {
        $unicodeChars = ['你好', 'مرحبا', 'שלום', 'Привет', '🎉🚀', 'café'];

        for ($i = 0; $i < 100; $i++) {
            $input = [];
            foreach ($unicodeChars as $idx => $char) {
                $input["key_{$idx}_{$i}"] = $char . $i;
            }
            $result = Canonicalize::json($input);
            $this->assertIsString($result);
        }
    }

    // ========== URL ENCODING STRESS ==========

    #[Test]
    public function urlEncodedStress1000(): void
    {
        for ($i = 0; $i < 1000; $i++) {
            $input = "key$i=value$i&other=test";
            $result = Canonicalize::urlEncoded($input);
            $this->assertIsString($result);
        }
    }

    #[Test]
    public function urlEncodedManyParams(): void
    {
        for ($count = 10; $count <= 200; $count += 10) {
            $params = [];
            for ($i = 0; $i < $count; $i++) {
                $params["param_$i"] = "value_$i";
            }
            $result = Canonicalize::urlEncoded($params);
            $this->assertIsString($result);
        }
    }

    #[Test]
    public function urlEncodedSpecialCharsStress(): void
    {
        $specials = ' +/=&?#%';

        for ($i = 0; $i < 100; $i++) {
            $value = '';
            for ($j = 0; $j < 10; $j++) {
                $value .= $specials[array_rand(str_split($specials))] . chr(65 + ($j % 26));
            }
            $result = Canonicalize::urlEncoded(['key' => $value]);
            $this->assertIsString($result);
        }
    }

    // ========== BINDING NORMALIZATION STRESS ==========

    #[Test]
    public function bindingNormalizationStress1000(): void
    {
        $methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];

        for ($i = 0; $i < 1000; $i++) {
            $method = $methods[$i % count($methods)];
            $path = "/api/v1/resource/$i";
            $query = "page=$i&limit=10";

            $result = Canonicalize::normalizeBinding($method, $path, $query);
            $this->assertStringContainsString($method, $result);
        }
    }

    #[Test]
    public function bindingNormalizationLongPaths(): void
    {
        for ($segments = 1; $segments <= 50; $segments++) {
            $path = '/' . implode('/', array_fill(0, $segments, 'segment'));
            $result = Canonicalize::normalizeBinding('GET', $path);
            $this->assertStringContainsString('GET|/', $result);
        }
    }

    // ========== PROOF GENERATION STRESS ==========

    #[Test]
    public function proofGenerationStress1000(): void
    {
        for ($i = 0; $i < 1000; $i++) {
            $proof = Proof::ashBuildProofHmac(
                "secret_$i",
                (string)(1000000000 + $i),
                "POST|/api/$i|",
                hash('sha256', "body_$i")
            );
            $this->assertSame(64, strlen($proof));
        }
    }

    #[Test]
    public function proofVerificationStress500(): void
    {
        $nonce = str_repeat('a', 64);
        $contextId = 'ctx_stress_verify';

        for ($i = 0; $i < 500; $i++) {
            $timestamp = (string)(1000000000 + $i);
            $binding = "POST|/api/resource/$i|";
            $bodyHash = Proof::hashBody("content_$i");

            $clientSecret = Proof::deriveClientSecret($nonce, $contextId, $binding);
            $proof = Proof::ashBuildProofHmac($clientSecret, $timestamp, $binding, $bodyHash);
            $verified = Proof::ashVerifyProof($nonce, $contextId, $binding, $timestamp, $bodyHash, $proof);

            $this->assertTrue($verified);
        }
    }

    #[Test]
    public function proofBuildInputStress(): void
    {
        for ($i = 0; $i < 500; $i++) {
            $input = new BuildProofInput(
                mode: AshMode::Balanced,
                binding: "POST|/api/$i|",
                contextId: "ctx_$i",
                canonicalPayload: Canonicalize::json(['iteration' => $i])
            );

            $proof = Proof::build($input);
            $this->assertNotEmpty($proof);
        }
    }

    // ========== HASH GENERATION STRESS ==========

    #[Test]
    public function hashBodyStress1000(): void
    {
        for ($i = 0; $i < 1000; $i++) {
            $hash = Proof::hashBody("body content iteration $i " . str_repeat('x', $i % 100));
            $this->assertSame(64, strlen($hash));
        }
    }

    #[Test]
    public function hashLargeBodyStress(): void
    {
        $sizes = [1000, 5000, 10000, 50000, 100000];

        foreach ($sizes as $size) {
            $body = str_repeat('a', $size);
            $hash = Proof::hashBody($body);
            $this->assertSame(64, strlen($hash));
        }
    }

    // ========== SCOPED PROOF STRESS ==========

    #[Test]
    public function scopedProofStress500(): void
    {
        for ($i = 0; $i < 500; $i++) {
            $payload = [
                'id' => $i,
                'name' => "user_$i",
                'email' => "user$i@example.com",
                'extra' => str_repeat('x', 100)
            ];
            $scope = ['id', 'name'];

            $result = Proof::ashBuildProofScoped(
                "secret_$i",
                (string)(1000000000 + $i),
                "POST|/api/$i|",
                $payload,
                $scope
            );

            $this->assertArrayHasKey('proof', $result);
            $this->assertArrayHasKey('scopeHash', $result);
        }
    }

    #[Test]
    public function scopedProofVerificationStress(): void
    {
        $nonce = str_repeat('b', 64);
        $contextId = 'ctx_scoped_stress';

        for ($i = 0; $i < 200; $i++) {
            $payload = ['field' => "value_$i"];
            $scope = ['field'];
            $timestamp = (string)(1000000000 + $i);
            $binding = "POST|/api/$i|";

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
    }

    // ========== UNIFIED PROOF CHAIN STRESS ==========

    #[Test]
    public function unifiedProofChainStress(): void
    {
        $secret = 'chain-stress-secret';
        $previousProof = null;

        for ($i = 0; $i < 100; $i++) {
            $result = Proof::ashBuildProofUnified(
                $secret,
                (string)(1000000000 + $i),
                "POST|/api/step$i|",
                ['step' => $i],
                ['step'],
                $previousProof
            );

            $this->assertArrayHasKey('proof', $result);
            $previousProof = $result['proof'];
        }
    }

    // ========== TIMING SAFE COMPARISON STRESS ==========

    #[Test]
    public function timingSafeCompareStress1000(): void
    {
        for ($i = 0; $i < 1000; $i++) {
            $str = hash('sha256', "test_$i");
            $this->assertTrue(Compare::timingSafe($str, $str));
        }
    }

    #[Test]
    public function timingSafeCompareUnequalStress(): void
    {
        for ($i = 0; $i < 1000; $i++) {
            $str1 = hash('sha256', "test_$i");
            $str2 = hash('sha256', "different_$i");
            $this->assertFalse(Compare::timingSafe($str1, $str2));
        }
    }

    // ========== BASE64URL STRESS ==========

    #[Test]
    public function base64UrlRoundTripStress(): void
    {
        for ($i = 0; $i < 1000; $i++) {
            $original = random_bytes(32 + ($i % 100));
            $encoded = Proof::base64UrlEncode($original);
            $decoded = Proof::base64UrlDecode($encoded);
            $this->assertSame($original, $decoded);
        }
    }

    // ========== CLIENT SECRET DERIVATION STRESS ==========

    #[Test]
    public function clientSecretDerivationStress(): void
    {
        for ($i = 0; $i < 1000; $i++) {
            $secret = Proof::deriveClientSecret(sprintf('%032x', $i) . sprintf('%032x', $i + 1000), sprintf('%032x', $i) . sprintf('%032x', $i + 2000), 'POST|/api|');
            $this->assertSame(64, strlen($secret));
        }
    }

    // ========== CONCURRENT ACCESS SIMULATION ==========

    #[Test]
    public function simulatedConcurrentProofGeneration(): void
    {
        $results = [];

        for ($i = 0; $i < 100; $i++) {
            // Simulate different "threads" generating proofs
            $results[] = Proof::ashBuildProofHmac(
                "secret_thread_$i",
                (string)time(),
                "POST|/api/concurrent|",
                hash('sha256', "body_$i")
            );
        }

        // All proofs should be unique
        $unique = array_unique($results);
        $this->assertCount(100, $unique);
    }

    // ========== MEMORY STRESS ==========

    #[Test]
    public function memoryStressLargePayload(): void
    {
        // Process multiple large payloads
        for ($i = 0; $i < 10; $i++) {
            $largePayload = [];
            for ($j = 0; $j < 1000; $j++) {
                $largePayload["key_$j"] = str_repeat("value_$j", 10);
            }

            $canonical = Canonicalize::json($largePayload);
            $hash = Proof::hashBody($canonical);

            $this->assertSame(64, strlen($hash));
        }
    }

    // ========== EDGE CASE STRESS ==========

    #[Test]
    public function emptyInputsStress(): void
    {
        for ($i = 0; $i < 100; $i++) {
            $this->assertSame('{}', Canonicalize::json((object)[]));
            $this->assertSame('[]', Canonicalize::json([]));
            $this->assertSame('""', Canonicalize::json(''));
            $this->assertSame('null', Canonicalize::json(null));
        }
    }

    #[Test]
    public function specialCharactersStress(): void
    {
        $specials = [
            "\"quotes\"",
            "back\\slash",
            "new\nline",
            "tab\there",
            "null\x00char",
            "🎉emoji🚀",
            "中文字符",
            "العربية",
        ];

        for ($i = 0; $i < 100; $i++) {
            foreach ($specials as $special) {
                $result = Canonicalize::json(['data' => $special]);
                $this->assertIsString($result);
            }
        }
    }

    // ========== COMBINED WORKFLOW STRESS ==========

    #[Test]
    public function fullWorkflowStress(): void
    {
        $nonce = str_repeat('c', 64);
        $contextId = 'ctx_workflow';

        for ($i = 0; $i < 100; $i++) {
            // 1. Canonicalize JSON payload
            $payload = ['action' => 'update', 'id' => $i, 'data' => "value_$i"];
            $canonical = Canonicalize::json($payload);

            // 2. Normalize binding
            $binding = Canonicalize::normalizeBinding('POST', "/api/resource/$i", "version=$i");

            // 3. Hash body
            $bodyHash = Proof::hashBody($canonical);

            // 4. Build proof
            $secret = Proof::deriveClientSecret($nonce, $contextId, $binding);
            $timestamp = (string)(1000000000 + $i);
            $proof = Proof::ashBuildProofHmac($secret, $timestamp, $binding, $bodyHash);

            // 5. Verify proof
            $verified = Proof::ashVerifyProof($nonce, $contextId, $binding, $timestamp, $bodyHash, $proof);

            $this->assertTrue($verified);
        }
    }
}
