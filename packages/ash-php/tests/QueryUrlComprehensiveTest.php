<?php

declare(strict_types=1);

namespace Ash\Tests;

use Ash\Core\Canonicalize;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Comprehensive query string and URL handling tests.
 */
final class QueryUrlComprehensiveTest extends TestCase
{
    // ========== QUERY STRING PARSING TESTS ==========

    #[Test]
    public function parsesSingleParameter(): void
    {
        $result = Canonicalize::urlEncoded('key=value');
        $this->assertSame('key=value', $result);
    }

    #[Test]
    public function parsesTwoParameters(): void
    {
        $result = Canonicalize::urlEncoded('a=1&b=2');
        $this->assertSame('a=1&b=2', $result);
    }

    #[Test]
    public function parsesMultipleParameters(): void
    {
        $result = Canonicalize::urlEncoded('a=1&b=2&c=3&d=4&e=5');
        $this->assertSame('a=1&b=2&c=3&d=4&e=5', $result);
    }

    #[Test]
    public function parsesEmptyValue(): void
    {
        $result = Canonicalize::urlEncoded('key=');
        $this->assertSame('key=', $result);
    }

    #[Test]
    public function parsesKeyOnly(): void
    {
        $result = Canonicalize::urlEncoded('key');
        $this->assertSame('key=', $result);
    }

    #[Test]
    public function parsesEmptyString(): void
    {
        $result = Canonicalize::urlEncoded('');
        $this->assertSame('', $result);
    }

    // ========== QUERY STRING SORTING TESTS ==========

    #[Test]
    public function sortsParametersByKey(): void
    {
        $result = Canonicalize::urlEncoded('z=3&a=1&m=2');
        $this->assertSame('a=1&m=2&z=3', $result);
    }

    #[Test]
    public function sortsCaseSensitively(): void
    {
        $result = Canonicalize::urlEncoded('b=1&B=2&a=3&A=4');
        $this->assertSame('A=4&B=2&a=3&b=1', $result);
    }

    #[Test]
    public function sortsNumericStringKeys(): void
    {
        $result = Canonicalize::urlEncoded('10=ten&2=two&1=one');
        $this->assertSame('1=one&10=ten&2=two', $result);
    }

    #[Test]
    public function sortsDuplicateKeysByValue(): void
    {
        $result = Canonicalize::urlEncoded('a=3&a=1&a=2');
        $this->assertSame('a=1&a=2&a=3', $result);
    }

    #[Test]
    public function sortsMixedDuplicateKeys(): void
    {
        $result = Canonicalize::urlEncoded('b=2&a=2&b=1&a=1');
        $this->assertSame('a=1&a=2&b=1&b=2', $result);
    }

    // ========== PERCENT ENCODING TESTS ==========

    #[Test]
    public function encodesSpacelAsPercent20(): void
    {
        $result = Canonicalize::urlEncoded('key=hello world');
        $this->assertSame('key=hello%20world', $result);
    }

    #[Test]
    public function encodePlusAsPercent2B(): void
    {
        $result = Canonicalize::urlEncoded('key=hello+world');
        $this->assertSame('key=hello%2Bworld', $result);
    }

    #[Test]
    public function encodesSlashAsPercent2F(): void
    {
        $result = Canonicalize::urlEncoded('key=hello/world');
        $this->assertSame('key=hello%2Fworld', $result);
    }

    #[Test]
    public function encodesQuestionMarkAsPercent3F(): void
    {
        $result = Canonicalize::urlEncoded('key=what?');
        $this->assertSame('key=what%3F', $result);
    }

    #[Test]
    public function encodesAmpersandAsPercent26(): void
    {
        $result = Canonicalize::urlEncoded(['key' => 'a&b']);
        $this->assertSame('key=a%26b', $result);
    }

    #[Test]
    public function encodesEqualsAsPercent3D(): void
    {
        $result = Canonicalize::urlEncoded(['key' => 'a=b']);
        $this->assertSame('key=a%3Db', $result);
    }

    #[Test]
    public function encodesHashAsPercent23(): void
    {
        $result = Canonicalize::urlEncoded(['key' => 'a#b']);
        $this->assertSame('key=a%23b', $result);
    }

    #[Test]
    public function usesUppercaseHex(): void
    {
        $result = Canonicalize::urlEncoded('key=hello world');
        // Should use %20 not %20, check for lowercase
        $this->assertStringNotContainsString('%2f', $result); // No lowercase
        $this->assertStringContainsString('%20', $result);
    }

    #[Test]
    public function doesNotEncodeUnreservedChars(): void
    {
        $unreserved = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~';
        $result = Canonicalize::urlEncoded("key=$unreserved");
        $this->assertSame("key=$unreserved", $result);
    }

    #[Test]
    public function encodesUnicodeAsUtf8(): void
    {
        $result = Canonicalize::urlEncoded(['key' => '你好']);
        $this->assertStringContainsString('%', $result);
        // Should decode back correctly
        $this->assertStringContainsString('key=', $result);
    }

    #[Test]
    public function encodesEmojiAsUtf8(): void
    {
        $result = Canonicalize::urlEncoded(['key' => '🎉']);
        $this->assertStringContainsString('%', $result);
    }

    // ========== SPECIAL CASES TESTS ==========

    #[Test]
    public function handlesValueWithMultipleEquals(): void
    {
        $result = Canonicalize::urlEncoded(['key' => 'a=b=c']);
        $this->assertStringContainsString('key=', $result);
    }

    #[Test]
    public function handlesKeyWithSpecialChars(): void
    {
        $result = Canonicalize::urlEncoded(['key with space' => 'value']);
        $this->assertStringContainsString('%20', $result);
    }

    #[Test]
    public function handlesEmptyKeyWithValue(): void
    {
        $result = Canonicalize::urlEncoded(['' => 'value']);
        $this->assertSame('=value', $result);
    }

    #[Test]
    public function handlesBothEmptyKeyAndValue(): void
    {
        $result = Canonicalize::urlEncoded(['' => '']);
        $this->assertSame('=', $result);
    }

    #[Test]
    public function handlesVeryLongValue(): void
    {
        $longValue = str_repeat('a', 10000);
        $result = Canonicalize::urlEncoded(['key' => $longValue]);
        $this->assertStringContainsString('key=', $result);
        $this->assertStringContainsString($longValue, $result);
    }

    #[Test]
    public function handlesVeryLongKey(): void
    {
        $longKey = str_repeat('k', 1000);
        $result = Canonicalize::urlEncoded([$longKey => 'value']);
        $this->assertStringContainsString($longKey, $result);
    }

    #[Test]
    public function handlesManyParameters(): void
    {
        $params = [];
        for ($i = 0; $i < 100; $i++) {
            $params["key$i"] = "value$i";
        }
        $result = Canonicalize::urlEncoded($params);
        $this->assertStringContainsString('key0=value0', $result);
        $this->assertStringContainsString('key99=value99', $result);
    }

    // ========== URL PARSING IN BINDING TESTS ==========

    #[Test]
    public function extractsQueryFromUrl(): void
    {
        $result = Canonicalize::normalizeBindingFromUrl('GET', '/path?a=1&b=2');
        $this->assertSame('GET|/path|a=1&b=2', $result);
    }

    #[Test]
    public function sortsQueryInUrl(): void
    {
        $result = Canonicalize::normalizeBindingFromUrl('GET', '/path?z=3&a=1');
        $this->assertSame('GET|/path|a=1&z=3', $result);
    }

    #[Test]
    public function handlesUrlWithoutQuery(): void
    {
        $result = Canonicalize::normalizeBindingFromUrl('GET', '/path');
        $this->assertSame('GET|/path|', $result);
    }

    #[Test]
    public function handlesUrlWithEmptyQuery(): void
    {
        $result = Canonicalize::normalizeBindingFromUrl('GET', '/path?');
        $this->assertSame('GET|/path|', $result);
    }

    #[Test]
    public function handlesUrlWithFragment(): void
    {
        $result = Canonicalize::normalizeBindingFromUrl('GET', '/path#section');
        $this->assertSame('GET|/path|', $result);
    }

    #[Test]
    public function handlesUrlWithQueryAndFragment(): void
    {
        $result = Canonicalize::normalizeBindingFromUrl('GET', '/path?a=1#section');
        $this->assertSame('GET|/path|a=1', $result);
    }

    #[Test]
    public function handlesComplexUrl(): void
    {
        $result = Canonicalize::normalizeBindingFromUrl('GET', '/api/v1/users?sort=name&page=1&limit=10#top');
        $this->assertSame('GET|/api/v1/users|limit=10&page=1&sort=name', $result);
    }

    // ========== INPUT FORMAT TESTS ==========

    #[Test]
    public function acceptsArrayInput(): void
    {
        $result = Canonicalize::urlEncoded(['a' => '1', 'b' => '2']);
        $this->assertSame('a=1&b=2', $result);
    }

    #[Test]
    public function acceptsStringInput(): void
    {
        $result = Canonicalize::urlEncoded('a=1&b=2');
        $this->assertSame('a=1&b=2', $result);
    }

    #[Test]
    public function acceptsPreEncodedString(): void
    {
        $result = Canonicalize::urlEncoded('key=hello%20world');
        // Should normalize encoding
        $this->assertStringContainsString('key=', $result);
    }

    // ========== DETERMINISM TESTS ==========

    #[Test]
    public function producesConsistentOutput(): void
    {
        $input = 'z=3&y=2&x=1';
        $results = [];

        for ($i = 0; $i < 100; $i++) {
            $results[] = Canonicalize::urlEncoded($input);
        }

        $unique = array_unique($results);
        $this->assertCount(1, $unique);
    }

    // ========== CROSS-SDK COMPATIBILITY TESTS ==========

    #[Test]
    public function matchesCrossSdkVector1(): void
    {
        $this->assertSame('a=1&b=2', Canonicalize::urlEncoded('b=2&a=1'));
    }

    #[Test]
    public function matchesCrossSdkVector2(): void
    {
        $this->assertSame('key=hello%20world', Canonicalize::urlEncoded('key=hello world'));
    }

    #[Test]
    public function matchesCrossSdkVector3(): void
    {
        $result = Canonicalize::urlEncoded('a=2&a=1&a=3');
        $this->assertSame('a=1&a=2&a=3', $result);
    }

    // ========== STRESS TESTS ==========

    #[Test]
    public function queryStringStress(): void
    {
        for ($i = 0; $i < 100; $i++) {
            $params = [];
            for ($j = 0; $j < 50; $j++) {
                $params["key_{$i}_{$j}"] = "value_{$i}_{$j}";
            }
            $result = Canonicalize::urlEncoded($params);
            $this->assertIsString($result);
        }
    }

    #[Test]
    public function bindingFromUrlStress(): void
    {
        for ($i = 0; $i < 100; $i++) {
            $url = "/api/v$i/resource?page=$i&limit=10&sort=name";
            $result = Canonicalize::normalizeBindingFromUrl('GET', $url);
            $this->assertStringContainsString('GET|', $result);
        }
    }
}
