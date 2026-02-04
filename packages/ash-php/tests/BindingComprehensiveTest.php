<?php

declare(strict_types=1);

namespace Ash\Tests;

use Ash\Core\Canonicalize;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Comprehensive binding normalization tests.
 */
final class BindingComprehensiveTest extends TestCase
{
    // ========== HTTP METHOD TESTS ==========

    #[Test]
    public function normalizeGetMethod(): void
    {
        $this->assertSame('GET|/path|', Canonicalize::normalizeBinding('GET', '/path'));
    }

    #[Test]
    public function normalizePostMethod(): void
    {
        $this->assertSame('POST|/path|', Canonicalize::normalizeBinding('POST', '/path'));
    }

    #[Test]
    public function normalizePutMethod(): void
    {
        $this->assertSame('PUT|/path|', Canonicalize::normalizeBinding('PUT', '/path'));
    }

    #[Test]
    public function normalizeDeleteMethod(): void
    {
        $this->assertSame('DELETE|/path|', Canonicalize::normalizeBinding('DELETE', '/path'));
    }

    #[Test]
    public function normalizePatchMethod(): void
    {
        $this->assertSame('PATCH|/path|', Canonicalize::normalizeBinding('PATCH', '/path'));
    }

    #[Test]
    public function normalizeOptionsMethod(): void
    {
        $this->assertSame('OPTIONS|/path|', Canonicalize::normalizeBinding('OPTIONS', '/path'));
    }

    #[Test]
    public function normalizeHeadMethod(): void
    {
        $this->assertSame('HEAD|/path|', Canonicalize::normalizeBinding('HEAD', '/path'));
    }

    #[Test]
    public function uppercasesLowercaseMethod(): void
    {
        $this->assertSame('GET|/path|', Canonicalize::normalizeBinding('get', '/path'));
    }

    #[Test]
    public function uppercasesMixedCaseMethod(): void
    {
        $this->assertSame('POST|/path|', Canonicalize::normalizeBinding('PoSt', '/path'));
    }

    // ========== PATH NORMALIZATION TESTS ==========

    #[Test]
    public function preservesSimplePath(): void
    {
        $this->assertSame('GET|/api/users|', Canonicalize::normalizeBinding('GET', '/api/users'));
    }

    #[Test]
    public function addsLeadingSlash(): void
    {
        $this->assertSame('GET|/path|', Canonicalize::normalizeBinding('GET', 'path'));
    }

    #[Test]
    public function removesTrailingSlash(): void
    {
        $this->assertSame('GET|/path|', Canonicalize::normalizeBinding('GET', '/path/'));
    }

    #[Test]
    public function preservesRootPath(): void
    {
        $this->assertSame('GET|/|', Canonicalize::normalizeBinding('GET', '/'));
    }

    #[Test]
    public function collapsesDoubleSlashes(): void
    {
        $this->assertSame('GET|/path/to|', Canonicalize::normalizeBinding('GET', '/path//to'));
    }

    #[Test]
    public function collapsesMultipleSlashes(): void
    {
        $this->assertSame('GET|/path/to/resource|', Canonicalize::normalizeBinding('GET', '///path///to////resource'));
    }

    #[Test]
    public function handlesNestedPath(): void
    {
        $this->assertSame('GET|/api/v1/users/123|', Canonicalize::normalizeBinding('GET', '/api/v1/users/123'));
    }

    #[Test]
    public function handlesDeeplyNestedPath(): void
    {
        $path = '/a/b/c/d/e/f/g/h/i/j';
        $this->assertSame("GET|$path|", Canonicalize::normalizeBinding('GET', $path));
    }

    #[Test]
    public function removesFragment(): void
    {
        $this->assertSame('GET|/path|', Canonicalize::normalizeBinding('GET', '/path#section'));
    }

    #[Test]
    public function removesFragmentWithQuery(): void
    {
        $this->assertSame('GET|/path|a=1', Canonicalize::normalizeBinding('GET', '/path', 'a=1#section'));
    }

    // ========== QUERY STRING TESTS ==========

    #[Test]
    public function appendsQueryString(): void
    {
        $this->assertSame('GET|/path|foo=bar', Canonicalize::normalizeBinding('GET', '/path', 'foo=bar'));
    }

    #[Test]
    public function sortsQueryParameters(): void
    {
        $this->assertSame('GET|/path|a=1&b=2&c=3', Canonicalize::normalizeBinding('GET', '/path', 'c=3&a=1&b=2'));
    }

    #[Test]
    public function sortsQueryParametersByKey(): void
    {
        $this->assertSame('GET|/path|alpha=1&beta=2&gamma=3', Canonicalize::normalizeBinding('GET', '/path', 'gamma=3&alpha=1&beta=2'));
    }

    #[Test]
    public function handlesDuplicateKeys(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/path', 'a=2&a=1&a=3');
        $this->assertSame('GET|/path|a=1&a=2&a=3', $result);
    }

    #[Test]
    public function handlesEmptyQueryValue(): void
    {
        $this->assertSame('GET|/path|a=&b=2', Canonicalize::normalizeBinding('GET', '/path', 'b=2&a='));
    }

    #[Test]
    public function handlesQueryWithSpecialChars(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/path', 'key=hello%20world');
        $this->assertStringContainsString('key=', $result);
    }

    #[Test]
    public function handlesEmptyQueryString(): void
    {
        $this->assertSame('GET|/path|', Canonicalize::normalizeBinding('GET', '/path', ''));
    }

    #[Test]
    public function handlesQueryWithMultipleEquals(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/path', 'key=value=with=equals');
        $this->assertStringContainsString('key=', $result);
    }

    // ========== FROM URL TESTS ==========

    #[Test]
    public function normalizeFromUrlSimple(): void
    {
        $this->assertSame('GET|/api/users|', Canonicalize::normalizeBindingFromUrl('GET', '/api/users'));
    }

    #[Test]
    public function normalizeFromUrlWithQuery(): void
    {
        $this->assertSame('GET|/api/users|page=1&sort=name', Canonicalize::normalizeBindingFromUrl('GET', '/api/users?sort=name&page=1'));
    }

    #[Test]
    public function normalizeFromUrlWithFragment(): void
    {
        $this->assertSame('GET|/api/users|', Canonicalize::normalizeBindingFromUrl('GET', '/api/users#section'));
    }

    #[Test]
    public function normalizeFromUrlWithQueryAndFragment(): void
    {
        $this->assertSame('GET|/api/users|page=1', Canonicalize::normalizeBindingFromUrl('GET', '/api/users?page=1#section'));
    }

    // ========== SPECIAL CHARACTERS IN PATH TESTS ==========

    #[Test]
    public function handlesPathWithDash(): void
    {
        $this->assertSame('GET|/api/user-profile|', Canonicalize::normalizeBinding('GET', '/api/user-profile'));
    }

    #[Test]
    public function handlesPathWithUnderscore(): void
    {
        $this->assertSame('GET|/api/user_profile|', Canonicalize::normalizeBinding('GET', '/api/user_profile'));
    }

    #[Test]
    public function handlesPathWithDot(): void
    {
        $this->assertSame('GET|/api/file.json|', Canonicalize::normalizeBinding('GET', '/api/file.json'));
    }

    #[Test]
    public function handlesPathWithTilde(): void
    {
        $this->assertSame('GET|/~user/profile|', Canonicalize::normalizeBinding('GET', '/~user/profile'));
    }

    #[Test]
    public function handlesPathWithPercentEncoded(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/api/user%20name');
        $this->assertStringContainsString('/api/', $result);
    }

    // ========== UNICODE PATH TESTS ==========

    #[Test]
    public function handlesUnicodePath(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/api/用户');
        $this->assertStringContainsString('GET|', $result);
    }

    #[Test]
    public function handlesEmojiInPath(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/api/🎉');
        $this->assertStringContainsString('GET|', $result);
    }

    // ========== EDGE CASES ==========

    #[Test]
    public function handlesVeryLongPath(): void
    {
        $path = '/' . str_repeat('a', 1000);
        $result = Canonicalize::normalizeBinding('GET', $path);
        $this->assertStringContainsString('GET|/', $result);
    }

    #[Test]
    public function handlesPathWithManySegments(): void
    {
        $segments = array_fill(0, 100, 'seg');
        $path = '/' . implode('/', $segments);
        $result = Canonicalize::normalizeBinding('GET', $path);
        $this->assertStringContainsString('GET|/', $result);
    }

    #[Test]
    public function handlesQueryWithManyParameters(): void
    {
        $params = [];
        for ($i = 0; $i < 100; $i++) {
            $params[] = "key$i=value$i";
        }
        $query = implode('&', $params);
        $result = Canonicalize::normalizeBinding('GET', '/path', $query);
        $this->assertStringContainsString('key0=value0', $result);
    }

    // ========== DETERMINISM TESTS ==========

    #[Test]
    public function producesDeterministicOutput(): void
    {
        $results = [];
        for ($i = 0; $i < 100; $i++) {
            $results[] = Canonicalize::normalizeBinding('POST', '/api/update', 'z=3&a=1');
        }
        $unique = array_unique($results);
        $this->assertCount(1, $unique);
    }

    // ========== CROSS-SDK COMPATIBILITY TESTS ==========

    #[Test]
    public function matchesCrossSdkVector1(): void
    {
        $this->assertSame('POST|/api/update|', Canonicalize::normalizeBinding('POST', '/api/update'));
    }

    #[Test]
    public function matchesCrossSdkVector2(): void
    {
        $this->assertSame('GET|/api/users|page=1&sort=name', Canonicalize::normalizeBinding('GET', '/api/users', 'sort=name&page=1'));
    }

    #[Test]
    public function matchesCrossSdkVector3(): void
    {
        $this->assertSame('DELETE|/api/users/123|', Canonicalize::normalizeBinding('delete', '/api/users/123/'));
    }

    // ========== FORMAT VALIDATION TESTS ==========

    #[Test]
    public function outputHasThreeParts(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/path');
        $parts = explode('|', $result);
        $this->assertCount(3, $parts);
    }

    #[Test]
    public function outputHasMethodFirst(): void
    {
        $result = Canonicalize::normalizeBinding('POST', '/path');
        $parts = explode('|', $result);
        $this->assertSame('POST', $parts[0]);
    }

    #[Test]
    public function outputHasPathSecond(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/api/users');
        $parts = explode('|', $result);
        $this->assertSame('/api/users', $parts[1]);
    }

    #[Test]
    public function outputHasQueryThird(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/path', 'a=1');
        $parts = explode('|', $result);
        $this->assertSame('a=1', $parts[2]);
    }

    #[Test]
    public function outputHasEmptyQueryWhenNone(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/path');
        $parts = explode('|', $result);
        $this->assertSame('', $parts[2]);
    }
}
