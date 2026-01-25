<?php

declare(strict_types=1);

namespace Ash\Tests;

use Ash\Core\Canonicalize;
use Ash\Core\Exceptions\CanonicalizationException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Tests for ASH canonicalization.
 */
final class CanonicalizeTest extends TestCase
{
    // JSON Canonicalization Tests

    #[Test]
    public function jsonSimpleObject(): void
    {
        $result = Canonicalize::json(['b' => 2, 'a' => 1]);
        $this->assertSame('{"a":1,"b":2}', $result);
    }

    #[Test]
    public function jsonNestedObject(): void
    {
        $result = Canonicalize::json(['z' => ['b' => 2, 'a' => 1], 'a' => 1]);
        $this->assertSame('{"a":1,"z":{"a":1,"b":2}}', $result);
    }

    #[Test]
    public function jsonArrayPreservesOrder(): void
    {
        $result = Canonicalize::json([3, 1, 2]);
        $this->assertSame('[3,1,2]', $result);
    }

    #[Test]
    public function jsonHandlesNull(): void
    {
        $result = Canonicalize::json(null);
        $this->assertSame('null', $result);
    }

    #[Test]
    public function jsonHandlesBooleans(): void
    {
        $this->assertSame('true', Canonicalize::json(true));
        $this->assertSame('false', Canonicalize::json(false));
    }

    #[Test]
    public function jsonHandlesStrings(): void
    {
        $result = Canonicalize::json('hello');
        $this->assertSame('"hello"', $result);
    }

    #[Test]
    public function jsonEscapesSpecialCharacters(): void
    {
        $result = Canonicalize::json("hello\n\"world\"");
        $this->assertSame('"hello\n\"world\""', $result);
    }

    #[Test]
    public function jsonEscapesBackspace(): void
    {
        $result = Canonicalize::json("hello\x08world");
        $this->assertSame('"hello\bworld"', $result);
    }

    #[Test]
    public function jsonEscapesFormFeed(): void
    {
        $result = Canonicalize::json("hello\x0Cworld");
        $this->assertSame('"hello\fworld"', $result);
    }

    #[Test]
    public function jsonEscapesAllRfc8785ControlChars(): void
    {
        // Test all RFC 8785 required escapes
        $result = Canonicalize::json("\x08\t\n\x0C\r");
        $this->assertSame('"\b\t\n\f\r"', $result);
    }

    #[Test]
    public function jsonEscapesOtherControlCharsAsUnicode(): void
    {
        // Control char 0x01 should become \u0001
        $result = Canonicalize::json("\x01");
        $this->assertSame('"\u0001"', $result);
    }

    #[Test]
    public function jsonHandlesIntegers(): void
    {
        $result = Canonicalize::json(42);
        $this->assertSame('42', $result);
    }

    #[Test]
    public function jsonHandlesFloats(): void
    {
        $result = Canonicalize::json(3.14);
        $this->assertSame('3.14', $result);
    }

    #[Test]
    public function jsonConvertsNegativeZeroToZero(): void
    {
        $result = Canonicalize::json(-0.0);
        $this->assertSame('0', $result);
    }

    #[Test]
    public function jsonRejectsNan(): void
    {
        $this->expectException(CanonicalizationException::class);
        $this->expectExceptionMessage('NaN');
        Canonicalize::json(NAN);
    }

    #[Test]
    public function jsonRejectsInfinity(): void
    {
        $this->expectException(CanonicalizationException::class);
        $this->expectExceptionMessage('Infinity');
        Canonicalize::json(INF);
    }

    #[Test]
    public function jsonAppliesNfcNormalization(): void
    {
        // e with combining acute accent (decomposed form)
        $decomposed = "caf\u{0065}\u{0301}";
        $result = Canonicalize::json($decomposed);
        // Should normalize to composed form (e with combining acute becomes single char)
        $this->assertSame('"caf' . "\u{00E9}" . '"', $result);
    }

    // URL-Encoded Canonicalization Tests

    #[Test]
    public function urlEncodedSimplePairs(): void
    {
        $result = Canonicalize::urlEncoded('b=2&a=1');
        $this->assertSame('a=1&b=2', $result);
    }

    #[Test]
    public function urlEncodedAcceptsDictInput(): void
    {
        $result = Canonicalize::urlEncoded(['b' => '2', 'a' => '1']);
        $this->assertSame('a=1&b=2', $result);
    }

    #[Test]
    public function urlEncodedPreservesValueOrderForDuplicateKeys(): void
    {
        $result = Canonicalize::urlEncoded('a=2&a=1&a=3');
        $this->assertSame('a=2&a=1&a=3', $result);
    }

    #[Test]
    public function urlEncodedHandlesEmptyValues(): void
    {
        $result = Canonicalize::urlEncoded('a=&b=2');
        $this->assertSame('a=&b=2', $result);
    }

    #[Test]
    public function urlEncodedDecodesPlusAsSpace(): void
    {
        $result = Canonicalize::urlEncoded('a=hello+world');
        $this->assertSame('a=hello%20world', $result);
    }

    #[Test]
    public function urlEncodedProperlyPercentEncodes(): void
    {
        $result = Canonicalize::urlEncoded('a=hello world');
        $this->assertSame('a=hello%20world', $result);
    }

    #[Test]
    public function urlEncodedUsesUppercaseHex(): void
    {
        // Verify that percent-encoding uses uppercase hex (A-F not a-f)
        $result = Canonicalize::urlEncoded(['key' => 'hello/world']);
        // / encodes to %2F (uppercase F, not lowercase f)
        $this->assertSame('key=hello%2Fworld', $result);
        $this->assertStringNotContainsString('%2f', $result); // No lowercase
    }

    // Binding Normalization Tests (v2.3.1+ format: METHOD|PATH|QUERY)

    #[Test]
    public function normalizeBindingSimple(): void
    {
        $result = Canonicalize::normalizeBinding('post', '/api/update');
        $this->assertSame('POST|/api/update|', $result);
    }

    #[Test]
    public function normalizeBindingUppercasesMethod(): void
    {
        $result = Canonicalize::normalizeBinding('get', '/path');
        $this->assertSame('GET|/path|', $result);
    }

    #[Test]
    public function normalizeBindingWithQueryString(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/path', 'foo=bar');
        $this->assertSame('GET|/path|foo=bar', $result);
    }

    #[Test]
    public function normalizeBindingQuerySorted(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/path', 'z=3&a=1');
        $this->assertSame('GET|/path|a=1&z=3', $result);
    }

    #[Test]
    public function normalizeBindingRemovesFragment(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/path#section');
        $this->assertSame('GET|/path|', $result);
    }

    #[Test]
    public function normalizeBindingAddsLeadingSlash(): void
    {
        $result = Canonicalize::normalizeBinding('GET', 'path');
        $this->assertSame('GET|/path|', $result);
    }

    #[Test]
    public function normalizeBindingCollapsesSlashes(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '//path///to////resource');
        $this->assertSame('GET|/path/to/resource|', $result);
    }

    #[Test]
    public function normalizeBindingRemovesTrailingSlash(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/path/');
        $this->assertSame('GET|/path|', $result);
    }

    #[Test]
    public function normalizeBindingPreservesRoot(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/');
        $this->assertSame('GET|/|', $result);
    }

    #[Test]
    public function normalizeBindingFromUrlWithQuery(): void
    {
        $result = Canonicalize::normalizeBindingFromUrl('GET', '/api/users?page=1&sort=name');
        $this->assertSame('GET|/api/users|page=1&sort=name', $result);
    }

    #[Test]
    public function normalizeBindingFromUrlWithoutQuery(): void
    {
        $result = Canonicalize::normalizeBindingFromUrl('POST', '/api/users');
        $this->assertSame('POST|/api/users|', $result);
    }
}
