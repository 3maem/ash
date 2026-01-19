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

    // Binding Normalization Tests

    #[Test]
    public function normalizeBindingSimple(): void
    {
        $result = Canonicalize::normalizeBinding('post', '/api/update');
        $this->assertSame('POST /api/update', $result);
    }

    #[Test]
    public function normalizeBindingUppercasesMethod(): void
    {
        $result = Canonicalize::normalizeBinding('get', '/path');
        $this->assertSame('GET /path', $result);
    }

    #[Test]
    public function normalizeBindingRemovesQueryString(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/path?foo=bar');
        $this->assertSame('GET /path', $result);
    }

    #[Test]
    public function normalizeBindingRemovesFragment(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/path#section');
        $this->assertSame('GET /path', $result);
    }

    #[Test]
    public function normalizeBindingAddsLeadingSlash(): void
    {
        $result = Canonicalize::normalizeBinding('GET', 'path');
        $this->assertSame('GET /path', $result);
    }

    #[Test]
    public function normalizeBindingCollapsesSlashes(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '//path///to////resource');
        $this->assertSame('GET /path/to/resource', $result);
    }

    #[Test]
    public function normalizeBindingRemovesTrailingSlash(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/path/');
        $this->assertSame('GET /path', $result);
    }

    #[Test]
    public function normalizeBindingPreservesRoot(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/');
        $this->assertSame('GET /', $result);
    }
}
