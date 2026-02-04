<?php

declare(strict_types=1);

namespace Ash\Tests;

use Ash\Ash;
use Ash\Core\Canonicalize;
use Ash\Core\Exceptions\CanonicalizationException;
use Ash\Core\Proof;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Comprehensive edge case and boundary tests.
 */
final class EdgeCasesComprehensiveTest extends TestCase
{
    // ========== NULL AND EMPTY VALUE TESTS ==========

    #[Test]
    public function jsonNullTopLevel(): void
    {
        $this->assertSame('null', Canonicalize::json(null));
    }

    #[Test]
    public function jsonNullInObject(): void
    {
        $result = Canonicalize::json(['key' => null]);
        $this->assertSame('{"key":null}', $result);
    }

    #[Test]
    public function jsonNullInArray(): void
    {
        $result = Canonicalize::json([null, null, null]);
        $this->assertSame('[null,null,null]', $result);
    }

    #[Test]
    public function jsonEmptyString(): void
    {
        $this->assertSame('""', Canonicalize::json(''));
    }

    #[Test]
    public function jsonEmptyArray(): void
    {
        $this->assertSame('[]', Canonicalize::json([]));
    }

    #[Test]
    public function jsonEmptyAssociativeArray(): void
    {
        // PHP arrays are used for both arrays and objects in JSON
        // An empty array [] becomes [] in JSON, not {}
        $this->assertSame('[]', Canonicalize::json([]));
    }

    #[Test]
    public function jsonNestedEmptyStructures(): void
    {
        $input = ['array' => [], 'string' => '', 'null' => null];
        $result = Canonicalize::json($input);
        $this->assertStringContainsString('"array":[]', $result);
        $this->assertStringContainsString('"null":null', $result);
        $this->assertStringContainsString('"string":""', $result);
    }

    // ========== BOOLEAN EDGE CASES ==========

    #[Test]
    public function jsonTrueStandalone(): void
    {
        $this->assertSame('true', Canonicalize::json(true));
    }

    #[Test]
    public function jsonFalseStandalone(): void
    {
        $this->assertSame('false', Canonicalize::json(false));
    }

    #[Test]
    public function jsonBooleanVsIntegerOne(): void
    {
        // true should not be 1
        $this->assertSame('true', Canonicalize::json(true));
        $this->assertSame('1', Canonicalize::json(1));
    }

    #[Test]
    public function jsonBooleanVsIntegerZero(): void
    {
        // false should not be 0
        $this->assertSame('false', Canonicalize::json(false));
        $this->assertSame('0', Canonicalize::json(0));
    }

    // ========== NUMBER EDGE CASES ==========

    #[Test]
    public function jsonZero(): void
    {
        $this->assertSame('0', Canonicalize::json(0));
    }

    #[Test]
    public function jsonNegativeZero(): void
    {
        // Negative zero should become positive zero per RFC 8785
        $this->assertSame('0', Canonicalize::json(-0.0));
    }

    #[Test]
    public function jsonOnePointZero(): void
    {
        // 1.0 should be rendered as 1
        $this->assertSame('1', Canonicalize::json(1.0));
    }

    #[Test]
    public function jsonMaxSafeInteger(): void
    {
        $maxSafe = 9007199254740991; // 2^53 - 1
        $result = Canonicalize::json($maxSafe);
        $this->assertSame('9007199254740991', $result);
    }

    #[Test]
    public function jsonMinSafeInteger(): void
    {
        $minSafe = -9007199254740991;
        $result = Canonicalize::json($minSafe);
        $this->assertSame('-9007199254740991', $result);
    }

    #[Test]
    public function jsonVerySmallFloat(): void
    {
        $result = Canonicalize::json(0.000000001);
        $this->assertIsString($result);
    }

    #[Test]
    public function jsonVeryLargeFloat(): void
    {
        $result = Canonicalize::json(1e100);
        $this->assertIsString($result);
    }

    #[Test]
    public function jsonRejectsNaN(): void
    {
        $this->expectException(CanonicalizationException::class);
        Canonicalize::json(NAN);
    }

    #[Test]
    public function jsonRejectsPositiveInfinity(): void
    {
        $this->expectException(CanonicalizationException::class);
        Canonicalize::json(INF);
    }

    #[Test]
    public function jsonRejectsNegativeInfinity(): void
    {
        $this->expectException(CanonicalizationException::class);
        Canonicalize::json(-INF);
    }

    // ========== STRING EDGE CASES ==========

    #[Test]
    public function jsonSingleCharacterString(): void
    {
        $this->assertSame('"a"', Canonicalize::json('a'));
    }

    #[Test]
    public function jsonStringWithOnlySpaces(): void
    {
        $this->assertSame('"   "', Canonicalize::json('   '));
    }

    #[Test]
    public function jsonStringWithOnlyNewlines(): void
    {
        $this->assertSame('"\n\n\n"', Canonicalize::json("\n\n\n"));
    }

    #[Test]
    public function jsonStringWithAllEscapeChars(): void
    {
        $input = "\"\\/\b\f\n\r\t";
        $result = Canonicalize::json($input);
        $this->assertStringContainsString('\\"', $result);
        $this->assertStringContainsString('\\\\', $result);
        $this->assertStringContainsString('\\b', $result);
        $this->assertStringContainsString('\\f', $result);
        $this->assertStringContainsString('\\n', $result);
        $this->assertStringContainsString('\\r', $result);
        $this->assertStringContainsString('\\t', $result);
    }

    #[Test]
    public function jsonStringWithLowControlChars(): void
    {
        for ($i = 0; $i < 32; $i++) {
            $char = chr($i);
            $result = Canonicalize::json($char);
            $this->assertIsString($result);
            // Should be escaped somehow
            $this->assertNotSame('"' . $char . '"', $result);
        }
    }

    #[Test]
    public function jsonStringWithDeleteChar(): void
    {
        $result = Canonicalize::json("\x7F");
        $this->assertIsString($result);
    }

    // ========== OBJECT KEY EDGE CASES ==========

    #[Test]
    public function jsonEmptyStringKey(): void
    {
        $result = Canonicalize::json(['' => 'value']);
        $this->assertSame('{"":"value"}', $result);
    }

    #[Test]
    public function jsonNumericStringKeys(): void
    {
        $result = Canonicalize::json(['2' => 'two', '1' => 'one', '10' => 'ten']);
        // Should sort as strings: "1" < "10" < "2"
        $this->assertSame('{"1":"one","10":"ten","2":"two"}', $result);
    }

    #[Test]
    public function jsonKeyWithQuote(): void
    {
        $result = Canonicalize::json(['"quoted"' => 'value']);
        $this->assertStringContainsString('\\"quoted\\"', $result);
    }

    #[Test]
    public function jsonKeyWithBackslash(): void
    {
        $result = Canonicalize::json(['back\\slash' => 'value']);
        $this->assertStringContainsString('back\\\\slash', $result);
    }

    #[Test]
    public function jsonKeyWithNewline(): void
    {
        $result = Canonicalize::json(["new\nline" => 'value']);
        $this->assertStringContainsString('\\n', $result);
    }

    #[Test]
    public function jsonKeyWithUnicode(): void
    {
        $result = Canonicalize::json(['日本語' => 'value']);
        $this->assertStringContainsString('日本語', $result);
    }

    // ========== ARRAY EDGE CASES ==========

    #[Test]
    public function jsonSingleElementArray(): void
    {
        $this->assertSame('[1]', Canonicalize::json([1]));
    }

    #[Test]
    public function jsonArrayWithAllTypes(): void
    {
        $input = [1, 'string', true, false, null, [], (object)[]];
        $result = Canonicalize::json($input);
        $this->assertSame('[1,"string",true,false,null,[],{}]', $result);
    }

    #[Test]
    public function jsonDeeplyNestedArray(): void
    {
        $input = [[[[[[[[[[1]]]]]]]]]];
        $result = Canonicalize::json($input);
        $this->assertSame('[[[[[[[[[[1]]]]]]]]]]', $result);
    }

    // ========== BINDING EDGE CASES ==========

    #[Test]
    public function bindingRootPath(): void
    {
        $this->assertSame('GET|/|', Canonicalize::normalizeBinding('GET', '/'));
    }

    #[Test]
    public function bindingEmptyPath(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '');
        $this->assertStringContainsString('GET|/', $result);
    }

    #[Test]
    public function bindingPathWithOnlySlashes(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '///');
        $this->assertSame('GET|/|', $result);
    }

    #[Test]
    public function bindingPathWithDotSegment(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/path/./to');
        $this->assertStringContainsString('/path/', $result);
    }

    #[Test]
    public function bindingPathWithDoubleDotSegment(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/path/../other');
        $this->assertIsString($result);
    }

    #[Test]
    public function bindingEmptyQueryString(): void
    {
        $result = Canonicalize::normalizeBinding('GET', '/path', '');
        $this->assertSame('GET|/path|', $result);
    }

    #[Test]
    public function bindingQueryWithOnlyQuestionMark(): void
    {
        $result = Canonicalize::normalizeBindingFromUrl('GET', '/path?');
        $this->assertSame('GET|/path|', $result);
    }

    // ========== PROOF EDGE CASES ==========

    #[Test]
    public function proofWithEmptySecret(): void
    {
        $proof = Proof::ashBuildProofHmac('', '1234567890', 'POST|/api|', 'abc123');
        $this->assertSame(64, strlen($proof));
    }

    #[Test]
    public function proofWithEmptyTimestamp(): void
    {
        $proof = Proof::ashBuildProofHmac('secret', '', 'POST|/api|', 'abc123');
        $this->assertSame(64, strlen($proof));
    }

    #[Test]
    public function proofWithEmptyBinding(): void
    {
        $proof = Proof::ashBuildProofHmac('secret', '1234567890', '', 'abc123');
        $this->assertSame(64, strlen($proof));
    }

    #[Test]
    public function proofWithEmptyBodyHash(): void
    {
        $proof = Proof::ashBuildProofHmac('secret', '1234567890', 'POST|/api|', '');
        $this->assertSame(64, strlen($proof));
    }

    #[Test]
    public function proofWithAllEmpty(): void
    {
        $proof = Proof::ashBuildProofHmac('', '', '', '');
        $this->assertSame(64, strlen($proof));
    }

    #[Test]
    public function proofWithUnicodeSecret(): void
    {
        $proof = Proof::ashBuildProofHmac('密码🔐', '1234567890', 'POST|/api|', 'abc123');
        $this->assertSame(64, strlen($proof));
    }

    #[Test]
    public function proofWithBinarySecret(): void
    {
        $proof = Proof::ashBuildProofHmac("\x00\x01\x02\xff", '1234567890', 'POST|/api|', 'abc123');
        $this->assertSame(64, strlen($proof));
    }

    // ========== HASH EDGE CASES ==========

    #[Test]
    public function hashEmptyBody(): void
    {
        $hash = Proof::hashBody('');
        // SHA-256 of empty string is well-known
        $this->assertSame('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', $hash);
    }

    #[Test]
    public function hashSingleByte(): void
    {
        $hash = Proof::hashBody('a');
        $this->assertSame(64, strlen($hash));
    }

    #[Test]
    public function hashNullByte(): void
    {
        $hash = Proof::hashBody("\x00");
        $this->assertSame(64, strlen($hash));
    }

    #[Test]
    public function hashOnlyNullBytes(): void
    {
        $hash = Proof::hashBody("\x00\x00\x00");
        $this->assertSame(64, strlen($hash));
    }

    // ========== BASE64URL EDGE CASES ==========

    #[Test]
    public function base64UrlEncodeEmpty(): void
    {
        $encoded = Proof::base64UrlEncode('');
        $this->assertSame('', $encoded);
    }

    #[Test]
    public function base64UrlEncodeSingleByte(): void
    {
        $encoded = Proof::base64UrlEncode('a');
        $decoded = Proof::base64UrlDecode($encoded);
        $this->assertSame('a', $decoded);
    }

    #[Test]
    public function base64UrlEncodeSpecialCharsInData(): void
    {
        // Data that would produce + and / in standard base64
        $data = "\xfb\xff\xfe";
        $encoded = Proof::base64UrlEncode($data);

        $this->assertStringNotContainsString('+', $encoded);
        $this->assertStringNotContainsString('/', $encoded);

        $decoded = Proof::base64UrlDecode($encoded);
        $this->assertSame($data, $decoded);
    }

    // ========== SCOPED PROOF EDGE CASES ==========

    #[Test]
    public function scopedProofEmptyScope(): void
    {
        $result = Proof::ashBuildProofScoped(
            'secret',
            '1234567890',
            'POST|/api|',
            ['name' => 'John'],
            []
        );
        $this->assertArrayHasKey('proof', $result);
    }

    #[Test]
    public function scopedProofEmptyPayload(): void
    {
        $result = Proof::ashBuildProofScoped(
            'secret',
            '1234567890',
            'POST|/api|',
            [],
            ['name']
        );
        $this->assertArrayHasKey('proof', $result);
    }

    #[Test]
    public function scopedProofNonExistentField(): void
    {
        $result = Proof::ashBuildProofScoped(
            'secret',
            '1234567890',
            'POST|/api|',
            ['name' => 'John'],
            ['nonexistent']
        );
        $this->assertArrayHasKey('proof', $result);
    }

    // ========== TIMING SAFE COMPARE EDGE CASES ==========

    #[Test]
    public function timingSafeCompareEmptyStrings(): void
    {
        $this->assertTrue(Ash::timingSafeCompare('', ''));
    }

    #[Test]
    public function timingSafeCompareOneEmpty(): void
    {
        $this->assertFalse(Ash::timingSafeCompare('', 'notempty'));
        $this->assertFalse(Ash::timingSafeCompare('notempty', ''));
    }

    #[Test]
    public function timingSafeCompareSingleChar(): void
    {
        $this->assertTrue(Ash::timingSafeCompare('a', 'a'));
        $this->assertFalse(Ash::timingSafeCompare('a', 'b'));
    }

    #[Test]
    public function timingSafeCompareWithNullBytes(): void
    {
        $this->assertTrue(Ash::timingSafeCompare("\x00", "\x00"));
        $this->assertFalse(Ash::timingSafeCompare("\x00", "\x01"));
    }

    // ========== UNICODE EDGE CASES ==========

    #[Test]
    public function jsonSurrogatePairs(): void
    {
        // Emoji that uses surrogate pairs in UTF-16
        $result = Canonicalize::json('🎉');
        $this->assertSame('"🎉"', $result);
    }

    #[Test]
    public function jsonCombiningCharacters(): void
    {
        // e followed by combining acute accent
        $decomposed = "e\u{0301}";
        $result = Canonicalize::json($decomposed);
        // Should be NFC normalized
        $this->assertSame('"é"', $result);
    }

    #[Test]
    public function jsonZeroWidthChars(): void
    {
        $zwj = "\u{200D}"; // Zero-width joiner
        $result = Canonicalize::json($zwj);
        $this->assertIsString($result);
    }

    #[Test]
    public function jsonRtlChars(): void
    {
        $rtl = "مرحبا";
        $result = Canonicalize::json($rtl);
        $this->assertStringContainsString($rtl, $result);
    }
}
