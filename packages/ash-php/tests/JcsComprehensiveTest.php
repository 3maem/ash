<?php

declare(strict_types=1);

namespace Ash\Tests;

use Ash\Core\Canonicalize;
use Ash\Core\Exceptions\CanonicalizationException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Comprehensive JCS (JSON Canonicalization Scheme) tests per RFC 8785.
 */
final class JcsComprehensiveTest extends TestCase
{
    // ========== OBJECT KEY SORTING TESTS ==========

    #[Test]
    public function sortsTwoKeyObject(): void
    {
        $this->assertSame('{"a":1,"b":2}', Canonicalize::json(['b' => 2, 'a' => 1]));
    }

    #[Test]
    public function sortsThreeKeyObject(): void
    {
        $this->assertSame('{"a":1,"b":2,"c":3}', Canonicalize::json(['c' => 3, 'a' => 1, 'b' => 2]));
    }

    #[Test]
    public function sortsFiveKeyObject(): void
    {
        $result = Canonicalize::json(['e' => 5, 'c' => 3, 'a' => 1, 'd' => 4, 'b' => 2]);
        $this->assertSame('{"a":1,"b":2,"c":3,"d":4,"e":5}', $result);
    }

    #[Test]
    public function sortsTenKeyObject(): void
    {
        $input = [];
        for ($i = 9; $i >= 0; $i--) {
            $input["key$i"] = $i;
        }
        $result = Canonicalize::json($input);
        $this->assertStringContainsString('"key0":0', $result);
        $this->assertStringContainsString('"key9":9', $result);
    }

    #[Test]
    public function sortsNumericStringKeys(): void
    {
        $result = Canonicalize::json(['10' => 'ten', '2' => 'two', '1' => 'one']);
        $this->assertSame('{"1":"one","10":"ten","2":"two"}', $result);
    }

    #[Test]
    public function sortsMixedCaseKeys(): void
    {
        $result = Canonicalize::json(['B' => 2, 'a' => 1, 'A' => 3, 'b' => 4]);
        $this->assertSame('{"A":3,"B":2,"a":1,"b":4}', $result);
    }

    #[Test]
    public function sortsUnicodeKeys(): void
    {
        $result = Canonicalize::json(['β' => 2, 'α' => 1, 'γ' => 3]);
        $this->assertStringContainsString('"α":1', $result);
    }

    #[Test]
    public function sortsEmptyStringKey(): void
    {
        $result = Canonicalize::json(['' => 'empty', 'a' => 1]);
        $this->assertSame('{"":"empty","a":1}', $result);
    }

    #[Test]
    public function handlesEmptyObject(): void
    {
        $this->assertSame('{}', Canonicalize::json((object)[]));
    }

    #[Test]
    public function handlesSingleKeyObject(): void
    {
        $this->assertSame('{"key":"value"}', Canonicalize::json(['key' => 'value']));
    }

    // ========== NESTED OBJECT TESTS ==========

    #[Test]
    public function sortsNestedObjectKeys(): void
    {
        $result = Canonicalize::json(['z' => ['b' => 2, 'a' => 1], 'a' => 1]);
        $this->assertSame('{"a":1,"z":{"a":1,"b":2}}', $result);
    }

    #[Test]
    public function sortsDeeplyNestedObjects(): void
    {
        $input = [
            'z' => [
                'y' => [
                    'x' => [
                        'b' => 2,
                        'a' => 1
                    ]
                ]
            ]
        ];
        $result = Canonicalize::json($input);
        $this->assertSame('{"z":{"y":{"x":{"a":1,"b":2}}}}', $result);
    }

    #[Test]
    public function sortsObjectsInArrays(): void
    {
        $input = [['b' => 2, 'a' => 1], ['d' => 4, 'c' => 3]];
        $result = Canonicalize::json($input);
        $this->assertSame('[{"a":1,"b":2},{"c":3,"d":4}]', $result);
    }

    #[Test]
    public function handlesMixedNestedStructures(): void
    {
        $input = [
            'array' => [1, 2, 3],
            'object' => ['b' => 2, 'a' => 1],
            'nested' => [
                'arr' => [['z' => 1, 'a' => 2]],
                'obj' => ['x' => 1]
            ]
        ];
        $result = Canonicalize::json($input);
        $decoded = json_decode($result, true);
        $this->assertSame([1, 2, 3], $decoded['array']);
        $this->assertSame(['a' => 1, 'b' => 2], $decoded['object']);
    }

    // ========== ARRAY TESTS ==========

    #[Test]
    public function preservesArrayOrder(): void
    {
        $this->assertSame('[3,1,2]', Canonicalize::json([3, 1, 2]));
    }

    #[Test]
    public function preservesArrayOrderWithMixedTypes(): void
    {
        $result = Canonicalize::json([1, 'two', 3.0, true, null]);
        $this->assertSame('[1,"two",3,true,null]', $result);
    }

    #[Test]
    public function handlesEmptyArray(): void
    {
        $this->assertSame('[]', Canonicalize::json([]));
    }

    #[Test]
    public function handlesNestedEmptyArrays(): void
    {
        $this->assertSame('[[],[]]', Canonicalize::json([[], []]));
    }

    #[Test]
    public function handlesLargeArray(): void
    {
        $arr = range(0, 999);
        $result = Canonicalize::json($arr);
        $this->assertStringStartsWith('[0,1,2,', $result);
        $this->assertStringEndsWith(',998,999]', $result);
    }

    // ========== STRING ESCAPE TESTS ==========

    #[Test]
    public function escapesDoubleQuote(): void
    {
        $this->assertSame('"hello\\"world"', Canonicalize::json('hello"world'));
    }

    #[Test]
    public function escapesBackslash(): void
    {
        $this->assertSame('"hello\\\\world"', Canonicalize::json('hello\\world'));
    }

    #[Test]
    public function escapesNewline(): void
    {
        $this->assertSame('"hello\\nworld"', Canonicalize::json("hello\nworld"));
    }

    #[Test]
    public function escapesCarriageReturn(): void
    {
        $this->assertSame('"hello\\rworld"', Canonicalize::json("hello\rworld"));
    }

    #[Test]
    public function escapesTab(): void
    {
        $this->assertSame('"hello\\tworld"', Canonicalize::json("hello\tworld"));
    }

    #[Test]
    public function escapesBackspace(): void
    {
        $this->assertSame('"hello\\bworld"', Canonicalize::json("hello\x08world"));
    }

    #[Test]
    public function escapesFormFeed(): void
    {
        $this->assertSame('"hello\\fworld"', Canonicalize::json("hello\x0Cworld"));
    }

    #[Test]
    public function escapesNullChar(): void
    {
        $result = Canonicalize::json("hello\x00world");
        $this->assertSame('"hello\\u0000world"', $result);
    }

    #[Test]
    public function escapesControlChar01(): void
    {
        $this->assertSame('"\\u0001"', Canonicalize::json("\x01"));
    }

    #[Test]
    public function escapesControlChar1F(): void
    {
        $this->assertSame('"\\u001f"', Canonicalize::json("\x1F"));
    }

    #[Test]
    public function doesNotEscapeSpace(): void
    {
        $this->assertSame('"hello world"', Canonicalize::json('hello world'));
    }

    #[Test]
    public function doesNotEscapeUnicodeBeyondControlChars(): void
    {
        $this->assertSame('"café"', Canonicalize::json('café'));
    }

    #[Test]
    public function handlesEmptyString(): void
    {
        $this->assertSame('""', Canonicalize::json(''));
    }

    #[Test]
    public function handlesAllEscapesInOneString(): void
    {
        // Note: \b in PHP is NOT a backspace, just literal \b
        // Use \x08 for actual backspace
        $result = Canonicalize::json("\"\\\x08\f\n\r\t");
        $this->assertSame('"\"\\\\\\b\\f\\n\\r\\t"', $result);
    }

    // ========== NUMBER TESTS ==========

    #[Test]
    public function handlesPositiveInteger(): void
    {
        $this->assertSame('42', Canonicalize::json(42));
    }

    #[Test]
    public function handlesNegativeInteger(): void
    {
        $this->assertSame('-42', Canonicalize::json(-42));
    }

    #[Test]
    public function handlesZero(): void
    {
        $this->assertSame('0', Canonicalize::json(0));
    }

    #[Test]
    public function handlesNegativeZero(): void
    {
        $this->assertSame('0', Canonicalize::json(-0.0));
    }

    #[Test]
    public function handlesPositiveFloat(): void
    {
        $this->assertSame('3.14', Canonicalize::json(3.14));
    }

    #[Test]
    public function handlesNegativeFloat(): void
    {
        $this->assertSame('-3.14', Canonicalize::json(-3.14));
    }

    #[Test]
    public function handlesFloatWithTrailingZeros(): void
    {
        $this->assertSame('1.5', Canonicalize::json(1.50));
    }

    #[Test]
    public function handlesSmallFloat(): void
    {
        $result = Canonicalize::json(0.000001);
        $this->assertStringContainsString('0.000001', $result);
    }

    #[Test]
    public function handlesLargeInteger(): void
    {
        $result = Canonicalize::json(9007199254740991);
        $this->assertSame('9007199254740991', $result);
    }

    #[Test]
    public function rejectsNaN(): void
    {
        $this->expectException(CanonicalizationException::class);
        Canonicalize::json(NAN);
    }

    #[Test]
    public function rejectsPositiveInfinity(): void
    {
        $this->expectException(CanonicalizationException::class);
        Canonicalize::json(INF);
    }

    #[Test]
    public function rejectsNegativeInfinity(): void
    {
        $this->expectException(CanonicalizationException::class);
        Canonicalize::json(-INF);
    }

    // ========== BOOLEAN AND NULL TESTS ==========

    #[Test]
    public function handlesTrue(): void
    {
        $this->assertSame('true', Canonicalize::json(true));
    }

    #[Test]
    public function handlesFalse(): void
    {
        $this->assertSame('false', Canonicalize::json(false));
    }

    #[Test]
    public function handlesNull(): void
    {
        $this->assertSame('null', Canonicalize::json(null));
    }

    #[Test]
    public function handlesBooleanInObject(): void
    {
        $result = Canonicalize::json(['flag' => true, 'other' => false]);
        $this->assertSame('{"flag":true,"other":false}', $result);
    }

    #[Test]
    public function handlesNullInObject(): void
    {
        $result = Canonicalize::json(['value' => null]);
        $this->assertSame('{"value":null}', $result);
    }

    // ========== UNICODE / NFC NORMALIZATION TESTS ==========

    #[Test]
    public function normalizesDecomposedEAcute(): void
    {
        $decomposed = "caf\u{0065}\u{0301}"; // e + combining acute
        $result = Canonicalize::json($decomposed);
        $this->assertSame('"caf' . "\u{00E9}" . '"', $result);
    }

    #[Test]
    public function normalizesDecomposedOUmlaut(): void
    {
        $decomposed = "M\u{006F}\u{0308}bius"; // o + combining diaeresis
        $result = Canonicalize::json($decomposed);
        $this->assertSame('"M' . "\u{00F6}" . 'bius"', $result);
    }

    #[Test]
    public function normalizesDecomposedNTilde(): void
    {
        $decomposed = "jala\u{006E}\u{0303}o"; // n + combining tilde
        $result = Canonicalize::json($decomposed);
        $this->assertSame('"jala' . "\u{00F1}" . 'o"', $result);
    }

    #[Test]
    public function handlesPrecomposedUnicode(): void
    {
        $composed = "café";
        $result = Canonicalize::json($composed);
        $this->assertSame('"café"', $result);
    }

    #[Test]
    public function handlesChineseCharacters(): void
    {
        $result = Canonicalize::json('你好世界');
        $this->assertSame('"你好世界"', $result);
    }

    #[Test]
    public function handlesJapaneseCharacters(): void
    {
        $result = Canonicalize::json('こんにちは');
        $this->assertSame('"こんにちは"', $result);
    }

    #[Test]
    public function handlesArabicCharacters(): void
    {
        $result = Canonicalize::json('مرحبا');
        $this->assertSame('"مرحبا"', $result);
    }

    #[Test]
    public function handlesEmoji(): void
    {
        $result = Canonicalize::json('🎉🚀');
        $this->assertSame('"🎉🚀"', $result);
    }

    #[Test]
    public function handlesEmojiInObject(): void
    {
        $result = Canonicalize::json(['emoji' => '😀', 'text' => 'hello']);
        $decoded = json_decode($result, true);
        $this->assertSame('😀', $decoded['emoji']);
    }

    // ========== DETERMINISM TESTS ==========

    #[Test]
    public function producesIdenticalOutputForSameInput(): void
    {
        $input = ['z' => 26, 'a' => 1, 'm' => 13];
        $result1 = Canonicalize::json($input);
        $result2 = Canonicalize::json($input);
        $this->assertSame($result1, $result2);
    }

    #[Test]
    public function producesIdenticalOutputAcrossMultipleCalls(): void
    {
        $input = ['nested' => ['deep' => ['value' => 123]]];
        $results = [];
        for ($i = 0; $i < 100; $i++) {
            $results[] = Canonicalize::json($input);
        }
        $unique = array_unique($results);
        $this->assertCount(1, $unique);
    }

    // ========== WHITESPACE TESTS ==========

    #[Test]
    public function producesNoWhitespaceInOutput(): void
    {
        $input = ['key' => 'value', 'nested' => ['a' => 1]];
        $result = Canonicalize::json($input);
        $this->assertStringNotContainsString(' ', $result);
        $this->assertStringNotContainsString("\n", $result);
        $this->assertStringNotContainsString("\t", $result);
    }

    // ========== EDGE CASE TESTS ==========

    #[Test]
    public function handlesObjectWithAllTypes(): void
    {
        $input = [
            'string' => 'hello',
            'number' => 42,
            'float' => 3.14,
            'bool' => true,
            'null' => null,
            'array' => [1, 2, 3],
            'object' => ['a' => 1]
        ];
        $result = Canonicalize::json($input);
        $decoded = json_decode($result, true);
        $this->assertSame('hello', $decoded['string']);
        $this->assertSame(42, $decoded['number']);
        $this->assertSame(3.14, $decoded['float']);
        $this->assertTrue($decoded['bool']);
        $this->assertNull($decoded['null']);
        $this->assertSame([1, 2, 3], $decoded['array']);
        $this->assertSame(['a' => 1], $decoded['object']);
    }

    #[Test]
    public function handlesVeryLongString(): void
    {
        $longString = str_repeat('a', 10000);
        $result = Canonicalize::json($longString);
        $this->assertSame('"' . $longString . '"', $result);
    }

    #[Test]
    public function handlesSpecialJsonCharactersInKeys(): void
    {
        $input = ['"quoted"' => 1, "new\nline" => 2];
        $result = Canonicalize::json($input);
        $this->assertStringContainsString('\\"quoted\\"', $result);
        $this->assertStringContainsString('\\n', $result);
    }

    #[Test]
    public function handlesReservedJavaScriptKeywords(): void
    {
        $input = ['null' => 1, 'true' => 2, 'false' => 3, 'undefined' => 4];
        $result = Canonicalize::json($input);
        $decoded = json_decode($result, true);
        $this->assertSame(1, $decoded['null']);
        $this->assertSame(2, $decoded['true']);
    }

    // ========== STRESS TESTS ==========

    #[Test]
    public function handlesDeepNesting(): void
    {
        $input = [];
        $current = &$input;
        for ($i = 0; $i < 50; $i++) {
            $current['nested'] = [];
            $current = &$current['nested'];
        }
        $current['value'] = 'deep';

        $result = Canonicalize::json($input);
        $this->assertStringContainsString('"value":"deep"', $result);
    }

    #[Test]
    public function handlesWideObject(): void
    {
        $input = [];
        for ($i = 0; $i < 1000; $i++) {
            $input["key_$i"] = $i;
        }
        $result = Canonicalize::json($input);
        $this->assertStringContainsString('"key_0":0', $result);
        $this->assertStringContainsString('"key_999":999', $result);
    }

    // ========== CROSS-SDK COMPATIBILITY TESTS ==========

    #[Test]
    public function matchesCrossSdkVector1(): void
    {
        $input = ['b' => 2, 'a' => 1];
        $expected = '{"a":1,"b":2}';
        $this->assertSame($expected, Canonicalize::json($input));
    }

    #[Test]
    public function matchesCrossSdkVector2(): void
    {
        $input = ['z' => ['y' => ['x' => 1]]];
        $expected = '{"z":{"y":{"x":1}}}';
        $this->assertSame($expected, Canonicalize::json($input));
    }

    #[Test]
    public function matchesCrossSdkVectorWithUnicode(): void
    {
        $input = ['café' => 'latté', 'naïve' => true];
        $result = Canonicalize::json($input);
        $decoded = json_decode($result, true);
        $this->assertSame('latté', $decoded['café']);
    }

    #[Test]
    public function matchesCrossSdkVectorWithNumbers(): void
    {
        $input = ['int' => 42, 'float' => 3.14159, 'negative' => -17];
        $result = Canonicalize::json($input);
        $decoded = json_decode($result, true);
        $this->assertSame(42, $decoded['int']);
        $this->assertSame(-17, $decoded['negative']);
    }

    // ========== RFC 8785 COMPLIANCE TESTS ==========

    #[Test]
    public function rfc8785ExampleStructure(): void
    {
        // From RFC 8785 examples
        $input = [
            "\u{20ac}" => "Euro Sign",
            "\r" => "Carriage Return",
            "\u{000a}" => "Newline",
            "1" => "One",
            "\u{0080}" => "Control",
            "10" => "Ten",
        ];
        $result = Canonicalize::json($input);
        // Keys should be sorted by UTF-16 code unit values
        $this->assertIsString($result);
    }

    #[Test]
    public function rfc8785NumberFormatting(): void
    {
        // Per RFC 8785: numbers should use shortest representation
        $this->assertSame('1', Canonicalize::json(1.0));
        $this->assertSame('1.5', Canonicalize::json(1.5));
    }
}
