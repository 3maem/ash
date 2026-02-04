/**
 * JCS Canonicalization Comprehensive Tests (RFC 8785)
 *
 * Tests for JSON Canonicalization Scheme covering:
 * - Object key sorting (byte-wise)
 * - Unicode normalization (NFC)
 * - Number handling (-0, integers, floats)
 * - String escaping (control chars, Unicode)
 * - Nested structures
 * - Edge cases and special characters
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  ashInit,
  ashCanonicalizeJson,
  ashCanonicalizeJsonNative,
  ashCanonicalizeJsonValueNative,
  MAX_RECURSION_DEPTH,
  MAX_PAYLOAD_SIZE,
} from './index';

// Initialize WASM
beforeAll(() => {
  try {
    ashInit();
  } catch {
    // WASM not available, tests will use native fallback
  }
});

describe('JCS Canonicalization Comprehensive Tests', () => {
  describe('Object Key Sorting (RFC 8785 Section 3.2.3)', () => {
    it('sorts single-character keys alphabetically', () => {
      const input = '{"z":1,"a":2,"m":3}';
      expect(ashCanonicalizeJsonNative(input)).toBe('{"a":2,"m":3,"z":1}');
    });

    it('sorts multi-character keys lexicographically', () => {
      const input = '{"banana":1,"apple":2,"cherry":3}';
      expect(ashCanonicalizeJsonNative(input)).toBe('{"apple":2,"banana":1,"cherry":3}');
    });

    it('sorts keys with numbers correctly (string comparison, not numeric)', () => {
      const input = '{"a10":1,"a2":2,"a1":3}';
      // Byte-wise sorting: "a1" < "a10" < "a2"
      expect(ashCanonicalizeJsonNative(input)).toBe('{"a1":3,"a10":1,"a2":2}');
    });

    it('sorts keys with mixed case (uppercase before lowercase in ASCII)', () => {
      const input = '{"b":1,"B":2,"a":3,"A":4}';
      // ASCII: A(65) < B(66) < a(97) < b(98)
      expect(ashCanonicalizeJsonNative(input)).toBe('{"A":4,"B":2,"a":3,"b":1}');
    });

    it('sorts keys with special characters', () => {
      const input = '{"_a":1,"a":2,"-a":3}';
      // ASCII: -(45) < _(95) < a(97)
      expect(ashCanonicalizeJsonNative(input)).toBe('{"-a":3,"_a":1,"a":2}');
    });

    it('sorts numeric string keys correctly', () => {
      const input = '{"100":1,"20":2,"3":3}';
      // Byte-wise: "100" < "20" < "3" (comparing first char: 1 < 2 < 3)
      expect(ashCanonicalizeJsonNative(input)).toBe('{"100":1,"20":2,"3":3}');
    });

    it('sorts empty string key first', () => {
      const input = '{"a":1,"":2}';
      expect(ashCanonicalizeJsonNative(input)).toBe('{"":2,"a":1}');
    });

    it('sorts keys with spaces', () => {
      const input = '{"a b":1," a":2,"a":3}';
      // Space (32) < a (97)
      expect(ashCanonicalizeJsonNative(input)).toBe('{" a":2,"a":3,"a b":1}');
    });

    it('handles deeply nested key sorting', () => {
      const input = '{"b":{"z":1,"a":2},"a":{"y":3,"x":4}}';
      expect(ashCanonicalizeJsonNative(input)).toBe('{"a":{"x":4,"y":3},"b":{"a":2,"z":1}}');
    });

    it('maintains consistency with WASM implementation', () => {
      const inputs = [
        '{"z":1,"a":2}',
        '{"nested":{"b":2,"a":1}}',
        '{"arr":[{"z":1,"a":2}]}',
      ];
      for (const input of inputs) {
        expect(ashCanonicalizeJsonNative(input)).toBe(ashCanonicalizeJson(input));
      }
    });
  });

  describe('Unicode Key Sorting (RFC 8785 Section 3.2.3)', () => {
    it('sorts Unicode keys by UTF-8 byte representation', () => {
      // Greek letters: alpha(α U+03B1), beta(β U+03B2)
      const input = '{"β":1,"α":2}';
      expect(ashCanonicalizeJsonNative(input)).toBe('{"α":2,"β":1}');
    });

    it('sorts ASCII before non-ASCII (UTF-8 byte order)', () => {
      const input = '{"é":1,"e":2}';
      // ASCII 'e' (0x65) comes before UTF-8 'é' (0xC3 0xA9)
      expect(ashCanonicalizeJsonNative(input)).toBe('{"e":2,"é":1}');
    });

    it('handles emoji keys', () => {
      const input = '{"🍎":1,"🍌":2,"a":3}';
      const result = ashCanonicalizeJsonNative(input);
      expect(result).toContain('"a":3');
      // ASCII 'a' should come before emojis in UTF-8 byte order
      expect(result.indexOf('"a"')).toBeLessThan(result.indexOf('"🍎"'));
    });

    it('normalizes combining characters (NFC)', () => {
      // e + combining acute (U+0065 U+0301) vs precomposed é (U+00E9)
      const decomposed = '{"e\u0301":1}';
      const precomposed = '{"é":1}';
      // Both should normalize to the same form
      expect(ashCanonicalizeJsonNative(decomposed)).toBe(ashCanonicalizeJsonNative(precomposed));
    });

    it('handles various Unicode scripts', () => {
      const input = '{"日本":1,"한국":2,"العربية":3}';
      const result = ashCanonicalizeJsonNative(input);
      expect(() => JSON.parse(result)).not.toThrow();
    });

    it('handles zero-width characters in keys', () => {
      const input = '{"a\u200Bb":1,"ab":2}';
      const result = ashCanonicalizeJsonNative(input);
      expect(() => JSON.parse(result)).not.toThrow();
    });
  });

  describe('Number Handling (RFC 8785 Section 3.2.2)', () => {
    it('converts -0 to 0', () => {
      const input = '{"n":-0}';
      expect(ashCanonicalizeJsonNative(input)).toBe('{"n":0}');
    });

    it('preserves positive zero', () => {
      const input = '{"n":0}';
      expect(ashCanonicalizeJsonNative(input)).toBe('{"n":0}');
    });

    it('preserves integer values', () => {
      const inputs = [
        ['{"n":1}', '{"n":1}'],
        ['{"n":-1}', '{"n":-1}'],
        ['{"n":42}', '{"n":42}'],
        ['{"n":9007199254740991}', '{"n":9007199254740991}'], // MAX_SAFE_INTEGER
      ];
      for (const [input, expected] of inputs) {
        expect(ashCanonicalizeJsonNative(input)).toBe(expected);
      }
    });

    it('preserves float values', () => {
      const inputs = [
        ['{"n":1.5}', '{"n":1.5}'],
        ['{"n":-1.5}', '{"n":-1.5}'],
        ['{"n":0.1}', '{"n":0.1}'],
        ['{"n":3.14159}', '{"n":3.14159}'],
      ];
      for (const [input, expected] of inputs) {
        expect(ashCanonicalizeJsonNative(input)).toBe(expected);
      }
    });

    it('handles scientific notation input', () => {
      const input = '{"n":1e10}';
      const result = ashCanonicalizeJsonNative(input);
      // JavaScript will convert to standard notation if possible
      expect(JSON.parse(result).n).toBe(1e10);
    });

    it('rejects NaN', () => {
      expect(() => ashCanonicalizeJsonValueNative({ n: NaN })).toThrow(/NaN/);
    });

    it('rejects Infinity', () => {
      expect(() => ashCanonicalizeJsonValueNative({ n: Infinity })).toThrow(/Infinity/);
    });

    it('rejects negative Infinity', () => {
      expect(() => ashCanonicalizeJsonValueNative({ n: -Infinity })).toThrow(/Infinity/);
    });

    it('handles very small numbers', () => {
      const input = '{"n":0.0000001}';
      const result = ashCanonicalizeJsonNative(input);
      expect(JSON.parse(result).n).toBe(0.0000001);
    });

    it('handles numbers at precision boundaries', () => {
      const result = ashCanonicalizeJsonValueNative({ n: Number.MAX_SAFE_INTEGER });
      expect(JSON.parse(result).n).toBe(Number.MAX_SAFE_INTEGER);
    });
  });

  describe('String Escaping (RFC 8785 Section 3.2.2.2)', () => {
    it('escapes backspace as \\b', () => {
      const input = JSON.stringify({ s: 'a\bb' });
      expect(ashCanonicalizeJsonNative(input)).toBe('{"s":"a\\bb"}');
    });

    it('escapes tab as \\t', () => {
      const input = JSON.stringify({ s: 'a\tb' });
      expect(ashCanonicalizeJsonNative(input)).toBe('{"s":"a\\tb"}');
    });

    it('escapes newline as \\n', () => {
      const input = JSON.stringify({ s: 'a\nb' });
      expect(ashCanonicalizeJsonNative(input)).toBe('{"s":"a\\nb"}');
    });

    it('escapes form feed as \\f', () => {
      const input = JSON.stringify({ s: 'a\fb' });
      expect(ashCanonicalizeJsonNative(input)).toBe('{"s":"a\\fb"}');
    });

    it('escapes carriage return as \\r', () => {
      const input = JSON.stringify({ s: 'a\rb' });
      expect(ashCanonicalizeJsonNative(input)).toBe('{"s":"a\\rb"}');
    });

    it('escapes double quote as \\"', () => {
      const input = JSON.stringify({ s: 'a"b' });
      expect(ashCanonicalizeJsonNative(input)).toBe('{"s":"a\\"b"}');
    });

    it('escapes backslash as \\\\', () => {
      const input = JSON.stringify({ s: 'a\\b' });
      expect(ashCanonicalizeJsonNative(input)).toBe('{"s":"a\\\\b"}');
    });

    it('escapes control characters 0x00-0x1F with \\uXXXX', () => {
      // Test control char 0x01 (not one of the special escapes)
      const input = JSON.stringify({ s: '\u0001' });
      expect(ashCanonicalizeJsonNative(input)).toBe('{"s":"\\u0001"}');
    });

    it('uses lowercase hex for \\uXXXX escapes', () => {
      const input = JSON.stringify({ s: '\u001F' });
      expect(ashCanonicalizeJsonNative(input)).toBe('{"s":"\\u001f"}');
    });

    it('does not escape printable ASCII characters', () => {
      const input = '{"s":"Hello, World! 123"}';
      expect(ashCanonicalizeJsonNative(input)).toBe('{"s":"Hello, World! 123"}');
    });

    it('does not escape non-ASCII Unicode characters', () => {
      const input = '{"s":"日本語"}';
      expect(ashCanonicalizeJsonNative(input)).toBe('{"s":"日本語"}');
    });

    it('handles mixed escaped and unescaped content', () => {
      const input = JSON.stringify({ s: 'line1\nline2\ttab' });
      expect(ashCanonicalizeJsonNative(input)).toBe('{"s":"line1\\nline2\\ttab"}');
    });
  });

  describe('Nested Structures', () => {
    it('canonicalizes nested objects', () => {
      const input = '{"outer":{"inner":{"deep":"value"}}}';
      expect(ashCanonicalizeJsonNative(input)).toBe('{"outer":{"inner":{"deep":"value"}}}');
    });

    it('sorts keys at all nesting levels', () => {
      const input = '{"b":{"z":{"q":1},"a":{"y":2}},"a":1}';
      expect(ashCanonicalizeJsonNative(input)).toBe('{"a":1,"b":{"a":{"y":2},"z":{"q":1}}}');
    });

    it('preserves array order', () => {
      const input = '{"arr":[3,1,2]}';
      expect(ashCanonicalizeJsonNative(input)).toBe('{"arr":[3,1,2]}');
    });

    it('canonicalizes objects within arrays', () => {
      const input = '{"arr":[{"b":1,"a":2}]}';
      expect(ashCanonicalizeJsonNative(input)).toBe('{"arr":[{"a":2,"b":1}]}');
    });

    it('handles arrays of arrays', () => {
      const input = '{"arr":[[3,2,1],[6,5,4]]}';
      expect(ashCanonicalizeJsonNative(input)).toBe('{"arr":[[3,2,1],[6,5,4]]}');
    });

    it('handles mixed nested structures', () => {
      const input = '{"a":[{"z":1,"a":2},{"y":[3,2,1]}],"b":{"c":{"d":4}}}';
      expect(ashCanonicalizeJsonNative(input)).toBe('{"a":[{"a":2,"z":1},{"y":[3,2,1]}],"b":{"c":{"d":4}}}');
    });

    it('handles deeply nested structures up to limit', () => {
      let deep = { value: 1 };
      for (let i = 0; i < 60; i++) {
        deep = { nested: deep } as any;
      }
      const input = JSON.stringify(deep);
      expect(() => ashCanonicalizeJsonNative(input)).not.toThrow();
    });

    it('rejects structures exceeding recursion depth', () => {
      let deep = { value: 1 };
      for (let i = 0; i < MAX_RECURSION_DEPTH + 10; i++) {
        deep = { nested: deep } as any;
      }
      const input = JSON.stringify(deep);
      expect(() => ashCanonicalizeJsonNative(input)).toThrow(/depth/i);
    });
  });

  describe('Special Values', () => {
    it('handles null', () => {
      expect(ashCanonicalizeJsonNative('null')).toBe('null');
      expect(ashCanonicalizeJsonNative('{"a":null}')).toBe('{"a":null}');
    });

    it('handles true', () => {
      expect(ashCanonicalizeJsonNative('true')).toBe('true');
      expect(ashCanonicalizeJsonNative('{"a":true}')).toBe('{"a":true}');
    });

    it('handles false', () => {
      expect(ashCanonicalizeJsonNative('false')).toBe('false');
      expect(ashCanonicalizeJsonNative('{"a":false}')).toBe('{"a":false}');
    });

    it('handles empty object', () => {
      expect(ashCanonicalizeJsonNative('{}')).toBe('{}');
    });

    it('handles empty array', () => {
      expect(ashCanonicalizeJsonNative('[]')).toBe('[]');
    });

    it('handles empty string', () => {
      expect(ashCanonicalizeJsonNative('""')).toBe('""');
    });

    it('rejects undefined values', () => {
      expect(() => ashCanonicalizeJsonValueNative({ a: undefined })).toThrow(/undefined/);
    });

    it('handles object with all value types', () => {
      const input = '{"str":"hello","num":42,"float":3.14,"bool":true,"nil":null,"arr":[1,2],"obj":{"a":1}}';
      const result = ashCanonicalizeJsonNative(input);
      expect(() => JSON.parse(result)).not.toThrow();
    });
  });

  describe('Edge Cases', () => {
    it('handles very long strings', () => {
      const longStr = 'a'.repeat(10000);
      const input = JSON.stringify({ s: longStr });
      const result = ashCanonicalizeJsonNative(input);
      expect(JSON.parse(result).s).toBe(longStr);
    });

    it('handles many keys', () => {
      const obj: Record<string, number> = {};
      for (let i = 0; i < 1000; i++) {
        obj[`key${i}`] = i;
      }
      const input = JSON.stringify(obj);
      const result = ashCanonicalizeJsonNative(input);
      expect(() => JSON.parse(result)).not.toThrow();
    });

    it('handles large arrays', () => {
      const arr = Array.from({ length: 10000 }, (_, i) => i);
      const input = JSON.stringify({ arr });
      const result = ashCanonicalizeJsonNative(input);
      expect(JSON.parse(result).arr.length).toBe(10000);
    });

    it('rejects payload exceeding max size', () => {
      const hugeStr = 'a'.repeat(MAX_PAYLOAD_SIZE + 1);
      expect(() => ashCanonicalizeJsonNative(hugeStr)).toThrow(/size/i);
    });

    it('rejects BigInt values with helpful message', () => {
      expect(() => ashCanonicalizeJsonValueNative({ n: BigInt(123) })).toThrow(/BigInt/);
    });

    it('handles object with numeric-like string keys', () => {
      const input = '{"1":1,"01":2,"001":3}';
      const result = ashCanonicalizeJsonNative(input);
      const parsed = JSON.parse(result);
      expect(parsed['1']).toBe(1);
      expect(parsed['01']).toBe(2);
      expect(parsed['001']).toBe(3);
    });

    it('handles whitespace in input (stripped)', () => {
      const input = '{\n  "b": 1,\n  "a": 2\n}';
      expect(ashCanonicalizeJsonNative(input)).toBe('{"a":2,"b":1}');
    });

    it('produces identical output for semantically identical JSON', () => {
      const inputs = [
        '{"a":1,"b":2}',
        '{"b":2,"a":1}',
        '{ "a" : 1 , "b" : 2 }',
        '{"b": 2, "a": 1}',
      ];
      const results = inputs.map(i => ashCanonicalizeJsonNative(i));
      expect(new Set(results).size).toBe(1);
    });

    it('handles consecutive escapes', () => {
      const input = JSON.stringify({ s: '\n\t\r\n' });
      expect(ashCanonicalizeJsonNative(input)).toBe('{"s":"\\n\\t\\r\\n"}');
    });
  });

  describe('Cross-SDK Compatibility', () => {
    it('produces deterministic output for complex nested structures', () => {
      const input = {
        users: [
          { name: 'Bob', id: 2 },
          { name: 'Alice', id: 1 },
        ],
        metadata: {
          version: '1.0',
          timestamp: 1234567890,
        },
      };
      const result1 = ashCanonicalizeJsonNative(JSON.stringify(input));
      const result2 = ashCanonicalizeJsonNative(JSON.stringify(input));
      expect(result1).toBe(result2);
    });

    it('matches expected canonical form for test vectors', () => {
      // Test vectors that should match across all SDK implementations
      const testVectors = [
        ['{"a":1}', '{"a":1}'],
        ['{"b":1,"a":2}', '{"a":2,"b":1}'],
        ['{"n":-0}', '{"n":0}'],
        ['[1,2,3]', '[1,2,3]'],
        ['{"arr":[{"b":1,"a":2}]}', '{"arr":[{"a":2,"b":1}]}'],
      ];
      for (const [input, expected] of testVectors) {
        expect(ashCanonicalizeJsonNative(input)).toBe(expected);
      }
    });

    it('handles Unicode test vectors consistently', () => {
      const testVectors = [
        '{"emoji":"🎉"}',
        '{"greek":"αβγ"}',
        '{"chinese":"中文"}',
        '{"arabic":"العربية"}',
      ];
      for (const input of testVectors) {
        const result = ashCanonicalizeJsonNative(input);
        expect(() => JSON.parse(result)).not.toThrow();
      }
    });
  });
});
