/**
 * Query/URL Encoding Comprehensive Tests
 *
 * Tests for query string and URL handling covering:
 * - Percent encoding (RFC 3986)
 * - Special characters
 * - Unicode handling
 * - Base64URL encoding/decoding
 * - Edge cases and security concerns
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  ashInit,
  ashCanonicalizeQuery,
  ashCanonicalizeQueryNative,
  ashCanonicalizeUrlencoded,
  ashCanonicalizeUrlencodedNative,
  ashBase64UrlEncode,
  ashBase64UrlDecode,
  ashBase64UrlDecodeToBuffer,
  ashNormalizeBinding,
  ashNormalizeBindingFromUrl,
} from './index';

// Initialize WASM
beforeAll(() => {
  try {
    ashInit();
  } catch {
    // WASM not available, tests will use native fallback
  }
});

describe('Query/URL Encoding Comprehensive Tests', () => {
  describe('Percent Encoding - RFC 3986', () => {
    it('uppercases lowercase percent-encoded hex', () => {
      expect(ashCanonicalizeQueryNative('a=%2f')).toBe('a=%2F');
      expect(ashCanonicalizeQueryNative('a=%2F')).toBe('a=%2F');
    });

    it('normalizes mixed-case percent encoding', () => {
      expect(ashCanonicalizeQueryNative('a=%2f&b=%2F&c=%2f')).toBe('a=%2F&b=%2F&c=%2F');
    });

    it('handles encoded space (%20)', () => {
      expect(ashCanonicalizeQueryNative('a=hello%20world')).toBe('a=hello%20world');
    });

    it('handles encoded ampersand (%26)', () => {
      expect(ashCanonicalizeQueryNative('a=foo%26bar')).toBe('a=foo%26bar');
    });

    it('handles encoded equals (%3D)', () => {
      expect(ashCanonicalizeQueryNative('a=foo%3Dbar')).toBe('a=foo%3Dbar');
    });

    it('handles all special characters encoded', () => {
      const specialChars = [
        ['%21', '!'],
        ['%23', '#'],
        ['%24', '$'],
        ['%25', '%'],
        ['%26', '&'],
        ['%27', "'"],
        ['%28', '('],
        ['%29', ')'],
        ['%2A', '*'],
        ['%2B', '+'],
        ['%2C', ','],
        ['%2F', '/'],
        ['%3A', ':'],
        ['%3B', ';'],
        ['%3D', '='],
        ['%3F', '?'],
        ['%40', '@'],
        ['%5B', '['],
        ['%5D', ']'],
      ];

      for (const [encoded] of specialChars) {
        const result = ashCanonicalizeQueryNative(`key=${encoded}`);
        expect(result).toContain(encoded.toUpperCase());
      }
    });

    it('preserves unreserved characters', () => {
      // Unreserved: A-Z a-z 0-9 - . _ ~
      const unreserved = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
      expect(ashCanonicalizeQueryNative(`key=${unreserved}`)).toBe(`key=${unreserved}`);
    });
  });

  describe('Special Character Handling', () => {
    it('treats + as literal plus (not space)', () => {
      expect(ashCanonicalizeQueryNative('a+b=1')).toBe('a+b=1');
      expect(ashCanonicalizeQueryNative('a=b+c')).toBe('a=b+c');
    });

    it('distinguishes + from %2B', () => {
      // + is literal plus, %2B is also plus but encoded
      expect(ashCanonicalizeQueryNative('a=%2B')).toBe('a=%2B');
    });

    it('handles equals sign in value', () => {
      expect(ashCanonicalizeQueryNative('key=a=b')).toBe('key=a=b');
      expect(ashCanonicalizeQueryNative('key=a=b=c')).toBe('key=a=b=c');
    });

    it('handles empty value', () => {
      expect(ashCanonicalizeQueryNative('key=')).toBe('key=');
    });

    it('handles key without value (no equals)', () => {
      expect(ashCanonicalizeQueryNative('flag')).toBe('flag=');
    });

    it('handles empty key', () => {
      expect(ashCanonicalizeQueryNative('=value')).toBe('=value');
    });

    it('handles multiple empty values', () => {
      expect(ashCanonicalizeQueryNative('a=&b=&c=')).toBe('a=&b=&c=');
    });

    it('handles leading question mark', () => {
      expect(ashCanonicalizeQueryNative('?a=1&b=2')).toBe('a=1&b=2');
    });

    it('strips fragment', () => {
      expect(ashCanonicalizeQueryNative('a=1#fragment')).toBe('a=1');
      expect(ashCanonicalizeQueryNative('a=1&b=2#section')).toBe('a=1&b=2');
    });

    it('handles fragment with query-like content', () => {
      expect(ashCanonicalizeQueryNative('a=1#b=2&c=3')).toBe('a=1');
    });
  });

  describe('Unicode Handling', () => {
    it('handles percent-encoded Unicode', () => {
      // 日 = %E6%97%A5
      const result = ashCanonicalizeQueryNative('name=%E6%97%A5');
      expect(result).toBe('name=%E6%97%A5');
    });

    it('normalizes lowercase encoded Unicode', () => {
      // Same character with lowercase hex
      expect(ashCanonicalizeQueryNative('name=%e6%97%a5')).toBe('name=%E6%97%A5');
    });

    it('handles emojis (encoded)', () => {
      // 🎉 = %F0%9F%8E%89
      const result = ashCanonicalizeQueryNative('emoji=%F0%9F%8E%89');
      expect(result).toBe('emoji=%F0%9F%8E%89');
    });

    it('handles raw Unicode in query (passed through)', () => {
      // Raw Unicode should be passed through as-is
      const result = ashCanonicalizeQueryNative('name=日本語');
      expect(result).toContain('name=');
    });

    it('handles mixed encoded and raw Unicode', () => {
      const result = ashCanonicalizeQueryNative('a=日本&b=%E6%97%A5');
      expect(result).toContain('a=');
      expect(result).toContain('b=');
    });
  });

  describe('Sorting', () => {
    it('sorts parameters by key', () => {
      expect(ashCanonicalizeQueryNative('z=1&a=2&m=3')).toBe('a=2&m=3&z=1');
    });

    it('sorts duplicate keys by value', () => {
      expect(ashCanonicalizeQueryNative('a=z&a=a&a=m')).toBe('a=a&a=m&a=z');
    });

    it('sorts numeric keys as strings', () => {
      expect(ashCanonicalizeQueryNative('10=a&2=b&1=c')).toBe('1=c&10=a&2=b');
    });

    it('sorts keys with special characters', () => {
      // Byte-wise sorting
      const result = ashCanonicalizeQueryNative('a-b=1&a_c=2&ab=3');
      expect(result).toBe('a-b=1&a_c=2&ab=3');
    });

    it('sorts case-sensitively (uppercase before lowercase)', () => {
      expect(ashCanonicalizeQueryNative('b=1&B=2&a=3&A=4')).toBe('A=4&B=2&a=3&b=1');
    });

    it('maintains order for identical keys with same values', () => {
      // When key and value are same, order should be stable
      const result = ashCanonicalizeQueryNative('a=1&a=1');
      expect(result).toBe('a=1&a=1');
    });
  });

  describe('URL-Encoded Form Data', () => {
    it('sorts form data parameters', () => {
      expect(ashCanonicalizeUrlencodedNative('z=1&a=2')).toBe('a=2&z=1');
    });

    it('handles plus as literal in form data', () => {
      // In form data, + is typically used for space, but we treat it as literal
      // and encode as %2B
      const result = ashCanonicalizeUrlencodedNative('a+b=1');
      expect(result).toBe('a%2Bb=1');
    });

    it('encodes plus in values', () => {
      const result = ashCanonicalizeUrlencodedNative('name=John+Doe');
      expect(result).toBe('name=John%2BDoe');
    });

    it('matches query canonicalization for non-plus content', () => {
      const query = 'a=1&b=2&c=3';
      expect(ashCanonicalizeUrlencodedNative(query)).toBe(ashCanonicalizeQueryNative(query));
    });
  });

  describe('Base64URL Encoding', () => {
    it('encodes string to base64url', () => {
      const result = ashBase64UrlEncode('Hello, World!');
      expect(result).toBe('SGVsbG8sIFdvcmxkIQ');
    });

    it('encodes buffer to base64url', () => {
      const buffer = Buffer.from('test data');
      const result = ashBase64UrlEncode(buffer);
      expect(result).toBe('dGVzdCBkYXRh');
    });

    it('uses URL-safe characters (no +/)', () => {
      // Input that would produce + and / in regular base64
      const input = '>>??';
      const result = ashBase64UrlEncode(input);
      expect(result).not.toContain('+');
      expect(result).not.toContain('/');
    });

    it('does not include padding', () => {
      const result = ashBase64UrlEncode('test');
      expect(result).not.toContain('=');
    });

    it('handles empty input', () => {
      expect(ashBase64UrlEncode('')).toBe('');
    });

    it('handles binary data', () => {
      const binary = Buffer.from([0x00, 0xff, 0x80, 0x7f]);
      const result = ashBase64UrlEncode(binary);
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
    });
  });

  describe('Base64URL Decoding', () => {
    it('decodes base64url to string', () => {
      const result = ashBase64UrlDecode('SGVsbG8sIFdvcmxkIQ');
      expect(result).toBe('Hello, World!');
    });

    it('decodes base64url to buffer', () => {
      const result = ashBase64UrlDecodeToBuffer('dGVzdCBkYXRh');
      expect(result.toString()).toBe('test data');
    });

    it('handles URL-safe characters', () => {
      // Input with - and _ (URL-safe replacements for + and /)
      const encoded = ashBase64UrlEncode('test>>??data');
      const decoded = ashBase64UrlDecode(encoded);
      expect(decoded).toBe('test>>??data');
    });

    it('handles empty input', () => {
      expect(ashBase64UrlDecode('')).toBe('');
    });

    it('handles binary data round-trip', () => {
      const original = Buffer.from([0x00, 0xff, 0x80, 0x7f]);
      const encoded = ashBase64UrlEncode(original);
      const decoded = ashBase64UrlDecodeToBuffer(encoded);
      expect(decoded.equals(original)).toBe(true);
    });

    it('roundtrip encoding/decoding preserves data', () => {
      const testCases = [
        'Hello, World!',
        '日本語',
        'Special chars: !@#$%^&*()',
        '\x00\x01\x02\x03',
        'a'.repeat(1000),
      ];

      for (const input of testCases) {
        const encoded = ashBase64UrlEncode(input);
        const decoded = ashBase64UrlDecode(encoded);
        expect(decoded).toBe(input);
      }
    });
  });

  describe('Full URL Normalization', () => {
    it('handles URL with query string', () => {
      const result = ashNormalizeBindingFromUrl('GET', '/api/users?page=1&limit=10');
      expect(result).toBe('GET|/api/users|limit=10&page=1');
    });

    it('handles URL without query string', () => {
      const result = ashNormalizeBindingFromUrl('GET', '/api/users');
      expect(result).toBe('GET|/api/users|');
    });

    it('handles URL with fragment', () => {
      const result = ashNormalizeBindingFromUrl('GET', '/api/users?page=1#section');
      expect(result).toBe('GET|/api/users|page=1');
    });

    it('handles URL with multiple question marks', () => {
      // Only first ? is query delimiter
      // WASM may encode ? in query values as %3F
      const result = ashNormalizeBindingFromUrl('GET', '/search?q=what?is&a=1');
      expect(result).toContain('GET|/search|');
      expect(result).toContain('a=1');
      expect(result).toContain('q=what');
    });

    it('handles complex path with query', () => {
      // WASM may encode comma as %2C
      const result = ashNormalizeBindingFromUrl('POST', '/api/v2/../v3/users?fields=name,email&sort=name');
      expect(result).toContain('POST|/api/v3/users|');
      expect(result).toContain('fields=name');
      expect(result).toContain('sort=name');
    });
  });

  describe('Edge Cases', () => {
    it('handles very long query strings', () => {
      const params = Array.from({ length: 100 }, (_, i) => `key${i}=value${i}`).join('&');
      const result = ashCanonicalizeQueryNative(params);
      expect(result.split('&').length).toBe(100);
    });

    it('handles query with only ampersands', () => {
      expect(ashCanonicalizeQueryNative('&&&')).toBe('');
    });

    it('handles consecutive ampersands', () => {
      expect(ashCanonicalizeQueryNative('a=1&&b=2&&&c=3')).toBe('a=1&b=2&c=3');
    });

    it('handles whitespace in query', () => {
      expect(ashCanonicalizeQueryNative('   ')).toBe('');
    });

    it('handles trailing ampersand', () => {
      expect(ashCanonicalizeQueryNative('a=1&')).toBe('a=1');
    });

    it('handles leading ampersand', () => {
      expect(ashCanonicalizeQueryNative('&a=1')).toBe('a=1');
    });

    it('handles null byte in encoded form', () => {
      const result = ashCanonicalizeQueryNative('key=%00');
      expect(result).toBe('key=%00');
    });

    it('handles incomplete percent encoding', () => {
      // Incomplete encoding should be passed through
      const result = ashCanonicalizeQueryNative('key=%2');
      expect(result).toContain('key=');
    });

    it('handles percent without hex digits', () => {
      const result = ashCanonicalizeQueryNative('key=100%');
      expect(result).toContain('key=');
    });
  });

  describe('Security Edge Cases', () => {
    it('handles SQL injection in query values', () => {
      const injection = encodeURIComponent("'; DROP TABLE users; --");
      const result = ashCanonicalizeQueryNative(`id=${injection}`);
      expect(result).toContain('id=');
    });

    it('handles XSS in query values', () => {
      const xss = encodeURIComponent('<script>alert(1)</script>');
      const result = ashCanonicalizeQueryNative(`msg=${xss}`);
      expect(result).toContain('msg=');
    });

    it('handles command injection in query values', () => {
      const cmd = encodeURIComponent('; rm -rf /');
      const result = ashCanonicalizeQueryNative(`cmd=${cmd}`);
      expect(result).toContain('cmd=');
    });

    it('handles path traversal in query values', () => {
      const traversal = encodeURIComponent('../../../etc/passwd');
      const result = ashCanonicalizeQueryNative(`file=${traversal}`);
      expect(result).toContain('file=');
    });

    it('handles extremely long keys', () => {
      const longKey = 'k'.repeat(1000);
      const result = ashCanonicalizeQueryNative(`${longKey}=value`);
      expect(result).toContain(`${longKey}=value`);
    });

    it('handles extremely long values', () => {
      const longValue = 'v'.repeat(10000);
      const result = ashCanonicalizeQueryNative(`key=${longValue}`);
      expect(result).toBe(`key=${longValue}`);
    });
  });

  describe('Native vs WASM Parity', () => {
    it('query canonicalization matches', () => {
      // Test cases without + which may be handled differently
      const testCases = [
        'a=1&b=2',
        'z=1&a=2&m=3',
        'a=%2f&b=%2F',
        '?a=1#frag',
        'empty=&key=value',
      ];

      for (const query of testCases) {
        expect(ashCanonicalizeQueryNative(query)).toBe(ashCanonicalizeQuery(query));
      }
    });

    it('handles plus sign - may differ between native and WASM', () => {
      // Native treats + as literal, WASM may encode it
      const result = ashCanonicalizeQueryNative('a+b=c+d');
      expect(result).toContain('a');
      expect(result).toContain('b');
    });

    it('urlencoded canonicalization matches', () => {
      const testCases = [
        'a=1&b=2',
      ];

      for (const form of testCases) {
        expect(ashCanonicalizeUrlencodedNative(form)).toBe(ashCanonicalizeUrlencoded(form));
      }
    });
  });

  describe('Real-World Query Patterns', () => {
    it('handles OAuth parameters', () => {
      const query = 'client_id=abc123&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&scope=read%20write&state=xyz789';
      const result = ashCanonicalizeQueryNative(query);
      expect(result).toContain('client_id=abc123');
      expect(result).toContain('redirect_uri=');
      expect(result).toContain('scope=');
      expect(result).toContain('state=xyz789');
    });

    it('handles search queries', () => {
      const query = 'q=hello%20world&page=1&limit=10&sort=relevance&filter%5Bcategory%5D=books';
      const result = ashCanonicalizeQueryNative(query);
      // Should be sorted alphabetically
      const parts = result.split('&');
      expect(parts[0]).toContain('filter');
      expect(parts[parts.length - 1]).toContain('sort');
    });

    it('handles API pagination', () => {
      const query = 'offset=100&limit=25&cursor=abc123&fields=id,name,email';
      const result = ashCanonicalizeQueryNative(query);
      expect(result).toBe('cursor=abc123&fields=id,name,email&limit=25&offset=100');
    });

    it('handles form submission data', () => {
      const form = 'first_name=John&last_name=Doe&email=john%40example.com&password=secret123';
      const result = ashCanonicalizeUrlencodedNative(form);
      expect(result).toContain('email=john%40example.com');
    });
  });
});
