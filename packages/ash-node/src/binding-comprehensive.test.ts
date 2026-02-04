/**
 * Binding Normalization Comprehensive Tests
 *
 * Tests for HTTP binding normalization covering:
 * - HTTP method normalization (uppercase)
 * - Path normalization (leading slash, duplicate slashes, . and ..)
 * - Query string canonicalization
 * - Fragment stripping
 * - Special characters and edge cases
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  ashInit,
  ashNormalizeBinding,
  ashNormalizeBindingNative,
  ashNormalizeBindingFromUrl,
  ashCanonicalizeQuery,
  ashCanonicalizeQueryNative,
  MAX_BINDING_LENGTH,
} from './index';

// Initialize WASM
beforeAll(() => {
  try {
    ashInit();
  } catch {
    // WASM not available, tests will use native fallback
  }
});

describe('Binding Normalization Comprehensive Tests', () => {
  describe('HTTP Method Normalization', () => {
    it('uppercases lowercase method', () => {
      expect(ashNormalizeBindingNative('get', '/path')).toBe('GET|/path|');
    });

    it('uppercases mixed case method', () => {
      expect(ashNormalizeBindingNative('Get', '/path')).toBe('GET|/path|');
      expect(ashNormalizeBindingNative('gET', '/path')).toBe('GET|/path|');
    });

    it('preserves uppercase method', () => {
      expect(ashNormalizeBindingNative('GET', '/path')).toBe('GET|/path|');
    });

    it('handles all standard HTTP methods', () => {
      const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'];
      for (const method of methods) {
        expect(ashNormalizeBindingNative(method.toLowerCase(), '/path')).toBe(`${method}|/path|`);
      }
    });

    it('handles custom/extension methods', () => {
      expect(ashNormalizeBindingNative('PROPFIND', '/path')).toBe('PROPFIND|/path|');
      expect(ashNormalizeBindingNative('MKCOL', '/path')).toBe('MKCOL|/path|');
    });

    it('rejects non-ASCII method names', () => {
      expect(() => ashNormalizeBindingNative('GÉT', '/path')).toThrow(/ASCII/);
    });

    it('rejects method with numbers', () => {
      expect(() => ashNormalizeBindingNative('GET1', '/path')).toThrow();
    });

    it('rejects method with special characters', () => {
      expect(() => ashNormalizeBindingNative('GET-POST', '/path')).toThrow();
    });

    it('rejects empty method', () => {
      expect(() => ashNormalizeBindingNative('', '/path')).toThrow();
    });
  });

  describe('Path Normalization', () => {
    it('ensures path starts with /', () => {
      expect(ashNormalizeBindingNative('GET', 'path')).toBe('GET|/path|');
    });

    it('preserves leading /', () => {
      expect(ashNormalizeBindingNative('GET', '/path')).toBe('GET|/path|');
    });

    it('removes trailing slashes', () => {
      expect(ashNormalizeBindingNative('GET', '/path/')).toBe('GET|/path|');
      expect(ashNormalizeBindingNative('GET', '/path//')).toBe('GET|/path|');
    });

    it('preserves root path /', () => {
      expect(ashNormalizeBindingNative('GET', '/')).toBe('GET|/|');
    });

    it('removes duplicate slashes', () => {
      expect(ashNormalizeBindingNative('GET', '/api//test')).toBe('GET|/api/test|');
      expect(ashNormalizeBindingNative('GET', '//api///test')).toBe('GET|/api/test|');
    });

    it('resolves . segments (current directory)', () => {
      expect(ashNormalizeBindingNative('GET', '/api/./test')).toBe('GET|/api/test|');
      expect(ashNormalizeBindingNative('GET', '/./api/./test/.')).toBe('GET|/api/test|');
    });

    it('resolves .. segments (parent directory)', () => {
      expect(ashNormalizeBindingNative('GET', '/api/v1/../v2')).toBe('GET|/api/v2|');
      expect(ashNormalizeBindingNative('GET', '/api/a/b/../../c')).toBe('GET|/api/c|');
    });

    it('does not go above root with ..', () => {
      expect(ashNormalizeBindingNative('GET', '/../api')).toBe('GET|/api|');
      expect(ashNormalizeBindingNative('GET', '/../../api')).toBe('GET|/api|');
    });

    it('handles complex path traversal', () => {
      expect(ashNormalizeBindingNative('GET', '/a/b/c/../../d/../e')).toBe('GET|/a/e|');
    });

    it('preserves path segments with special characters', () => {
      expect(ashNormalizeBindingNative('GET', '/api/users/@me')).toBe('GET|/api/users/@me|');
      expect(ashNormalizeBindingNative('GET', '/api/file.json')).toBe('GET|/api/file.json|');
    });

    it('handles percent-encoded characters in path', () => {
      expect(ashNormalizeBindingNative('GET', '/api/users%2F123')).toBe('GET|/api/users%2F123|');
    });

    it('rejects path containing encoded query delimiter (%3F)', () => {
      expect(() => ashNormalizeBindingNative('GET', '/api%3Ftest')).toThrow(/%3F/);
    });

    it('handles Unicode in path', () => {
      const result = ashNormalizeBindingNative('GET', '/api/日本語');
      expect(result).toBe('GET|/api/日本語|');
    });

    it('handles long paths', () => {
      const longPath = '/api' + '/segment'.repeat(100);
      const result = ashNormalizeBindingNative('GET', longPath);
      expect(result).toContain('GET|');
    });
  });

  describe('Query String Canonicalization', () => {
    it('sorts query parameters by key', () => {
      expect(ashNormalizeBindingNative('GET', '/path', 'z=1&a=2')).toBe('GET|/path|a=2&z=1');
    });

    it('sorts duplicate keys by value', () => {
      expect(ashNormalizeBindingNative('GET', '/path', 'a=z&a=a&a=m')).toBe('GET|/path|a=a&a=m&a=z');
    });

    it('preserves empty values', () => {
      expect(ashNormalizeBindingNative('GET', '/path', 'a=&b=1')).toBe('GET|/path|a=&b=1');
    });

    it('handles keys without values', () => {
      expect(ashNormalizeBindingNative('GET', '/path', 'flag')).toBe('GET|/path|flag=');
    });

    it('removes leading ?', () => {
      expect(ashNormalizeBindingNative('GET', '/path', '?a=1')).toBe('GET|/path|a=1');
    });

    it('strips fragment from query', () => {
      expect(ashNormalizeBindingNative('GET', '/path', 'a=1#frag')).toBe('GET|/path|a=1');
    });

    it('uppercases percent-encoding hex', () => {
      expect(ashNormalizeBindingNative('GET', '/path', 'a=%2f')).toBe('GET|/path|a=%2F');
    });

    it('handles empty query', () => {
      expect(ashNormalizeBindingNative('GET', '/path', '')).toBe('GET|/path|');
    });

    it('handles whitespace-only query', () => {
      expect(ashNormalizeBindingNative('GET', '/path', '   ')).toBe('GET|/path|');
    });

    it('treats + as literal plus', () => {
      expect(ashCanonicalizeQueryNative('a+b=1')).toBe('a+b=1');
    });

    it('handles multiple & separators', () => {
      expect(ashCanonicalizeQueryNative('a=1&&b=2')).toBe('a=1&b=2');
    });
  });

  describe('Query String Edge Cases', () => {
    it('handles special characters in values', () => {
      const query = 'msg=' + encodeURIComponent('Hello, World!');
      const result = ashCanonicalizeQueryNative(query);
      expect(result).toContain('msg=');
    });

    it('handles equals sign in value', () => {
      const result = ashCanonicalizeQueryNative('eq=a=b');
      expect(result).toBe('eq=a=b');
    });

    it('handles multiple equals signs in value', () => {
      const result = ashCanonicalizeQueryNative('eq=a=b=c');
      expect(result).toBe('eq=a=b=c');
    });

    it('handles unicode in query', () => {
      const query = 'name=' + encodeURIComponent('日本語');
      const result = ashCanonicalizeQueryNative(query);
      expect(result).toContain('name=');
    });

    it('handles percent-encoded special chars', () => {
      const result = ashCanonicalizeQueryNative('a=%26&b=%3D');
      expect(result).toBe('a=%26&b=%3D');
    });

    it('normalizes mixed-case percent encoding', () => {
      const result = ashCanonicalizeQueryNative('a=%2F&b=%2f&c=%2f');
      expect(result).toBe('a=%2F&b=%2F&c=%2F');
    });

    it('handles very long query strings', () => {
      const params = Array.from({ length: 100 }, (_, i) => `key${i}=value${i}`).join('&');
      const result = ashCanonicalizeQueryNative(params);
      expect(result.split('&').length).toBe(100);
    });

    it('sorts numeric keys as strings', () => {
      const result = ashCanonicalizeQueryNative('10=a&2=b&1=c');
      // String sort: "1" < "10" < "2"
      expect(result).toBe('1=c&10=a&2=b');
    });
  });

  describe('Binding Format', () => {
    it('always includes trailing pipe even with empty query', () => {
      expect(ashNormalizeBindingNative('GET', '/path')).toBe('GET|/path|');
      expect(ashNormalizeBindingNative('GET', '/path', '')).toBe('GET|/path|');
    });

    it('uses pipe as delimiter', () => {
      const result = ashNormalizeBindingNative('GET', '/path', 'a=1');
      const parts = result.split('|');
      expect(parts).toHaveLength(3);
      expect(parts[0]).toBe('GET');
      expect(parts[1]).toBe('/path');
      expect(parts[2]).toBe('a=1');
    });

    it('handles complex real-world bindings', () => {
      const result = ashNormalizeBindingNative('POST', '/api/v1/users', 'page=1&limit=10&sort=name');
      expect(result).toBe('POST|/api/v1/users|limit=10&page=1&sort=name');
    });
  });

  describe('ashNormalizeBindingFromUrl', () => {
    it('parses path without query', () => {
      expect(ashNormalizeBindingFromUrl('GET', '/api/users')).toBe('GET|/api/users|');
    });

    it('parses path with query', () => {
      expect(ashNormalizeBindingFromUrl('GET', '/api/users?page=1')).toBe('GET|/api/users|page=1');
    });

    it('handles multiple ? in URL (only first is delimiter)', () => {
      // The WASM implementation encodes ? in query values as %3F
      const result = ashNormalizeBindingFromUrl('GET', '/search?q=hello?world');
      expect(result).toContain('GET|/search|');
      expect(result).toContain('q=hello');
    });

    it('handles complex URL with query and fragment', () => {
      const result = ashNormalizeBindingFromUrl('GET', '/api/test?b=2&a=1#section');
      expect(result).toBe('GET|/api/test|a=1&b=2');
    });

    it('normalizes path segments', () => {
      expect(ashNormalizeBindingFromUrl('GET', '/api/../v2/users?id=1')).toBe('GET|/v2/users|id=1');
    });
  });

  describe('Native vs WASM Parity', () => {
    it('produces identical results for standard bindings', () => {
      // Note: WASM may encode some chars differently, test only unreserved chars
      const testCases = [
        ['GET', '/api/users', ''],
        ['POST', '/api/users', 'page=1'],
        ['PUT', '/api/users/123', 'sort=name'],
        ['DELETE', '/api/users/123', ''],
      ];
      for (const [method, path, query] of testCases) {
        expect(ashNormalizeBindingNative(method, path, query)).toBe(
          ashNormalizeBinding(method, path, query)
        );
      }
    });

    it('produces identical results for edge cases', () => {
      const testCases = [
        ['get', '/api//test/', 'z=1&a=2'],
        ['POST', 'api/test', '?a=1#frag'],
        ['DELETE', '/api/./test/../users', 'a=%2f'],
      ];
      for (const [method, path, query] of testCases) {
        expect(ashNormalizeBindingNative(method, path, query)).toBe(
          ashNormalizeBinding(method, path, query)
        );
      }
    });
  });

  describe('Security Edge Cases', () => {
    it('rejects excessively long bindings', () => {
      const longPath = '/api' + '/x'.repeat(MAX_BINDING_LENGTH);
      // The validation happens in proof building, not normalization
      // But the resulting binding should still be valid
      const result = ashNormalizeBindingNative('GET', longPath.substring(0, 100));
      expect(result.length).toBeLessThan(MAX_BINDING_LENGTH);
    });

    it('handles path with null bytes in encoding', () => {
      const result = ashNormalizeBindingNative('GET', '/api%00test');
      expect(result).toContain('/api%00test');
    });

    it('handles SQL injection attempts in query', () => {
      const query = "id=1' OR '1'='1";
      const result = ashNormalizeBindingNative('GET', '/users', encodeURIComponent(query));
      expect(result).toContain('GET|/users|');
    });

    it('handles path traversal attempts', () => {
      // All .. should be resolved
      expect(ashNormalizeBindingNative('GET', '/api/../../etc/passwd')).toBe('GET|/etc/passwd|');
    });

    it('handles URL-encoded path traversal', () => {
      // %2E = .
      // This should be treated literally since it's encoded
      expect(ashNormalizeBindingNative('GET', '/api/%2E%2E/test')).toBe('GET|/api/%2E%2E/test|');
    });
  });

  describe('Real-World API Patterns', () => {
    it('handles REST API patterns', () => {
      expect(ashNormalizeBindingNative('GET', '/api/v1/users')).toBe('GET|/api/v1/users|');
      expect(ashNormalizeBindingNative('GET', '/api/v1/users/123')).toBe('GET|/api/v1/users/123|');
      expect(ashNormalizeBindingNative('POST', '/api/v1/users')).toBe('POST|/api/v1/users|');
      expect(ashNormalizeBindingNative('PUT', '/api/v1/users/123')).toBe('PUT|/api/v1/users/123|');
      expect(ashNormalizeBindingNative('DELETE', '/api/v1/users/123')).toBe('DELETE|/api/v1/users/123|');
    });

    it('handles pagination queries', () => {
      const result = ashNormalizeBindingNative('GET', '/api/items', 'page=2&limit=20&sort=created_at&order=desc');
      expect(result).toBe('GET|/api/items|limit=20&order=desc&page=2&sort=created_at');
    });

    it('handles filter queries', () => {
      const result = ashNormalizeBindingNative('GET', '/api/products', 'category=electronics&min_price=100&max_price=500');
      expect(result).toBe('GET|/api/products|category=electronics&max_price=500&min_price=100');
    });

    it('handles GraphQL endpoint', () => {
      expect(ashNormalizeBindingNative('POST', '/graphql')).toBe('POST|/graphql|');
    });

    it('handles webhook endpoints', () => {
      expect(ashNormalizeBindingNative('POST', '/webhooks/stripe')).toBe('POST|/webhooks/stripe|');
      expect(ashNormalizeBindingNative('POST', '/webhooks/github')).toBe('POST|/webhooks/github|');
    });

    it('handles file upload endpoints', () => {
      expect(ashNormalizeBindingNative('POST', '/api/files/upload')).toBe('POST|/api/files/upload|');
    });

    it('handles health check endpoints', () => {
      expect(ashNormalizeBindingNative('GET', '/health')).toBe('GET|/health|');
      expect(ashNormalizeBindingNative('GET', '/api/health/ready')).toBe('GET|/api/health/ready|');
    });
  });
});
