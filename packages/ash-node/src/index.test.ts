import { describe, it, expect, beforeAll } from 'vitest';
import {
  ashInit,
  ashCanonicalizeJson,
  ashCanonicalizeUrlencoded,
  ashBuildProof,
  ashVerifyProof,
  ashNormalizeBinding,
  ashTimingSafeEqual,
  ashVersion,
  ashLibraryVersion,
} from './index';

describe('ASH Node.js SDK', () => {
  beforeAll(() => {
    ashInit();
  });

  describe('ashVersion', () => {
    it('returns protocol version', () => {
      const version = ashVersion();
      expect(version).toBe('ASHv1');
    });
  });

  describe('ashLibraryVersion', () => {
    it('returns library version', () => {
      const version = ashLibraryVersion();
      expect(version).toMatch(/^\d+\.\d+\.\d+$/);
    });
  });

  describe('ashCanonicalizeJson', () => {
    it('sorts keys alphabetically', () => {
      const result = ashCanonicalizeJson('{"z":1,"a":2,"m":3}');
      expect(result).toBe('{"a":2,"m":3,"z":1}');
    });

    it('handles nested objects', () => {
      const result = ashCanonicalizeJson('{"b":{"y":1,"x":2},"a":1}');
      expect(result).toBe('{"a":1,"b":{"x":2,"y":1}}');
    });

    it('handles arrays', () => {
      const result = ashCanonicalizeJson('{"a":[3,1,2]}');
      expect(result).toBe('{"a":[3,1,2]}');
    });

    it('handles empty object', () => {
      const result = ashCanonicalizeJson('{}');
      expect(result).toBe('{}');
    });
  });

  describe('ashCanonicalizeUrlencoded', () => {
    it('sorts parameters alphabetically', () => {
      const result = ashCanonicalizeUrlencoded('z=1&a=2&m=3');
      expect(result).toBe('a=2&m=3&z=1');
    });

    it('handles empty string', () => {
      const result = ashCanonicalizeUrlencoded('');
      expect(result).toBe('');
    });

    it('handles single parameter', () => {
      const result = ashCanonicalizeUrlencoded('foo=bar');
      expect(result).toBe('foo=bar');
    });
  });

  describe('ashNormalizeBinding', () => {
    it('uppercases method and uses pipe format', () => {
      const result = ashNormalizeBinding('post', '/api/test');
      expect(result).toBe('POST|/api/test|');
    });

    it('removes trailing slashes', () => {
      const result = ashNormalizeBinding('GET', '/api/test/');
      expect(result).toBe('GET|/api/test|');
    });

    it('removes duplicate slashes', () => {
      const result = ashNormalizeBinding('GET', '/api//test');
      expect(result).toBe('GET|/api/test|');
    });

    it('includes canonicalized query string', () => {
      const result = ashNormalizeBinding('GET', '/api/test', 'z=1&a=2');
      expect(result).toBe('GET|/api/test|a=2&z=1');
    });
  });

  describe('ashBuildProof', () => {
    it('generates consistent proofs', () => {
      const proof1 = ashBuildProof(
        'balanced',
        'POST /api/test',
        'ctx123',
        null,
        '{"a":1}'
      );
      const proof2 = ashBuildProof(
        'balanced',
        'POST /api/test',
        'ctx123',
        null,
        '{"a":1}'
      );
      expect(proof1).toBe(proof2);
    });

    it('generates different proofs for different payloads', () => {
      const proof1 = ashBuildProof(
        'balanced',
        'POST /api/test',
        'ctx123',
        null,
        '{"a":1}'
      );
      const proof2 = ashBuildProof(
        'balanced',
        'POST /api/test',
        'ctx123',
        null,
        '{"a":2}'
      );
      expect(proof1).not.toBe(proof2);
    });
  });

  describe('ashVerifyProof', () => {
    it('returns true for matching proofs', () => {
      const proof = ashBuildProof(
        'balanced',
        'POST /api/test',
        'ctx123',
        null,
        '{"a":1}'
      );
      expect(ashVerifyProof(proof, proof)).toBe(true);
    });

    it('returns false for non-matching proofs', () => {
      const proof1 = ashBuildProof(
        'balanced',
        'POST /api/test',
        'ctx123',
        null,
        '{"a":1}'
      );
      const proof2 = ashBuildProof(
        'balanced',
        'POST /api/test',
        'ctx123',
        null,
        '{"a":2}'
      );
      expect(ashVerifyProof(proof1, proof2)).toBe(false);
    });
  });

  describe('ashTimingSafeEqual', () => {
    it('returns true for equal strings', () => {
      expect(ashTimingSafeEqual('hello', 'hello')).toBe(true);
    });

    it('returns false for different strings', () => {
      expect(ashTimingSafeEqual('hello', 'world')).toBe(false);
    });

    it('returns false for different lengths', () => {
      expect(ashTimingSafeEqual('hello', 'hi')).toBe(false);
    });
  });
});
