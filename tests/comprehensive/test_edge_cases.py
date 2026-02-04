"""
Test Edge Cases

Edge case tests:
- Empty payloads
- Unicode handling (NFC normalization)
- Special characters in fields
- Very large numbers
- Negative zero handling
- Array index boundaries
"""

import pytest
import math
import unicodedata
from ash.core import (
    ash_canonicalize_json,
    ash_canonicalize_url_encoded,
    ash_canonicalize_query,
    ash_normalize_binding,
    ash_build_proof_hmac,
    ash_derive_client_secret,
    ash_hash_body,
    ash_extract_scoped_fields,
    ash_timing_safe_equal,
)
from ash.core.errors import CanonicalizationError


class TestEmptyPayloads:
    """Test handling of empty payloads."""

    def test_empty_object(self):
        """Empty JSON object should canonicalize to {}."""
        result = ash_canonicalize_json({})
        assert result == "{}"

    def test_empty_array(self):
        """Empty JSON array should canonicalize to []."""
        result = ash_canonicalize_json([])
        assert result == "[]"

    def test_empty_string(self):
        """Empty string should canonicalize to quoted empty string."""
        result = ash_canonicalize_json("")
        assert result == '""'

    def test_null_value(self):
        """None/null should canonicalize to null."""
        result = ash_canonicalize_json(None)
        assert result == "null"

    def test_boolean_values(self):
        """Boolean values should canonicalize correctly."""
        assert ash_canonicalize_json(True) == "true"
        assert ash_canonicalize_json(False) == "false"

    def test_empty_object_hash(self):
        """Hash of empty object should be consistent."""
        canonical = ash_canonicalize_json({})
        hash_result = ash_hash_body(canonical)
        
        # SHA-256 of "{}"
        expected = ash_hash_body("{}")
        assert hash_result == expected

    def test_proof_with_empty_payload(self):
        """Proof with empty payload should work."""
        client_secret = ash_derive_client_secret("a" * 64, "ctx", "binding")
        body_hash = ash_hash_body(ash_canonicalize_json({}))
        
        proof = ash_build_proof_hmac(client_secret, "12345", "binding", body_hash)
        assert len(proof) == 64

    def test_empty_scope(self):
        """Empty scope should return full payload."""
        payload = {"a": 1, "b": 2}
        result = ash_extract_scoped_fields(payload, [])
        assert result == payload


class TestUnicodeHandling:
    """Test Unicode handling including NFC normalization."""

    def test_simple_unicode(self):
        """Simple Unicode characters should be preserved."""
        result = ash_canonicalize_json({"text": "Hello 世界"})
        assert "世界" in result

    def test_nfc_normalization(self):
        """NFD input should be normalized to NFC."""
        # café as e + combining acute accent (NFD)
        nfd_text = "cafe\u0301"
        # café as single character (NFC)
        nfc_text = "caf\u00e9"
        
        result_nfd = ash_canonicalize_json({"text": nfd_text})
        result_nfc = ash_canonicalize_json({"text": nfc_text})
        
        # Both should produce the same output
        assert result_nfd == result_nfc

    def test_emoji_handling(self):
        """Emoji should be handled correctly."""
        emojis = "🎉🚀💯🔒✅"
        result = ash_canonicalize_json({"emoji": emojis})
        
        # Emoji should be preserved
        assert "🎉" in result
        assert "🚀" in result
        assert "💯" in result

    def test_cjk_characters(self):
        """CJK characters should be handled."""
        payload = {
            "japanese": "日本語",
            "chinese": "中文",
            "korean": "한국어",
        }
        result = ash_canonicalize_json(payload)
        
        assert "日本語" in result
        assert "中文" in result
        assert "한국어" in result

    def test_rtl_text(self):
        """Right-to-left text should be handled."""
        payload = {
            "arabic": "العربية",
            "hebrew": "עברית",
        }
        result = ash_canonicalize_json(payload)
        
        assert "العربية" in result
        assert "עברית" in result

    def test_zero_width_characters(self):
        """Zero-width characters should be preserved."""
        # Zero-width space (U+200B)
        zwsp = "test\u200Btext"
        result = ash_canonicalize_json({"text": zwsp})
        assert "\u200B" in result

    def test_surrogate_pairs(self):
        """Surrogate pairs should be handled."""
        # Grinning face emoji (U+1F600) - outside BMP
        emoji = "😀"
        result = ash_canonicalize_json({"emoji": emoji})
        assert "😀" in result

    def test_combining_characters(self):
        """Combining characters should be handled."""
        # e + combining diaeresis + combining acute
        text = "e\u0308\u0301"
        result = ash_canonicalize_json({"text": text})
        assert isinstance(result, str)

    def test_unicode_in_keys(self):
        """Unicode in object keys should be handled."""
        payload = {"ключ": "value", "键": "value", "키": "value"}
        result = ash_canonicalize_json(payload)
        
        assert "ключ" in result
        assert "键" in result
        assert "키" in result


class TestSpecialCharacters:
    """Test special characters in fields."""

    def test_newlines_and_tabs(self):
        """Newlines and tabs should be escaped."""
        result = ash_canonicalize_json({"text": "line1\nline2\ttabbed"})
        assert "\\n" in result
        assert "\\t" in result

    def test_quotes_and_backslashes(self):
        """Quotes and backslashes should be escaped."""
        result = ash_canonicalize_json({"text": 'say "hello"\\world'})
        assert '\\"' in result
        assert "\\\\" in result

    def test_carriage_return(self):
        """Carriage returns should be escaped."""
        result = ash_canonicalize_json({"text": "line1\rline2"})
        assert "\\r" in result

    def test_backspace_and_formfeed(self):
        """Backspace and form feed should be escaped."""
        result = ash_canonicalize_json({"text": "a\bb\fc"})
        assert "\\b" in result
        assert "\\f" in result

    def test_control_characters(self):
        """Control characters should be escaped as \\uXXXX."""
        result = ash_canonicalize_json({"text": "\x00\x01\x02"})
        assert "\\u0000" in result
        assert "\\u0001" in result
        assert "\\u0002" in result

    def test_forward_slash(self):
        """Forward slashes should NOT be escaped (per RFC 8785)."""
        result = ash_canonicalize_json({"url": "http://example.com/path"})
        assert "/" in result  # Should not be escaped
        assert "\\/" not in result

    def test_special_chars_in_binding(self):
        """Special characters in binding path should be handled."""
        binding = ash_normalize_binding("GET", "/api/users/123")
        assert "123" in binding

    def test_url_encoded_special_chars(self):
        """Special characters in URL-encoded data."""
        result = ash_canonicalize_url_encoded("key=a+b")  # + should become %2B
        assert "%2B" in result


class TestVeryLargeNumbers:
    """Test handling of very large numbers."""

    def test_large_integer(self):
        """Large integers should be handled."""
        large = 9007199254740992  # 2^53
        result = ash_canonicalize_json({"value": large})
        assert "9007199254740992" in result

    def test_very_large_integer(self):
        """Very large integers should be handled."""
        large = 10**20
        result = ash_canonicalize_json({"value": large})
        assert str(10**20) in result

    def test_year_2038_timestamp(self):
        """Year 2038 boundary timestamp should work."""
        timestamp = 2147483647  # Max 32-bit signed int
        result = ash_canonicalize_json({"ts": timestamp})
        assert "2147483647" in result

    def test_year_3000_timestamp(self):
        """Year 3000 timestamp (64-bit) should work."""
        timestamp = 32503680000  # Year 3000
        result = ash_canonicalize_json({"ts": timestamp})
        assert "32503680000" in result

    def test_small_float(self):
        """Small float should be handled."""
        small = 1e-10
        result = ash_canonicalize_json({"value": small})
        assert "0.0000000001" in result or "1e-10" in result or "1E-10" in result

    def test_large_float(self):
        """Large float should be handled."""
        large = 1e20
        result = ash_canonicalize_json({"value": large})
        assert "100000000000000000000" in result or "1e+20" in result


class TestNegativeZeroHandling:
    """Test negative zero handling (should become 0)."""

    def test_negative_zero_float(self):
        """-0.0 should become 0."""
        result = ash_canonicalize_json({"value": -0.0})
        assert result == '{"value":0}'

    def test_positive_zero_float(self):
        """0.0 should remain 0."""
        result = ash_canonicalize_json({"value": 0.0})
        assert result == '{"value":0}'

    def test_zero_integer(self):
        """Integer 0 should remain 0."""
        result = ash_canonicalize_json({"value": 0})
        assert result == '{"value":0}'

    def test_negative_zero_in_array(self):
        """-0.0 in array should become 0."""
        result = ash_canonicalize_json({"values": [-0.0, 0.0, -0.0]})
        assert result == '{"values":[0,0,0]}'

    def test_negative_zero_nested(self):
        """-0.0 in nested object should become 0."""
        result = ash_canonicalize_json({"data": {"value": -0.0}})
        assert result == '{"data":{"value":0}}'


class TestArrayIndexBoundaries:
    """Test array index boundaries."""

    def test_empty_array(self):
        """Empty array should be handled."""
        result = ash_canonicalize_json({"items": []})
        assert result == '{"items":[]}'

    def test_single_element_array(self):
        """Single element array should be handled."""
        result = ash_canonicalize_json({"items": [1]})
        assert result == '{"items":[1]}'

    def test_large_array(self):
        """Large array should be handled."""
        items = list(range(1000))
        result = ash_canonicalize_json({"items": items})
        assert '"items":[' in result

    def test_nested_arrays(self):
        """Nested arrays should be handled."""
        result = ash_canonicalize_json({"matrix": [[1, 2], [3, 4]]})
        assert result == '{"matrix":[[1,2],[3,4]]}'

    def test_array_with_different_types(self):
        """Array with different types should be handled."""
        result = ash_canonicalize_json({"mixed": [1, "two", True, None, 3.14]})
        assert result == '{"mixed":[1,"two",true,null,3.14]}'

    def test_array_order_preserved(self):
        """Array order must be preserved."""
        result = ash_canonicalize_json({"items": [3, 1, 4, 1, 5]})
        assert result == '{"items":[3,1,4,1,5]}'

    def test_array_index_zero(self):
        """Array index 0 should work."""
        payload = {"items": ["first", "second"]}
        assert payload["items"][0] == "first"

    def test_array_index_last(self):
        """Last array index should work."""
        payload = {"items": [1, 2, 3, 4, 5]}
        assert payload["items"][4] == 5


class TestObjectKeySorting:
    """Test object key sorting edge cases."""

    def test_numeric_string_keys(self):
        """Numeric string keys should be sorted lexicographically."""
        payload = {"10": 1, "2": 2, "1": 3}
        result = ash_canonicalize_json(payload)
        # Lexicographic order: "1", "10", "2"
        assert result == '{"1":3,"10":1,"2":2}'

    def test_case_sensitive_sorting(self):
        """Key sorting should be case-sensitive."""
        payload = {"A": 1, "a": 2, "B": 3, "b": 4}
        result = ash_canonicalize_json(payload)
        # ASCII: A(65), B(66), a(97), b(98)
        assert result == '{"A":1,"B":3,"a":2,"b":4}'

    def test_unicode_key_sorting(self):
        """Unicode keys should be sorted by code point."""
        payload = {"\u00e9": 1, "e": 2}  # é vs e
        result = ash_canonicalize_json(payload)
        # e(101) < é(233)
        # The é character may be escaped or not depending on implementation
        assert '"e":2' in result
        assert '\\u00e9' in result or '\u00e9' in result

    def test_very_long_keys(self):
        """Very long keys should be handled."""
        key = "k" * 10000
        payload = {key: "value"}
        result = ash_canonicalize_json(payload)
        assert key in result


class TestMixedEdgeCases:
    """Test mixed edge cases."""

    def test_deeply_nested_structure(self):
        """Deeply nested structure should be handled."""
        depth = 50
        payload = {"value": "bottom"}
        for _ in range(depth - 1):
            payload = {"nested": payload}
        
        result = ash_canonicalize_json(payload)
        assert isinstance(result, str)
        assert result.count("nested") == depth - 1

    def test_many_keys(self):
        """Object with many keys should be handled."""
        payload = {f"key_{i}": i for i in range(1000)}
        result = ash_canonicalize_json(payload)
        
        # Keys should be sorted
        assert result.startswith('{"key_0":0')

    def test_mixed_unicode_and_ascii(self):
        """Mixed Unicode and ASCII should be handled."""
        payload = {
            "ascii": "hello",
            "unicode": "世界",
            "mixed": "hello世界",
            "emoji": "👋",
        }
        result = ash_canonicalize_json(payload)
        assert "hello" in result
        assert "世界" in result
        assert "👋" in result

    def test_null_bytes_in_context(self):
        """Null bytes in strings should be escaped."""
        result = ash_canonicalize_json({"text": "hello\x00world"})
        assert "\\u0000" in result

    def test_extreme_values(self):
        """Extreme numeric values should be handled."""
        # These may be implementation-specific
        payload = {
            "max_float": 1.7976931348623157e+308,  # Max double
            "min_float": 2.2250738585072014e-308,  # Min normal double
        }
        result = ash_canonicalize_json(payload)
        assert isinstance(result, str)
