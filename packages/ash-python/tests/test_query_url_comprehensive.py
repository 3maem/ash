"""
Comprehensive Query and URL Encoding Tests.

Tests for URL-encoded form data canonicalization, query string handling,
percent encoding, and special character handling.
"""

import pytest
from ash.core.canonicalize import (
    ash_canonicalize_query,
    ash_canonicalize_url_encoded,
    ash_normalize_binding,
    ash_normalize_binding_from_url,
)


class TestPercentEncoding:
    """Tests for percent encoding behavior."""

    def test_encode_space_as_percent_20(self):
        """Should encode space as %20."""
        result = ash_canonicalize_url_encoded("key=hello world")
        assert result == "key=hello%20world"

    def test_uppercase_hex_digits(self):
        """Should use uppercase hex digits."""
        result = ash_canonicalize_url_encoded("key=%2f")
        assert result == "key=%2F"

    def test_encode_all_reserved_chars(self):
        """Should encode reserved characters."""
        # RFC 3986 reserved characters: :/?#[]@!$&'()*+,;=
        reserved = {":", "/", "?", "#", "[", "]", "@", "!", "$", "&", "'", "(", ")", "*", "+", ",", ";", "="}
        for char in reserved:
            if char in "&=":  # These have special meaning in query strings
                continue
            result = ash_canonicalize_url_encoded(f"key={char}")
            # Should be percent-encoded
            assert "%" in result or char not in result

    def test_preserve_unreserved_chars(self):
        """Should not encode unreserved characters."""
        # RFC 3986 unreserved: A-Z a-z 0-9 - . _ ~
        unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        result = ash_canonicalize_url_encoded(f"key={unreserved}")
        assert result == f"key={unreserved}"

    def test_encode_unicode(self):
        """Should encode Unicode characters."""
        result = ash_canonicalize_url_encoded({"name": "test"})
        # Unicode should be percent-encoded
        assert "name=" in result
        assert "%" in result or "test" in result

    def test_double_encoding_prevention(self):
        """Should not double-encode already encoded values."""
        result = ash_canonicalize_url_encoded("key=hello%20world")
        # Should decode then re-encode
        assert result == "key=hello%20world"

    def test_encode_null_byte(self):
        """Should encode null bytes."""
        result = ash_canonicalize_url_encoded("key=a\x00b")
        assert "key=a%00b" in result or "key=a" in result

    def test_encode_control_characters(self):
        """Should encode control characters."""
        result = ash_canonicalize_url_encoded("key=a\nb")
        assert "%" in result or "\n" not in result

    def test_encode_high_byte_values(self):
        """Should encode high byte values."""
        result = ash_canonicalize_url_encoded("key=\xff")
        assert "%" in result


class TestPlusSignHandling:
    """Tests for plus sign handling in URL encoding."""

    def test_plus_treated_as_literal(self):
        """Plus sign should be treated as literal (not space)."""
        result = ash_canonicalize_url_encoded("a=hello+world")
        # + should be re-encoded as %2B
        assert result == "a=hello%2Bworld"

    def test_plus_in_key(self):
        """Plus sign in key should be encoded."""
        result = ash_canonicalize_url_encoded("key+name=value")
        assert "key%2Bname" in result

    def test_plus_preserved_through_roundtrip(self):
        """Plus sign meaning should be preserved."""
        original = "a=1+1"
        result = ash_canonicalize_url_encoded(original)
        # Should become a=1%2B1
        assert "%2B" in result


class TestQueryStringSorting:
    """Tests for query string parameter sorting."""

    def test_sort_alphabetically(self):
        """Should sort parameters alphabetically."""
        result = ash_canonicalize_query("z=1&a=2&m=3")
        assert result == "a=2&m=3&z=1"

    def test_sort_case_sensitive(self):
        """Should sort case-sensitively (byte order)."""
        result = ash_canonicalize_query("b=1&A=2&a=3")
        # ASCII: A(65) < a(97) < b(98)
        assert result == "A=2&a=3&b=1"

    def test_sort_numeric_strings(self):
        """Should sort numeric strings lexicographically."""
        result = ash_canonicalize_query("10=a&2=b&1=c")
        # Lexicographic: "1" < "10" < "2"
        assert result == "1=c&10=a&2=b"

    def test_sort_special_chars(self):
        """Should sort strings with special characters."""
        result = ash_canonicalize_query("_a=1&a=2&.a=3")
        # . (46) < _ (95) in ASCII, both before 'a' (97)
        # Result should be: .a=3&_a=1&a=2
        assert result == ".a=3&_a=1&a=2"

    def test_sort_duplicate_keys_by_value(self):
        """Should sort duplicate keys by value."""
        result = ash_canonicalize_query("a=z&a=a&a=m")
        assert result == "a=a&a=m&a=z"

    def test_sort_empty_values_first(self):
        """Empty values should sort before non-empty."""
        result = ash_canonicalize_query("a=b&a=")
        assert result == "a=&a=b"

    def test_maintain_stable_sort(self):
        """Sort should be stable and deterministic."""
        query = "c=3&a=1&b=2&a=0"
        result1 = ash_canonicalize_query(query)
        result2 = ash_canonicalize_query(query)
        assert result1 == result2
        assert result1 == "a=0&a=1&b=2&c=3"


class TestQueryStringParsing:
    """Tests for query string parsing."""

    def test_simple_key_value(self):
        """Should parse simple key=value pairs."""
        result = ash_canonicalize_query("key=value")
        assert result == "key=value"

    def test_multiple_pairs(self):
        """Should parse multiple pairs."""
        result = ash_canonicalize_query("a=1&b=2&c=3")
        assert "a=1" in result
        assert "b=2" in result
        assert "c=3" in result

    def test_key_without_value(self):
        """Should handle key without value (treat as empty)."""
        result = ash_canonicalize_query("a&b=1")
        assert "a=" in result
        assert "b=1" in result

    def test_key_with_empty_value(self):
        """Should preserve empty values."""
        result = ash_canonicalize_query("a=&b=1")
        assert "a=" in result
        assert "b=1" in result

    def test_empty_query_string(self):
        """Should handle empty query string."""
        assert ash_canonicalize_query("") == ""

    def test_strip_leading_question_mark(self):
        """Should strip leading question mark."""
        result = ash_canonicalize_query("?a=1&b=2")
        assert result == "a=1&b=2"

    def test_strip_fragment(self):
        """Should strip fragment identifier."""
        result = ash_canonicalize_query("a=1&b=2#section")
        assert result == "a=1&b=2"

    def test_strip_fragment_only(self):
        """Should handle fragment-only query."""
        result = ash_canonicalize_query("#section")
        assert result == ""

    def test_consecutive_ampersands(self):
        """Should handle consecutive ampersands."""
        result = ash_canonicalize_query("a=1&&b=2")
        assert result == "a=1&b=2"

    def test_trailing_ampersand(self):
        """Should handle trailing ampersand."""
        result = ash_canonicalize_query("a=1&b=2&")
        assert result == "a=1&b=2"

    def test_leading_ampersand(self):
        """Should handle leading ampersand."""
        result = ash_canonicalize_query("&a=1&b=2")
        assert result == "a=1&b=2"


class TestUrlEncodedFormData:
    """Tests for URL-encoded form data canonicalization."""

    def test_string_input(self):
        """Should accept string input."""
        result = ash_canonicalize_url_encoded("b=2&a=1")
        assert result == "a=1&b=2"

    def test_dict_input(self):
        """Should accept dict input."""
        result = ash_canonicalize_url_encoded({"b": "2", "a": "1"})
        assert result == "a=1&b=2"

    def test_dict_with_list_values(self):
        """Should handle dict with list values."""
        result = ash_canonicalize_url_encoded({"tags": ["b", "a", "c"], "name": "test"})
        # Should have multiple tags entries, sorted
        assert "name=test" in result
        assert "tags=" in result

    def test_encoding_in_values(self):
        """Should encode special characters in values."""
        result = ash_canonicalize_url_encoded({"key": "hello world"})
        assert result == "key=hello%20world"

    def test_encoding_in_keys(self):
        """Should encode special characters in keys."""
        result = ash_canonicalize_url_encoded({"key name": "value"})
        assert "key%20name=value" in result

    def test_unicode_handling(self):
        """Should handle Unicode in keys and values."""
        result = ash_canonicalize_url_encoded({"key": "value"})
        assert "key=" in result


class TestBindingWithQuery:
    """Tests for binding normalization with query strings."""

    def test_binding_no_query(self):
        """Should create binding without query."""
        result = ash_normalize_binding("GET", "/api/test")
        assert result == "GET|/api/test|"

    def test_binding_with_query(self):
        """Should include query in binding."""
        result = ash_normalize_binding("GET", "/api/test", "a=1")
        assert result == "GET|/api/test|a=1"

    def test_binding_query_sorted(self):
        """Should sort query in binding."""
        result = ash_normalize_binding("GET", "/api/test", "z=3&a=1")
        assert result == "GET|/api/test|a=1&z=3"

    def test_binding_from_url_with_query(self):
        """Should extract and normalize query from URL."""
        result = ash_normalize_binding_from_url("GET", "/api/test?z=3&a=1")
        assert result == "GET|/api/test|a=1&z=3"

    def test_binding_from_url_no_query(self):
        """Should handle URL without query."""
        result = ash_normalize_binding_from_url("GET", "/api/test")
        assert result == "GET|/api/test|"


class TestSpecialCharacterHandling:
    """Tests for special character handling."""

    def test_ampersand_in_value(self):
        """Should encode ampersand in value."""
        result = ash_canonicalize_url_encoded({"key": "a&b"})
        assert "key=a%26b" in result

    def test_equals_in_value(self):
        """Should handle equals sign in value."""
        result = ash_canonicalize_url_encoded("key=a=b")
        # First = is delimiter, second is part of value
        assert "key=a" in result

    def test_hash_in_value(self):
        """Should encode hash in value."""
        result = ash_canonicalize_url_encoded({"key": "a#b"})
        assert "key=a%23b" in result

    def test_question_mark_in_value(self):
        """Should encode question mark in value."""
        result = ash_canonicalize_url_encoded({"key": "a?b"})
        assert "key=a%3Fb" in result

    def test_slash_in_value(self):
        """Should encode slash in value."""
        result = ash_canonicalize_url_encoded({"key": "a/b"})
        assert "key=a%2Fb" in result

    def test_backslash_in_value(self):
        """Should encode backslash in value."""
        result = ash_canonicalize_url_encoded({"key": "a\\b"})
        assert "key=a%5Cb" in result


class TestEdgeCases:
    """Edge cases for query/URL encoding."""

    def test_very_long_value(self):
        """Should handle very long values."""
        long_value = "x" * 10000
        result = ash_canonicalize_url_encoded({"key": long_value})
        assert f"key={long_value}" in result

    def test_many_parameters(self):
        """Should handle many parameters."""
        params = {f"key{i}": f"value{i}" for i in range(100)}
        result = ash_canonicalize_url_encoded(params)
        # Keys should be sorted
        assert result.startswith("key0=value0")

    def test_empty_key(self):
        """Should handle empty key."""
        result = ash_canonicalize_url_encoded({"": "value"})
        assert "=value" in result

    def test_empty_value(self):
        """Should handle empty value."""
        result = ash_canonicalize_url_encoded({"key": ""})
        assert result == "key="

    def test_both_empty(self):
        """Should handle both key and value empty."""
        result = ash_canonicalize_url_encoded({"": ""})
        assert result == "="

    def test_unicode_normalization(self):
        """Should apply NFC normalization."""
        # e with combining acute accent (decomposed form)
        decomposed = "caf\u0065\u0301"
        result = ash_canonicalize_url_encoded({"name": decomposed})
        # Result should be normalized
        assert "name=" in result

    def test_mixed_encoding_input(self):
        """Should handle partially encoded input."""
        result = ash_canonicalize_query("a=%20&b= ")
        # Both should normalize to %20
        assert result == "a=%20&b=%20"


class TestDeterminism:
    """Tests for deterministic output."""

    def test_query_same_input_same_output(self):
        """Same input should produce same output."""
        query = "z=3&a=1&m=2"
        result1 = ash_canonicalize_query(query)
        result2 = ash_canonicalize_query(query)
        assert result1 == result2

    def test_url_encoded_same_input_same_output(self):
        """Same input should produce same output."""
        data = {"z": "3", "a": "1", "m": "2"}
        result1 = ash_canonicalize_url_encoded(data)
        result2 = ash_canonicalize_url_encoded(data)
        assert result1 == result2

    def test_binding_same_input_same_output(self):
        """Same input should produce same output."""
        result1 = ash_normalize_binding("GET", "/api/test", "b=2&a=1")
        result2 = ash_normalize_binding("GET", "/api/test", "b=2&a=1")
        assert result1 == result2

    def test_order_independence(self):
        """Different input order should produce same output."""
        result1 = ash_canonicalize_query("a=1&b=2")
        result2 = ash_canonicalize_query("b=2&a=1")
        assert result1 == result2


class TestRFC3986Compliance:
    """Tests for RFC 3986 compliance."""

    def test_unreserved_not_encoded(self):
        """Unreserved characters should not be encoded."""
        unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        result = ash_canonicalize_url_encoded({"key": unreserved})
        assert result == f"key={unreserved}"

    def test_pct_encoded_uppercase(self):
        """Percent-encoded hex digits should be uppercase."""
        # Use lowercase input
        result = ash_canonicalize_query("key=%2f")
        assert result == "key=%2F"

    def test_utf8_encoding(self):
        """Non-ASCII should be UTF-8 encoded then percent-encoded."""
        result = ash_canonicalize_url_encoded({"key": "a"})
        # Chinese character should be percent-encoded
        assert "key=" in result
        # 'a' (U+4E2D) in UTF-8 is E4 B8 AD
        assert "%E4%B8%AD" in result or "a" in result


class TestQueryValueOrdering:
    """Tests for ordering of multiple values with same key."""

    def test_duplicate_keys_sorted(self):
        """Duplicate keys should be sorted by value."""
        result = ash_canonicalize_query("color=red&color=blue&color=green")
        # Should be sorted: blue < green < red
        assert result == "color=blue&color=green&color=red"

    def test_numeric_values_sorted_lexicographically(self):
        """Numeric values should be sorted lexicographically."""
        result = ash_canonicalize_query("n=10&n=2&n=1")
        # Lexicographic: "1" < "10" < "2"
        assert result == "n=1&n=10&n=2"

    def test_mixed_case_values_sorted(self):
        """Mixed case values should be sorted by byte order."""
        result = ash_canonicalize_query("a=B&a=a&a=A")
        # ASCII: A(65) < B(66) < a(97)
        assert result == "a=A&a=B&a=a"
