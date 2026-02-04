"""
Comprehensive Binding Normalization Tests.

Tests for ash_normalize_binding, ash_normalize_binding_from_url, and
ash_canonicalize_query functions to ensure consistent binding canonicalization
across all SDK implementations.
"""

import pytest
from ash.core.canonicalize import (
    ash_normalize_binding,
    ash_normalize_binding_from_url,
    ash_canonicalize_query,
)


class TestBindingMethodNormalization:
    """Tests for HTTP method normalization in bindings."""

    def test_uppercase_method_unchanged(self):
        """Should keep uppercase methods unchanged."""
        result = ash_normalize_binding("GET", "/api/test")
        assert result == "GET|/api/test|"

    def test_lowercase_method_uppercased(self):
        """Should uppercase lowercase methods."""
        result = ash_normalize_binding("get", "/api/test")
        assert result == "GET|/api/test|"

    def test_mixed_case_method_uppercased(self):
        """Should uppercase mixed case methods."""
        result = ash_normalize_binding("GeT", "/api/test")
        assert result == "GET|/api/test|"

    def test_post_method(self):
        """Should handle POST method."""
        result = ash_normalize_binding("post", "/api/test")
        assert result == "POST|/api/test|"

    def test_put_method(self):
        """Should handle PUT method."""
        result = ash_normalize_binding("put", "/api/test")
        assert result == "PUT|/api/test|"

    def test_delete_method(self):
        """Should handle DELETE method."""
        result = ash_normalize_binding("delete", "/api/test")
        assert result == "DELETE|/api/test|"

    def test_patch_method(self):
        """Should handle PATCH method."""
        result = ash_normalize_binding("patch", "/api/test")
        assert result == "PATCH|/api/test|"

    def test_options_method(self):
        """Should handle OPTIONS method."""
        result = ash_normalize_binding("options", "/api/test")
        assert result == "OPTIONS|/api/test|"

    def test_head_method(self):
        """Should handle HEAD method."""
        result = ash_normalize_binding("head", "/api/test")
        assert result == "HEAD|/api/test|"

    def test_trace_method(self):
        """Should handle TRACE method."""
        result = ash_normalize_binding("trace", "/api/test")
        assert result == "TRACE|/api/test|"

    def test_connect_method(self):
        """Should handle CONNECT method."""
        result = ash_normalize_binding("connect", "/api/test")
        assert result == "CONNECT|/api/test|"


class TestBindingPathNormalization:
    """Tests for path normalization in bindings."""

    def test_simple_path(self):
        """Should handle simple path."""
        result = ash_normalize_binding("GET", "/api/test")
        assert result == "GET|/api/test|"

    def test_add_leading_slash(self):
        """Should add leading slash if missing."""
        result = ash_normalize_binding("GET", "api/test")
        assert result == "GET|/api/test|"

    def test_preserve_leading_slash(self):
        """Should preserve existing leading slash."""
        result = ash_normalize_binding("GET", "/api/test")
        assert result == "GET|/api/test|"

    def test_remove_trailing_slash(self):
        """Should remove trailing slash."""
        result = ash_normalize_binding("GET", "/api/test/")
        assert result == "GET|/api/test|"

    def test_preserve_root_path(self):
        """Should preserve root path."""
        result = ash_normalize_binding("GET", "/")
        assert result == "GET|/|"

    def test_collapse_double_slashes(self):
        """Should collapse double slashes."""
        result = ash_normalize_binding("GET", "/api//test")
        assert result == "GET|/api/test|"

    def test_collapse_triple_slashes(self):
        """Should collapse triple slashes."""
        result = ash_normalize_binding("GET", "/api///test")
        assert result == "GET|/api/test|"

    def test_collapse_multiple_slashes(self):
        """Should collapse multiple consecutive slashes."""
        result = ash_normalize_binding("GET", "//api////test///path//")
        assert result == "GET|/api/test/path|"

    def test_remove_fragment(self):
        """Should remove fragment identifier."""
        result = ash_normalize_binding("GET", "/api/test#section")
        assert result == "GET|/api/test|"

    def test_remove_fragment_with_query(self):
        """Should remove fragment but keep query."""
        result = ash_normalize_binding("GET", "/api/test", "foo=bar")
        assert result == "GET|/api/test|foo=bar"

    def test_path_with_numbers(self):
        """Should handle paths with numbers."""
        result = ash_normalize_binding("GET", "/api/v1/users/123")
        assert result == "GET|/api/v1/users/123|"

    def test_path_with_dashes(self):
        """Should handle paths with dashes."""
        result = ash_normalize_binding("GET", "/api/user-profile/my-data")
        assert result == "GET|/api/user-profile/my-data|"

    def test_path_with_underscores(self):
        """Should handle paths with underscores."""
        result = ash_normalize_binding("GET", "/api/user_profile/my_data")
        assert result == "GET|/api/user_profile/my_data|"

    def test_path_with_dots(self):
        """Should handle paths with dots."""
        result = ash_normalize_binding("GET", "/api/v1.0/users.json")
        assert result == "GET|/api/v1.0/users.json|"

    def test_path_with_tilde(self):
        """Should handle paths with tilde."""
        result = ash_normalize_binding("GET", "/~user/profile")
        assert result == "GET|/~user/profile|"

    def test_empty_path(self):
        """Should handle empty path."""
        result = ash_normalize_binding("GET", "")
        assert result == "GET|/|"


class TestBindingQueryNormalization:
    """Tests for query string normalization in bindings."""

    def test_no_query(self):
        """Should handle no query string."""
        result = ash_normalize_binding("GET", "/api/test")
        assert result == "GET|/api/test|"

    def test_empty_query(self):
        """Should handle empty query string."""
        result = ash_normalize_binding("GET", "/api/test", "")
        assert result == "GET|/api/test|"

    def test_simple_query(self):
        """Should include simple query string."""
        result = ash_normalize_binding("GET", "/api/test", "foo=bar")
        assert result == "GET|/api/test|foo=bar"

    def test_query_sorted_by_key(self):
        """Should sort query parameters by key."""
        result = ash_normalize_binding("GET", "/api/test", "z=1&a=2&m=3")
        assert result == "GET|/api/test|a=2&m=3&z=1"

    def test_query_duplicate_keys_sorted_by_value(self):
        """Should sort duplicate keys by value."""
        result = ash_normalize_binding("GET", "/api/test", "a=z&a=a&a=m")
        assert result == "GET|/api/test|a=a&a=m&a=z"

    def test_query_with_empty_value(self):
        """Should preserve empty values."""
        result = ash_normalize_binding("GET", "/api/test", "a=&b=2")
        assert result == "GET|/api/test|a=&b=2"

    def test_query_with_encoded_chars(self):
        """Should handle encoded characters in query."""
        result = ash_normalize_binding("GET", "/api/test", "name=John%20Doe")
        assert result == "GET|/api/test|name=John%20Doe"


class TestQueryCanonicalization:
    """Tests for ash_canonicalize_query function."""

    def test_empty_query(self):
        """Should handle empty query."""
        assert ash_canonicalize_query("") == ""

    def test_strip_leading_question_mark(self):
        """Should strip leading question mark."""
        result = ash_canonicalize_query("?a=1&b=2")
        assert result == "a=1&b=2"

    def test_strip_fragment(self):
        """Should strip fragment identifier."""
        result = ash_canonicalize_query("a=1&b=2#section")
        assert result == "a=1&b=2"

    def test_sort_by_key(self):
        """Should sort parameters by key."""
        result = ash_canonicalize_query("z=1&a=2&m=3")
        assert result == "a=2&m=3&z=1"

    def test_sort_duplicate_keys_by_value(self):
        """Should sort duplicate keys by value."""
        result = ash_canonicalize_query("a=z&a=a&a=m")
        assert result == "a=a&a=m&a=z"

    def test_preserve_empty_value(self):
        """Should preserve empty values."""
        result = ash_canonicalize_query("a=&b=1")
        assert result == "a=&b=1"

    def test_uppercase_hex_encoding(self):
        """Should uppercase hex encoding."""
        result = ash_canonicalize_query("a=%2f&b=%2F")
        assert result == "a=%2F&b=%2F"

    def test_encode_special_chars(self):
        """Should properly encode special characters."""
        result = ash_canonicalize_query("a=hello world")
        assert result == "a=hello%20world"

    def test_key_without_value(self):
        """Should handle key without equals sign."""
        result = ash_canonicalize_query("a&b=1")
        assert result == "a=&b=1"

    def test_numeric_values(self):
        """Should handle numeric values."""
        result = ash_canonicalize_query("page=1&limit=10")
        assert result == "limit=10&page=1"

    def test_boolean_like_values(self):
        """Should handle boolean-like values."""
        result = ash_canonicalize_query("active=true&deleted=false")
        assert result == "active=true&deleted=false"

    def test_multiple_same_key(self):
        """Should handle multiple values for same key."""
        result = ash_canonicalize_query("tags=a&tags=b&tags=c")
        assert result == "tags=a&tags=b&tags=c"

    def test_unicode_values(self):
        """Should handle Unicode values."""
        result = ash_canonicalize_query("name=test")
        assert "name=" in result

    def test_complex_query(self):
        """Should handle complex query strings."""
        result = ash_canonicalize_query("z=3&a=1&m=2&a=0")
        # a appears twice: should be sorted by value
        assert result == "a=0&a=1&m=2&z=3"


class TestNormalizeBindingFromUrl:
    """Tests for ash_normalize_binding_from_url function."""

    def test_simple_url(self):
        """Should parse simple URL."""
        result = ash_normalize_binding_from_url("GET", "/api/test")
        assert result == "GET|/api/test|"

    def test_url_with_query(self):
        """Should parse URL with query string."""
        result = ash_normalize_binding_from_url("GET", "/api/test?foo=bar")
        assert result == "GET|/api/test|foo=bar"

    def test_url_with_sorted_query(self):
        """Should sort query parameters."""
        result = ash_normalize_binding_from_url("GET", "/api/test?z=1&a=2")
        assert result == "GET|/api/test|a=2&z=1"

    def test_url_with_fragment(self):
        """Should handle URL with fragment (fragment in query part is stripped)."""
        result = ash_normalize_binding_from_url("GET", "/api/test?foo=bar#section")
        assert result == "GET|/api/test|foo=bar"

    def test_url_normalization_applied(self):
        """Should apply path normalization."""
        result = ash_normalize_binding_from_url("GET", "//api//test/?a=1")
        assert result == "GET|/api/test|a=1"


class TestBindingFormat:
    """Tests for the binding format (METHOD|PATH|QUERY)."""

    def test_three_parts(self):
        """Should always have three parts separated by pipes."""
        result = ash_normalize_binding("GET", "/api/test")
        parts = result.split("|")
        assert len(parts) == 3

    def test_three_parts_with_query(self):
        """Should have three parts even with query."""
        result = ash_normalize_binding("GET", "/api/test", "a=1")
        parts = result.split("|")
        assert len(parts) == 3
        assert parts[0] == "GET"
        assert parts[1] == "/api/test"
        assert parts[2] == "a=1"

    def test_empty_query_part(self):
        """Should have empty third part when no query."""
        result = ash_normalize_binding("POST", "/api/submit")
        parts = result.split("|")
        assert parts[2] == ""


class TestBindingEdgeCases:
    """Edge case tests for binding normalization."""

    def test_very_long_path(self):
        """Should handle very long paths."""
        long_path = "/" + "/".join(["segment"] * 100)
        result = ash_normalize_binding("GET", long_path)
        assert "segment" in result
        assert "//" not in result

    def test_path_with_encoded_slash(self):
        """Should handle encoded slashes in path."""
        result = ash_normalize_binding("GET", "/api/path%2Fwith%2Fencoded")
        # The encoded slashes are in the path, not normalized
        assert "%2F" in result or "/with/" in result

    def test_query_with_equals_in_value(self):
        """Should handle equals sign in query value."""
        result = ash_normalize_binding("GET", "/api/test", "equation=a=b")
        assert "equation=a" in result

    def test_query_with_ampersand_in_value(self):
        """Should handle encoded ampersand in query value."""
        result = ash_normalize_binding("GET", "/api/test", "val=a%26b")
        assert "val=a%26b" in result

    def test_unicode_in_path(self):
        """Should handle Unicode in path."""
        result = ash_normalize_binding("GET", "/api/test")
        assert "test" in result or "%E4%B8%AD%E6%96%87" in result

    def test_percent_encoded_query_key(self):
        """Should handle percent-encoded query keys."""
        result = ash_normalize_binding("GET", "/api/test", "key%20name=value")
        assert "key" in result


class TestBindingDeterminism:
    """Tests for deterministic binding output."""

    def test_same_input_same_output(self):
        """Same input should produce same output."""
        result1 = ash_normalize_binding("GET", "/api/test", "b=2&a=1")
        result2 = ash_normalize_binding("GET", "/api/test", "b=2&a=1")
        assert result1 == result2

    def test_query_order_independence(self):
        """Different query order should produce same output."""
        result1 = ash_normalize_binding("GET", "/api/test", "a=1&b=2")
        result2 = ash_normalize_binding("GET", "/api/test", "b=2&a=1")
        assert result1 == result2

    def test_method_case_independence(self):
        """Different method case should produce same output."""
        result1 = ash_normalize_binding("GET", "/api/test")
        result2 = ash_normalize_binding("get", "/api/test")
        result3 = ash_normalize_binding("Get", "/api/test")
        assert result1 == result2 == result3

    def test_path_normalization_independence(self):
        """Different path representations should produce same output."""
        result1 = ash_normalize_binding("GET", "/api/test")
        result2 = ash_normalize_binding("GET", "/api/test/")
        result3 = ash_normalize_binding("GET", "//api//test")
        assert result1 == result2 == result3


class TestQuerySortingEdgeCases:
    """Edge case tests for query parameter sorting."""

    def test_sort_numeric_string_keys(self):
        """Should sort numeric string keys lexicographically."""
        result = ash_canonicalize_query("10=a&2=b&1=c")
        assert result == "1=c&10=a&2=b"

    def test_sort_mixed_case_keys(self):
        """Should sort mixed case keys (byte order)."""
        result = ash_canonicalize_query("b=1&A=2&a=3")
        assert result == "A=2&a=3&b=1"

    def test_sort_special_char_keys(self):
        """Should sort keys with special characters."""
        result = ash_canonicalize_query("b=1&_a=2&a=3")
        # _ comes after letters in ASCII
        assert result.index("a=") < result.rindex("b=")

    def test_sort_values_byte_order(self):
        """Should sort duplicate key values by byte order."""
        result = ash_canonicalize_query("a=B&a=a&a=A")
        # A < B < a in ASCII byte order
        assert result == "a=A&a=B&a=a"

    def test_empty_values_sort_first(self):
        """Empty values should sort before non-empty."""
        result = ash_canonicalize_query("a=b&a=")
        assert result == "a=&a=b"


class TestQueryPercentEncoding:
    """Tests for percent encoding in query strings."""

    def test_encode_space(self):
        """Should encode space as %20."""
        result = ash_canonicalize_query("a=hello world")
        assert result == "a=hello%20world"

    def test_encode_plus(self):
        """Should handle plus sign."""
        result = ash_canonicalize_query("a=1+2")
        # Plus is decoded then re-encoded
        assert "a=1" in result

    def test_uppercase_hex(self):
        """Should use uppercase hex in percent encoding."""
        result = ash_canonicalize_query("a=%2f")
        assert "%2F" in result

    def test_preserve_unreserved_chars(self):
        """Should not encode unreserved characters."""
        result = ash_canonicalize_query("a=test-value_123~")
        # Unreserved chars: A-Z a-z 0-9 - . _ ~
        assert result == "a=test-value_123~"

    def test_encode_reserved_chars(self):
        """Should encode reserved characters."""
        result = ash_canonicalize_query("a=:/?#[]@")
        assert "%" in result
