"""Tests for ASH canonicalization."""

import pytest
from ash.core.canonicalize import (
    canonicalize_json,
    canonicalize_url_encoded,
    normalize_binding,
)
from ash.core.errors import CanonicalizationError


class TestCanonicalizeJson:
    """Tests for JSON canonicalization."""

    def test_simple_object(self):
        """Should canonicalize simple objects."""
        result = canonicalize_json({"b": 2, "a": 1})
        assert result == '{"a":1,"b":2}'

    def test_nested_object(self):
        """Should canonicalize nested objects."""
        result = canonicalize_json({"z": {"b": 2, "a": 1}, "a": 1})
        assert result == '{"a":1,"z":{"a":1,"b":2}}'

    def test_array(self):
        """Should preserve array order."""
        result = canonicalize_json([3, 1, 2])
        assert result == "[3,1,2]"

    def test_null(self):
        """Should handle null."""
        result = canonicalize_json(None)
        assert result == "null"

    def test_boolean(self):
        """Should handle booleans."""
        assert canonicalize_json(True) == "true"
        assert canonicalize_json(False) == "false"

    def test_string(self):
        """Should handle strings."""
        result = canonicalize_json("hello")
        assert result == '"hello"'

    def test_string_escaping(self):
        """Should escape special characters."""
        result = canonicalize_json('hello\n"world"')
        assert result == '"hello\\n\\"world\\""'

    def test_number_integer(self):
        """Should handle integers."""
        result = canonicalize_json(42)
        assert result == "42"

    def test_number_float(self):
        """Should handle floats."""
        result = canonicalize_json(3.14)
        assert result == "3.14"

    def test_number_negative_zero(self):
        """Should convert -0 to 0."""
        result = canonicalize_json(-0.0)
        assert result == "0"

    def test_reject_nan(self):
        """Should reject NaN."""
        with pytest.raises(CanonicalizationError, match="NaN"):
            canonicalize_json(float("nan"))

    def test_reject_infinity(self):
        """Should reject Infinity."""
        with pytest.raises(CanonicalizationError, match="Infinity"):
            canonicalize_json(float("inf"))

    def test_unicode_nfc(self):
        """Should apply NFC normalization."""
        # é as e + combining acute accent
        decomposed = "caf\u0065\u0301"
        result = canonicalize_json(decomposed)
        # Should normalize to composed form
        assert result == '"café"'


class TestCanonicalizeUrlEncoded:
    """Tests for URL-encoded canonicalization."""

    def test_simple_pairs(self):
        """Should canonicalize simple key-value pairs."""
        result = canonicalize_url_encoded("b=2&a=1")
        assert result == "a=1&b=2"

    def test_dict_input(self):
        """Should accept dict input."""
        result = canonicalize_url_encoded({"b": "2", "a": "1"})
        assert result == "a=1&b=2"

    def test_duplicate_keys(self):
        """Should sort duplicate keys by value (byte-wise)."""
        result = canonicalize_url_encoded("a=2&a=1&a=3")
        assert result == "a=1&a=2&a=3"

    def test_empty_value(self):
        """Should handle empty values."""
        result = canonicalize_url_encoded("a=&b=2")
        assert result == "a=&b=2"

    def test_plus_as_literal(self):
        """Should treat + as literal plus (not space). ASH protocol spec."""
        result = canonicalize_url_encoded("a=hello+world")
        assert result == "a=hello%2Bworld"

    def test_percent_encoding(self):
        """Should properly percent-encode."""
        result = canonicalize_url_encoded("a=hello world")
        assert result == "a=hello%20world"


class TestNormalizeBinding:
    """Tests for binding normalization (v2.3.1+ format: METHOD|PATH|QUERY)."""

    def test_simple_binding(self):
        """Should normalize simple binding."""
        result = normalize_binding("post", "/api/update")
        assert result == "POST|/api/update|"

    def test_uppercase_method(self):
        """Should uppercase method."""
        result = normalize_binding("get", "/path")
        assert result == "GET|/path|"

    def test_with_query_string(self):
        """Should include canonicalized query string."""
        result = normalize_binding("GET", "/path", "foo=bar")
        assert result == "GET|/path|foo=bar"

    def test_query_sorted(self):
        """Should sort query parameters."""
        result = normalize_binding("GET", "/path", "z=3&a=1")
        assert result == "GET|/path|a=1&z=3"

    def test_remove_fragment(self):
        """Should remove fragment from path."""
        result = normalize_binding("GET", "/path#section")
        assert result == "GET|/path|"

    def test_add_leading_slash(self):
        """Should add leading slash."""
        result = normalize_binding("GET", "path")
        assert result == "GET|/path|"

    def test_collapse_slashes(self):
        """Should collapse duplicate slashes."""
        result = normalize_binding("GET", "//path///to////resource")
        assert result == "GET|/path/to/resource|"

    def test_remove_trailing_slash(self):
        """Should remove trailing slash."""
        result = normalize_binding("GET", "/path/")
        assert result == "GET|/path|"

    def test_preserve_root(self):
        """Should preserve root path."""
        result = normalize_binding("GET", "/")
        assert result == "GET|/|"
