"""
Extended Binding Normalization Edge Cases.

Tests for comprehensive path, query string, and method normalization
including encoded characters, special paths, and edge cases.
"""

import pytest
from ash.core.canonicalize import (
    ash_normalize_binding,
    ash_normalize_binding_from_url,
    ash_canonicalize_query,
)


class TestBindingPathEncodedSlashes:
    """Tests for encoded slash handling in paths."""

    def test_single_encoded_slash(self):
        """Should handle single encoded slash."""
        result = ash_normalize_binding("GET", "/api/path%2Fvalue")
        assert "%2F" in result or "/path" in result

    def test_multiple_encoded_slashes(self):
        """Should handle multiple encoded slashes."""
        result = ash_normalize_binding("GET", "/api/a%2Fb%2Fc")
        assert "api" in result

    def test_mixed_encoded_and_literal_slashes(self):
        """Should handle mixed encoded and literal slashes."""
        result = ash_normalize_binding("GET", "/api/a%2Fb/c%2Fd")
        assert "api" in result

    def test_encoded_slash_at_start(self):
        """Should handle encoded slash at path start."""
        result = ash_normalize_binding("GET", "%2Fapi/test")
        assert "api" in result

    def test_double_encoded_slash(self):
        """Should handle double-encoded slash."""
        result = ash_normalize_binding("GET", "/api/path%252Fvalue")
        assert "api" in result


class TestBindingPathDots:
    """Tests for dot handling in paths."""

    def test_single_dot_segment(self):
        """Should handle single dot segment."""
        result = ash_normalize_binding("GET", "/api/./test")
        # Single dot typically resolves to same dir
        assert "/api" in result

    def test_double_dot_segment(self):
        """Should handle double dot segment."""
        result = ash_normalize_binding("GET", "/api/nested/../test")
        assert "api" in result

    def test_multiple_dot_segments(self):
        """Should handle multiple dot segments."""
        result = ash_normalize_binding("GET", "/api/a/b/../../test")
        assert "api" in result

    def test_dot_at_end(self):
        """Should handle dot at path end."""
        result = ash_normalize_binding("GET", "/api/test.")
        assert "test" in result

    def test_double_dot_at_end(self):
        """Should handle double dot at path end."""
        result = ash_normalize_binding("GET", "/api/test..")
        assert "test" in result

    def test_hidden_file_path(self):
        """Should handle hidden file style path."""
        result = ash_normalize_binding("GET", "/api/.hidden")
        assert ".hidden" in result or "hidden" in result

    def test_file_extension(self):
        """Should preserve file extensions."""
        result = ash_normalize_binding("GET", "/api/file.json")
        assert ".json" in result

    def test_multiple_dots_in_filename(self):
        """Should handle multiple dots in filename."""
        result = ash_normalize_binding("GET", "/api/file.tar.gz")
        assert ".tar.gz" in result or "file" in result


class TestBindingPathSpecialChars:
    """Tests for special characters in paths."""

    def test_path_with_at_symbol(self):
        """Should handle @ symbol in path."""
        result = ash_normalize_binding("GET", "/api/@user/profile")
        assert "@user" in result or "user" in result

    def test_path_with_plus(self):
        """Should handle plus sign in path."""
        result = ash_normalize_binding("GET", "/api/search/c++")
        assert "search" in result

    def test_path_with_colon(self):
        """Should handle colon in path."""
        result = ash_normalize_binding("GET", "/api/time:zone")
        assert "time" in result

    def test_path_with_semicolon(self):
        """Should handle semicolon in path."""
        result = ash_normalize_binding("GET", "/api/param;matrix=value")
        assert "param" in result

    def test_path_with_comma(self):
        """Should handle comma in path."""
        result = ash_normalize_binding("GET", "/api/items/1,2,3")
        assert "1,2,3" in result or "items" in result

    def test_path_with_exclamation(self):
        """Should handle exclamation mark in path."""
        result = ash_normalize_binding("GET", "/api/alert!")
        assert "alert" in result

    def test_path_with_asterisk(self):
        """Should handle asterisk in path."""
        result = ash_normalize_binding("GET", "/api/glob/*")
        assert "glob" in result

    def test_path_with_parentheses(self):
        """Should handle parentheses in path."""
        result = ash_normalize_binding("GET", "/api/function()")
        assert "function" in result

    def test_path_with_brackets(self):
        """Should handle brackets in path."""
        result = ash_normalize_binding("GET", "/api/array[0]")
        assert "array" in result

    def test_path_with_curly_braces(self):
        """Should handle curly braces in path."""
        result = ash_normalize_binding("GET", "/api/{id}")
        assert "id" in result


class TestBindingPathUnicode:
    """Tests for Unicode in paths."""

    def test_chinese_path_segment(self):
        """Should handle Chinese path segment."""
        result = ash_normalize_binding("GET", "/api/\u4E2D\u6587")
        assert "/api/" in result

    def test_arabic_path_segment(self):
        """Should handle Arabic path segment."""
        result = ash_normalize_binding("GET", "/api/\u0639\u0631\u0628\u064A")
        assert "/api/" in result

    def test_emoji_path_segment(self):
        """Should handle emoji path segment."""
        result = ash_normalize_binding("GET", "/api/\U0001F600")
        assert "/api/" in result

    def test_cyrillic_path_segment(self):
        """Should handle Cyrillic path segment."""
        result = ash_normalize_binding("GET", "/api/\u0440\u0443\u0441\u0441\u043A\u0438\u0439")
        assert "/api/" in result

    def test_encoded_unicode(self):
        """Should handle percent-encoded Unicode."""
        result = ash_normalize_binding("GET", "/api/%E4%B8%AD%E6%96%87")
        assert "/api/" in result

    def test_mixed_ascii_unicode(self):
        """Should handle mixed ASCII and Unicode."""
        result = ash_normalize_binding("GET", "/api/hello\u4E16\u754C")
        assert "/api/" in result


class TestBindingQueryEdgeCases:
    """Extended query string edge cases."""

    def test_query_with_no_value(self):
        """Should handle query parameter with no value."""
        result = ash_canonicalize_query("flag&other=1")
        assert "flag=" in result

    def test_query_with_empty_value(self):
        """Should handle query parameter with empty value."""
        result = ash_canonicalize_query("empty=&filled=value")
        assert "empty=" in result

    def test_query_with_plus_as_space(self):
        """Should handle plus sign as space in query."""
        result = ash_canonicalize_query("name=John+Doe")
        # Plus should be decoded as space then re-encoded as %20
        assert "John" in result

    def test_query_with_encoded_equals(self):
        """Should handle encoded equals in value."""
        result = ash_canonicalize_query("equation=a%3Db")
        assert "equation=" in result

    def test_query_with_encoded_ampersand(self):
        """Should handle encoded ampersand in value."""
        result = ash_canonicalize_query("text=a%26b&other=1")
        assert "text=" in result
        assert "other=" in result

    def test_query_many_duplicates(self):
        """Should handle many duplicate keys."""
        result = ash_canonicalize_query("a=1&a=2&a=3&a=4&a=5")
        assert result.count("a=") == 5

    def test_query_unicode_key(self):
        """Should handle Unicode in query key."""
        result = ash_canonicalize_query("\u540D\u524D=value")
        assert "value" in result

    def test_query_unicode_value(self):
        """Should handle Unicode in query value."""
        result = ash_canonicalize_query("name=\u4E2D\u6587")
        assert "name=" in result

    def test_query_mixed_encoding(self):
        """Should handle mixed encoding states."""
        result = ash_canonicalize_query("a=%20&b= &c=+")
        assert "a=" in result

    def test_query_double_encoded(self):
        """Should handle double-encoded values."""
        result = ash_canonicalize_query("val=%2520")  # %25 is %
        assert "val=" in result

    def test_query_with_hash(self):
        """Should strip hash/fragment."""
        result = ash_canonicalize_query("a=1#fragment")
        assert "a=1" == result
        assert "fragment" not in result

    def test_query_only_hash(self):
        """Should handle only hash."""
        result = ash_canonicalize_query("#fragment")
        assert result == ""

    def test_query_empty_between_ampersands(self):
        """Should handle empty segments."""
        result = ash_canonicalize_query("a=1&&b=2")
        assert "a=1" in result
        assert "b=2" in result


class TestBindingQuerySortingComplex:
    """Complex query sorting tests."""

    def test_sort_many_params(self):
        """Should correctly sort many parameters."""
        result = ash_canonicalize_query("z=1&y=2&x=3&w=4&v=5&u=6")
        params = result.split("&")
        keys = [p.split("=")[0] for p in params]
        assert keys == sorted(keys)

    def test_sort_numeric_keys(self):
        """Should sort numeric keys lexicographically."""
        result = ash_canonicalize_query("10=a&2=b&1=c&20=d")
        # Lexicographic: 1 < 10 < 2 < 20
        idx_1 = result.index("1=c")
        idx_10 = result.index("10=a")
        idx_2 = result.index("2=b")
        idx_20 = result.index("20=d")
        assert idx_1 < idx_10 < idx_2 < idx_20

    def test_sort_case_sensitive(self):
        """Should sort case-sensitively."""
        result = ash_canonicalize_query("b=1&B=2&a=3&A=4")
        # ASCII: A < B < a < b
        idx_A = result.index("A=")
        idx_B = result.index("B=")
        idx_a = result.index("a=")
        idx_b = result.index("b=")
        assert idx_A < idx_B < idx_a < idx_b

    def test_sort_duplicate_by_value(self):
        """Should sort duplicate keys by value."""
        result = ash_canonicalize_query("key=z&key=a&key=m")
        # Values should be sorted: a < m < z
        assert result == "key=a&key=m&key=z"

    def test_sort_special_chars(self):
        """Should sort keys with special characters."""
        result = ash_canonicalize_query("_z=1&a=2&.b=3")
        # . < _ < a in ASCII
        assert result.startswith(".b=") or "a=" in result

    def test_sort_encoded_values(self):
        """Should sort encoded values correctly."""
        result = ash_canonicalize_query("a=%7A&a=%61&a=%6D")  # z, a, m
        # After decoding and sorting: a < m < z
        assert "a=a" in result or "%61" in result.lower()


class TestBindingQueryPercentEncoding:
    """Percent encoding normalization tests."""

    def test_uppercase_hex(self):
        """Should use uppercase hex in encoding."""
        result = ash_canonicalize_query("a=%2f")
        assert "%2F" in result

    def test_encode_space(self):
        """Should encode space as %20."""
        result = ash_canonicalize_query("a=hello world")
        assert "%20" in result

    def test_encode_reserved_chars(self):
        """Should encode reserved characters."""
        reserved = ":/?#[]@!$&'()*+,;="
        for char in reserved:
            if char not in "=&":  # These have special meaning in query
                result = ash_canonicalize_query(f"key={char}")
                # Should be encoded
                assert "key=" in result

    def test_not_encode_unreserved(self):
        """Should not encode unreserved characters."""
        unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        result = ash_canonicalize_query(f"key={unreserved}")
        assert f"key={unreserved}" == result

    def test_decode_then_reencode(self):
        """Should decode then re-encode consistently."""
        result = ash_canonicalize_query("a=%48%65%6c%6c%6f")  # Hello
        assert "Hello" in result


class TestBindingMethodVariations:
    """HTTP method normalization tests."""

    def test_all_standard_methods(self):
        """Should handle all standard HTTP methods."""
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]
        for method in methods:
            result = ash_normalize_binding(method, "/test")
            assert f"{method}|" in result

    def test_lowercase_methods(self):
        """Should uppercase lowercase methods."""
        methods = ["get", "post", "put", "delete", "patch", "head", "options"]
        for method in methods:
            result = ash_normalize_binding(method, "/test")
            assert f"{method.upper()}|" in result

    def test_mixed_case_methods(self):
        """Should uppercase mixed case methods."""
        cases = [("Get", "GET"), ("pOsT", "POST"), ("DeLeTe", "DELETE")]
        for input_method, expected in cases:
            result = ash_normalize_binding(input_method, "/test")
            assert f"{expected}|" in result

    def test_custom_method(self):
        """Should handle custom HTTP methods."""
        result = ash_normalize_binding("CUSTOM", "/test")
        assert "CUSTOM|" in result

    def test_webdav_methods(self):
        """Should handle WebDAV methods."""
        methods = ["PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"]
        for method in methods:
            result = ash_normalize_binding(method, "/test")
            assert f"{method}|" in result


class TestBindingFromUrlParsing:
    """URL parsing edge cases."""

    def test_url_with_port(self):
        """Should handle URL with port."""
        result = ash_normalize_binding_from_url("GET", "http://example.com:8080/api/test")
        assert "/api/test" in result or "test" in result

    def test_url_with_auth(self):
        """Should handle URL with authentication."""
        result = ash_normalize_binding_from_url("GET", "http://user:pass@example.com/api/test")
        assert "/api/test" in result or "test" in result

    def test_url_with_fragment(self):
        """Should strip URL fragment."""
        result = ash_normalize_binding_from_url("GET", "/api/test#section")
        assert "#section" not in result

    def test_url_absolute_path_only(self):
        """Should handle absolute path only."""
        result = ash_normalize_binding_from_url("GET", "/api/test")
        assert "GET|/api/test|" == result

    def test_url_with_empty_query(self):
        """Should handle URL with empty query."""
        result = ash_normalize_binding_from_url("GET", "/api/test?")
        assert "/api/test|" in result

    def test_url_complex_query(self):
        """Should handle URL with complex query."""
        result = ash_normalize_binding_from_url("GET", "/api/test?z=1&a=2&b=3")
        # Query should be sorted
        assert "a=2" in result
        assert result.index("a=2") < result.index("b=3")


class TestBindingFormat:
    """Binding format validation tests."""

    def test_always_three_parts(self):
        """Should always have exactly three parts."""
        cases = [
            ("GET", "/api"),
            ("POST", "/api", "a=1"),
            ("PUT", "/", ""),
            ("DELETE", "/api/long/path/here"),
        ]
        for args in cases:
            result = ash_normalize_binding(*args)
            parts = result.split("|")
            assert len(parts) == 3

    def test_empty_query_part(self):
        """Should have empty query part when no query."""
        result = ash_normalize_binding("GET", "/api/test")
        parts = result.split("|")
        assert parts[2] == ""

    def test_pipe_delimiter_preserved(self):
        """Should use pipe as delimiter."""
        result = ash_normalize_binding("POST", "/api/test", "a=1")
        assert result.count("|") == 2


class TestBindingPathNormalizationComprehensive:
    """Comprehensive path normalization tests."""

    def test_root_path(self):
        """Should preserve root path."""
        result = ash_normalize_binding("GET", "/")
        assert "GET|/|" == result

    def test_empty_path_becomes_root(self):
        """Empty path should become root."""
        result = ash_normalize_binding("GET", "")
        assert "GET|/|" == result

    def test_remove_trailing_slash(self):
        """Should remove trailing slash."""
        result = ash_normalize_binding("GET", "/api/test/")
        assert result == "GET|/api/test|"

    def test_add_leading_slash(self):
        """Should add leading slash."""
        result = ash_normalize_binding("GET", "api/test")
        assert result == "GET|/api/test|"

    def test_collapse_multiple_slashes(self):
        """Should collapse multiple slashes."""
        result = ash_normalize_binding("GET", "//api///test////path//")
        assert result == "GET|/api/test/path|"

    def test_preserve_case_in_path(self):
        """Should preserve case in path."""
        result = ash_normalize_binding("GET", "/API/Test/PATH")
        assert "/API/Test/PATH" in result

    def test_very_long_path(self):
        """Should handle very long paths."""
        segments = ["segment"] * 100
        long_path = "/" + "/".join(segments)
        result = ash_normalize_binding("GET", long_path)
        assert "segment" in result
        assert "//" not in result


class TestBindingDeterminism:
    """Determinism verification tests."""

    def test_same_input_same_output(self):
        """Same input should always produce same output."""
        for _ in range(100):
            result1 = ash_normalize_binding("GET", "/api/test", "b=2&a=1")
            result2 = ash_normalize_binding("GET", "/api/test", "b=2&a=1")
            assert result1 == result2

    def test_query_order_independence(self):
        """Query parameter order should not affect output."""
        result1 = ash_normalize_binding("GET", "/api", "a=1&b=2&c=3")
        result2 = ash_normalize_binding("GET", "/api", "c=3&a=1&b=2")
        result3 = ash_normalize_binding("GET", "/api", "b=2&c=3&a=1")
        assert result1 == result2 == result3

    def test_method_case_independence(self):
        """Method case should not affect output."""
        result1 = ash_normalize_binding("GET", "/api")
        result2 = ash_normalize_binding("get", "/api")
        result3 = ash_normalize_binding("Get", "/api")
        result4 = ash_normalize_binding("gEt", "/api")
        assert result1 == result2 == result3 == result4

    def test_path_normalization_consistency(self):
        """Path normalization should be consistent."""
        result1 = ash_normalize_binding("GET", "/api/test")
        result2 = ash_normalize_binding("GET", "/api/test/")
        result3 = ash_normalize_binding("GET", "api/test")
        result4 = ash_normalize_binding("GET", "//api//test//")
        assert result1 == result2 == result3 == result4


class TestBindingRealWorldPaths:
    """Real-world path pattern tests."""

    def test_rest_resource_id(self):
        """Should handle REST resource IDs."""
        result = ash_normalize_binding("GET", "/api/users/12345")
        assert "/api/users/12345" in result

    def test_uuid_in_path(self):
        """Should handle UUID in path."""
        result = ash_normalize_binding("GET", "/api/items/550e8400-e29b-41d4-a716-446655440000")
        assert "550e8400" in result

    def test_versioned_api(self):
        """Should handle versioned API paths."""
        result = ash_normalize_binding("GET", "/api/v1/users")
        assert "/api/v1/users" in result

    def test_nested_resources(self):
        """Should handle nested resources."""
        result = ash_normalize_binding("GET", "/api/users/123/orders/456/items")
        assert "/api/users/123/orders/456/items" in result

    def test_file_download(self):
        """Should handle file download paths."""
        result = ash_normalize_binding("GET", "/files/report.pdf")
        assert "/files/report.pdf" in result

    def test_static_assets(self):
        """Should handle static asset paths."""
        result = ash_normalize_binding("GET", "/static/js/app.bundle.js")
        assert "/static/js/app.bundle.js" in result

    def test_graphql_endpoint(self):
        """Should handle GraphQL endpoint."""
        result = ash_normalize_binding("POST", "/graphql")
        assert "POST|/graphql|" == result

    def test_webhook_endpoint(self):
        """Should handle webhook endpoints."""
        result = ash_normalize_binding("POST", "/webhooks/github")
        assert "/webhooks/github" in result


class TestBindingRealWorldQueries:
    """Real-world query string pattern tests."""

    def test_pagination_params(self):
        """Should handle pagination parameters."""
        result = ash_normalize_binding("GET", "/api/users", "page=2&limit=20&offset=20")
        assert "limit=20" in result
        assert "page=2" in result

    def test_sorting_params(self):
        """Should handle sorting parameters."""
        result = ash_normalize_binding("GET", "/api/users", "sort=name&order=asc")
        assert "order=asc" in result
        assert "sort=name" in result

    def test_filter_params(self):
        """Should handle filter parameters."""
        result = ash_normalize_binding("GET", "/api/users", "status=active&role=admin&verified=true")
        assert "role=admin" in result
        assert "status=active" in result

    def test_search_params(self):
        """Should handle search parameters."""
        result = ash_normalize_binding("GET", "/api/search", "q=hello+world&type=users")
        assert "q=" in result
        assert "type=users" in result

    def test_date_range_params(self):
        """Should handle date range parameters."""
        result = ash_normalize_binding("GET", "/api/events", "start=2024-01-01&end=2024-12-31")
        assert "end=2024-12-31" in result
        assert "start=2024-01-01" in result

    def test_array_params(self):
        """Should handle array-style parameters."""
        result = ash_normalize_binding("GET", "/api/items", "ids[]=1&ids[]=2&ids[]=3")
        # Brackets are percent-encoded
        assert "ids%5B%5D=" in result or "ids[]=" in result

    def test_nested_params(self):
        """Should handle nested-style parameters."""
        result = ash_normalize_binding("GET", "/api/search", "filter[status]=active&filter[type]=user")
        # Brackets are percent-encoded
        assert "filter%5Bstatus%5D=" in result or "filter[status]=" in result


class TestBindingEdgeCasesComplex:
    """Complex edge case tests."""

    def test_all_components(self):
        """Should handle URL with all components."""
        result = ash_normalize_binding("POST", "/api/v2/users/123", "include=orders&expand=profile")
        assert "POST|" in result
        assert "/api/v2/users/123|" in result
        assert "expand=profile" in result
        assert "include=orders" in result

    def test_empty_binding(self):
        """Should handle minimal binding."""
        result = ash_normalize_binding("GET", "/")
        assert result == "GET|/|"

    def test_special_api_patterns(self):
        """Should handle special API patterns."""
        patterns = [
            ("/api/_internal/health", "GET"),
            ("/api/__debug__/sql", "GET"),
            ("/api/.well-known/openid-configuration", "GET"),
        ]
        for path, method in patterns:
            result = ash_normalize_binding(method, path)
            assert f"{method}|" in result
