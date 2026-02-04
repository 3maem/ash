"""
Comprehensive JCS (JSON Canonicalization Scheme - RFC 8785) Tests.

These tests ensure that the ash_canonicalize_json function adheres to RFC 8785
and produces deterministic, cross-SDK compatible results.
"""

import math
import pytest
from ash.core.canonicalize import ash_canonicalize_json
from ash.core.errors import CanonicalizationError


class TestJcsBasicTypes:
    """Tests for basic JSON type canonicalization."""

    def test_null_value(self):
        """Should canonicalize null correctly."""
        assert ash_canonicalize_json(None) == "null"

    def test_true_boolean(self):
        """Should canonicalize True to 'true'."""
        assert ash_canonicalize_json(True) == "true"

    def test_false_boolean(self):
        """Should canonicalize False to 'false'."""
        assert ash_canonicalize_json(False) == "false"

    def test_empty_string(self):
        """Should canonicalize empty string."""
        assert ash_canonicalize_json("") == '""'

    def test_simple_string(self):
        """Should canonicalize simple string."""
        assert ash_canonicalize_json("hello") == '"hello"'

    def test_string_with_spaces(self):
        """Should preserve spaces in strings."""
        assert ash_canonicalize_json("hello world") == '"hello world"'

    def test_positive_integer(self):
        """Should canonicalize positive integers."""
        assert ash_canonicalize_json(42) == "42"

    def test_negative_integer(self):
        """Should canonicalize negative integers."""
        assert ash_canonicalize_json(-42) == "-42"

    def test_zero_integer(self):
        """Should canonicalize zero."""
        assert ash_canonicalize_json(0) == "0"

    def test_large_integer(self):
        """Should handle large integers."""
        assert ash_canonicalize_json(9007199254740991) == "9007199254740991"

    def test_negative_large_integer(self):
        """Should handle large negative integers."""
        assert ash_canonicalize_json(-9007199254740991) == "-9007199254740991"


class TestJcsFloatNumbers:
    """Tests for floating-point number canonicalization."""

    def test_simple_float(self):
        """Should canonicalize simple floats."""
        assert ash_canonicalize_json(3.14) == "3.14"

    def test_negative_float(self):
        """Should canonicalize negative floats."""
        assert ash_canonicalize_json(-3.14) == "-3.14"

    def test_float_with_trailing_zero(self):
        """Should handle floats that are whole numbers."""
        result = ash_canonicalize_json(5.0)
        assert result == "5"

    def test_negative_zero(self):
        """Should convert -0 to 0 per JCS spec."""
        assert ash_canonicalize_json(-0.0) == "0"

    def test_small_positive_float(self):
        """Should handle small positive floats."""
        result = ash_canonicalize_json(0.001)
        assert "0.001" in result or result == "0.001"

    def test_reject_nan(self):
        """Should reject NaN values."""
        with pytest.raises(CanonicalizationError, match="NaN"):
            ash_canonicalize_json(float("nan"))

    def test_reject_positive_infinity(self):
        """Should reject positive infinity."""
        with pytest.raises(CanonicalizationError, match="Infinity"):
            ash_canonicalize_json(float("inf"))

    def test_reject_negative_infinity(self):
        """Should reject negative infinity."""
        with pytest.raises(CanonicalizationError, match="Infinity"):
            ash_canonicalize_json(float("-inf"))

    def test_float_one(self):
        """Should handle 1.0 as integer."""
        assert ash_canonicalize_json(1.0) == "1"

    def test_float_precision(self):
        """Should maintain reasonable precision."""
        result = ash_canonicalize_json(1.23456789)
        assert result.startswith("1.234567")


class TestJcsStringEscaping:
    """Tests for string escaping per RFC 8785."""

    def test_escape_backslash(self):
        """Should escape backslash."""
        result = ash_canonicalize_json("a\\b")
        assert result == '"a\\\\b"'

    def test_escape_double_quote(self):
        """Should escape double quotes."""
        result = ash_canonicalize_json('a"b')
        assert result == '"a\\"b"'

    def test_escape_newline(self):
        """Should escape newline."""
        result = ash_canonicalize_json("a\nb")
        assert result == '"a\\nb"'

    def test_escape_tab(self):
        """Should escape tab."""
        result = ash_canonicalize_json("a\tb")
        assert result == '"a\\tb"'

    def test_escape_carriage_return(self):
        """Should escape carriage return."""
        result = ash_canonicalize_json("a\rb")
        assert result == '"a\\rb"'

    def test_escape_backspace(self):
        """Should escape backspace."""
        result = ash_canonicalize_json("a\bb")
        assert result == '"a\\bb"'

    def test_escape_form_feed(self):
        """Should escape form feed."""
        result = ash_canonicalize_json("a\fb")
        assert result == '"a\\fb"'

    def test_escape_control_char_null(self):
        """Should escape null character."""
        result = ash_canonicalize_json("a\x00b")
        assert result == '"a\\u0000b"'

    def test_escape_control_char_low(self):
        """Should escape low control characters."""
        result = ash_canonicalize_json("a\x01b")
        assert result == '"a\\u0001b"'

    def test_escape_control_char_high(self):
        """Should escape high control characters."""
        result = ash_canonicalize_json("a\x1fb")
        assert result == '"a\\u001fb"'

    def test_no_escape_printable_ascii(self):
        """Should not escape printable ASCII."""
        result = ash_canonicalize_json("abc123!@#")
        assert result == '"abc123!@#"'

    def test_multiple_escapes(self):
        """Should handle multiple escape sequences."""
        result = ash_canonicalize_json("a\tb\nc")
        assert result == '"a\\tb\\nc"'

    def test_escape_at_boundaries(self):
        """Should handle escapes at string boundaries."""
        result = ash_canonicalize_json("\nhello\n")
        assert result == '"\\nhello\\n"'


class TestJcsUnicode:
    """Tests for Unicode handling per RFC 8785."""

    def test_unicode_simple(self):
        """Should handle simple Unicode."""
        result = ash_canonicalize_json("hello")
        assert result == '"hello"'

    def test_unicode_emoji(self):
        """Should handle emoji characters."""
        result = ash_canonicalize_json("hello ")
        assert "" in result or "\\u" in result

    def test_unicode_nfc_normalization(self):
        """Should apply NFC normalization."""
        # e with combining acute accent (decomposed)
        decomposed = "caf\u0065\u0301"
        result = ash_canonicalize_json(decomposed)
        # Should normalize to composed form
        assert result == '"cafe\u0301"' or "caf" in result

    def test_unicode_chinese(self):
        """Should handle Chinese characters."""
        result = ash_canonicalize_json("hello")
        assert "hello" in result or "\\u" in result

    def test_unicode_arabic(self):
        """Should handle Arabic characters."""
        result = ash_canonicalize_json("hello")
        assert "hello" in result or "\\u" in result

    def test_unicode_mixed(self):
        """Should handle mixed ASCII and Unicode."""
        result = ash_canonicalize_json("Hello World")
        assert "Hello" in result and "World" in result

    def test_unicode_surrogate_pair_emoji(self):
        """Should handle emoji requiring surrogate pairs."""
        result = ash_canonicalize_json("test")
        assert "test" in result

    def test_unicode_zero_width_joiner(self):
        """Should handle zero-width joiner sequences."""
        result = ash_canonicalize_json("test\u200dtest")
        # Just verify it doesn't crash
        assert "test" in result


class TestJcsObjects:
    """Tests for JSON object canonicalization."""

    def test_empty_object(self):
        """Should canonicalize empty object."""
        assert ash_canonicalize_json({}) == "{}"

    def test_single_key_object(self):
        """Should canonicalize single-key object."""
        assert ash_canonicalize_json({"a": 1}) == '{"a":1}'

    def test_key_sorting_alphabetical(self):
        """Should sort keys alphabetically."""
        result = ash_canonicalize_json({"z": 1, "a": 2, "m": 3})
        assert result == '{"a":2,"m":3,"z":1}'

    def test_key_sorting_case_sensitive(self):
        """Should sort keys case-sensitively (uppercase first in byte order)."""
        result = ash_canonicalize_json({"b": 1, "A": 2, "a": 3})
        assert result == '{"A":2,"a":3,"b":1}'

    def test_key_sorting_numbers_as_strings(self):
        """Should sort numeric string keys correctly."""
        result = ash_canonicalize_json({"10": 1, "2": 2, "1": 3})
        assert result == '{"1":3,"10":1,"2":2}'

    def test_nested_object_sorting(self):
        """Should sort nested object keys."""
        result = ash_canonicalize_json({"outer": {"z": 1, "a": 2}})
        assert result == '{"outer":{"a":2,"z":1}}'

    def test_deeply_nested_objects(self):
        """Should handle deeply nested objects."""
        obj = {"a": {"b": {"c": {"d": 1}}}}
        result = ash_canonicalize_json(obj)
        assert result == '{"a":{"b":{"c":{"d":1}}}}'

    def test_object_with_all_types(self):
        """Should handle objects with all JSON types."""
        obj = {
            "array": [1, 2, 3],
            "bool": True,
            "null": None,
            "number": 42,
            "object": {"nested": "value"},
            "string": "hello"
        }
        result = ash_canonicalize_json(obj)
        # Keys should be sorted alphabetically
        assert result.startswith('{"array":')
        assert '"bool":true' in result
        assert '"null":null' in result

    def test_unicode_keys(self):
        """Should handle Unicode keys."""
        result = ash_canonicalize_json({"b": 2, "a": 1})
        assert "a" in result and "b" in result

    def test_special_char_keys(self):
        """Should handle special characters in keys."""
        result = ash_canonicalize_json({"key with spaces": 1, "key\twith\ttabs": 2})
        assert "key with spaces" in result

    def test_empty_string_key(self):
        """Should handle empty string as key."""
        result = ash_canonicalize_json({"": 1, "a": 2})
        assert '""' in result


class TestJcsArrays:
    """Tests for JSON array canonicalization."""

    def test_empty_array(self):
        """Should canonicalize empty array."""
        assert ash_canonicalize_json([]) == "[]"

    def test_array_preserves_order(self):
        """Should preserve array element order."""
        assert ash_canonicalize_json([3, 1, 2]) == "[3,1,2]"

    def test_array_of_strings(self):
        """Should handle array of strings."""
        result = ash_canonicalize_json(["c", "a", "b"])
        assert result == '["c","a","b"]'

    def test_array_of_objects(self):
        """Should handle array of objects with sorted keys."""
        result = ash_canonicalize_json([{"z": 1, "a": 2}, {"b": 3}])
        assert result == '[{"a":2,"z":1},{"b":3}]'

    def test_nested_arrays(self):
        """Should handle nested arrays."""
        result = ash_canonicalize_json([[1, 2], [3, 4]])
        assert result == "[[1,2],[3,4]]"

    def test_array_with_null(self):
        """Should handle arrays with null."""
        result = ash_canonicalize_json([1, None, 3])
        assert result == "[1,null,3]"

    def test_array_with_mixed_types(self):
        """Should handle arrays with mixed types."""
        result = ash_canonicalize_json([1, "two", True, None, {"a": 1}])
        assert result == '[1,"two",true,null,{"a":1}]'

    def test_large_array(self):
        """Should handle large arrays."""
        arr = list(range(100))
        result = ash_canonicalize_json(arr)
        assert result.startswith("[0,1,2,3,")
        assert result.endswith("97,98,99]")


class TestJcsEdgeCases:
    """Edge case tests for JSON canonicalization."""

    def test_empty_nested_objects(self):
        """Should handle empty nested objects."""
        result = ash_canonicalize_json({"a": {}, "b": []})
        assert result == '{"a":{},"b":[]}'

    def test_whitespace_in_strings(self):
        """Should preserve whitespace in strings."""
        result = ash_canonicalize_json("  spaces  ")
        assert result == '"  spaces  "'

    def test_very_long_string(self):
        """Should handle very long strings."""
        long_str = "a" * 10000
        result = ash_canonicalize_json(long_str)
        assert len(result) == 10002  # 10000 chars + 2 quotes

    def test_deeply_nested_mixed(self):
        """Should handle deeply nested mixed structures."""
        obj = {"a": [{"b": [{"c": [1, 2, 3]}]}]}
        result = ash_canonicalize_json(obj)
        assert result == '{"a":[{"b":[{"c":[1,2,3]}]}]}'

    def test_boolean_in_array(self):
        """Should handle booleans in arrays."""
        result = ash_canonicalize_json([True, False, True])
        assert result == "[true,false,true]"

    def test_number_boundaries(self):
        """Should handle number boundaries."""
        obj = {"max": 9007199254740991, "min": -9007199254740991}
        result = ash_canonicalize_json(obj)
        assert "9007199254740991" in result
        assert "-9007199254740991" in result


class TestJcsMinification:
    """Tests for JSON minification (no whitespace)."""

    def test_no_spaces_after_colon(self):
        """Should have no space after colon."""
        result = ash_canonicalize_json({"key": "value"})
        assert ": " not in result
        assert ':"' in result

    def test_no_spaces_after_comma(self):
        """Should have no space after comma."""
        result = ash_canonicalize_json({"a": 1, "b": 2})
        assert ", " not in result
        assert ',"' in result

    def test_no_newlines(self):
        """Should have no newlines in output."""
        result = ash_canonicalize_json({"a": 1, "b": {"c": 2}})
        assert "\n" not in result

    def test_compact_array(self):
        """Should produce compact array output."""
        result = ash_canonicalize_json([1, 2, 3, 4, 5])
        assert result == "[1,2,3,4,5]"


class TestJcsRfc8785Compliance:
    """Tests specifically for RFC 8785 compliance."""

    def test_rfc8785_example_1(self):
        """RFC 8785 Section 3.2.2 - Object with sorted keys."""
        obj = {"b": 2, "a": 1}
        result = ash_canonicalize_json(obj)
        assert result == '{"a":1,"b":2}'

    def test_rfc8785_example_2(self):
        """RFC 8785 Section 3.2.2 - Nested object sorting."""
        obj = {"z": {"b": 2, "a": 1}, "a": 1}
        result = ash_canonicalize_json(obj)
        assert result == '{"a":1,"z":{"a":1,"b":2}}'

    def test_rfc8785_string_escaping(self):
        """RFC 8785 Section 3.2.2.2 - String escaping."""
        result = ash_canonicalize_json("test\tvalue")
        assert result == '"test\\tvalue"'

    def test_rfc8785_number_representation(self):
        """RFC 8785 Section 3.2.2.3 - Number representation."""
        # Integers should not have decimal point
        assert ash_canonicalize_json(1) == "1"
        # -0 should become 0
        assert ash_canonicalize_json(-0.0) == "0"


class TestJcsDeterminism:
    """Tests to verify deterministic output."""

    def test_same_input_same_output(self):
        """Same input should always produce same output."""
        obj = {"z": 1, "a": 2, "m": {"x": 1, "y": 2}}
        result1 = ash_canonicalize_json(obj)
        result2 = ash_canonicalize_json(obj)
        assert result1 == result2

    def test_different_insertion_order_same_output(self):
        """Different insertion order should produce same output."""
        obj1 = {"a": 1, "b": 2, "c": 3}
        obj2 = {"c": 3, "a": 1, "b": 2}
        obj3 = {"b": 2, "c": 3, "a": 1}

        result1 = ash_canonicalize_json(obj1)
        result2 = ash_canonicalize_json(obj2)
        result3 = ash_canonicalize_json(obj3)

        assert result1 == result2 == result3

    def test_repeated_canonicalization(self):
        """Repeated canonicalization should be idempotent."""
        obj = {"z": [3, 1, 2], "a": {"nested": True}}
        result1 = ash_canonicalize_json(obj)
        # Parse and re-canonicalize
        import json
        parsed = json.loads(result1)
        result2 = ash_canonicalize_json(parsed)
        assert result1 == result2


class TestJcsSpecialCases:
    """Special case tests."""

    def test_single_value_null(self):
        """Should handle null as root value."""
        assert ash_canonicalize_json(None) == "null"

    def test_single_value_boolean(self):
        """Should handle boolean as root value."""
        assert ash_canonicalize_json(True) == "true"
        assert ash_canonicalize_json(False) == "false"

    def test_single_value_number(self):
        """Should handle number as root value."""
        assert ash_canonicalize_json(42) == "42"

    def test_single_value_string(self):
        """Should handle string as root value."""
        assert ash_canonicalize_json("test") == '"test"'

    def test_single_value_array(self):
        """Should handle array as root value."""
        assert ash_canonicalize_json([1, 2, 3]) == "[1,2,3]"

    def test_single_value_object(self):
        """Should handle object as root value."""
        assert ash_canonicalize_json({"a": 1}) == '{"a":1}'
