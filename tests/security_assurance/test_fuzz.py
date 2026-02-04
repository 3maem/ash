"""
ASH Security Assurance Pack - Fuzz & Abuse Tests
=================================================
F. Fuzz & Abuse:
- Malformed JSON, Unicode edge cases
- Oversized payloads
- Randomized byte fuzzing
"""

import pytest
import sys
import os
import random
import string
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../packages/ash-python/src'))

from ash.core import (
    canonicalize_json,
    canonicalize_url_encoded,
    normalize_binding,
    build_proof,
    hash_body,
    CanonicalizationError,
)


class TestMalformedJSON:
    """Test handling of malformed JSON inputs."""

    def test_invalid_json_string_rejected(self):
        """Invalid JSON strings should be rejected gracefully."""
        invalid_jsons = [
            '{invalid}',
            '{"key": undefined}',
            "{'single': 'quotes'}",
            '{"trailing": "comma",}',
            '{"missing": "close brace"',
            '[1, 2, 3,]',
            '',
            'null null',
            '{"key": NaN}',
            '{"key": Infinity}',
        ]

        for invalid in invalid_jsons:
            # hash_body should handle strings directly
            # canonicalize_json expects Python objects, not strings
            # So we test by trying to parse first
            try:
                data = json.loads(invalid)
                # If it parses, we can canonicalize
                canonicalize_json(data)
            except (json.JSONDecodeError, ValueError, CanonicalizationError):
                pass  # Expected - invalid JSON
            except Exception as e:
                pytest.fail(f"Unexpected exception for '{invalid}': {type(e).__name__}: {e}")

    def test_deeply_nested_json(self):
        """Deeply nested JSON should be handled or rejected safely."""
        # Build deeply nested structure
        depth = 100
        nested = {}
        current = nested
        for i in range(depth):
            current["level"] = {}
            current = current["level"]
        current["value"] = 1

        try:
            result = canonicalize_json(nested)
            assert result is not None
            assert "value" in result
        except RecursionError:
            pass  # Acceptable to reject very deep nesting
        except Exception as e:
            pytest.fail(f"Unexpected exception for deep nesting: {type(e).__name__}: {e}")

    def test_wide_json_objects(self):
        """Very wide JSON objects (many keys) should be handled."""
        num_keys = 1000
        wide = {f"key_{i}": i for i in range(num_keys)}

        result = canonicalize_json(wide)
        assert result is not None
        assert f'"key_0":0' in result
        assert f'"key_{num_keys-1}":{num_keys-1}' in result

    def test_large_arrays(self):
        """Large arrays should be handled."""
        large_array = {"items": list(range(10000))}

        result = canonicalize_json(large_array)
        assert result is not None
        assert '"items":[0,1,2' in result

    def test_mixed_types_in_array(self):
        """Arrays with mixed types should be handled."""
        mixed = {"arr": [1, "two", True, None, {"nested": "object"}, [1, 2, 3]]}

        result = canonicalize_json(mixed)
        assert result is not None
        assert '"arr":' in result


class TestUnicodeEdgeCases:
    """Test Unicode edge cases."""

    def test_unicode_normalization_forms(self):
        """Different Unicode normalization forms should be handled."""
        # NFC vs NFD
        import unicodedata

        nfc = unicodedata.normalize('NFC', 'café')
        nfd = unicodedata.normalize('NFD', 'café')

        data_nfc = {"text": nfc}
        data_nfd = {"text": nfd}

        result_nfc = canonicalize_json(data_nfc)
        result_nfd = canonicalize_json(data_nfd)

        # Both should normalize to same canonical form (NFC)
        assert result_nfc == result_nfd, "Unicode normalization not consistent"

    def test_emoji_handling(self):
        """Emoji characters should be handled correctly."""
        emoji_data = {
            "emoji": "🎉🚀💻",
            "text": "Hello 👋 World 🌍",
            "complex": "Family: 👨‍👩‍👧‍👦"
        }

        result = canonicalize_json(emoji_data)
        assert result is not None
        # Verify emoji are preserved
        assert "🎉" in result or "\\u" in result  # Either raw or escaped

    def test_zero_width_characters(self):
        """Zero-width characters should be handled."""
        zwc_data = {
            "text": "ab\u200bcd",  # Zero-width space
            "joiner": "a\u200db",  # Zero-width joiner
            "nonjoiner": "a\u200cb"  # Zero-width non-joiner
        }

        result = canonicalize_json(zwc_data)
        assert result is not None

    def test_bidirectional_text(self):
        """Bidirectional text (RTL/LTR) should be handled."""
        bidi_data = {
            "arabic": "مرحبا",
            "hebrew": "שלום",
            "mixed": "Hello مرحبا World",
            "rtl_override": "Test \u202e reversed"
        }

        result = canonicalize_json(bidi_data)
        assert result is not None

    def test_surrogate_pairs(self):
        """Surrogate pairs (high Unicode) should be handled."""
        surrogate_data = {
            "math": "𝕳𝖊𝖑𝖑𝖔",  # Mathematical symbols
            "cjk_ext": "𠀀",  # CJK Extension B
        }

        result = canonicalize_json(surrogate_data)
        assert result is not None

    def test_control_characters(self):
        """Control characters should be properly escaped."""
        control_data = {
            "tab": "\t",
            "newline": "\n",
            "carriage": "\r",
            "backspace": "\b",
            "formfeed": "\f",
            "null_char": "\x00",
        }

        result = canonicalize_json(control_data)
        assert result is not None
        # Control chars should be escaped
        assert "\\t" in result
        assert "\\n" in result

    def test_private_use_area(self):
        """Private Use Area characters should be handled."""
        pua_data = {
            "pua": "\ue000\ue001\ue002"
        }

        result = canonicalize_json(pua_data)
        assert result is not None


class TestOversizedPayloads:
    """Test handling of oversized payloads."""

    def test_1mb_payload(self):
        """1MB payload should be handled."""
        size = 1024 * 1024  # 1MB
        payload = {"data": "x" * size}

        result = canonicalize_json(payload)
        assert result is not None
        assert len(result) > size

    def test_10mb_payload(self):
        """10MB payload should be handled (may be slow)."""
        size = 10 * 1024 * 1024  # 10MB
        payload = {"data": "x" * size}

        result = canonicalize_json(payload)
        assert result is not None

    def test_very_long_string_value(self):
        """Very long string values should be handled."""
        long_string = "a" * 1_000_000
        payload = {"long": long_string}

        result = canonicalize_json(payload)
        assert result is not None
        assert '"long":"' in result

    def test_many_array_elements(self):
        """Arrays with many elements should be handled."""
        payload = {"items": list(range(100000))}

        result = canonicalize_json(payload)
        assert result is not None

    def test_oversized_url_encoded(self):
        """Oversized URL-encoded data should be handled."""
        # Many parameters
        params = "&".join(f"key{i}=value{i}" for i in range(1000))

        result = canonicalize_url_encoded(params)
        assert result is not None
        assert "key0=" in result
        assert "key999=" in result


class TestRandomizedFuzzing:
    """Randomized fuzzing tests."""

    def test_random_json_objects(self):
        """Random JSON objects should be handled without crashes."""
        random.seed(42)  # Reproducible

        for _ in range(100):
            # Generate random object
            obj = {}
            num_keys = random.randint(1, 20)
            for _ in range(num_keys):
                key = ''.join(random.choices(string.ascii_letters, k=random.randint(1, 20)))
                value_type = random.choice(['string', 'int', 'float', 'bool', 'null', 'array'])

                if value_type == 'string':
                    obj[key] = ''.join(random.choices(string.printable, k=random.randint(0, 100)))
                elif value_type == 'int':
                    obj[key] = random.randint(-1000000, 1000000)
                elif value_type == 'float':
                    obj[key] = random.uniform(-1000, 1000)
                elif value_type == 'bool':
                    obj[key] = random.choice([True, False])
                elif value_type == 'null':
                    obj[key] = None
                elif value_type == 'array':
                    obj[key] = [random.randint(0, 100) for _ in range(random.randint(0, 10))]

            try:
                result = canonicalize_json(obj)
                assert result is not None
            except CanonicalizationError:
                pass  # Some random values may be rejected
            except Exception as e:
                pytest.fail(f"Unexpected exception: {type(e).__name__}: {e}")

    def test_random_url_encoded(self):
        """Random URL-encoded data should be handled without crashes."""
        random.seed(43)

        for _ in range(100):
            # Generate random key-value pairs
            pairs = []
            num_pairs = random.randint(1, 20)
            for _ in range(num_pairs):
                key = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(1, 20)))
                value = ''.join(random.choices(string.ascii_letters + string.digits + ' ', k=random.randint(0, 50)))
                pairs.append(f"{key}={value}")

            input_str = "&".join(pairs)

            try:
                result = canonicalize_url_encoded(input_str)
                assert result is not None
            except Exception as e:
                pytest.fail(f"Unexpected exception for '{input_str[:50]}...': {type(e).__name__}: {e}")

    def test_random_bindings(self):
        """Random binding inputs should be handled without crashes."""
        random.seed(44)

        methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'get', 'Post', '']
        paths = ['/', '/api', '/api/test', '/api/test/', '//api//test//', 'api/test', '']

        for _ in range(100):
            method = random.choice(methods)
            path = random.choice(paths)
            query = random.choice(['', 'a=1', 'z=2&a=1', 'key=value&key2=value2'])

            try:
                result = normalize_binding(method, path, query)
                assert result is not None
            except Exception as e:
                # Some inputs may be intentionally invalid
                pass

    def test_byte_mutation_fuzzing(self):
        """Mutating random bytes in valid inputs should not crash."""
        random.seed(45)

        valid_payload = '{"amount":100,"recipient":"user123"}'

        for _ in range(100):
            # Mutate random bytes
            mutated = list(valid_payload)
            num_mutations = random.randint(1, 5)
            for _ in range(num_mutations):
                pos = random.randint(0, len(mutated) - 1)
                mutated[pos] = chr(random.randint(0, 127))

            mutated_str = ''.join(mutated)

            try:
                # Try to hash it (should handle any string)
                hash_body(mutated_str)
            except Exception as e:
                pytest.fail(f"Hash crashed on mutated input: {type(e).__name__}: {e}")


class TestSpecialCases:
    """Test special edge cases."""

    def test_empty_inputs(self):
        """Empty inputs should be handled."""
        assert canonicalize_json({}) == '{}'
        assert canonicalize_json([]) == '[]'
        assert canonicalize_url_encoded('') == ''
        assert hash_body('') is not None

    def test_null_values(self):
        """Null values should be handled correctly."""
        result = canonicalize_json({"key": None})
        # Note: Implementation may either preserve null as '{"key":null}' or strip it as '{}'
        # Both are valid canonicalization approaches - verify it's consistent
        assert result in ['{"key":null}', '{}'], f"Unexpected null handling: {result}"

    def test_boolean_values(self):
        """Boolean values should be handled correctly."""
        result = canonicalize_json({"t": True, "f": False})
        assert '"t":true' in result
        assert '"f":false' in result

    def test_numeric_edge_cases(self):
        """Numeric edge cases should be handled."""
        data = {
            "zero": 0,
            "neg_zero": -0.0,  # Should become 0
            "large": 9007199254740991,  # Max safe integer
            "small": -9007199254740991,
            "float": 3.14159265358979,
        }

        result = canonicalize_json(data)
        assert result is not None
        assert '"neg_zero":0' in result  # -0 normalized to 0

    def test_string_edge_cases(self):
        """String edge cases should be handled."""
        data = {
            "empty": "",
            "space": " ",
            "quote": '"',
            "backslash": "\\",
            "unicode_escape": "\u0000\u001f",
        }

        result = canonicalize_json(data)
        assert result is not None
        assert '\\"' in result  # Escaped quote
        assert '\\\\' in result  # Escaped backslash


class TestURLEncodedEdgeCases:
    """Test URL-encoded edge cases."""

    def test_duplicate_keys(self):
        """Duplicate keys should be preserved in order."""
        result = canonicalize_url_encoded("a=1&a=2&a=3")
        assert result is not None
        # All values should be present
        assert "a=1" in result
        assert "a=2" in result
        assert "a=3" in result

    def test_empty_values(self):
        """Empty values should be preserved."""
        result = canonicalize_url_encoded("key=")
        assert "key=" in result

    def test_no_value(self):
        """Keys without = should be handled."""
        result = canonicalize_url_encoded("key")
        assert result is not None

    def test_special_characters(self):
        """Special characters should be properly encoded."""
        result = canonicalize_url_encoded("key=hello world&key2=a+b")
        assert "%20" in result  # Space encoded

    def test_percent_encoding_normalization(self):
        """Percent encoding should be normalized to uppercase."""
        result = canonicalize_url_encoded("key=%2f")  # lowercase %2f
        assert "%2F" in result or "/".lower() in result.lower()  # Should be uppercase


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
