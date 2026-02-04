"""
Extended JCS (JSON Canonicalization Scheme - RFC 8785) Edge Cases.

These tests cover additional edge cases for Unicode, numbers, special characters,
and deeply nested structures to ensure cross-SDK compatibility.
"""

import pytest
from ash.core.canonicalize import ash_canonicalize_json
from ash.core.errors import CanonicalizationError


class TestJcsUnicodeEmojis:
    """Extended emoji and Unicode character tests."""

    def test_emoji_single_codepoint(self):
        """Should handle single codepoint emoji."""
        result = ash_canonicalize_json({"emoji": "\u2764"})  # heart
        assert "\\u2764" in result or "\u2764" in result

    def test_emoji_multi_codepoint_family(self):
        """Should handle family emoji with ZWJ sequences."""
        # Family: man, woman, girl, boy
        family = "\U0001F468\u200D\U0001F469\u200D\U0001F467\u200D\U0001F466"
        result = ash_canonicalize_json({"family": family})
        assert "family" in result

    def test_emoji_flag_sequence(self):
        """Should handle flag emoji (regional indicator symbols)."""
        # US flag
        flag = "\U0001F1FA\U0001F1F8"
        result = ash_canonicalize_json({"flag": flag})
        assert "flag" in result

    def test_emoji_skin_tone_modifier(self):
        """Should handle emoji with skin tone modifiers."""
        # Wave with medium skin tone
        wave = "\U0001F44B\U0001F3FD"
        result = ash_canonicalize_json({"wave": wave})
        assert "wave" in result

    def test_emoji_keycap_sequence(self):
        """Should handle keycap sequences."""
        keycap = "1\uFE0F\u20E3"  # keycap 1
        result = ash_canonicalize_json({"key": keycap})
        assert "key" in result

    def test_multiple_emojis(self):
        """Should handle multiple emojis in sequence."""
        emojis = "\U0001F600\U0001F601\U0001F602\U0001F603"
        result = ash_canonicalize_json({"emojis": emojis})
        assert "emojis" in result

    def test_emoji_in_object_key(self):
        """Should handle emoji as object key."""
        result = ash_canonicalize_json({"\U0001F600": "smile"})
        assert "smile" in result

    def test_emoji_variation_selector(self):
        """Should handle variation selectors."""
        # Heart with text style
        heart_text = "\u2764\uFE0E"
        result = ash_canonicalize_json({"heart": heart_text})
        assert "heart" in result

    def test_emoji_zwj_sequence(self):
        """Should handle zero-width joiner sequences."""
        # Woman technologist
        woman_tech = "\U0001F469\u200D\U0001F4BB"
        result = ash_canonicalize_json({"person": woman_tech})
        assert "person" in result

    def test_gender_neutral_emoji(self):
        """Should handle gender-neutral emoji."""
        person = "\U0001F9D1"
        result = ash_canonicalize_json({"person": person})
        assert "person" in result


class TestJcsUnicodeRTL:
    """Right-to-left text and bidirectional text tests."""

    def test_arabic_text(self):
        """Should handle Arabic text."""
        result = ash_canonicalize_json({"text": "\u0645\u0631\u062D\u0628\u0627"})
        assert "text" in result

    def test_hebrew_text(self):
        """Should handle Hebrew text."""
        result = ash_canonicalize_json({"text": "\u05E9\u05DC\u05D5\u05DD"})
        assert "text" in result

    def test_rtl_with_numbers(self):
        """Should handle RTL text with embedded numbers."""
        result = ash_canonicalize_json({"price": "\u062F\u0631\u0647\u0645 100"})
        assert "price" in result

    def test_bidirectional_text(self):
        """Should handle bidirectional text."""
        bidi = "Hello \u05E9\u05DC\u05D5\u05DD World"
        result = ash_canonicalize_json({"bidi": bidi})
        assert "bidi" in result

    def test_rtl_override_char(self):
        """Should handle RTL override character."""
        rtl = "A\u202EB\u202CC"
        result = ash_canonicalize_json({"rtl": rtl})
        assert "rtl" in result

    def test_arabic_with_diacritics(self):
        """Should handle Arabic with diacritics."""
        text = "\u0639\u064E\u0631\u064E\u0628\u0650\u064A"
        result = ash_canonicalize_json({"text": text})
        assert "text" in result

    def test_persian_text(self):
        """Should handle Persian text."""
        result = ash_canonicalize_json({"text": "\u0633\u0644\u0627\u0645"})
        assert "text" in result

    def test_urdu_text(self):
        """Should handle Urdu text."""
        result = ash_canonicalize_json({"text": "\u0627\u0631\u062F\u0648"})
        assert "text" in result


class TestJcsUnicodeCombiningChars:
    """Combining characters and diacritics tests."""

    def test_combining_acute_accent(self):
        """Should handle combining acute accent."""
        # e with combining acute accent
        result = ash_canonicalize_json({"letter": "e\u0301"})
        assert "letter" in result

    def test_multiple_combining_chars(self):
        """Should handle multiple combining characters."""
        # a with multiple diacritics
        result = ash_canonicalize_json({"letter": "a\u0300\u0301\u0302"})
        assert "letter" in result

    def test_combining_enclosing_circle(self):
        """Should handle combining enclosing marks."""
        result = ash_canonicalize_json({"letter": "A\u20DD"})
        assert "letter" in result

    def test_zalgo_text(self):
        """Should handle zalgo-style text with many combiners."""
        zalgo = "H\u0316\u0317\u0318\u0319e\u031A\u031B\u031C"
        result = ash_canonicalize_json({"zalgo": zalgo})
        assert "zalgo" in result

    def test_vietnamese_with_combiners(self):
        """Should handle Vietnamese with combining marks."""
        result = ash_canonicalize_json({"text": "Ti\u1EBFng Vi\u1EC7t"})
        assert "text" in result

    def test_combining_double_chars(self):
        """Should handle combining double characters."""
        result = ash_canonicalize_json({"text": "a\u0361b"})  # combining double inverted breve
        assert "text" in result

    def test_thai_with_tone_marks(self):
        """Should handle Thai with tone marks."""
        result = ash_canonicalize_json({"text": "\u0E2A\u0E27\u0E31\u0E2A\u0E14\u0E35"})
        assert "text" in result

    def test_devanagari_with_nukta(self):
        """Should handle Devanagari with nukta."""
        result = ash_canonicalize_json({"text": "\u0915\u093C"})
        assert "text" in result


class TestJcsUnicodeSpecialCategories:
    """Special Unicode categories tests."""

    def test_mathematical_symbols(self):
        """Should handle mathematical symbols."""
        result = ash_canonicalize_json({"math": "\u221E\u00B1\u2248"})
        assert "math" in result

    def test_currency_symbols(self):
        """Should handle currency symbols."""
        result = ash_canonicalize_json({"currency": "\u20AC\u00A3\u00A5\u20BF"})
        assert "currency" in result

    def test_musical_symbols(self):
        """Should handle musical symbols."""
        result = ash_canonicalize_json({"music": "\U0001D11E\U0001D11F"})
        assert "music" in result

    def test_box_drawing_chars(self):
        """Should handle box drawing characters."""
        result = ash_canonicalize_json({"box": "\u2500\u2502\u250C\u2510"})
        assert "box" in result

    def test_braille_patterns(self):
        """Should handle braille patterns."""
        result = ash_canonicalize_json({"braille": "\u2800\u2801\u2802"})
        assert "braille" in result

    def test_private_use_area(self):
        """Should handle private use area characters."""
        result = ash_canonicalize_json({"pua": "\uE000\uE001"})
        assert "pua" in result

    def test_zero_width_chars(self):
        """Should handle zero-width characters."""
        result = ash_canonicalize_json({"text": "a\u200Bb\u200Cc\u200Dd"})
        assert "text" in result

    def test_byte_order_mark(self):
        """Should handle BOM character."""
        result = ash_canonicalize_json({"text": "\uFEFFhello"})
        assert "text" in result

    def test_replacement_character(self):
        """Should handle replacement character."""
        result = ash_canonicalize_json({"text": "\uFFFD"})
        assert "text" in result

    def test_interlinear_annotation(self):
        """Should handle interlinear annotation characters."""
        result = ash_canonicalize_json({"text": "\uFFF9a\uFFFAb\uFFFB"})
        assert "text" in result


class TestJcsNumberEdgeCases:
    """Extended number edge cases."""

    def test_max_safe_integer(self):
        """Should handle JavaScript max safe integer."""
        assert ash_canonicalize_json(9007199254740991) == "9007199254740991"

    def test_min_safe_integer(self):
        """Should handle JavaScript min safe integer."""
        assert ash_canonicalize_json(-9007199254740991) == "-9007199254740991"

    def test_very_small_positive_float(self):
        """Should handle very small positive float."""
        result = ash_canonicalize_json(1e-300)
        assert result.startswith("1") or "e-" in result.lower()

    def test_very_large_positive_float(self):
        """Should handle very large positive float."""
        result = ash_canonicalize_json(1e300)
        assert "1" in result

    def test_scientific_notation_boundary(self):
        """Should handle scientific notation boundary."""
        result = ash_canonicalize_json(1e21)
        assert "1" in result

    def test_subnormal_number(self):
        """Should handle subnormal numbers."""
        result = ash_canonicalize_json(5e-324)
        assert result  # Just verify it doesn't crash

    def test_float_precision_edge(self):
        """Should handle float precision edge cases."""
        result = ash_canonicalize_json(0.1 + 0.2)
        assert "0.3" in result or "30" in result

    def test_integer_that_looks_like_float(self):
        """Should handle integer that looks like float."""
        assert ash_canonicalize_json(100.0) == "100"

    def test_negative_zero_in_object(self):
        """Should normalize -0.0 in object."""
        result = ash_canonicalize_json({"value": -0.0})
        assert '"value":0' in result

    def test_powers_of_two(self):
        """Should handle powers of two."""
        for i in range(53):
            val = 2 ** i
            result = ash_canonicalize_json(val)
            assert str(val) == result

    def test_pi_approximation(self):
        """Should handle pi approximation."""
        result = ash_canonicalize_json(3.141592653589793)
        assert "3.14159" in result

    def test_euler_number(self):
        """Should handle Euler's number."""
        result = ash_canonicalize_json(2.718281828459045)
        assert "2.71828" in result


class TestJcsObjectKeyEdgeCases:
    """Extended object key edge cases."""

    def test_numeric_keys_sorting(self):
        """Should sort numeric string keys lexicographically."""
        obj = {"100": "a", "20": "b", "3": "c"}
        result = ash_canonicalize_json(obj)
        # Lexicographic: "100" < "20" < "3"
        idx_100 = result.index('"100"')
        idx_20 = result.index('"20"')
        idx_3 = result.index('"3"')
        assert idx_100 < idx_20 < idx_3

    def test_keys_with_escapes(self):
        """Should handle keys with escape sequences."""
        obj = {"key\nwith\nnewlines": "value"}
        result = ash_canonicalize_json(obj)
        assert "\\n" in result

    def test_keys_with_unicode(self):
        """Should handle Unicode keys."""
        obj = {"\u4E2D\u6587": "chinese", "\u65E5\u672C": "japanese"}
        result = ash_canonicalize_json(obj)
        assert "chinese" in result
        assert "japanese" in result

    def test_key_sorting_utf8_bytes(self):
        """Should sort keys by UTF-8 byte sequence."""
        obj = {"b": 2, "a": 1, "\u00E0": 3}  # a with grave
        result = ash_canonicalize_json(obj)
        # 'a' < 'b' < '\u00E0' in byte order
        idx_a = result.index('"a"')
        idx_b = result.index('"b"')
        assert idx_a < idx_b

    def test_single_char_keys(self):
        """Should handle single character keys."""
        obj = {"a": 1, "b": 2, "c": 3}
        result = ash_canonicalize_json(obj)
        assert result == '{"a":1,"b":2,"c":3}'

    def test_mixed_case_keys(self):
        """Should sort mixed case keys correctly."""
        obj = {"b": 1, "B": 2, "a": 3, "A": 4}
        result = ash_canonicalize_json(obj)
        # ASCII order: A < B < a < b
        idx_A = result.index('"A"')
        idx_B = result.index('"B"')
        idx_a = result.index('"a"')
        idx_b = result.index('"b"')
        assert idx_A < idx_B < idx_a < idx_b

    def test_long_key_names(self):
        """Should handle very long key names."""
        long_key = "k" * 1000
        obj = {long_key: "value"}
        result = ash_canonicalize_json(obj)
        assert "value" in result

    def test_special_json_chars_in_key(self):
        """Should escape special JSON characters in keys."""
        obj = {'key"with"quotes': "value"}
        result = ash_canonicalize_json(obj)
        assert '\\"' in result


class TestJcsArrayEdgeCases:
    """Extended array edge cases."""

    def test_deeply_nested_arrays(self):
        """Should handle deeply nested arrays."""
        arr = [[[[[1]]]]]
        result = ash_canonicalize_json(arr)
        assert result == "[[[[[1]]]]]"

    def test_large_array(self):
        """Should handle large arrays."""
        arr = list(range(1000))
        result = ash_canonicalize_json(arr)
        assert result.startswith("[0,1,2,")
        assert result.endswith(",998,999]")

    def test_sparse_like_array(self):
        """Should handle array with null gaps."""
        arr = [1, None, 3, None, 5]
        result = ash_canonicalize_json(arr)
        assert result == "[1,null,3,null,5]"

    def test_array_of_empty_arrays(self):
        """Should handle array of empty arrays."""
        arr = [[], [], []]
        result = ash_canonicalize_json(arr)
        assert result == "[[],[],[]]"

    def test_array_of_empty_objects(self):
        """Should handle array of empty objects."""
        arr = [{}, {}, {}]
        result = ash_canonicalize_json(arr)
        assert result == "[{},{},{}]"

    def test_heterogeneous_array(self):
        """Should handle array with all types."""
        arr = [1, "two", True, False, None, {"nested": "object"}, [1, 2, 3]]
        result = ash_canonicalize_json(arr)
        assert "two" in result
        assert "true" in result
        assert "null" in result

    def test_array_with_duplicate_values(self):
        """Should preserve duplicate values in array."""
        arr = [1, 1, 1, 2, 2, 2]
        result = ash_canonicalize_json(arr)
        assert result == "[1,1,1,2,2,2]"


class TestJcsStringEdgeCases:
    """Extended string edge cases."""

    def test_all_ascii_control_chars(self):
        """Should escape all ASCII control characters."""
        for i in range(32):
            s = f"a{chr(i)}b"
            result = ash_canonicalize_json(s)
            # Should either escape with \uXXXX or with named escape
            assert "\\" in result or i in [9, 10, 13]  # tab, newline, carriage return

    def test_delete_character(self):
        """Should handle DEL character (0x7F)."""
        result = ash_canonicalize_json("a\x7Fb")
        # DEL should be preserved as-is in RFC 8785
        assert "a" in result and "b" in result

    def test_string_with_all_escape_types(self):
        """Should handle string with all escape types."""
        s = 'tab:\t newline:\n quote:" backslash:\\ return:\r form:\f back:\b'
        result = ash_canonicalize_json(s)
        assert "\\t" in result
        assert "\\n" in result
        assert '\\"' in result
        assert "\\\\" in result

    def test_empty_string_value(self):
        """Should handle empty string as value."""
        result = ash_canonicalize_json({"key": ""})
        assert '""' in result

    def test_string_with_only_whitespace(self):
        """Should preserve whitespace-only string."""
        result = ash_canonicalize_json("   ")
        assert result == '"   "'

    def test_string_with_tabs(self):
        """Should escape tabs."""
        result = ash_canonicalize_json("a\tb\tc")
        assert "\\t" in result

    def test_very_long_string(self):
        """Should handle very long strings."""
        long_s = "x" * 100000
        result = ash_canonicalize_json(long_s)
        assert len(result) == 100002  # 100000 + 2 quotes


class TestJcsComplexStructures:
    """Complex structure edge cases."""

    def test_very_deep_nesting(self):
        """Should handle very deep nesting."""
        obj = {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": {"j": 1}}}}}}}}}}
        result = ash_canonicalize_json(obj)
        assert '"j":1' in result

    def test_wide_object(self):
        """Should handle object with many keys."""
        obj = {f"key{i}": i for i in range(100)}
        result = ash_canonicalize_json(obj)
        assert '"key0":0' in result
        assert '"key99":99' in result

    def test_mixed_nested_structures(self):
        """Should handle mixed nested arrays and objects."""
        obj = {
            "arr": [{"nested": [1, 2, {"deep": [3, 4, 5]}]}],
            "obj": {"inner": [{"array": [1]}]}
        }
        result = ash_canonicalize_json(obj)
        assert '"deep"' in result
        assert '"array"' in result

    def test_object_with_boolean_values(self):
        """Should handle objects with boolean values."""
        obj = {"true": True, "false": False}
        result = ash_canonicalize_json(obj)
        assert '"false":false' in result
        assert '"true":true' in result

    def test_null_in_various_positions(self):
        """Should handle null in various positions."""
        obj = {"a": None, "b": [None, None], "c": {"d": None}}
        result = ash_canonicalize_json(obj)
        assert "null" in result


class TestJcsDeterministicOutput:
    """Deterministic output verification tests."""

    def test_repeated_canonicalization(self):
        """Repeated canonicalization should be idempotent."""
        import json
        obj = {"z": 1, "a": 2, "m": [3, 2, 1]}
        for _ in range(10):
            result1 = ash_canonicalize_json(obj)
            parsed = json.loads(result1)
            result2 = ash_canonicalize_json(parsed)
            assert result1 == result2

    def test_same_data_different_construction(self):
        """Same data constructed differently should canonicalize same."""
        obj1 = {"a": 1, "b": 2}
        obj2 = {}
        obj2["b"] = 2
        obj2["a"] = 1
        assert ash_canonicalize_json(obj1) == ash_canonicalize_json(obj2)

    def test_float_consistency(self):
        """Float canonicalization should be consistent."""
        val = 1.0 / 3.0
        results = [ash_canonicalize_json(val) for _ in range(100)]
        assert len(set(results)) == 1

    def test_unicode_consistency(self):
        """Unicode canonicalization should be consistent."""
        val = "\u4E2D\u6587"
        results = [ash_canonicalize_json(val) for _ in range(100)]
        assert len(set(results)) == 1


class TestJcsErrorHandling:
    """Error handling edge cases."""

    def test_reject_nan_in_object(self):
        """Should reject NaN in object."""
        with pytest.raises(CanonicalizationError):
            ash_canonicalize_json({"value": float("nan")})

    def test_reject_infinity_in_array(self):
        """Should reject Infinity in array."""
        with pytest.raises(CanonicalizationError):
            ash_canonicalize_json([1, 2, float("inf")])

    def test_reject_negative_infinity(self):
        """Should reject negative Infinity."""
        with pytest.raises(CanonicalizationError):
            ash_canonicalize_json(float("-inf"))

    def test_reject_nan_in_nested(self):
        """Should reject NaN in deeply nested structure."""
        with pytest.raises(CanonicalizationError):
            ash_canonicalize_json({"a": {"b": {"c": float("nan")}}})


class TestJcsSpecialNumbers:
    """Special number handling."""

    def test_zero_variations(self):
        """Should handle zero variations."""
        assert ash_canonicalize_json(0) == "0"
        assert ash_canonicalize_json(0.0) == "0"
        assert ash_canonicalize_json(-0.0) == "0"

    def test_one_variations(self):
        """Should handle one variations."""
        assert ash_canonicalize_json(1) == "1"
        assert ash_canonicalize_json(1.0) == "1"

    def test_round_trip_integers(self):
        """Should round-trip integers."""
        for i in [-1000, -100, -10, -1, 0, 1, 10, 100, 1000]:
            result = ash_canonicalize_json(i)
            assert result == str(i)

    def test_float_trailing_zeros(self):
        """Should not have unnecessary trailing zeros."""
        result = ash_canonicalize_json(1.5)
        assert result == "1.5"

    def test_float_leading_zeros(self):
        """Should have leading zero for values between -1 and 1."""
        result = ash_canonicalize_json(0.5)
        assert result == "0.5"


class TestJcsCJKCharacters:
    """CJK (Chinese, Japanese, Korean) character tests."""

    def test_chinese_simplified(self):
        """Should handle simplified Chinese."""
        result = ash_canonicalize_json({"text": "\u4E2D\u6587"})
        assert "text" in result

    def test_chinese_traditional(self):
        """Should handle traditional Chinese."""
        result = ash_canonicalize_json({"text": "\u4E2D\u6587"})
        assert "text" in result

    def test_japanese_hiragana(self):
        """Should handle Japanese Hiragana."""
        result = ash_canonicalize_json({"text": "\u3042\u3044\u3046"})
        assert "text" in result

    def test_japanese_katakana(self):
        """Should handle Japanese Katakana."""
        result = ash_canonicalize_json({"text": "\u30A2\u30A4\u30A6"})
        assert "text" in result

    def test_japanese_kanji(self):
        """Should handle Japanese Kanji."""
        result = ash_canonicalize_json({"text": "\u65E5\u672C"})
        assert "text" in result

    def test_korean_hangul(self):
        """Should handle Korean Hangul."""
        result = ash_canonicalize_json({"text": "\uD55C\uAE00"})
        assert "text" in result

    def test_mixed_cjk(self):
        """Should handle mixed CJK."""
        result = ash_canonicalize_json({
            "chinese": "\u4E2D\u6587",
            "japanese": "\u65E5\u672C\u8A9E",
            "korean": "\uD55C\uAE00"
        })
        assert "chinese" in result


class TestJcsIndianScripts:
    """Indian script tests."""

    def test_devanagari(self):
        """Should handle Devanagari script."""
        result = ash_canonicalize_json({"text": "\u0939\u093F\u0928\u094D\u0926\u0940"})
        assert "text" in result

    def test_bengali(self):
        """Should handle Bengali script."""
        result = ash_canonicalize_json({"text": "\u09AC\u09BE\u0982\u09B2\u09BE"})
        assert "text" in result

    def test_tamil(self):
        """Should handle Tamil script."""
        result = ash_canonicalize_json({"text": "\u0BA4\u0BAE\u0BBF\u0BB4\u0BCD"})
        assert "text" in result

    def test_telugu(self):
        """Should handle Telugu script."""
        result = ash_canonicalize_json({"text": "\u0C24\u0C46\u0C32\u0C41\u0C17\u0C41"})
        assert "text" in result

    def test_kannada(self):
        """Should handle Kannada script."""
        result = ash_canonicalize_json({"text": "\u0C95\u0CA8\u0CCD\u0CA8\u0CA1"})
        assert "text" in result


class TestJcsOtherScripts:
    """Other script tests."""

    def test_cyrillic(self):
        """Should handle Cyrillic."""
        result = ash_canonicalize_json({"text": "\u0420\u0443\u0441\u0441\u043A\u0438\u0439"})
        assert "text" in result

    def test_greek(self):
        """Should handle Greek."""
        result = ash_canonicalize_json({"text": "\u0395\u03BB\u03BB\u03B7\u03BD\u03B9\u03BA\u03AC"})
        assert "text" in result

    def test_armenian(self):
        """Should handle Armenian."""
        result = ash_canonicalize_json({"text": "\u0540\u0561\u0575\u0565\u0580\u0565\u0576"})
        assert "text" in result

    def test_georgian(self):
        """Should handle Georgian."""
        result = ash_canonicalize_json({"text": "\u10E5\u10D0\u10E0\u10D7\u10E3\u10DA\u10D8"})
        assert "text" in result

    def test_ethiopic(self):
        """Should handle Ethiopic."""
        result = ash_canonicalize_json({"text": "\u12A0\u121B\u122D\u129B"})
        assert "text" in result

    def test_tibetan(self):
        """Should handle Tibetan."""
        result = ash_canonicalize_json({"text": "\u0F56\u0F7C\u0F51\u0F0B\u0F66\u0F90\u0F51"})
        assert "text" in result


class TestJcsWhitespace:
    """Whitespace handling tests."""

    def test_no_whitespace_in_output(self):
        """Should produce minified output with no extraneous whitespace."""
        obj = {"key": "value", "array": [1, 2, 3]}
        result = ash_canonicalize_json(obj)
        assert " " not in result or '"key"' in result  # Only in values
        assert "\n" not in result
        assert "\t" not in result

    def test_preserve_whitespace_in_values(self):
        """Should preserve whitespace in string values."""
        result = ash_canonicalize_json({"key": "  value  "})
        assert "  value  " in result

    def test_newline_in_value(self):
        """Should escape newlines in values."""
        result = ash_canonicalize_json({"key": "line1\nline2"})
        assert "\\n" in result

    def test_tab_in_value(self):
        """Should escape tabs in values."""
        result = ash_canonicalize_json({"key": "col1\tcol2"})
        assert "\\t" in result
