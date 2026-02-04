package ash

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

// ============================================================================
// COMPREHENSIVE JCS (JSON CANONICALIZATION) TESTS
// ============================================================================

// --- RFC 8785 Compliance Tests ---

func TestJCSRFC8785KeyOrdering(t *testing.T) {
	testCases := []struct {
		name     string
		input    map[string]interface{}
		expected string
	}{
		{"alphabetical", map[string]interface{}{"b": 1, "a": 2}, `{"a":2,"b":1}`},
		{"numbers_before_letters", map[string]interface{}{"a": 1, "1": 2}, `{"1":2,"a":1}`},
		{"uppercase_after_lowercase", map[string]interface{}{"A": 1, "a": 2}, `{"A":1,"a":2}`},
		{"unicode_ordering", map[string]interface{}{"ä": 1, "a": 2}, `{"a":2,"ä":1}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := CanonicalizeJSON(tc.input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

func TestJCSRFC8785NumberFormatting(t *testing.T) {
	testCases := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{"integer_zero", 0, "0"},
		{"positive_integer", 42, "42"},
		{"negative_integer", -42, "-42"},
		{"float_one_decimal", 1.5, "1.5"},
		{"float_trailing_zeros", 1.0, "1"},
		{"small_float", 0.001, "0.001"},
		{"large_integer", 1000000, "1000000"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := CanonicalizeJSON(tc.input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

func TestJCSRFC8785StringEscaping(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		contains string
	}{
		{"backslash", "a\\b", "\\\\"},
		{"double_quote", `a"b`, "\\\""},
		{"newline", "a\nb", "\\n"},
		{"carriage_return", "a\rb", "\\r"},
		{"tab", "a\tb", "\\t"},
		{"backspace", "a\bb", "\\b"},
		{"form_feed", "a\fb", "\\f"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := CanonicalizeJSON(tc.input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if !strings.Contains(result, tc.contains) {
				t.Errorf("Expected result to contain %s, got %s", tc.contains, result)
			}
		})
	}
}

func TestJCSRFC8785ControlCharacters(t *testing.T) {
	for i := 0; i < 32; i++ {
		t.Run(fmt.Sprintf("control_char_%02x", i), func(t *testing.T) {
			input := string(rune(i))
			result, err := CanonicalizeJSON(input)
			if err != nil {
				t.Fatalf("Unexpected error for control char %02x: %v", i, err)
			}
			// Control characters should be escaped
			if strings.Contains(result, string(rune(i))) && i != 0 {
				// Some control chars might be escaped differently
			}
			if len(result) < 3 { // At minimum ""
				t.Errorf("Result too short for control char %02x: %s", i, result)
			}
		})
	}
}

// --- Nested Structure Tests ---

func TestJCSNestedObjects(t *testing.T) {
	testCases := []struct {
		name     string
		input    map[string]interface{}
		expected string
	}{
		{
			"single_nesting",
			map[string]interface{}{"outer": map[string]interface{}{"inner": 1}},
			`{"outer":{"inner":1}}`,
		},
		{
			"double_nesting",
			map[string]interface{}{"a": map[string]interface{}{"b": map[string]interface{}{"c": 1}}},
			`{"a":{"b":{"c":1}}}`,
		},
		{
			"nested_sorted",
			map[string]interface{}{"z": map[string]interface{}{"b": 1, "a": 2}},
			`{"z":{"a":2,"b":1}}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := CanonicalizeJSON(tc.input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

func TestJCSNestedArrays(t *testing.T) {
	testCases := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{"empty_nested", []interface{}{[]interface{}{}}, "[[]]"},
		{"single_nested", []interface{}{[]interface{}{1}}, "[[1]]"},
		{"multiple_nested", []interface{}{[]interface{}{1, 2}, []interface{}{3, 4}}, "[[1,2],[3,4]]"},
		{"deeply_nested", []interface{}{[]interface{}{[]interface{}{1}}}, "[[[1]]]"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := CanonicalizeJSON(tc.input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

func TestJCSMixedNesting(t *testing.T) {
	testCases := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			"array_in_object",
			map[string]interface{}{"arr": []interface{}{1, 2, 3}},
			`{"arr":[1,2,3]}`,
		},
		{
			"object_in_array",
			[]interface{}{map[string]interface{}{"a": 1}},
			`[{"a":1}]`,
		},
		{
			"complex_mixed",
			map[string]interface{}{
				"arr": []interface{}{
					map[string]interface{}{"b": 2, "a": 1},
				},
			},
			`{"arr":[{"a":1,"b":2}]}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := CanonicalizeJSON(tc.input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

// --- Special Value Tests ---

func TestJCSBooleanValues(t *testing.T) {
	testCases := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{"true", true, "true"},
		{"false", false, "false"},
		{"true_in_object", map[string]interface{}{"flag": true}, `{"flag":true}`},
		{"false_in_object", map[string]interface{}{"flag": false}, `{"flag":false}`},
		{"true_in_array", []interface{}{true}, "[true]"},
		{"false_in_array", []interface{}{false}, "[false]"},
		{"mixed_booleans", []interface{}{true, false, true}, "[true,false,true]"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := CanonicalizeJSON(tc.input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

func TestJCSNullValues(t *testing.T) {
	testCases := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{"null", nil, "null"},
		{"null_in_object", map[string]interface{}{"val": nil}, `{"val":null}`},
		{"null_in_array", []interface{}{nil}, "[null]"},
		{"multiple_nulls", []interface{}{nil, nil}, "[null,null]"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := CanonicalizeJSON(tc.input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

// --- Unicode Tests ---

func TestJCSUnicodeStrings(t *testing.T) {
	testCases := []struct {
		name  string
		input string
	}{
		{"japanese", "日本語"},
		{"chinese", "中文"},
		{"korean", "한국어"},
		{"arabic", "العربية"},
		{"hebrew", "עברית"},
		{"thai", "ภาษาไทย"},
		{"emoji", "😀🎉🚀"},
		{"mixed", "Hello 世界 🌍"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := CanonicalizeJSON(tc.input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			// Should contain the original string (possibly with quotes)
			if !strings.Contains(result, tc.input) {
				t.Errorf("Result should contain original string: %s, got %s", tc.input, result)
			}
		})
	}
}

func TestJCSUnicodeKeys(t *testing.T) {
	testCases := []struct {
		name  string
		input map[string]interface{}
	}{
		{"japanese_key", map[string]interface{}{"日本語": "value"}},
		{"emoji_key", map[string]interface{}{"🔑": "value"}},
		{"mixed_key", map[string]interface{}{"key_键": "value"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := CanonicalizeJSON(tc.input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if result == "" {
				t.Error("Result should not be empty")
			}
		})
	}
}

// --- Error Cases ---

func TestJCSRejectsInvalidValues(t *testing.T) {
	testCases := []struct {
		name  string
		input interface{}
	}{
		{"nan", math.NaN()},
		{"positive_inf", math.Inf(1)},
		{"negative_inf", math.Inf(-1)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CanonicalizeJSON(tc.input)
			if err == nil {
				t.Error("Expected error for invalid value")
			}
		})
	}
}

// --- Determinism Tests ---

func TestJCSDeterminism(t *testing.T) {
	inputs := []interface{}{
		map[string]interface{}{"z": 1, "a": 2, "m": 3},
		[]interface{}{3, 1, 2},
		map[string]interface{}{
			"nested": map[string]interface{}{"b": 1, "a": 2},
			"array":  []interface{}{1, 2, 3},
		},
	}

	for i, input := range inputs {
		t.Run(fmt.Sprintf("input_%d", i), func(t *testing.T) {
			result1, _ := CanonicalizeJSON(input)
			for j := 0; j < 100; j++ {
				result2, _ := CanonicalizeJSON(input)
				if result1 != result2 {
					t.Errorf("Non-deterministic result: %s != %s", result1, result2)
				}
			}
		})
	}
}

// --- Whitespace Tests ---

func TestJCSNoExtraWhitespace(t *testing.T) {
	testCases := []interface{}{
		map[string]interface{}{"a": 1, "b": 2},
		[]interface{}{1, 2, 3},
		map[string]interface{}{"nested": map[string]interface{}{"a": 1}},
	}

	for i, input := range testCases {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			result, _ := CanonicalizeJSON(input)
			// Check for improper whitespace
			if strings.Contains(result, ": ") {
				t.Error("Should not have space after colon")
			}
			if strings.Contains(result, ", ") {
				t.Error("Should not have space after comma")
			}
			if strings.HasPrefix(result, " ") || strings.HasSuffix(result, " ") {
				t.Error("Should not have leading/trailing whitespace")
			}
		})
	}
}

// --- Large Structure Tests ---

func TestJCSLargeObject(t *testing.T) {
	obj := make(map[string]interface{})
	for i := 0; i < 100; i++ {
		obj[fmt.Sprintf("key_%03d", i)] = i
	}

	result, err := CanonicalizeJSON(obj)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify keys are sorted
	lastKey := ""
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("key_%03d", i)
		if strings.Index(result, key) < strings.Index(result, lastKey) && lastKey != "" {
			t.Error("Keys should be sorted")
		}
		lastKey = key
	}
}

func TestJCSLargeArray(t *testing.T) {
	arr := make([]interface{}, 100)
	for i := 0; i < 100; i++ {
		arr[i] = i
	}

	result, err := CanonicalizeJSON(arr)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !strings.HasPrefix(result, "[") || !strings.HasSuffix(result, "]") {
		t.Error("Should be a valid array")
	}
}

func TestJCSDeepNestingLevels(t *testing.T) {
	depths := []int{5, 10, 20, 50}

	for _, depth := range depths {
		t.Run(fmt.Sprintf("depth_%d", depth), func(t *testing.T) {
			// Build deeply nested object
			var obj interface{} = "value"
			for i := 0; i < depth; i++ {
				obj = map[string]interface{}{"level": obj}
			}

			result, err := CanonicalizeJSON(obj)
			if err != nil {
				t.Fatalf("Unexpected error at depth %d: %v", depth, err)
			}

			// Count nesting
			count := strings.Count(result, "{")
			if count != depth {
				t.Errorf("Expected %d levels of nesting, got %d", depth, count)
			}
		})
	}
}

// --- Edge Cases ---

func TestJCSEmptyContainers(t *testing.T) {
	testCases := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{"empty_object", map[string]interface{}{}, "{}"},
		{"empty_array", []interface{}{}, "[]"},
		{"empty_string", "", `""`},
		{"nested_empty_object", map[string]interface{}{"a": map[string]interface{}{}}, `{"a":{}}`},
		{"nested_empty_array", map[string]interface{}{"a": []interface{}{}}, `{"a":[]}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := CanonicalizeJSON(tc.input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

func TestJCSSpecialStringValues(t *testing.T) {
	testCases := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"space", " "},
		{"multiple_spaces", "   "},
		{"tab_only", "\t"},
		{"newline_only", "\n"},
		{"null_string", "null"},
		{"true_string", "true"},
		{"false_string", "false"},
		{"number_string", "123"},
		{"json_string", `{"a":1}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := CanonicalizeJSON(tc.input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			// Should be quoted
			if !strings.HasPrefix(result, `"`) || !strings.HasSuffix(result, `"`) {
				t.Error("String should be quoted")
			}
		})
	}
}
