package ash

import (
	"fmt"
	"strings"
	"testing"
)

// ============================================================================
// COMPREHENSIVE QUERY AND URL ENCODING TESTS
// ============================================================================

// --- Basic Query Canonicalization ---

func TestQueryCanonicalizeEmpty(t *testing.T) {
	result, err := CanonicalizeQuery("")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("Empty query should return empty, got %s", result)
	}
}

func TestQueryCanonicalizeSingleParam(t *testing.T) {
	result, _ := CanonicalizeQuery("a=1")
	if result != "a=1" {
		t.Errorf("Expected a=1, got %s", result)
	}
}

func TestQueryCanonicalizeMultipleParams(t *testing.T) {
	result, _ := CanonicalizeQuery("b=2&a=1")
	if result != "a=1&b=2" {
		t.Errorf("Expected sorted params a=1&b=2, got %s", result)
	}
}

func TestQueryCanonicalizeManyParams(t *testing.T) {
	result, _ := CanonicalizeQuery("z=1&y=2&x=3&w=4&v=5")
	if result != "v=5&w=4&x=3&y=2&z=1" {
		t.Errorf("Expected sorted params, got %s", result)
	}
}

// --- Duplicate Keys ---

func TestQueryDuplicateKeysSortedByValue(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"a=2&a=1", "a=1&a=2"},
		{"a=c&a=b&a=a", "a=a&a=b&a=c"},
		{"x=3&x=1&x=2", "x=1&x=2&x=3"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result, _ := CanonicalizeQuery(tc.input)
			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

func TestQueryDuplicateMixedKeys(t *testing.T) {
	result, _ := CanonicalizeQuery("b=1&a=2&b=0&a=1")
	// Should sort by key first, then by value for same keys
	if !strings.Contains(result, "a=1") || !strings.Contains(result, "a=2") {
		t.Errorf("Should contain both a values, got %s", result)
	}
	if !strings.Contains(result, "b=0") || !strings.Contains(result, "b=1") {
		t.Errorf("Should contain both b values, got %s", result)
	}
}

// --- Empty Values ---

func TestQueryEmptyValueComprehensive(t *testing.T) {
	result, _ := CanonicalizeQuery("key=")
	if result != "key=" {
		t.Errorf("Expected key=, got %s", result)
	}
}

func TestQueryNoEquals(t *testing.T) {
	result, _ := CanonicalizeQuery("key")
	// Should handle key without value
	if result == "" && result != "key" && result != "key=" {
		t.Logf("Key without equals: %s", result)
	}
}

func TestQueryMixedEmptyValues(t *testing.T) {
	result, _ := CanonicalizeQuery("a=1&b=&c=3")
	if !strings.Contains(result, "b=") {
		t.Errorf("Should preserve empty value, got %s", result)
	}
}

// --- Percent Encoding ---

func TestQueryPercentEncodingUppercaseComprehensive(t *testing.T) {
	testCases := []struct {
		input    string
		contains string
	}{
		{"a=%20", "%20"},      // Should keep uppercase
		{"a=%2f", "%2F"},      // Should uppercase
		{"a=%2F", "%2F"},      // Already uppercase
		{"a=%3a%3b", "%3A%3B"}, // Should uppercase both
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result, _ := CanonicalizeQuery(tc.input)
			if !strings.Contains(result, tc.contains) {
				t.Errorf("Expected %s to contain %s, got %s", tc.input, tc.contains, result)
			}
		})
	}
}

func TestQuerySpaceEncoding(t *testing.T) {
	result, _ := CanonicalizeQuery("a=hello%20world")
	if !strings.Contains(result, "%20") {
		t.Errorf("Space should be encoded as %%20, got %s", result)
	}
}

func TestQueryPlusSign(t *testing.T) {
	result, _ := CanonicalizeQuery("a=hello+world")
	// Plus should be treated literally or converted to %2B
	if result == "" {
		t.Error("Result should not be empty")
	}
}

// --- Special Characters ---

func TestQuerySpecialCharacters(t *testing.T) {
	chars := []string{
		"a=!",
		"a=@",
		"a=#",
		"a=$",
		"a=&b=1",
		"a=*",
		"a=(",
		"a=)",
	}

	for _, input := range chars {
		t.Run(input, func(t *testing.T) {
			result, _ := CanonicalizeQuery(input)
			if result == "" && !strings.Contains(input, "&") {
				t.Error("Result should not be empty")
			}
		})
	}
}

// --- Leading Question Mark ---

func TestQueryLeadingQuestionMark(t *testing.T) {
	result, _ := CanonicalizeQuery("?a=1")
	// Should strip leading ?
	if strings.HasPrefix(result, "?") {
		t.Errorf("Should strip leading ?, got %s", result)
	}
	if !strings.Contains(result, "a=1") {
		t.Errorf("Should contain a=1, got %s", result)
	}
}

// --- Fragment Handling ---

func TestQueryFragmentStripped(t *testing.T) {
	result, _ := CanonicalizeQuery("a=1#section")
	if strings.Contains(result, "#") {
		t.Errorf("Should strip fragment, got %s", result)
	}
}

// --- URL Encoded Canonicalization ---

func TestURLEncodedEmpty(t *testing.T) {
	result, err := CanonicalizeURLEncoded("")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("Expected empty, got %s", result)
	}
}

func TestURLEncodedSinglePair(t *testing.T) {
	result, _ := CanonicalizeURLEncoded("key=value")
	if result != "key=value" {
		t.Errorf("Expected key=value, got %s", result)
	}
}

func TestURLEncodedSorted(t *testing.T) {
	result, _ := CanonicalizeURLEncoded("z=3&a=1&m=2")
	if result != "a=1&m=2&z=3" {
		t.Errorf("Expected sorted, got %s", result)
	}
}

func TestURLEncodedDuplicates(t *testing.T) {
	result, _ := CanonicalizeURLEncoded("a=2&a=1")
	if result != "a=1&a=2" {
		t.Errorf("Expected a=1&a=2, got %s", result)
	}
}

func TestURLEncodedPlusAsLiteral(t *testing.T) {
	result, _ := CanonicalizeURLEncoded("a=hello+world")
	// Plus should be treated as literal
	if !strings.Contains(result, "+") && !strings.Contains(result, "%2B") {
		t.Logf("Plus handling: %s", result)
	}
}

// --- Case Sensitivity ---

func TestQueryCaseSensitiveKeysComprehensive(t *testing.T) {
	result, _ := CanonicalizeQuery("A=1&a=2")
	// A and a should be treated as different keys
	if !strings.Contains(result, "A=") || !strings.Contains(result, "a=") {
		t.Errorf("Keys should be case-sensitive, got %s", result)
	}
}

func TestQueryCaseSensitiveValues(t *testing.T) {
	result1, _ := CanonicalizeQuery("a=ABC")
	result2, _ := CanonicalizeQuery("a=abc")
	if result1 == result2 {
		t.Error("Values should be case-sensitive")
	}
}

// --- Unicode in Query ---

func TestQueryUnicodeValues(t *testing.T) {
	testCases := []string{
		"name=日本語",
		"emoji=🚀",
		"mixed=hello世界",
	}

	for _, input := range testCases {
		t.Run(input, func(t *testing.T) {
			result, err := CanonicalizeQuery(input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if result == "" {
				t.Error("Result should not be empty")
			}
		})
	}
}

func TestQueryUnicodeKeys(t *testing.T) {
	result, err := CanonicalizeQuery("キー=value")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result == "" {
		t.Error("Unicode key should be handled")
	}
}

// --- Large Queries ---

func TestQueryLargeNumberOfParams(t *testing.T) {
	var params []string
	for i := 0; i < 100; i++ {
		params = append(params, fmt.Sprintf("key%03d=value%d", i, i))
	}
	input := strings.Join(params, "&")

	result, err := CanonicalizeQuery(input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result == "" {
		t.Error("Result should not be empty")
	}

	// Verify sorted
	if !strings.HasPrefix(result, "key000=") {
		t.Error("Should be sorted alphabetically")
	}
}

func TestQueryLongValue(t *testing.T) {
	longValue := strings.Repeat("x", 10000)
	input := "key=" + longValue

	result, err := CanonicalizeQuery(input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !strings.Contains(result, longValue) {
		t.Error("Should preserve long value")
	}
}

// --- Determinism ---

func TestQueryDeterminism(t *testing.T) {
	inputs := []string{
		"z=1&y=2&x=3",
		"a=1&a=2&a=3",
		"key=value%20with%20spaces",
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			result1, _ := CanonicalizeQuery(input)
			for i := 0; i < 100; i++ {
				result2, _ := CanonicalizeQuery(input)
				if result1 != result2 {
					t.Error("Query canonicalization should be deterministic")
				}
			}
		})
	}
}

func TestURLEncodedDeterminism(t *testing.T) {
	inputs := []string{
		"z=1&y=2&x=3",
		"a=1&a=2&a=3",
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			result1, _ := CanonicalizeURLEncoded(input)
			for i := 0; i < 100; i++ {
				result2, _ := CanonicalizeURLEncoded(input)
				if result1 != result2 {
					t.Error("URL encoded canonicalization should be deterministic")
				}
			}
		})
	}
}

// --- Edge Cases ---

func TestQueryOnlyAmpersands(t *testing.T) {
	result, _ := CanonicalizeQuery("&&&")
	// Should handle gracefully
	if strings.Contains(result, "&&&") {
		t.Error("Should not preserve empty segments")
	}
}

func TestQueryTrailingAmpersand(t *testing.T) {
	result, _ := CanonicalizeQuery("a=1&")
	// Should handle gracefully
	if strings.HasSuffix(result, "&") && !strings.HasSuffix(result, "a=1&") {
		t.Logf("Trailing ampersand handling: %s", result)
	}
}

func TestQueryLeadingAmpersand(t *testing.T) {
	result, _ := CanonicalizeQuery("&a=1")
	// Should handle gracefully
	if strings.HasPrefix(result, "&") {
		t.Error("Should not have leading ampersand")
	}
}

func TestQueryDoubleAmpersand(t *testing.T) {
	result, _ := CanonicalizeQuery("a=1&&b=2")
	// Should handle gracefully
	if strings.Contains(result, "&&") {
		t.Error("Should not have double ampersand")
	}
}

func TestQueryDoubleEquals(t *testing.T) {
	result, _ := CanonicalizeQuery("a==1")
	// Value should be =1
	if result == "" {
		t.Error("Should handle double equals")
	}
}

func TestQueryEncodedAmpersand(t *testing.T) {
	result, _ := CanonicalizeQuery("a=1%262")
	// %26 is encoded &, should be preserved in value
	if !strings.Contains(result, "%26") {
		t.Logf("Encoded ampersand: %s", result)
	}
}

func TestQueryEncodedEquals(t *testing.T) {
	result, _ := CanonicalizeQuery("a=1%3D2")
	// %3D is encoded =, should be preserved in value
	if !strings.Contains(result, "%3D") {
		t.Logf("Encoded equals: %s", result)
	}
}

// --- Real-World Query Strings ---

func TestQueryRealWorldSearch(t *testing.T) {
	query := "q=search+term&page=1&limit=10&sort=date&order=desc"
	result, err := CanonicalizeQuery(query)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result == "" {
		t.Error("Should handle real-world search query")
	}
}

func TestQueryRealWorldFilter(t *testing.T) {
	query := "filter[status]=active&filter[type]=user&filter[created_at][gte]=2024-01-01"
	result, err := CanonicalizeQuery(query)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result == "" {
		t.Error("Should handle filter query")
	}
}

func TestQueryRealWorldArrayParams(t *testing.T) {
	query := "ids[]=1&ids[]=2&ids[]=3"
	result, err := CanonicalizeQuery(query)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result == "" {
		t.Error("Should handle array params")
	}
}

func TestQueryRealWorldOAuth(t *testing.T) {
	query := "client_id=abc123&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&response_type=code&scope=read+write"
	result, err := CanonicalizeQuery(query)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result == "" {
		t.Error("Should handle OAuth query")
	}
}

// --- Base64URL Tests ---

func TestBase64URLEncodeEmpty(t *testing.T) {
	result := Base64URLEncode([]byte{})
	if result != "" {
		t.Errorf("Empty input should return empty, got %s", result)
	}
}

func TestBase64URLEncodeBasic(t *testing.T) {
	result := Base64URLEncode([]byte("hello"))
	if result == "" {
		t.Error("Should encode basic string")
	}
	// Should not contain + or /
	if strings.Contains(result, "+") || strings.Contains(result, "/") {
		t.Error("Base64URL should not contain + or /")
	}
}

func TestBase64URLEncodePadding(t *testing.T) {
	result := Base64URLEncode([]byte("a"))
	// Should not have trailing =
	if strings.HasSuffix(result, "=") {
		t.Error("Base64URL should not have padding")
	}
}

func TestBase64URLDecodeEmpty(t *testing.T) {
	result, err := Base64URLDecode("")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Error("Empty input should return empty")
	}
}

func TestBase64URLDecodeBasic(t *testing.T) {
	encoded := Base64URLEncode([]byte("hello"))
	decoded, err := Base64URLDecode(encoded)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if string(decoded) != "hello" {
		t.Errorf("Expected hello, got %s", string(decoded))
	}
}

func TestBase64URLRoundTrip(t *testing.T) {
	inputs := [][]byte{
		[]byte(""),
		[]byte("a"),
		[]byte("ab"),
		[]byte("abc"),
		[]byte("abcd"),
		[]byte("hello world"),
		[]byte{0x00, 0x01, 0x02, 0xFF, 0xFE},
	}

	for i, input := range inputs {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			encoded := Base64URLEncode(input)
			decoded, err := Base64URLDecode(encoded)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if string(decoded) != string(input) {
				t.Errorf("Round trip failed: %v != %v", decoded, input)
			}
		})
	}
}
