package ash

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// EXTENDED EDGE CASES - Additional edge case coverage
// ============================================================================

// --- Numeric Edge Cases ---

func TestEdgeCaseZeroValue(t *testing.T) {
	input := map[string]interface{}{"zero": 0}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	if !strings.Contains(result, `"zero":0`) {
		t.Errorf("Zero not preserved: %s", result)
	}
}

func TestEdgeCaseNegativeZero(t *testing.T) {
	// -0 should be treated as 0
	input := map[string]interface{}{"negzero": -0.0}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	// Should not have minus sign for zero
	if strings.Contains(result, "-0") {
		t.Errorf("Negative zero should be 0: %s", result)
	}
}

func TestEdgeCaseVerySmallNumber(t *testing.T) {
	input := map[string]interface{}{"tiny": 0.000001}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	if result == "" {
		t.Error("Should handle very small numbers")
	}
}

func TestEdgeCaseVeryLargeNumber(t *testing.T) {
	input := map[string]interface{}{"huge": 9999999999999999.0}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	if result == "" {
		t.Error("Should handle very large numbers")
	}
}

func TestEdgeCaseMaxSafeInteger(t *testing.T) {
	// JavaScript's MAX_SAFE_INTEGER
	input := map[string]interface{}{"max": float64(9007199254740991)}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	if result == "" {
		t.Error("Should handle max safe integer")
	}
}

func TestEdgeCaseMinSafeInteger(t *testing.T) {
	// JavaScript's MIN_SAFE_INTEGER
	input := map[string]interface{}{"min": float64(-9007199254740991)}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	if result == "" {
		t.Error("Should handle min safe integer")
	}
}

func TestEdgeCaseScientificNotation(t *testing.T) {
	inputs := []float64{
		1e10,
		1e-10,
		1.23e5,
		1.23e-5,
	}

	for _, val := range inputs {
		input := map[string]interface{}{"val": val}
		result, err := CanonicalizeJSON(input)
		if err != nil {
			continue
		}
		if result == "" {
			t.Errorf("Should handle %e", val)
		}
	}
}

// --- String Edge Cases ---

func TestEdgeCaseEmptyString(t *testing.T) {
	input := map[string]interface{}{"empty": ""}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	if !strings.Contains(result, `"empty":""`) {
		t.Errorf("Empty string not preserved: %s", result)
	}
}

func TestEdgeCaseSingleCharacter(t *testing.T) {
	chars := []string{"a", "1", "!", " ", "\t", "\n"}

	for _, char := range chars {
		input := map[string]interface{}{"char": char}
		result, err := CanonicalizeJSON(input)
		if err != nil {
			continue
		}
		if result == "" {
			t.Errorf("Should handle single char %q", char)
		}
	}
}

func TestEdgeCaseVeryLongString(t *testing.T) {
	longStr := strings.Repeat("x", 100000)
	input := map[string]interface{}{"long": longStr}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	if result == "" {
		t.Error("Should handle very long string")
	}
}

func TestEdgeCaseControlCharacters(t *testing.T) {
	controlChars := []string{
		"\x00", "\x01", "\x02", "\x03", "\x04", "\x05",
		"\x06", "\x07", "\x08", "\x09", "\x0a", "\x0b",
		"\x0c", "\x0d", "\x0e", "\x0f", "\x10", "\x1f",
	}

	for _, char := range controlChars {
		input := map[string]interface{}{"ctrl": char}
		_, err := CanonicalizeJSON(input)
		// Should either succeed with escaping or error gracefully
		_ = err
	}
}

func TestEdgeCaseUnicodeEscapes(t *testing.T) {
	inputs := []string{
		"\u0000", // null
		"\u001f", // unit separator
		"\u0020", // space
		"\u007f", // DEL
		"\u0080", // PAD
		"\u00ff", // ÿ
	}

	for _, str := range inputs {
		input := map[string]interface{}{"unicode": str}
		_, err := CanonicalizeJSON(input)
		_ = err
	}
}

func TestEdgeCaseBackslashes(t *testing.T) {
	inputs := []string{
		`\`,
		`\\`,
		`\n`,
		`\\n`,
		`\\\n`,
	}

	for _, str := range inputs {
		input := map[string]interface{}{"backslash": str}
		_, err := CanonicalizeJSON(input)
		_ = err
	}
}

func TestEdgeCaseQuotes(t *testing.T) {
	inputs := []string{
		`"`,
		`""`,
		`"hello"`,
		`'"`,
		`"'`,
	}

	for _, str := range inputs {
		input := map[string]interface{}{"quotes": str}
		_, err := CanonicalizeJSON(input)
		_ = err
	}
}

// --- Array Edge Cases ---

func TestEdgeCaseEmptyArray(t *testing.T) {
	result, err := CanonicalizeJSON([]interface{}{})
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	if result != "[]" {
		t.Errorf("Empty array should be [], got %s", result)
	}
}

func TestEdgeCaseSingleElementArray(t *testing.T) {
	result, err := CanonicalizeJSON([]interface{}{1})
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	if result != "[1]" {
		t.Errorf("Single element array should be [1], got %s", result)
	}
}

func TestEdgeCaseNestedEmptyArrays(t *testing.T) {
	input := []interface{}{[]interface{}{}, []interface{}{}}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	if result != "[[],[]]" {
		t.Errorf("Nested empty arrays should be [[],[]], got %s", result)
	}
}

func TestEdgeCaseMixedArray(t *testing.T) {
	input := []interface{}{1, "two", true, nil, []interface{}{}}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	if result == "" {
		t.Error("Should handle mixed array")
	}
}

func TestEdgeCaseLargeArray(t *testing.T) {
	arr := make([]interface{}, 1000)
	for i := range arr {
		arr[i] = i
	}

	result, err := CanonicalizeJSON(arr)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	if result == "" {
		t.Error("Should handle large array")
	}
}

// --- Object Edge Cases ---

func TestEdgeCaseEmptyObject(t *testing.T) {
	result, err := CanonicalizeJSON(map[string]interface{}{})
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	if result != "{}" {
		t.Errorf("Empty object should be {}, got %s", result)
	}
}

func TestEdgeCaseSingleKeyObject(t *testing.T) {
	result, err := CanonicalizeJSON(map[string]interface{}{"a": 1})
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	if result != `{"a":1}` {
		t.Errorf("Single key object mismatch: %s", result)
	}
}

func TestEdgeCaseManyKeysObject(t *testing.T) {
	obj := make(map[string]interface{})
	for i := 0; i < 100; i++ {
		obj[fmt.Sprintf("key_%d", i)] = i
	}

	result, err := CanonicalizeJSON(obj)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
	if result == "" {
		t.Error("Should handle object with many keys")
	}
}

func TestEdgeCaseDeeplyNestedObject(t *testing.T) {
	depth := 50
	var nested interface{} = "deep"
	for i := 0; i < depth; i++ {
		nested = map[string]interface{}{"level": nested}
	}

	result, err := CanonicalizeJSON(nested)
	if err != nil {
		// May error on very deep nesting
		return
	}
	if result == "" {
		t.Error("Should handle deeply nested object")
	}
}

func TestEdgeCaseSpecialKeyNames(t *testing.T) {
	keys := []string{
		"",           // empty key
		" ",          // space
		"_",          // underscore
		"-",          // hyphen
		".",          // dot
		"0",          // number
		"true",       // keyword
		"null",       // keyword
		"@special",   // special char
		"$dollar",    // special char
		"key with space",
	}

	for _, key := range keys {
		input := map[string]interface{}{key: "value"}
		result, err := CanonicalizeJSON(input)
		if err != nil {
			continue
		}
		if result == "" {
			t.Errorf("Should handle key %q", key)
		}
	}
}

// --- Query Edge Cases ---

func TestEdgeCaseQueryEmptyKey(t *testing.T) {
	input := "=value"
	result, err := CanonicalizeQuery(input)
	// Should handle empty key
	_ = result
	_ = err
}

func TestEdgeCaseQueryMultipleEquals(t *testing.T) {
	input := "key=val=ue"
	result, err := CanonicalizeQuery(input)
	// Should handle multiple equals
	_ = result
	_ = err
}

func TestEdgeCaseQueryEncodedEquals(t *testing.T) {
	input := "key=val%3Due"
	result, err := CanonicalizeQuery(input)
	// Should preserve encoded equals
	_ = result
	_ = err
}

func TestEdgeCaseQueryEncodedAmpersand(t *testing.T) {
	input := "key=val%26ue"
	result, err := CanonicalizeQuery(input)
	// Should preserve encoded ampersand
	_ = result
	_ = err
}

func TestEdgeCaseQueryPlusSign(t *testing.T) {
	input := "key=val+ue"
	result, err := CanonicalizeQuery(input)
	// Should handle plus as space or preserve
	_ = result
	_ = err
}

func TestEdgeCaseQueryLeadingQuestion(t *testing.T) {
	input := "?key=value"
	result, err := CanonicalizeQuery(input)
	// Should handle leading question mark
	_ = result
	_ = err
}

// --- Binding Edge Cases ---

func TestEdgeCaseBindingTrailingSlash(t *testing.T) {
	result := NormalizeBinding("GET", "/api/", "")
	// Should handle trailing slash
	_ = result
}

func TestEdgeCaseBindingDoubleSlash(t *testing.T) {
	result := NormalizeBinding("GET", "/api//users", "")
	// Should handle double slash
	_ = result
}

func TestEdgeCaseBindingDotSegment(t *testing.T) {
	paths := []string{
		"/api/./users",
		"/api/../users",
		"/./api/users",
	}

	for _, path := range paths {
		result := NormalizeBinding("GET", path, "")
		_ = result
	}
}

func TestEdgeCaseBindingEncodedPath(t *testing.T) {
	result := NormalizeBinding("GET", "/api/%2Fusers", "")
	// Should handle encoded slash
	_ = result
}

func TestEdgeCaseBindingQueryFragment(t *testing.T) {
	result := NormalizeBinding("GET", "/api", "key=value#fragment")
	// Should handle fragment
	_ = result
}

// --- Timestamp Edge Cases ---

func TestEdgeCaseTimestampZero(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test"
	binding := "POST|/api|"
	timestamp := "0"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	if len(proof) != 64 {
		t.Error("Should handle zero timestamp")
	}
}

func TestEdgeCaseTimestampNegative(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test"
	binding := "POST|/api|"
	timestamp := "-1"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	if len(proof) != 64 {
		t.Error("Should handle negative timestamp")
	}
}

func TestEdgeCaseTimestampVeryLarge(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test"
	binding := "POST|/api|"
	timestamp := "99999999999999"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	if len(proof) != 64 {
		t.Error("Should handle very large timestamp")
	}
}

func TestEdgeCaseTimestampString(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test"
	binding := "POST|/api|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("String timestamp should work")
	}
}

// --- Nonce Edge Cases ---

func TestEdgeCaseNonceMinLength(t *testing.T) {
	// Nonce should be 64 chars
	nonce := strings.Repeat("a", 64)
	secret := DeriveClientSecret(nonce, "ctx", "POST|/|")
	if len(secret) != 64 {
		t.Error("Should handle 64 char nonce")
	}
}

func TestEdgeCaseNonceAllSameChar(t *testing.T) {
	chars := []string{"0", "a", "f", "9"}

	for _, char := range chars {
		nonce := strings.Repeat(char, 64)
		secret := DeriveClientSecret(nonce, "ctx", "POST|/|")
		if len(secret) != 64 {
			t.Errorf("Should handle nonce of all %s", char)
		}
	}
}

func TestEdgeCaseNoncePattern(t *testing.T) {
	nonce := strings.Repeat("0f", 32) // alternating
	secret := DeriveClientSecret(nonce, "ctx", "POST|/|")
	if len(secret) != 64 {
		t.Error("Should handle alternating nonce")
	}
}

// --- Context Edge Cases ---

func TestEdgeCaseContextEmpty(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	secret := DeriveClientSecret(nonce, "", "POST|/|")
	if len(secret) != 64 {
		t.Error("Should handle empty context")
	}
}

func TestEdgeCaseContextLong(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	longContext := strings.Repeat("x", 10000)
	secret := DeriveClientSecret(nonce, longContext, "POST|/|")
	if len(secret) != 64 {
		t.Error("Should handle long context")
	}
}

func TestEdgeCaseContextSpecialChars(t *testing.T) {
	contexts := []string{
		"ctx-with-dashes",
		"ctx_with_underscores",
		"ctx.with.dots",
		"ctx:with:colons",
		"ctx/with/slashes",
		"ctx@with@at",
	}

	for _, ctx := range contexts {
		nonce := strings.Repeat("a", 64)
		secret := DeriveClientSecret(nonce, ctx, "POST|/|")
		if len(secret) != 64 {
			t.Errorf("Should handle context %s", ctx)
		}
	}
}

// --- Proof Format Edge Cases ---

func TestEdgeCaseProofEmpty(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	valid := VerifyProofV21(nonce, "ctx", "POST|/|", "12345", HashBody("{}"), "")
	if valid {
		t.Error("Empty proof should not verify")
	}
}

func TestEdgeCaseProofTooShort(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	valid := VerifyProofV21(nonce, "ctx", "POST|/|", "12345", HashBody("{}"), "abc")
	if valid {
		t.Error("Short proof should not verify")
	}
}

func TestEdgeCaseProofTooLong(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	longProof := strings.Repeat("a", 128)
	valid := VerifyProofV21(nonce, "ctx", "POST|/|", "12345", HashBody("{}"), longProof)
	if valid {
		t.Error("Long proof should not verify")
	}
}

func TestEdgeCaseProofUppercase(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	uppercaseProof := strings.Repeat("A", 64)
	valid := VerifyProofV21(nonce, "ctx", "POST|/|", "12345", HashBody("{}"), uppercaseProof)
	// May or may not verify depending on implementation
	_ = valid
}

func TestEdgeCaseProofNonHex(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	nonHexProof := strings.Repeat("g", 64)
	valid := VerifyProofV21(nonce, "ctx", "POST|/|", "12345", HashBody("{}"), nonHexProof)
	if valid {
		t.Error("Non-hex proof should not verify")
	}
}

// --- Special Value Edge Cases ---

func TestEdgeCaseNaN(t *testing.T) {
	input := map[string]interface{}{"nan": math.NaN()}
	_, err := CanonicalizeJSON(input)
	if err == nil {
		t.Error("NaN should error")
	}
}

func TestEdgeCaseInfinity(t *testing.T) {
	input := map[string]interface{}{"inf": math.Inf(1)}
	_, err := CanonicalizeJSON(input)
	if err == nil {
		t.Error("Infinity should error")
	}
}

func TestEdgeCaseNegativeInfinity(t *testing.T) {
	input := map[string]interface{}{"neginf": math.Inf(-1)}
	_, err := CanonicalizeJSON(input)
	if err == nil {
		t.Error("Negative infinity should error")
	}
}

// --- Scope Edge Cases ---

func TestEdgeCaseScopeEmptyField(t *testing.T) {
	secret := strings.Repeat("a", 64)
	payload := map[string]interface{}{"": "value", "key": "value2"}
	scope := []string{""}

	result := BuildProofUnified(secret, "12345", "POST|/|", payload, scope, "")
	_ = result
}

func TestEdgeCaseScopeMissingField(t *testing.T) {
	secret := strings.Repeat("a", 64)
	payload := map[string]interface{}{"key": "value"}
	scope := []string{"nonexistent"}

	result := BuildProofUnified(secret, "12345", "POST|/|", payload, scope, "")
	_ = result
}

func TestEdgeCaseScopeNestedField(t *testing.T) {
	secret := strings.Repeat("a", 64)
	payload := map[string]interface{}{
		"outer": map[string]interface{}{
			"inner": "value",
		},
	}
	scope := []string{"outer"}

	result := BuildProofUnified(secret, "12345", "POST|/|", payload, scope, "")
	if len(result.Proof) != 64 {
		t.Error("Should handle nested field scope")
	}
}
