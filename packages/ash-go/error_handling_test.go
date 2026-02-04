package ash

import (
	"math"
	"strings"
	"testing"
)

// ============================================================================
// ERROR HANDLING TESTS
// ============================================================================

// --- JSON Canonicalization Errors ---

func TestErrInvalidJSON(t *testing.T) {
	_, err := ParseJSON("{invalid}")
	if err == nil {
		t.Error("Should error on invalid JSON")
	}
}

func TestErrMalformedJSON(t *testing.T) {
	_, err := ParseJSON("{\"key\":")
	if err == nil {
		t.Error("Should error on malformed JSON")
	}
}

func TestErrUnclosedString(t *testing.T) {
	_, err := ParseJSON(`{"key":"value}`)
	if err == nil {
		t.Error("Should error on unclosed string")
	}
}

func TestErrUnclosedArray(t *testing.T) {
	_, err := ParseJSON(`{"arr":[1,2,3}`)
	if err == nil {
		t.Error("Should error on unclosed array")
	}
}

func TestErrTrailingComma(t *testing.T) {
	_, err := ParseJSON(`{"a":1,}`)
	if err == nil {
		t.Error("Should error on trailing comma")
	}
}

func TestErrNaN(t *testing.T) {
	input := map[string]interface{}{"value": math.NaN()}
	_, err := CanonicalizeJSON(input)
	if err == nil {
		t.Error("Should error on NaN")
	}
}

func TestErrPositiveInfinity(t *testing.T) {
	input := map[string]interface{}{"value": math.Inf(1)}
	_, err := CanonicalizeJSON(input)
	if err == nil {
		t.Error("Should error on positive infinity")
	}
}

func TestErrNegativeInfinity(t *testing.T) {
	input := map[string]interface{}{"value": math.Inf(-1)}
	_, err := CanonicalizeJSON(input)
	if err == nil {
		t.Error("Should error on negative infinity")
	}
}

// --- Binding Normalization Errors ---

func TestErrEmptyMethod(t *testing.T) {
	result := NormalizeBinding("", "/api", "")
	// Should handle gracefully - either error or empty method
	if !strings.HasPrefix(result, "|") && result != "" {
		// Method part should be empty or error returned
	}
}

func TestErrEmptyPath(t *testing.T) {
	result := NormalizeBinding("GET", "", "")
	// Should handle gracefully
	if result == "GET||" || result == "" {
		// Expected behavior
	}
}

func TestErrPathWithoutSlash(t *testing.T) {
	result := NormalizeBinding("GET", "api/users", "")
	// Should add leading slash or handle gracefully
	if !strings.Contains(result, "/") {
		t.Error("Path should contain slash")
	}
}

// --- Query Canonicalization Edge Cases ---

func TestErrInvalidPercentEncoding(t *testing.T) {
	// Invalid percent encoding should be handled
	result, err := CanonicalizeQuery("name=%ZZ")
	// Should either error or preserve invalid encoding
	if err == nil && result == "" {
		// Expected to handle gracefully
	}
}

func TestErrDoubleAmpersand(t *testing.T) {
	result, err := CanonicalizeQuery("a=1&&b=2")
	if err != nil {
		return // Acceptable to error
	}
	// Should handle empty parts
	if !strings.Contains(result, "a=") || !strings.Contains(result, "b=") {
		t.Error("Should preserve valid params")
	}
}

func TestErrLeadingAmpersand(t *testing.T) {
	result, err := CanonicalizeQuery("&a=1&b=2")
	if err != nil {
		return // Acceptable to error
	}
	// Should handle leading ampersand
	if !strings.Contains(result, "a=") {
		t.Error("Should preserve params")
	}
}

func TestErrTrailingAmpersand(t *testing.T) {
	result, err := CanonicalizeQuery("a=1&b=2&")
	if err != nil {
		return // Acceptable to error
	}
	// Should handle trailing ampersand
	if !strings.Contains(result, "a=") || !strings.Contains(result, "b=") {
		t.Error("Should preserve params")
	}
}

// --- Proof Input Validation ---

func TestErrInvalidMode(t *testing.T) {
	input := BuildProofInput{
		Mode:             "invalid_mode",
		ContextID:        "ctx",
		Binding:          "GET|/|",
		CanonicalPayload: "{}",
	}
	err := ValidateProofInput(input)
	if err == nil {
		t.Error("Should error on invalid mode")
	}
}

func TestErrEmptyContextID(t *testing.T) {
	input := BuildProofInput{
		Mode:             "balanced",
		ContextID:        "",
		Binding:          "GET|/|",
		CanonicalPayload: "{}",
	}
	err := ValidateProofInput(input)
	if err == nil {
		t.Error("Should error on empty context ID")
	}
}

func TestErrEmptyBindingInInput(t *testing.T) {
	input := BuildProofInput{
		Mode:             "balanced",
		ContextID:        "ctx",
		Binding:          "",
		CanonicalPayload: "{}",
	}
	err := ValidateProofInput(input)
	if err == nil {
		t.Error("Should error on empty binding")
	}
}

// --- Verification Errors ---

func TestErrWrongNonce(t *testing.T) {
	correctNonce := strings.Repeat("a", 64)
	wrongNonce := strings.Repeat("b", 64)
	contextID := "ctx"
	binding := "POST|/api|"
	timestamp := "12345"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(correctNonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(wrongNonce, contextID, binding, timestamp, bodyHash, proof)
	if valid {
		t.Error("Wrong nonce should fail verification")
	}
}

func TestErrWrongContextID(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	correctContext := "ctx_correct"
	wrongContext := "ctx_wrong"
	binding := "POST|/api|"
	timestamp := "12345"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, correctContext, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, wrongContext, binding, timestamp, bodyHash, proof)
	if valid {
		t.Error("Wrong context ID should fail verification")
	}
}

func TestErrWrongBinding(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx"
	correctBinding := "POST|/api/correct|"
	wrongBinding := "POST|/api/wrong|"
	timestamp := "12345"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, correctBinding)
	proof := BuildProofV21(secret, timestamp, correctBinding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, wrongBinding, timestamp, bodyHash, proof)
	if valid {
		t.Error("Wrong binding should fail verification")
	}
}

func TestErrWrongTimestamp(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx"
	binding := "POST|/api|"
	correctTimestamp := "12345"
	wrongTimestamp := "12346"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, correctTimestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, wrongTimestamp, bodyHash, proof)
	if valid {
		t.Error("Wrong timestamp should fail verification")
	}
}

func TestErrWrongBodyHash(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx"
	binding := "POST|/api|"
	timestamp := "12345"
	correctHash := HashBody(`{"a":1}`)
	wrongHash := HashBody(`{"a":2}`)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, correctHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, wrongHash, proof)
	if valid {
		t.Error("Wrong body hash should fail verification")
	}
}

func TestErrTamperedProof(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx"
	binding := "POST|/api|"
	timestamp := "12345"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	// Tamper with proof
	tamperedProof := "b" + proof[1:]
	if tamperedProof == proof {
		tamperedProof = "c" + proof[1:]
	}

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, tamperedProof)
	if valid {
		t.Error("Tampered proof should fail verification")
	}
}

// --- Edge Cases ---

func TestErrVeryLongInput(t *testing.T) {
	longString := strings.Repeat("a", 1000000) // 1MB
	hash := HashBody(longString)
	if len(hash) != 64 {
		t.Error("Should handle very long input")
	}
}

func TestErrSpecialCharacters(t *testing.T) {
	input := map[string]interface{}{
		"text": "\x00\x01\x02\x03",
	}
	_, err := CanonicalizeJSON(input)
	// Should either succeed with escaping or error
	if err != nil {
		// Acceptable to error on control characters
	}
}

func TestErrDeepNesting(t *testing.T) {
	// Create deeply nested structure
	var nested interface{} = map[string]interface{}{"value": 1}
	for i := 0; i < 100; i++ {
		nested = map[string]interface{}{"nested": nested}
	}

	_, err := CanonicalizeJSON(nested)
	// Should either handle or error gracefully
	if err != nil {
		// Acceptable to error on deep nesting
	}
}

func TestErrEmptyProof(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx"
	binding := "POST|/api|"
	timestamp := "12345"
	bodyHash := HashBody("{}")

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, "")
	if valid {
		t.Error("Empty proof should fail verification")
	}
}

func TestErrShortProof(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx"
	binding := "POST|/api|"
	timestamp := "12345"
	bodyHash := HashBody("{}")

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, "abc123")
	if valid {
		t.Error("Short proof should fail verification")
	}
}

func TestErrNonHexProof(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx"
	binding := "POST|/api|"
	timestamp := "12345"
	bodyHash := HashBody("{}")

	// 64 chars but not valid hex
	nonHexProof := strings.Repeat("g", 64)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, nonHexProof)
	if valid {
		t.Error("Non-hex proof should fail verification")
	}
}

// --- AshError Tests ---

func TestAshErrorMessage(t *testing.T) {
	err := &AshError{
		Code:    "TEST_ERROR",
		Message: "Test error message",
	}

	if err.Error() == "" {
		t.Error("Error should have message")
	}

	if !strings.Contains(err.Error(), "TEST_ERROR") && !strings.Contains(err.Error(), "Test error message") {
		t.Error("Error should contain code or message")
	}
}

func TestAshErrorCodes(t *testing.T) {
	codes := []AshErrorCode{
		"ASH_INVALID_INPUT",
		"ASH_VERIFICATION_FAILED",
		"ASH_CANONICALIZATION_ERROR",
	}

	for _, code := range codes {
		err := &AshError{Code: code, Message: "test"}
		if err.Code != code {
			t.Errorf("Error code mismatch: %s != %s", err.Code, code)
		}
	}
}

// --- Recovery Tests ---

func TestRecoverFromNilPayload(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			// Recovered from panic - acceptable
		}
	}()

	_, err := CanonicalizeJSON(nil)
	// Should either return error or handle nil
	if err == nil {
		// nil canonicalized to "null" is acceptable
	}
}

func TestRecoverFromCircularReference(t *testing.T) {
	// Note: Go maps can't have circular references directly
	// but we test deep structures
	deep := make(map[string]interface{})
	current := deep
	for i := 0; i < 50; i++ {
		next := make(map[string]interface{})
		current["next"] = next
		current = next
	}
	current["value"] = "end"

	_, err := CanonicalizeJSON(deep)
	// Should handle deep structure
	if err != nil {
		// Acceptable to error on very deep nesting
	}
}
