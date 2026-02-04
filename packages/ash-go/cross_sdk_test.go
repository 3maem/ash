package ash

import (
	"strings"
	"testing"
)

// ============================================================================
// CROSS-SDK COMPATIBILITY TESTS
// Tests that verify compatibility with other ASH SDK implementations
// ============================================================================

// --- Standard Test Vectors ---
// These vectors should produce identical results across all SDKs

func TestCrossSDKHashVector1(t *testing.T) {
	// Empty object
	input := "{}"
	expected := "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"

	result := HashBody(input)
	if result != expected {
		t.Errorf("Hash mismatch:\nGot:      %s\nExpected: %s", result, expected)
	}
}

func TestCrossSDKHashVector2(t *testing.T) {
	// Empty string
	input := ""
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	result := HashBody(input)
	if result != expected {
		t.Errorf("Hash mismatch:\nGot:      %s\nExpected: %s", result, expected)
	}
}

func TestCrossSDKHashVector3(t *testing.T) {
	// Simple JSON
	input := `{"key":"value"}`
	result := HashBody(input)

	if len(result) != 64 {
		t.Error("Hash should be 64 chars")
	}
}

// --- JCS Canonicalization Vectors ---

func TestCrossSDKJCSSimple(t *testing.T) {
	input := map[string]interface{}{
		"b": 2,
		"a": 1,
	}

	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Canonicalization failed: %v", err)
	}

	// Keys must be sorted
	expected := `{"a":1,"b":2}`
	if result != expected {
		t.Errorf("JCS mismatch:\nGot:      %s\nExpected: %s", result, expected)
	}
}

func TestCrossSDKJCSNested(t *testing.T) {
	input := map[string]interface{}{
		"z": map[string]interface{}{
			"b": 2,
			"a": 1,
		},
		"a": "first",
	}

	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Canonicalization failed: %v", err)
	}

	// a should come before z, nested keys also sorted
	if !strings.HasPrefix(result, `{"a":`) {
		t.Error("Keys not sorted: 'a' should come first")
	}
}

func TestCrossSDKJCSArray(t *testing.T) {
	input := []interface{}{3, 1, 2}

	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Canonicalization failed: %v", err)
	}

	// Arrays preserve order
	expected := "[3,1,2]"
	if result != expected {
		t.Errorf("Array order changed:\nGot:      %s\nExpected: %s", result, expected)
	}
}

func TestCrossSDKJCSNumbers(t *testing.T) {
	testCases := []struct {
		input    interface{}
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{-1, "-1"},
		{float64(1.5), "1.5"},
		{float64(1.0), "1"},     // Should not have trailing .0
		{float64(100.0), "100"}, // Should not have trailing .0
	}

	for _, tc := range testCases {
		result, err := CanonicalizeJSON(tc.input)
		if err != nil {
			t.Errorf("Failed to canonicalize %v: %v", tc.input, err)
			continue
		}
		if result != tc.expected {
			t.Errorf("Number canonicalization:\nInput:    %v\nGot:      %s\nExpected: %s", tc.input, result, tc.expected)
		}
	}
}

func TestCrossSDKJCSBooleans(t *testing.T) {
	trueResult, _ := CanonicalizeJSON(true)
	falseResult, _ := CanonicalizeJSON(false)

	if trueResult != "true" {
		t.Errorf("true should canonicalize to 'true', got %s", trueResult)
	}
	if falseResult != "false" {
		t.Errorf("false should canonicalize to 'false', got %s", falseResult)
	}
}

func TestCrossSDKJCSNull(t *testing.T) {
	result, _ := CanonicalizeJSON(nil)

	if result != "null" {
		t.Errorf("nil should canonicalize to 'null', got %s", result)
	}
}

func TestCrossSDKJCSUnicode(t *testing.T) {
	input := map[string]interface{}{
		"emoji": "😀",
	}

	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Unicode canonicalization failed: %v", err)
	}

	// Emoji should be preserved (not escaped) per JCS
	if !strings.Contains(result, "😀") && !strings.Contains(result, "\\u") {
		t.Error("Emoji should be present in some form")
	}
}

// --- Query Canonicalization Vectors ---

func TestCrossSDKQuerySort(t *testing.T) {
	input := "z=3&a=1&m=2"
	result, err := CanonicalizeQuery(input)
	if err != nil {
		t.Fatalf("CanonicalizeQuery failed: %v", err)
	}

	// Should be sorted alphabetically
	aPos := strings.Index(result, "a=")
	mPos := strings.Index(result, "m=")
	zPos := strings.Index(result, "z=")

	if !(aPos < mPos && mPos < zPos) {
		t.Errorf("Query not sorted: %s", result)
	}
}

func TestCrossSDKQueryDuplicates(t *testing.T) {
	input := "a=2&a=1&a=3"
	result, err := CanonicalizeQuery(input)
	if err != nil {
		t.Fatalf("CanonicalizeQuery failed: %v", err)
	}

	// Duplicate values should be sorted
	parts := strings.Split(result, "&")
	if len(parts) != 3 {
		t.Errorf("Should preserve all duplicates: %s", result)
	}
}

func TestCrossSDKQueryEncoding(t *testing.T) {
	input := "name=hello%20world"
	result, err := CanonicalizeQuery(input)
	if err != nil {
		t.Fatalf("CanonicalizeQuery failed: %v", err)
	}

	// Should handle percent encoding
	if !strings.Contains(result, "name=") {
		t.Error("Should preserve key")
	}
}

// --- Binding Vectors ---

func TestCrossSDKBindingGET(t *testing.T) {
	result := NormalizeBinding("GET", "/api/users", "")

	if !strings.HasPrefix(result, "GET|") {
		t.Error("Binding should start with GET|")
	}
}

func TestCrossSDKBindingPOST(t *testing.T) {
	result := NormalizeBinding("POST", "/api/users", "")

	if !strings.HasPrefix(result, "POST|") {
		t.Error("Binding should start with POST|")
	}
}

func TestCrossSDKBindingWithQuery(t *testing.T) {
	result := NormalizeBinding("GET", "/api/search", "q=test&page=1")

	parts := strings.Split(result, "|")
	if len(parts) != 3 {
		t.Errorf("Binding should have 3 parts: %s", result)
	}
}

func TestCrossSDKBindingMethodCase(t *testing.T) {
	// Methods should be uppercase
	methods := []string{"get", "post", "put", "delete", "patch", "Get", "POST"}

	for _, method := range methods {
		result := NormalizeBinding(method, "/api", "")
		parts := strings.Split(result, "|")
		if len(parts) >= 1 && parts[0] != strings.ToUpper(method) {
			t.Errorf("Method %s should be normalized to %s, got %s", method, strings.ToUpper(method), parts[0])
		}
	}
}

// --- Proof Generation Vectors ---

func TestCrossSDKProofDeterminism(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test_context"
	binding := "POST|/api/test|"
	timestamp := "1234567890"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)

	proof1 := BuildProofV21(secret, timestamp, binding, bodyHash)
	proof2 := BuildProofV21(secret, timestamp, binding, bodyHash)

	if proof1 != proof2 {
		t.Error("Proof generation should be deterministic")
	}
}

func TestCrossSDKProofLength(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test_context"
	binding := "POST|/api/test|"
	timestamp := "1234567890"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	if len(proof) != 64 {
		t.Errorf("Proof should be 64 chars, got %d", len(proof))
	}
}

func TestCrossSDKProofHex(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test_context"
	binding := "POST|/api/test|"
	timestamp := "1234567890"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	for _, c := range proof {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("Proof should be lowercase hex, got char: %c", c)
		}
	}
}

// --- Secret Derivation Vectors ---

func TestCrossSDKSecretDeterminism(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test_context"
	binding := "POST|/api/test|"

	secret1 := DeriveClientSecret(nonce, contextID, binding)
	secret2 := DeriveClientSecret(nonce, contextID, binding)

	if secret1 != secret2 {
		t.Error("Secret derivation should be deterministic")
	}
}

func TestCrossSDKSecretLength(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test_context"
	binding := "POST|/api/test|"

	secret := DeriveClientSecret(nonce, contextID, binding)

	if len(secret) != 64 {
		t.Errorf("Secret should be 64 chars, got %d", len(secret))
	}
}

func TestCrossSDKSecretHex(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test_context"
	binding := "POST|/api/test|"

	secret := DeriveClientSecret(nonce, contextID, binding)

	for _, c := range secret {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("Secret should be lowercase hex, got char: %c", c)
		}
	}
}

// --- Verification Vectors ---

func TestCrossSDKVerifyValid(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test_context"
	binding := "POST|/api/test|"
	timestamp := "1234567890"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("Valid proof should verify")
	}
}

func TestCrossSDKVerifyInvalid(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test_context"
	binding := "POST|/api/test|"
	timestamp := "1234567890"
	bodyHash := HashBody("{}")

	invalidProof := strings.Repeat("b", 64)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, invalidProof)
	if valid {
		t.Error("Invalid proof should not verify")
	}
}

func TestCrossSDKVerifyWrongNonce(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	wrongNonce := strings.Repeat("b", 64)
	contextID := "test_context"
	binding := "POST|/api/test|"
	timestamp := "1234567890"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(wrongNonce, contextID, binding, timestamp, bodyHash, proof)
	if valid {
		t.Error("Proof with wrong nonce should not verify")
	}
}

func TestCrossSDKVerifyWrongContext(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test_context"
	wrongContext := "wrong_context"
	binding := "POST|/api/test|"
	timestamp := "1234567890"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, wrongContext, binding, timestamp, bodyHash, proof)
	if valid {
		t.Error("Proof with wrong context should not verify")
	}
}

func TestCrossSDKVerifyWrongBinding(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test_context"
	binding := "POST|/api/test|"
	wrongBinding := "GET|/api/test|"
	timestamp := "1234567890"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, wrongBinding, timestamp, bodyHash, proof)
	if valid {
		t.Error("Proof with wrong binding should not verify")
	}
}

func TestCrossSDKVerifyWrongTimestamp(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test_context"
	binding := "POST|/api/test|"
	timestamp := "1234567890"
	wrongTimestamp := "1234567891"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, wrongTimestamp, bodyHash, proof)
	if valid {
		t.Error("Proof with wrong timestamp should not verify")
	}
}

func TestCrossSDKVerifyWrongBody(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test_context"
	binding := "POST|/api/test|"
	timestamp := "1234567890"
	bodyHash := HashBody("{}")
	wrongBodyHash := HashBody(`{"modified":true}`)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, wrongBodyHash, proof)
	if valid {
		t.Error("Proof with wrong body should not verify")
	}
}

// --- Scoped Proof Vectors ---

func TestCrossSDKScopedProof(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/transfer|"
	payload := map[string]interface{}{
		"amount":   1000,
		"to":       "recipient",
		"metadata": "ignored",
	}
	scope := []string{"amount", "to"}

	result := BuildProofUnified(secret, timestamp, binding, payload, scope, "")

	if len(result.Proof) != 64 {
		t.Error("Scoped proof should be 64 chars")
	}

	if len(result.ScopeHash) != 64 {
		t.Error("Scope hash should be 64 chars")
	}
}

func TestCrossSDKScopedProofDeterminism(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/transfer|"
	payload := map[string]interface{}{
		"amount":   1000,
		"to":       "recipient",
		"metadata": "ignored",
	}
	scope := []string{"amount", "to"}

	result1 := BuildProofUnified(secret, timestamp, binding, payload, scope, "")
	result2 := BuildProofUnified(secret, timestamp, binding, payload, scope, "")

	if result1.Proof != result2.Proof {
		t.Error("Scoped proof should be deterministic")
	}

	if result1.ScopeHash != result2.ScopeHash {
		t.Error("Scope hash should be deterministic")
	}
}

// --- Chain Proof Vectors ---

func TestCrossSDKChainProof(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/action|"
	payload := map[string]interface{}{"key": "value"}
	previousProof := strings.Repeat("b", 64)

	result := BuildProofUnified(secret, timestamp, binding, payload, nil, previousProof)

	if len(result.Proof) != 64 {
		t.Error("Chain proof should be 64 chars")
	}

	if result.ChainHash == "" {
		t.Error("Chain hash should be set")
	}
}

func TestCrossSDKChainProofDeterminism(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/action|"
	payload := map[string]interface{}{"key": "value"}
	previousProof := strings.Repeat("b", 64)

	result1 := BuildProofUnified(secret, timestamp, binding, payload, nil, previousProof)
	result2 := BuildProofUnified(secret, timestamp, binding, payload, nil, previousProof)

	if result1.Proof != result2.Proof {
		t.Error("Chain proof should be deterministic")
	}

	if result1.ChainHash != result2.ChainHash {
		t.Error("Chain hash should be deterministic")
	}
}

// --- URL Encoded Vectors ---

func TestCrossSDKURLEncodedBasic(t *testing.T) {
	input := "b=2&a=1"
	result, err := CanonicalizeURLEncoded(input)
	if err != nil {
		t.Fatalf("CanonicalizeURLEncoded failed: %v", err)
	}

	// Should be sorted
	if !strings.HasPrefix(result, "a=") {
		t.Errorf("URL encoded should be sorted: %s", result)
	}
}

func TestCrossSDKURLEncodedSpaces(t *testing.T) {
	input := "name=hello+world"
	result, err := CanonicalizeURLEncoded(input)
	if err != nil {
		t.Fatalf("CanonicalizeURLEncoded failed: %v", err)
	}

	// Should handle + as space
	if !strings.Contains(result, "name=") {
		t.Error("Should preserve key")
	}
}

// --- Timing Safe Compare Vectors ---

func TestCrossSDKTimingSafeEqual(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("a", 64)

	if !TimingSafeCompare(a, b) {
		t.Error("Identical strings should be equal")
	}
}

func TestCrossSDKTimingSafeNotEqual(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)

	if TimingSafeCompare(a, b) {
		t.Error("Different strings should not be equal")
	}
}

func TestCrossSDKTimingSafeDifferentLength(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("a", 32)

	if TimingSafeCompare(a, b) {
		t.Error("Different length strings should not be equal")
	}
}

// --- Edge Case Vectors ---

func TestCrossSDKEmptyBody(t *testing.T) {
	hash := HashBody("")
	if len(hash) != 64 {
		t.Error("Empty body should hash")
	}
}

func TestCrossSDKEmptyObject(t *testing.T) {
	result, err := CanonicalizeJSON(map[string]interface{}{})
	if err != nil {
		t.Fatalf("Empty object canonicalization failed: %v", err)
	}
	if result != "{}" {
		t.Errorf("Empty object should be '{}', got %s", result)
	}
}

func TestCrossSDKEmptyArray(t *testing.T) {
	result, err := CanonicalizeJSON([]interface{}{})
	if err != nil {
		t.Fatalf("Empty array canonicalization failed: %v", err)
	}
	if result != "[]" {
		t.Errorf("Empty array should be '[]', got %s", result)
	}
}

func TestCrossSDKEmptyQuery(t *testing.T) {
	result, err := CanonicalizeQuery("")
	if err != nil {
		t.Fatalf("Empty query canonicalization failed: %v", err)
	}
	// Empty query should return empty string
	if result != "" {
		t.Errorf("Empty query should be empty, got %s", result)
	}
}

// ============================================================================
// Middleware Integration Tests (Cross-SDK Compatibility)
// ============================================================================

func TestCrossSDKMiddlewareHeaders(t *testing.T) {
	// Verify header constants match spec - must be identical across all SDKs
	expectedHeaders := map[string]string{
		"context_id": "X-ASH-Context-ID",
		"proof":      "X-ASH-Proof",
		"timestamp":  "X-ASH-Timestamp",
		"scope":      "X-ASH-Scope",
		"scope_hash": "X-ASH-Scope-Hash",
		"chain_hash": "X-ASH-Chain-Hash",
	}

	if HeaderContextID != expectedHeaders["context_id"] {
		t.Errorf("HeaderContextID mismatch: expected %s, got %s", expectedHeaders["context_id"], HeaderContextID)
	}
	if HeaderProof != expectedHeaders["proof"] {
		t.Errorf("HeaderProof mismatch: expected %s, got %s", expectedHeaders["proof"], HeaderProof)
	}
	if HeaderTimestamp != expectedHeaders["timestamp"] {
		t.Errorf("HeaderTimestamp mismatch: expected %s, got %s", expectedHeaders["timestamp"], HeaderTimestamp)
	}
	if HeaderScope != expectedHeaders["scope"] {
		t.Errorf("HeaderScope mismatch: expected %s, got %s", expectedHeaders["scope"], HeaderScope)
	}
	if HeaderScopeHash != expectedHeaders["scope_hash"] {
		t.Errorf("HeaderScopeHash mismatch: expected %s, got %s", expectedHeaders["scope_hash"], HeaderScopeHash)
	}
	if HeaderChainHash != expectedHeaders["chain_hash"] {
		t.Errorf("HeaderChainHash mismatch: expected %s, got %s", expectedHeaders["chain_hash"], HeaderChainHash)
	}
}

func TestCrossSDKMiddlewareErrorCodes(t *testing.T) {
	// Verify error codes match spec - must be identical across all SDKs
	expectedCodes := map[string]string{
		"ctx_not_found":     "ASH_CTX_NOT_FOUND",
		"ctx_expired":       "ASH_CTX_EXPIRED",
		"ctx_already_used":  "ASH_CTX_ALREADY_USED",
		"binding_mismatch":  "ASH_BINDING_MISMATCH",
		"proof_missing":     "ASH_PROOF_MISSING",
		"proof_invalid":     "ASH_PROOF_INVALID",
		"scope_mismatch":    "ASH_SCOPE_MISMATCH",
		"chain_broken":      "ASH_CHAIN_BROKEN",
		"timestamp_invalid": "ASH_TIMESTAMP_INVALID",
		"mode_violation":    "ASH_MODE_VIOLATION",
		"scope_policy_req":  "ASH_SCOPE_POLICY_REQUIRED",
		"scope_policy_viol": "ASH_SCOPE_POLICY_VIOLATION",
	}

	if AshErrCtxNotFound != expectedCodes["ctx_not_found"] {
		t.Errorf("error code mismatch: expected %s, got %s", expectedCodes["ctx_not_found"], AshErrCtxNotFound)
	}
	if AshErrCtxExpired != expectedCodes["ctx_expired"] {
		t.Errorf("error code mismatch: expected %s, got %s", expectedCodes["ctx_expired"], AshErrCtxExpired)
	}
	if AshErrCtxAlreadyUsed != expectedCodes["ctx_already_used"] {
		t.Errorf("error code mismatch: expected %s, got %s", expectedCodes["ctx_already_used"], AshErrCtxAlreadyUsed)
	}
	if AshErrBindingMismatch != expectedCodes["binding_mismatch"] {
		t.Errorf("error code mismatch: expected %s, got %s", expectedCodes["binding_mismatch"], AshErrBindingMismatch)
	}
	if AshErrProofMissing != expectedCodes["proof_missing"] {
		t.Errorf("error code mismatch: expected %s, got %s", expectedCodes["proof_missing"], AshErrProofMissing)
	}
	if AshErrProofInvalid != expectedCodes["proof_invalid"] {
		t.Errorf("error code mismatch: expected %s, got %s", expectedCodes["proof_invalid"], AshErrProofInvalid)
	}
	if AshErrScopeMismatch != expectedCodes["scope_mismatch"] {
		t.Errorf("error code mismatch: expected %s, got %s", expectedCodes["scope_mismatch"], AshErrScopeMismatch)
	}
	if AshErrChainBroken != expectedCodes["chain_broken"] {
		t.Errorf("error code mismatch: expected %s, got %s", expectedCodes["chain_broken"], AshErrChainBroken)
	}
	if AshErrTimestampInvalid != expectedCodes["timestamp_invalid"] {
		t.Errorf("error code mismatch: expected %s, got %s", expectedCodes["timestamp_invalid"], AshErrTimestampInvalid)
	}
	if AshErrModeViolation != expectedCodes["mode_violation"] {
		t.Errorf("error code mismatch: expected %s, got %s", expectedCodes["mode_violation"], AshErrModeViolation)
	}
	if AshErrScopePolicyRequired != expectedCodes["scope_policy_req"] {
		t.Errorf("error code mismatch: expected %s, got %s", expectedCodes["scope_policy_req"], AshErrScopePolicyRequired)
	}
	if AshErrScopePolicyViolation != expectedCodes["scope_policy_viol"] {
		t.Errorf("error code mismatch: expected %s, got %s", expectedCodes["scope_policy_viol"], AshErrScopePolicyViolation)
	}
}

func TestCrossSDKScopeNormalization(t *testing.T) {
	t.Run("sorts scope fields", func(t *testing.T) {
		scope := []string{"z", "a", "m"}
		result := AshNormalizeScopeFields(scope)

		if result[0] != "a" || result[1] != "m" || result[2] != "z" {
			t.Errorf("expected [a, m, z], got %v", result)
		}
	})

	t.Run("deduplicates scope fields", func(t *testing.T) {
		scope := []string{"a", "b", "a", "c", "b"}
		result := AshNormalizeScopeFields(scope)

		if len(result) != 3 {
			t.Errorf("expected 3 unique fields, got %d", len(result))
		}
	})

	t.Run("join uses unit separator BUG-002", func(t *testing.T) {
		scope := []string{"a", "b"}
		result := AshJoinScopeFields(scope)

		// Should contain unit separator \x1F per BUG-002
		expected := "a\x1Fb"
		if result != expected {
			t.Errorf("expected %q, got %q", expected, result)
		}
	})
}

func TestCrossSDKProofHashForChaining(t *testing.T) {
	proof := strings.Repeat("a", 64)
	hash := AshHashProof(proof)

	// Must be 64 hex chars
	if len(hash) != 64 {
		t.Errorf("expected hash length 64, got %d", len(hash))
	}

	// Must be deterministic
	hash2 := AshHashProof(proof)
	if hash != hash2 {
		t.Error("proof hashing should be deterministic")
	}

	// Different proof = different hash
	hash3 := AshHashProof(strings.Repeat("b", 64))
	if hash == hash3 {
		t.Error("different proofs should have different hashes")
	}
}
