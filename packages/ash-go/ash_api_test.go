package ash

import (
	"strings"
	"testing"
)

// ============================================================================
// ASH STANDARDIZED API TESTS
// ============================================================================
// These tests verify that all Ash-prefixed functions work correctly and
// match their non-prefixed counterparts.
// ============================================================================

// --- Core Proof Function Tests ---

func TestAshBuildProofV21(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api|"
	bodyHash := HashBody("{}")

	// Both functions should produce identical results
	result1 := AshBuildProofV21(secret, timestamp, binding, bodyHash)
	result2 := BuildProofV21(secret, timestamp, binding, bodyHash)

	if result1 != result2 {
		t.Errorf("AshBuildProofV21 != BuildProofV21: %s != %s", result1, result2)
	}
	if len(result1) != 64 {
		t.Errorf("Proof should be 64 chars, got %d", len(result1))
	}
}

func TestAshVerifyProofV21(t *testing.T) {
	nonce := strings.Repeat("b", 32)
	contextID := "ctx-123"
	binding := "POST|/api|"
	timestamp := "1234567890"
	bodyHash := HashBody("{}")

	secret, err := AshDeriveClientSecret(nonce, contextID, binding)
	if err != nil {
		t.Fatal(err)
	}
	proof := AshBuildProofV21(secret, timestamp, binding, bodyHash)

	valid := AshVerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("AshVerifyProofV21 should verify valid proof")
	}
}

func TestAshDeriveClientSecret(t *testing.T) {
	nonce := strings.Repeat("a", 32)
	contextID := "ctx-123"
	binding := "POST|/api|"

	result1, err := AshDeriveClientSecret(nonce, contextID, binding)
	if err != nil {
		t.Fatal(err)
	}
	result2 := DeriveClientSecret(nonce, contextID, binding)

	if result1 != result2 {
		t.Errorf("AshDeriveClientSecret != DeriveClientSecret: %s != %s", result1, result2)
	}
	if len(result1) != 64 {
		t.Errorf("Secret should be 64 chars, got %d", len(result1))
	}
}

// --- Hash Function Tests ---

func TestAshHashBody(t *testing.T) {
	body := `{"key":"value"}`

	result1 := AshHashBody(body)
	result2 := HashBody(body)

	if result1 != result2 {
		t.Errorf("AshHashBody != HashBody: %s != %s", result1, result2)
	}
	if len(result1) != 64 {
		t.Errorf("Hash should be 64 chars, got %d", len(result1))
	}
}

func TestAshHashProof(t *testing.T) {
	proof := strings.Repeat("a", 64)

	result1 := AshHashProof(proof)
	result2 := HashProof(proof)

	if result1 != result2 {
		t.Errorf("AshHashProof != HashProof: %s != %s", result1, result2)
	}
}

func TestAshHashScopedBody(t *testing.T) {
	payload := map[string]interface{}{
		"amount": 100,
		"note":   "test",
	}
	scope := []string{"amount"}

	result1 := AshHashScopedBody(payload, scope)
	result2 := HashScopedBody(payload, scope)

	if result1 != result2 {
		t.Errorf("AshHashScopedBody != HashScopedBody: %s != %s", result1, result2)
	}
}

// --- Scoped Proof Function Tests ---

func TestAshBuildProofV21Scoped(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api|"
	payload := map[string]interface{}{"amount": 100}
	scope := []string{"amount"}

	result1 := AshBuildProofV21Scoped(secret, timestamp, binding, payload, scope)
	result2 := BuildProofV21Scoped(secret, timestamp, binding, payload, scope)

	if result1.Proof != result2.Proof {
		t.Errorf("Proofs don't match: %s != %s", result1.Proof, result2.Proof)
	}
	if result1.ScopeHash != result2.ScopeHash {
		t.Errorf("ScopeHashes don't match: %s != %s", result1.ScopeHash, result2.ScopeHash)
	}
}

func TestAshExtractScopedFields(t *testing.T) {
	payload := map[string]interface{}{
		"a": 1,
		"b": 2,
		"c": 3,
	}
	scope := []string{"a", "b"}

	result1 := AshExtractScopedFields(payload, scope)
	result2 := ExtractScopedFields(payload, scope)

	if len(result1) != len(result2) {
		t.Errorf("Results have different lengths: %d != %d", len(result1), len(result2))
	}
}

// --- Unified Proof Function Tests ---

func TestAshBuildProofUnified(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api|"
	payload := map[string]interface{}{"key": "value"}

	result1 := AshBuildProofUnified(secret, timestamp, binding, payload, nil, "")
	result2 := BuildProofUnified(secret, timestamp, binding, payload, nil, "")

	if result1.Proof != result2.Proof {
		t.Errorf("Proofs don't match: %s != %s", result1.Proof, result2.Proof)
	}
}

// --- Canonicalization Function Tests ---

func TestAshCanonicalizeJSON(t *testing.T) {
	value := map[string]interface{}{"b": 2, "a": 1}

	result1, err1 := AshCanonicalizeJSON(value)
	result2, err2 := CanonicalizeJSON(value)

	if err1 != nil || err2 != nil {
		t.Fatalf("Unexpected errors: %v, %v", err1, err2)
	}
	if result1 != result2 {
		t.Errorf("AshCanonicalizeJSON != CanonicalizeJSON: %s != %s", result1, result2)
	}
	if result1 != `{"a":1,"b":2}` {
		t.Errorf("Expected sorted keys, got %s", result1)
	}
}

func TestAshCanonicalizeQuery(t *testing.T) {
	query := "z=3&a=1&b=2"

	result1, err1 := AshCanonicalizeQuery(query)
	result2, err2 := CanonicalizeQuery(query)

	if err1 != nil || err2 != nil {
		t.Fatalf("Unexpected errors: %v, %v", err1, err2)
	}
	if result1 != result2 {
		t.Errorf("AshCanonicalizeQuery != CanonicalizeQuery: %s != %s", result1, result2)
	}
}

func TestAshCanonicalizeURLEncoded(t *testing.T) {
	input := "z=3&a=1&b=2"

	result1, err1 := AshCanonicalizeURLEncoded(input)
	result2, err2 := CanonicalizeURLEncoded(input)

	if err1 != nil || err2 != nil {
		t.Fatalf("Unexpected errors: %v, %v", err1, err2)
	}
	if result1 != result2 {
		t.Errorf("AshCanonicalizeURLEncoded != CanonicalizeURLEncoded: %s != %s", result1, result2)
	}
}

func TestAshCanonicalizeURLEncodedFromMap(t *testing.T) {
	data := map[string][]string{
		"z": {"3"},
		"a": {"1"},
	}

	result1 := AshCanonicalizeURLEncodedFromMap(data)
	result2 := CanonicalizeURLEncodedFromMap(data)

	if result1 != result2 {
		t.Errorf("AshCanonicalizeURLEncodedFromMap != CanonicalizeURLEncodedFromMap: %s != %s", result1, result2)
	}
}

// --- Binding Function Tests ---

func TestAshNormalizeBinding(t *testing.T) {
	result1 := AshNormalizeBinding("POST", "/api/users", "")
	result2 := NormalizeBinding("POST", "/api/users", "")

	if result1 != result2 {
		t.Errorf("AshNormalizeBinding != NormalizeBinding: %s != %s", result1, result2)
	}
}

func TestAshNormalizeBindingFromURL(t *testing.T) {
	result1 := AshNormalizeBindingFromURL("GET", "/api/users?page=1")
	result2 := NormalizeBindingFromURL("GET", "/api/users?page=1")

	if result1 != result2 {
		t.Errorf("AshNormalizeBindingFromURL != NormalizeBindingFromURL: %s != %s", result1, result2)
	}
}

// --- Comparison Function Tests ---

func TestAshTimingSafeCompare(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("a", 64)
	c := strings.Repeat("b", 64)

	if !AshTimingSafeCompare(a, b) {
		t.Error("Equal strings should return true")
	}
	if AshTimingSafeCompare(a, c) {
		t.Error("Different strings should return false")
	}
}

func TestAshTimingSafeCompareBytes(t *testing.T) {
	a := []byte(strings.Repeat("a", 64))
	b := []byte(strings.Repeat("a", 64))
	c := []byte(strings.Repeat("b", 64))

	if !AshTimingSafeCompareBytes(a, b) {
		t.Error("Equal bytes should return true")
	}
	if AshTimingSafeCompareBytes(a, c) {
		t.Error("Different bytes should return false")
	}
}

// --- Generation Function Tests ---

func TestAshGenerateNonce(t *testing.T) {
	nonce, err := AshGenerateNonce(32)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(nonce) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("Nonce should be 64 hex chars, got %d", len(nonce))
	}
}

func TestAshGenerateContextID(t *testing.T) {
	ctxID, err := AshGenerateContextID()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if ctxID == "" {
		t.Error("Context ID should not be empty")
	}
}

// --- Validation Function Tests ---

func TestAshIsValidMode(t *testing.T) {
	if !AshIsValidMode(ModeStrict) {
		t.Error("ModeStrict should be valid")
	}
	if !AshIsValidMode(ModeBalanced) {
		t.Error("ModeBalanced should be valid")
	}
	if !AshIsValidMode(ModeMinimal) {
		t.Error("ModeMinimal should be valid")
	}
	if AshIsValidMode("invalid") {
		t.Error("Invalid mode should return false")
	}
}

func TestAshIsValidHTTPMethod(t *testing.T) {
	// Only test methods that are supported by the SDK
	validMethods := []HttpMethod{"GET", "POST", "PUT", "PATCH", "DELETE"}
	for _, m := range validMethods {
		if !AshIsValidHTTPMethod(m) {
			t.Errorf("%s should be valid", m)
		}
	}

	// These methods are not supported
	unsupportedMethods := []HttpMethod{"HEAD", "OPTIONS", "TRACE"}
	for _, m := range unsupportedMethods {
		if AshIsValidHTTPMethod(m) {
			t.Errorf("%s should not be valid (unsupported)", m)
		}
	}
}

func TestAshValidateProofInput(t *testing.T) {
	input := BuildProofInput{
		Mode:             ModeBalanced,
		Binding:          "POST|/api|",
		ContextID:        "ctx-123",
		CanonicalPayload: "{}",
	}

	err := AshValidateProofInput(input)
	if err != nil {
		t.Errorf("Valid input should not return error: %v", err)
	}
}

func TestAshIsASCII(t *testing.T) {
	if !AshIsASCII("hello") {
		t.Error("ASCII string should return true")
	}
	if AshIsASCII("日本語") {
		t.Error("Non-ASCII string should return false")
	}
}

// --- Base64 Function Tests ---

func TestAshBase64URLEncode(t *testing.T) {
	data := []byte("hello")

	result1 := AshBase64URLEncode(data)
	result2 := Base64URLEncode(data)

	if result1 != result2 {
		t.Errorf("AshBase64URLEncode != Base64URLEncode: %s != %s", result1, result2)
	}
}

func TestAshBase64URLDecode(t *testing.T) {
	encoded := AshBase64URLEncode([]byte("hello"))

	result1, err1 := AshBase64URLDecode(encoded)
	result2, err2 := Base64URLDecode(encoded)

	if err1 != nil || err2 != nil {
		t.Fatalf("Unexpected errors: %v, %v", err1, err2)
	}
	if string(result1) != string(result2) {
		t.Errorf("Decoded results don't match")
	}
}

// --- Scope Function Tests ---

func TestAshNormalizeScopeFields(t *testing.T) {
	scope := []string{"c", "a", "b"}

	result1 := AshNormalizeScopeFields(scope)
	result2 := NormalizeScopeFields(scope)

	if len(result1) != len(result2) {
		t.Error("Results have different lengths")
	}
	for i := range result1 {
		if result1[i] != result2[i] {
			t.Errorf("Element %d differs: %s != %s", i, result1[i], result2[i])
		}
	}
}

func TestAshJoinScopeFields(t *testing.T) {
	scope := []string{"a", "b", "c"}

	result1 := AshJoinScopeFields(scope)
	result2 := JoinScopeFields(scope)

	if result1 != result2 {
		t.Errorf("AshJoinScopeFields != JoinScopeFields: %s != %s", result1, result2)
	}
}

// --- Error Constructor Tests ---

func TestAshNewError(t *testing.T) {
	err := AshNewError(ErrProofInvalid, "test message")

	if err.Code != ErrProofInvalid {
		t.Errorf("Code should be ErrProofInvalid, got %s", err.Code)
	}
	if err.Message != "test message" {
		t.Errorf("Message should be 'test message', got %s", err.Message)
	}
}

// --- Version Function Tests ---

func TestAshGetVersion(t *testing.T) {
	version := AshGetVersion()

	if version == "" {
		t.Error("Version should not be empty")
	}
}

// --- Parse Function Tests ---

func TestAshParseJSON(t *testing.T) {
	jsonStr := `{"b":2,"a":1}`

	result1, err1 := AshParseJSON(jsonStr)
	result2, err2 := ParseJSON(jsonStr)

	if err1 != nil || err2 != nil {
		t.Fatalf("Unexpected errors: %v, %v", err1, err2)
	}
	if result1 != result2 {
		t.Errorf("AshParseJSON != ParseJSON: %s != %s", result1, result2)
	}
}

// --- Integration Tests ---

func TestAshAPIIntegration(t *testing.T) {
	// Full workflow using only Ash-prefixed functions
	nonce, _ := AshGenerateNonce(32)
	contextID, _ := AshGenerateContextID()
	binding := AshNormalizeBinding("POST", "/api/transfer", "")

	payload := map[string]interface{}{
		"amount": 100,
		"to":     "alice",
	}
	canonical, _ := AshCanonicalizeJSON(payload)
	bodyHash := AshHashBody(canonical)

	secret, err := AshDeriveClientSecret(nonce, contextID, binding)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := "1234567890"
	proof := AshBuildProofV21(secret, timestamp, binding, bodyHash)

	valid := AshVerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("Ash API integration test failed: proof should verify")
	}
}

func TestAshAPIScopedIntegration(t *testing.T) {
	// Scoped workflow using Ash-prefixed functions
	nonce, _ := AshGenerateNonce(32)
	contextID, _ := AshGenerateContextID()
	binding := AshNormalizeBinding("POST", "/api/transfer", "")

	payload := map[string]interface{}{
		"amount":  100,
		"to":      "alice",
		"comment": "payment",
	}
	scope := []string{"amount", "to"}

	secret, err := AshDeriveClientSecret(nonce, contextID, binding)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := "1234567890"

	result := AshBuildProofUnified(secret, timestamp, binding, payload, scope, "")

	if len(result.Proof) != 64 {
		t.Error("Proof should be 64 chars")
	}
	if result.ScopeHash == "" {
		t.Error("Scoped proof should have scope hash")
	}
}
