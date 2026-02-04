package ash

import (
	"fmt"
	"strings"
	"testing"
)

// ============================================================================
// COMPREHENSIVE SCOPED AND CHAIN PROOF TESTS
// ============================================================================

// --- Basic Scoped Proof Tests ---

func TestScopedProofBasic(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/test|"
	payload := map[string]interface{}{
		"field1": "value1",
		"field2": "value2",
		"field3": "value3",
	}
	scope := []string{"field1", "field2"}

	result := BuildProofUnified(secret, timestamp, binding, payload, scope, "")

	if len(result.Proof) != 64 {
		t.Errorf("Proof should be 64 chars, got %d", len(result.Proof))
	}
	if result.ScopeHash == "" {
		t.Error("Scoped proof should have scope hash")
	}
}

func TestScopedProofDeterminism(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/test|"
	payload := map[string]interface{}{
		"a": 1,
		"b": 2,
		"c": 3,
	}
	scope := []string{"a", "b"}

	result1 := BuildProofUnified(secret, timestamp, binding, payload, scope, "")

	for i := 0; i < 100; i++ {
		result2 := BuildProofUnified(secret, timestamp, binding, payload, scope, "")
		if result1.Proof != result2.Proof {
			t.Errorf("Scoped proof should be deterministic")
		}
		if result1.ScopeHash != result2.ScopeHash {
			t.Errorf("Scope hash should be deterministic")
		}
	}
}

func TestScopedProofEmptyScope(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/test|"
	payload := map[string]interface{}{"a": 1}

	result := BuildProofUnified(secret, timestamp, binding, payload, []string{}, "")

	if len(result.Proof) != 64 {
		t.Error("Empty scope should still produce valid proof")
	}
}

func TestScopedProofNilScope(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/test|"
	payload := map[string]interface{}{"a": 1}

	result := BuildProofUnified(secret, timestamp, binding, payload, nil, "")

	if len(result.Proof) != 64 {
		t.Error("Nil scope should produce valid proof")
	}
}

// --- Scope Field Selection Tests ---

func TestScopedProofSingleField(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/test|"
	payload := map[string]interface{}{
		"keep":   "value",
		"ignore": "other",
	}

	result := BuildProofUnified(secret, timestamp, binding, payload, []string{"keep"}, "")

	if len(result.Proof) != 64 {
		t.Error("Single field scope should work")
	}
}

func TestScopedProofMultipleFields(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/test|"
	payload := map[string]interface{}{
		"a": 1,
		"b": 2,
		"c": 3,
		"d": 4,
	}

	result := BuildProofUnified(secret, timestamp, binding, payload, []string{"a", "c"}, "")

	if len(result.Proof) != 64 {
		t.Error("Multiple field scope should work")
	}
}

func TestScopedProofAllFields(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/test|"
	payload := map[string]interface{}{
		"a": 1,
		"b": 2,
	}

	result := BuildProofUnified(secret, timestamp, binding, payload, []string{"a", "b"}, "")

	if len(result.Proof) != 64 {
		t.Error("All fields scope should work")
	}
}

func TestScopedProofMissingField(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/test|"
	payload := map[string]interface{}{
		"a": 1,
	}

	// Request field that doesn't exist
	result := BuildProofUnified(secret, timestamp, binding, payload, []string{"nonexistent"}, "")

	// Should still produce a proof (empty scope extract)
	if len(result.Proof) != 64 {
		t.Error("Missing field scope should still produce proof")
	}
}

// --- Scope Change Detection Tests ---

func TestScopedProofDetectsFieldChange(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/test|"
	scope := []string{"amount"}

	payload1 := map[string]interface{}{"amount": 100, "note": "original"}
	payload2 := map[string]interface{}{"amount": 200, "note": "original"}

	result1 := BuildProofUnified(secret, timestamp, binding, payload1, scope, "")
	result2 := BuildProofUnified(secret, timestamp, binding, payload2, scope, "")

	if result1.Proof == result2.Proof {
		t.Error("Different scoped field values should produce different proofs")
	}
}

func TestScopedProofIgnoresNonScopedChange(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/test|"
	scope := []string{"amount"}

	payload1 := map[string]interface{}{"amount": 100, "note": "original"}
	payload2 := map[string]interface{}{"amount": 100, "note": "modified"}

	result1 := BuildProofUnified(secret, timestamp, binding, payload1, scope, "")
	result2 := BuildProofUnified(secret, timestamp, binding, payload2, scope, "")

	if result1.ScopeHash != result2.ScopeHash {
		t.Error("Non-scoped field changes should not affect scope hash")
	}
}

// --- Scope Order Independence Tests ---

func TestScopedProofOrderIndependence(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/test|"
	payload := map[string]interface{}{
		"a": 1,
		"b": 2,
		"c": 3,
	}

	result1 := BuildProofUnified(secret, timestamp, binding, payload, []string{"a", "b", "c"}, "")
	result2 := BuildProofUnified(secret, timestamp, binding, payload, []string{"c", "b", "a"}, "")
	result3 := BuildProofUnified(secret, timestamp, binding, payload, []string{"b", "a", "c"}, "")

	if result1.ScopeHash != result2.ScopeHash || result2.ScopeHash != result3.ScopeHash {
		t.Error("Scope order should not affect scope hash")
	}
}

// --- Chain Proof Tests ---

func TestChainProofBasic(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/test|"
	payload := map[string]interface{}{"a": 1}
	previousProof := strings.Repeat("b", 64)

	result := BuildProofUnified(secret, timestamp, binding, payload, nil, previousProof)

	if len(result.Proof) != 64 {
		t.Errorf("Chain proof should be 64 chars, got %d", len(result.Proof))
	}
	if result.ChainHash == "" {
		t.Error("Chain proof should have chain hash")
	}
}

func TestChainProofDeterminism(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/test|"
	payload := map[string]interface{}{"a": 1}
	previousProof := strings.Repeat("b", 64)

	result1 := BuildProofUnified(secret, timestamp, binding, payload, nil, previousProof)

	for i := 0; i < 100; i++ {
		result2 := BuildProofUnified(secret, timestamp, binding, payload, nil, previousProof)
		if result1.Proof != result2.Proof {
			t.Error("Chain proof should be deterministic")
		}
		if result1.ChainHash != result2.ChainHash {
			t.Error("Chain hash should be deterministic")
		}
	}
}

func TestChainProofNoPrevious(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/test|"
	payload := map[string]interface{}{"a": 1}

	result := BuildProofUnified(secret, timestamp, binding, payload, nil, "")

	if len(result.Proof) != 64 {
		t.Error("No previous proof should still produce valid proof")
	}
}

func TestChainProofDifferentPrevious(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/test|"
	payload := map[string]interface{}{"a": 1}

	result1 := BuildProofUnified(secret, timestamp, binding, payload, nil, strings.Repeat("1", 64))
	result2 := BuildProofUnified(secret, timestamp, binding, payload, nil, strings.Repeat("2", 64))

	if result1.Proof == result2.Proof {
		t.Error("Different previous proofs should produce different proofs")
	}
}

// --- Chain Sequence Tests ---

func TestChainProofSequence(t *testing.T) {
	secret := strings.Repeat("a", 64)
	binding := "POST|/api/test|"

	// Build a chain of proofs
	var previousProof string
	proofs := make([]string, 10)

	for i := 0; i < 10; i++ {
		timestamp := fmt.Sprintf("%d", 1000000+i)
		payload := map[string]interface{}{"step": i}
		result := BuildProofUnified(secret, timestamp, binding, payload, nil, previousProof)
		proofs[i] = result.Proof
		previousProof = result.Proof
	}

	// All proofs should be unique
	seen := make(map[string]bool)
	for i, proof := range proofs {
		if seen[proof] {
			t.Errorf("Proof %d should be unique", i)
		}
		seen[proof] = true
	}
}

func TestChainProofBreakDetection(t *testing.T) {
	secret := strings.Repeat("a", 64)
	binding := "POST|/api/test|"

	// Build chain
	result1 := BuildProofUnified(secret, "1000000", binding, map[string]interface{}{"step": 0}, nil, "")
	result2 := BuildProofUnified(secret, "1000001", binding, map[string]interface{}{"step": 1}, nil, result1.Proof)

	// Try to build with wrong previous
	wrongPrevious := strings.Repeat("x", 64)
	result3 := BuildProofUnified(secret, "1000001", binding, map[string]interface{}{"step": 1}, nil, wrongPrevious)

	if result2.Proof == result3.Proof {
		t.Error("Wrong previous proof should produce different result")
	}
}

// --- Combined Scope and Chain Tests ---

func TestScopedChainProof(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/test|"
	payload := map[string]interface{}{
		"amount":  100,
		"comment": "test",
	}
	scope := []string{"amount"}
	previousProof := strings.Repeat("b", 64)

	result := BuildProofUnified(secret, timestamp, binding, payload, scope, previousProof)

	if len(result.Proof) != 64 {
		t.Error("Combined scope+chain proof should be valid")
	}
	if result.ScopeHash == "" {
		t.Error("Should have scope hash")
	}
	if result.ChainHash == "" {
		t.Error("Should have chain hash")
	}
}

func TestScopedChainProofSequence(t *testing.T) {
	secret := strings.Repeat("a", 64)
	binding := "POST|/api/transfer|"
	scope := []string{"amount", "to"}

	var previousProof string
	for i := 0; i < 5; i++ {
		timestamp := fmt.Sprintf("%d", 1000000+i)
		payload := map[string]interface{}{
			"amount":  (i + 1) * 100,
			"to":      fmt.Sprintf("user_%d", i),
			"comment": "transfer",
		}

		result := BuildProofUnified(secret, timestamp, binding, payload, scope, previousProof)

		if len(result.Proof) != 64 {
			t.Errorf("Step %d: Invalid proof length", i)
		}
		if result.ScopeHash == "" {
			t.Errorf("Step %d: Missing scope hash", i)
		}

		previousProof = result.Proof
	}
}

// --- Extract Scoped Fields Tests ---

func TestExtractScopedFieldsBasic(t *testing.T) {
	payload := map[string]interface{}{
		"a": 1,
		"b": 2,
		"c": 3,
	}

	result := ExtractScopedFields(payload, []string{"a", "b"})

	if len(result) != 2 {
		t.Errorf("Should extract 2 fields, got %d", len(result))
	}
	if result["a"] != 1 || result["b"] != 2 {
		t.Error("Extracted fields should have correct values")
	}
	if _, exists := result["c"]; exists {
		t.Error("Should not include non-scoped field")
	}
}

func TestExtractScopedFieldsEmpty(t *testing.T) {
	payload := map[string]interface{}{
		"a": 1,
	}

	result := ExtractScopedFields(payload, []string{})

	// Empty scope returns entire payload (no filtering)
	if len(result) != len(payload) {
		t.Error("Empty scope should return full payload")
	}
}

func TestExtractScopedFieldsNil(t *testing.T) {
	payload := map[string]interface{}{
		"a": 1,
	}

	result := ExtractScopedFields(payload, nil)

	// Nil scope returns entire payload
	if result == nil {
		t.Error("Nil scope should not return nil")
	}
}

func TestExtractScopedFieldsMissing(t *testing.T) {
	payload := map[string]interface{}{
		"a": 1,
	}

	result := ExtractScopedFields(payload, []string{"nonexistent"})

	if len(result) != 0 {
		t.Error("Missing field should result in empty map")
	}
}

func TestExtractScopedFieldsNested(t *testing.T) {
	payload := map[string]interface{}{
		"user": map[string]interface{}{
			"name": "John",
			"age":  30,
		},
		"other": "value",
	}

	result := ExtractScopedFields(payload, []string{"user"})

	if len(result) != 1 {
		t.Error("Should extract nested field")
	}
	if result["user"] == nil {
		t.Error("Should include nested object")
	}
}

// --- Hash Proof Tests ---

func TestHashProofBasic(t *testing.T) {
	proof := strings.Repeat("a", 64)
	hash := HashProof(proof)

	if len(hash) != 64 {
		t.Errorf("Hash should be 64 chars, got %d", len(hash))
	}
}

func TestHashProofDeterminism(t *testing.T) {
	proof := strings.Repeat("a", 64)
	hash1 := HashProof(proof)

	for i := 0; i < 100; i++ {
		hash2 := HashProof(proof)
		if hash1 != hash2 {
			t.Error("Hash should be deterministic")
		}
	}
}

func TestHashProofUniqueness(t *testing.T) {
	proofs := []string{
		strings.Repeat("a", 64),
		strings.Repeat("b", 64),
		strings.Repeat("c", 64),
	}

	hashes := make(map[string]bool)
	for _, proof := range proofs {
		hash := HashProof(proof)
		if hashes[hash] {
			t.Error("Different proofs should produce different hashes")
		}
		hashes[hash] = true
	}
}

func TestHashProofFormat(t *testing.T) {
	proof := strings.Repeat("a", 64)
	hash := HashProof(proof)

	// Should be lowercase hex
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("Hash should be lowercase hex, found: %c", c)
		}
	}
}

// --- Real-World Scoped Scenarios ---

func TestScopedProofFinancialTransaction(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api/transfer|"
	payload := map[string]interface{}{
		"from":      "account_123",
		"to":        "account_456",
		"amount":    1000.50,
		"currency":  "USD",
		"reference": "TXN-001",
		"note":      "Payment for services",
	}
	// Only protect critical fields
	scope := []string{"from", "to", "amount", "currency"}

	result := BuildProofUnified(secret, timestamp, binding, payload, scope, "")

	if len(result.Proof) != 64 {
		t.Error("Financial transaction proof should be valid")
	}
	if result.ScopeHash == "" {
		t.Error("Should have scope hash for protected fields")
	}
}

func TestScopedProofUserProfile(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "PUT|/api/users/123|"
	payload := map[string]interface{}{
		"email":       "user@example.com",
		"password":    "hashed_password",
		"name":        "John Doe",
		"preferences": map[string]interface{}{"theme": "dark"},
	}
	// Protect sensitive fields
	scope := []string{"email", "password"}

	result := BuildProofUnified(secret, timestamp, binding, payload, scope, "")

	if len(result.Proof) != 64 {
		t.Error("User profile proof should be valid")
	}
}
