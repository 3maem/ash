package ash

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// REGRESSION TESTS - Tests for previously fixed bugs and edge cases
// ============================================================================

// --- Hash Regression Tests ---

func TestRegressionEmptyStringHash(t *testing.T) {
	// Ensure empty string produces consistent SHA-256 hash
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	result := HashBody("")

	if result != expected {
		t.Errorf("Empty string hash regression:\nGot:      %s\nExpected: %s", result, expected)
	}
}

func TestRegressionEmptyObjectHash(t *testing.T) {
	// Ensure empty object {} produces consistent hash
	expected := "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	result := HashBody("{}")

	if result != expected {
		t.Errorf("Empty object hash regression:\nGot:      %s\nExpected: %s", result, expected)
	}
}

func TestRegressionHashLowercase(t *testing.T) {
	// All hashes must be lowercase hex
	inputs := []string{"test", "TEST", "Test123", "special!@#"}

	for _, input := range inputs {
		hash := HashBody(input)
		if hash != strings.ToLower(hash) {
			t.Errorf("Hash not lowercase for input %q", input)
		}
	}
}

func TestRegressionHash64Chars(t *testing.T) {
	// All hashes must be exactly 64 characters
	inputs := []string{"", "a", strings.Repeat("x", 10000)}

	for _, input := range inputs {
		hash := HashBody(input)
		if len(hash) != 64 {
			t.Errorf("Hash length %d != 64 for input length %d", len(hash), len(input))
		}
	}
}

// --- JSON Canonicalization Regression Tests ---

func TestRegressionJCSSortedKeys(t *testing.T) {
	// Keys must be sorted alphabetically
	input := map[string]interface{}{
		"z": 1,
		"a": 2,
		"m": 3,
	}

	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Canonicalization failed: %v", err)
	}

	// a must come before m, m before z
	aPos := strings.Index(result, `"a"`)
	mPos := strings.Index(result, `"m"`)
	zPos := strings.Index(result, `"z"`)

	if !(aPos < mPos && mPos < zPos) {
		t.Errorf("Keys not sorted in order a < m < z: %s", result)
	}
}

func TestRegressionJCSNestedSorting(t *testing.T) {
	// Nested objects must also have sorted keys
	input := map[string]interface{}{
		"outer": map[string]interface{}{
			"z": 1,
			"a": 2,
		},
	}

	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Canonicalization failed: %v", err)
	}

	// In nested object, a must come before z
	if strings.Contains(result, `"z":1,"a":2`) {
		t.Errorf("Nested keys not sorted: %s", result)
	}
}

func TestRegressionJCSNoTrailingWhitespace(t *testing.T) {
	input := map[string]interface{}{"key": "value"}

	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Canonicalization failed: %v", err)
	}

	if strings.HasSuffix(result, " ") || strings.HasSuffix(result, "\n") {
		t.Errorf("Result has trailing whitespace: %q", result)
	}
}

func TestRegressionJCSNoLeadingWhitespace(t *testing.T) {
	input := map[string]interface{}{"key": "value"}

	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Canonicalization failed: %v", err)
	}

	if strings.HasPrefix(result, " ") || strings.HasPrefix(result, "\n") {
		t.Errorf("Result has leading whitespace: %q", result)
	}
}

func TestRegressionJCSNoInternalWhitespace(t *testing.T) {
	input := map[string]interface{}{"key": "value"}

	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Canonicalization failed: %v", err)
	}

	// Should not have spaces after colons or commas
	if strings.Contains(result, ": ") || strings.Contains(result, ", ") {
		t.Errorf("Result has internal whitespace: %s", result)
	}
}

func TestRegressionJCSIntegersNotFloats(t *testing.T) {
	input := map[string]interface{}{
		"int": 42,
	}

	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Canonicalization failed: %v", err)
	}

	// Integer should not have .0
	if strings.Contains(result, "42.0") {
		t.Errorf("Integer rendered as float: %s", result)
	}
}

func TestRegressionJCSArrayOrder(t *testing.T) {
	// Arrays must preserve order
	input := []interface{}{3, 1, 2}

	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Canonicalization failed: %v", err)
	}

	expected := "[3,1,2]"
	if result != expected {
		t.Errorf("Array order changed:\nGot:      %s\nExpected: %s", result, expected)
	}
}

func TestRegressionJCSNullValue(t *testing.T) {
	result, err := CanonicalizeJSON(nil)
	if err != nil {
		t.Fatalf("Canonicalization failed: %v", err)
	}

	if result != "null" {
		t.Errorf("nil should canonicalize to 'null', got %s", result)
	}
}

func TestRegressionJCSBooleanValues(t *testing.T) {
	trueResult, _ := CanonicalizeJSON(true)
	falseResult, _ := CanonicalizeJSON(false)

	if trueResult != "true" {
		t.Errorf("true should be 'true', got %s", trueResult)
	}
	if falseResult != "false" {
		t.Errorf("false should be 'false', got %s", falseResult)
	}
}

// --- Query Canonicalization Regression Tests ---

func TestRegressionQuerySorting(t *testing.T) {
	input := "z=3&a=1&m=2"
	result, err := CanonicalizeQuery(input)
	if err != nil {
		t.Fatalf("CanonicalizeQuery failed: %v", err)
	}

	// Should be sorted
	aPos := strings.Index(result, "a=")
	mPos := strings.Index(result, "m=")
	zPos := strings.Index(result, "z=")

	if !(aPos < mPos && mPos < zPos) {
		t.Errorf("Query not sorted: %s", result)
	}
}

func TestRegressionQueryDuplicateKeys(t *testing.T) {
	input := "a=3&a=1&a=2"
	result, err := CanonicalizeQuery(input)
	if err != nil {
		t.Fatalf("CanonicalizeQuery failed: %v", err)
	}

	// All values should be present
	if strings.Count(result, "a=") != 3 {
		t.Errorf("Duplicate keys not preserved: %s", result)
	}
}

func TestRegressionQueryEmptyValue(t *testing.T) {
	input := "key="
	result, err := CanonicalizeQuery(input)
	if err != nil {
		t.Fatalf("CanonicalizeQuery failed: %v", err)
	}

	if !strings.Contains(result, "key=") {
		t.Errorf("Empty value not preserved: %s", result)
	}
}

func TestRegressionQueryNoValue(t *testing.T) {
	input := "key"
	result, err := CanonicalizeQuery(input)

	// Should handle key without value
	_ = result
	_ = err
}

// --- Binding Regression Tests ---

func TestRegressionBindingFormat(t *testing.T) {
	result := NormalizeBinding("GET", "/api/users", "page=1")
	parts := strings.Split(result, "|")

	if len(parts) != 3 {
		t.Errorf("Binding should have exactly 3 parts: %s", result)
	}
}

func TestRegressionBindingMethodUppercase(t *testing.T) {
	methods := []string{"get", "post", "Get", "POST", "pUt"}

	for _, method := range methods {
		result := NormalizeBinding(method, "/api", "")
		parts := strings.Split(result, "|")

		if len(parts) >= 1 && parts[0] != strings.ToUpper(method) {
			t.Errorf("Method %s should be uppercased: %s", method, parts[0])
		}
	}
}

func TestRegressionBindingPathPreserved(t *testing.T) {
	paths := []string{
		"/",
		"/api",
		"/api/users",
		"/api/users/123",
		"/api/v1/users/123/posts",
	}

	for _, path := range paths {
		result := NormalizeBinding("GET", path, "")
		parts := strings.Split(result, "|")

		if len(parts) >= 2 && !strings.Contains(parts[1], path) {
			t.Errorf("Path %s not preserved in binding: %s", path, result)
		}
	}
}

// --- Proof Regression Tests ---

func TestRegressionProofDeterministic(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test"
	binding := "POST|/api|"
	timestamp := "12345"
	bodyHash := strings.Repeat("b", 64)

	secret := DeriveClientSecret(nonce, contextID, binding)

	proof1 := BuildProofV21(secret, timestamp, binding, bodyHash)
	proof2 := BuildProofV21(secret, timestamp, binding, bodyHash)
	proof3 := BuildProofV21(secret, timestamp, binding, bodyHash)

	if proof1 != proof2 || proof2 != proof3 {
		t.Error("Proof generation not deterministic")
	}
}

func TestRegressionProofLength(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test"
	binding := "POST|/api|"
	timestamp := "12345"
	bodyHash := strings.Repeat("b", 64)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	if len(proof) != 64 {
		t.Errorf("Proof length %d != 64", len(proof))
	}
}

func TestRegressionProofLowercase(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test"
	binding := "POST|/api|"
	timestamp := "12345"
	bodyHash := strings.Repeat("b", 64)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	if proof != strings.ToLower(proof) {
		t.Error("Proof should be lowercase hex")
	}
}

// --- Verification Regression Tests ---

func TestRegressionVerifyValidProof(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test"
	binding := "POST|/api|"
	timestamp := "12345"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("Valid proof should verify")
	}
}

func TestRegressionVerifyInvalidProof(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test"
	binding := "POST|/api|"
	timestamp := "12345"
	bodyHash := HashBody("{}")

	invalidProof := strings.Repeat("c", 64)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, invalidProof)
	if valid {
		t.Error("Invalid proof should not verify")
	}
}

func TestRegressionVerifyWrongNonce(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	wrongNonce := strings.Repeat("b", 64)
	contextID := "test"
	binding := "POST|/api|"
	timestamp := "12345"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(wrongNonce, contextID, binding, timestamp, bodyHash, proof)
	if valid {
		t.Error("Wrong nonce should fail verification")
	}
}

func TestRegressionVerifyWrongContext(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test"
	wrongContext := "wrong"
	binding := "POST|/api|"
	timestamp := "12345"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, wrongContext, binding, timestamp, bodyHash, proof)
	if valid {
		t.Error("Wrong context should fail verification")
	}
}

func TestRegressionVerifyWrongTimestamp(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test"
	binding := "POST|/api|"
	timestamp := "12345"
	wrongTimestamp := "12346"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, wrongTimestamp, bodyHash, proof)
	if valid {
		t.Error("Wrong timestamp should fail verification")
	}
}

func TestRegressionVerifyWrongBody(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test"
	binding := "POST|/api|"
	timestamp := "12345"
	bodyHash := HashBody("{}")
	wrongBodyHash := HashBody(`{"modified":true}`)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, wrongBodyHash, proof)
	if valid {
		t.Error("Wrong body hash should fail verification")
	}
}

// --- Secret Derivation Regression Tests ---

func TestRegressionSecretDeterministic(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test"
	binding := "POST|/api|"

	secret1 := DeriveClientSecret(nonce, contextID, binding)
	secret2 := DeriveClientSecret(nonce, contextID, binding)
	secret3 := DeriveClientSecret(nonce, contextID, binding)

	if secret1 != secret2 || secret2 != secret3 {
		t.Error("Secret derivation not deterministic")
	}
}

func TestRegressionSecretLength(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test"
	binding := "POST|/api|"

	secret := DeriveClientSecret(nonce, contextID, binding)

	if len(secret) != 64 {
		t.Errorf("Secret length %d != 64", len(secret))
	}
}

func TestRegressionSecretUnique(t *testing.T) {
	// Different inputs should produce different secrets
	secret1 := DeriveClientSecret(strings.Repeat("a", 64), "ctx1", "GET|/|")
	secret2 := DeriveClientSecret(strings.Repeat("a", 64), "ctx2", "GET|/|")
	secret3 := DeriveClientSecret(strings.Repeat("b", 64), "ctx1", "GET|/|")

	if secret1 == secret2 {
		t.Error("Different contexts should produce different secrets")
	}
	if secret1 == secret3 {
		t.Error("Different nonces should produce different secrets")
	}
}

// --- Timing Safe Compare Regression Tests ---

func TestRegressionTimingSafeEqual(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("a", 64)

	if !TimingSafeCompare(a, b) {
		t.Error("Equal strings should compare equal")
	}
}

func TestRegressionTimingSafeNotEqual(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)

	if TimingSafeCompare(a, b) {
		t.Error("Different strings should not compare equal")
	}
}

func TestRegressionTimingSafeDifferentLength(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("a", 32)

	if TimingSafeCompare(a, b) {
		t.Error("Different length strings should not compare equal")
	}
}

// --- Scoped Proof Regression Tests ---

func TestRegressionScopedProofDeterministic(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "12345"
	binding := "POST|/api|"
	payload := map[string]interface{}{"a": 1, "b": 2}
	scope := []string{"a"}

	result1 := BuildProofUnified(secret, timestamp, binding, payload, scope, "")
	result2 := BuildProofUnified(secret, timestamp, binding, payload, scope, "")

	if result1.Proof != result2.Proof {
		t.Error("Scoped proof not deterministic")
	}
}

func TestRegressionScopedProofScopeHash(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "12345"
	binding := "POST|/api|"
	payload := map[string]interface{}{"a": 1, "b": 2}
	scope := []string{"a"}

	result := BuildProofUnified(secret, timestamp, binding, payload, scope, "")

	if len(result.ScopeHash) != 64 {
		t.Errorf("Scope hash length %d != 64", len(result.ScopeHash))
	}
}

// --- Chain Proof Regression Tests ---

func TestRegressionChainProofDeterministic(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "12345"
	binding := "POST|/api|"
	payload := map[string]interface{}{"key": "value"}
	previousProof := strings.Repeat("b", 64)

	result1 := BuildProofUnified(secret, timestamp, binding, payload, nil, previousProof)
	result2 := BuildProofUnified(secret, timestamp, binding, payload, nil, previousProof)

	if result1.Proof != result2.Proof {
		t.Error("Chain proof not deterministic")
	}
}

func TestRegressionChainProofChainHash(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "12345"
	binding := "POST|/api|"
	payload := map[string]interface{}{"key": "value"}
	previousProof := strings.Repeat("b", 64)

	result := BuildProofUnified(secret, timestamp, binding, payload, nil, previousProof)

	if result.ChainHash == "" {
		t.Error("Chain hash should be set when previousProof provided")
	}
}

// --- URL Encoded Regression Tests ---

func TestRegressionURLEncodedSorted(t *testing.T) {
	input := "z=3&a=1&m=2"
	result, err := CanonicalizeURLEncoded(input)
	if err != nil {
		t.Fatalf("CanonicalizeURLEncoded failed: %v", err)
	}

	// Should be sorted
	aPos := strings.Index(result, "a=")
	mPos := strings.Index(result, "m=")
	zPos := strings.Index(result, "z=")

	if aPos != -1 && mPos != -1 && zPos != -1 {
		if !(aPos < mPos && mPos < zPos) {
			t.Errorf("URL encoded not sorted: %s", result)
		}
	}
}

// --- Mode Validation Regression Tests ---

func TestRegressionValidModes(t *testing.T) {
	validModes := []AshMode{ModeStrict, ModeBalanced, ModeMinimal}

	for _, mode := range validModes {
		input := BuildProofInput{
			Mode:             mode,
			ContextID:        "ctx",
			Binding:          "POST|/api|",
			CanonicalPayload: "{}",
		}

		err := ValidateProofInput(input)
		if err != nil {
			t.Errorf("Mode %v should be valid: %v", mode, err)
		}
	}
}

func TestRegressionInvalidMode(t *testing.T) {
	input := BuildProofInput{
		Mode:             AshMode("invalid"),
		ContextID:        "ctx",
		Binding:          "POST|/api|",
		CanonicalPayload: "{}",
	}

	err := ValidateProofInput(input)
	if err == nil {
		t.Error("Invalid mode should error")
	}
}

// --- Timestamp Handling Regression Tests ---

func TestRegressionTimestampInProof(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test"
	binding := "POST|/api|"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)

	// Different timestamps should produce different proofs
	proof1 := BuildProofV21(secret, "12345", binding, bodyHash)
	proof2 := BuildProofV21(secret, "12346", binding, bodyHash)

	if proof1 == proof2 {
		t.Error("Different timestamps should produce different proofs")
	}
}

func TestRegressionCurrentTimestamp(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "test"
	binding := "POST|/api|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("Current timestamp proof should verify")
	}
}
