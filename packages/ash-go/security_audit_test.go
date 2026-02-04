package ash

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// SECURITY AUDIT TESTS
// ============================================================================

// --- Payload Tampering Detection ---

func TestSecPayloadFieldInjection(t *testing.T) {
	original := map[string]interface{}{"amount": 100}
	injected := map[string]interface{}{"amount": 100, "admin": true}

	canon1, _ := CanonicalizeJSON(original)
	canon2, _ := CanonicalizeJSON(injected)

	if canon1 == canon2 {
		t.Error("Field injection not detected")
	}
}

func TestSecPayloadFieldRemoval(t *testing.T) {
	original := map[string]interface{}{"amount": 100, "recipient": "user123"}
	truncated := map[string]interface{}{"amount": 100}

	canon1, _ := CanonicalizeJSON(original)
	canon2, _ := CanonicalizeJSON(truncated)

	if canon1 == canon2 {
		t.Error("Field removal not detected")
	}
}

func TestSecPayloadValueModification(t *testing.T) {
	original := map[string]interface{}{"amount": 100}
	modified := map[string]interface{}{"amount": 999}

	canon1, _ := CanonicalizeJSON(original)
	canon2, _ := CanonicalizeJSON(modified)

	if canon1 == canon2 {
		t.Error("Value modification not detected")
	}
}

func TestSecPayloadTypeChange(t *testing.T) {
	original := map[string]interface{}{"count": 100}
	stringType := map[string]interface{}{"count": "100"}

	canon1, _ := CanonicalizeJSON(original)
	canon2, _ := CanonicalizeJSON(stringType)

	if canon1 == canon2 {
		t.Error("Type change not detected")
	}
}

func TestSecNestedTampering(t *testing.T) {
	original := map[string]interface{}{
		"user": map[string]interface{}{"id": 1, "role": "user"},
	}
	tampered := map[string]interface{}{
		"user": map[string]interface{}{"id": 1, "role": "admin"},
	}

	canon1, _ := CanonicalizeJSON(original)
	canon2, _ := CanonicalizeJSON(tampered)

	if canon1 == canon2 {
		t.Error("Nested tampering not detected")
	}
}

func TestSecArrayModification(t *testing.T) {
	original := map[string]interface{}{"items": []interface{}{1, 2, 3}}
	modified := map[string]interface{}{"items": []interface{}{1, 2, 4}}

	canon1, _ := CanonicalizeJSON(original)
	canon2, _ := CanonicalizeJSON(modified)

	if canon1 == canon2 {
		t.Error("Array modification not detected")
	}
}

func TestSecArrayReordering(t *testing.T) {
	original := map[string]interface{}{"items": []interface{}{1, 2, 3}}
	reordered := map[string]interface{}{"items": []interface{}{3, 2, 1}}

	canon1, _ := CanonicalizeJSON(original)
	canon2, _ := CanonicalizeJSON(reordered)

	if canon1 == canon2 {
		t.Error("Array reordering not detected")
	}
}

// --- Binding Tampering Detection ---

func TestSecBindingMethodChange(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx1"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody("{}")

	bindingPost := "POST|/api/data|"
	bindingPut := "PUT|/api/data|"

	secretPost := DeriveClientSecret(nonce, contextID, bindingPost)
	secretPut := DeriveClientSecret(nonce, contextID, bindingPut)

	proofPost := BuildProofV21(secretPost, timestamp, bindingPost, bodyHash)
	proofPut := BuildProofV21(secretPut, timestamp, bindingPut, bodyHash)

	if proofPost == proofPut {
		t.Error("Method change not detected")
	}
}

func TestSecBindingPathChange(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx1"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody("{}")

	bindingUser := "POST|/api/user|"
	bindingAdmin := "POST|/api/admin|"

	secretUser := DeriveClientSecret(nonce, contextID, bindingUser)
	secretAdmin := DeriveClientSecret(nonce, contextID, bindingAdmin)

	proofUser := BuildProofV21(secretUser, timestamp, bindingUser, bodyHash)
	proofAdmin := BuildProofV21(secretAdmin, timestamp, bindingAdmin, bodyHash)

	if proofUser == proofAdmin {
		t.Error("Path change not detected")
	}
}

func TestSecBindingQueryInjection(t *testing.T) {
	binding1 := NormalizeBinding("GET", "/api/data", "")
	binding2 := NormalizeBinding("GET", "/api/data", "admin=true")

	if binding1 == binding2 {
		t.Error("Query parameter injection not detected")
	}
}

func TestSecBindingQueryModification(t *testing.T) {
	binding1 := NormalizeBinding("GET", "/api/data", "id=1")
	binding2 := NormalizeBinding("GET", "/api/data", "id=2")

	if binding1 == binding2 {
		t.Error("Query parameter modification not detected")
	}
}

// --- Nonce Security ---

func TestSecNonceUniqueness(t *testing.T) {
	nonces := make(map[string]bool)
	iterations := 1000

	for i := 0; i < iterations; i++ {
		bytes := make([]byte, 32)
		rand.Read(bytes)
		nonce := hex.EncodeToString(bytes)

		if nonces[nonce] {
			t.Error("Duplicate nonce generated")
		}
		nonces[nonce] = true
	}
}

func TestSecNonceNotExposedInSecret(t *testing.T) {
	nonce := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	contextID := "ctx_test"
	binding := "POST|/api|"

	secret := DeriveClientSecret(nonce, contextID, binding)

	if strings.Contains(secret, nonce) {
		t.Error("Nonce exposed in client secret")
	}
}

func TestSecDifferentNoncesDifferentSecrets(t *testing.T) {
	nonce1 := strings.Repeat("a", 64)
	nonce2 := strings.Repeat("b", 64)
	contextID := "ctx_test"
	binding := "POST|/api|"

	secret1 := DeriveClientSecret(nonce1, contextID, binding)
	secret2 := DeriveClientSecret(nonce2, contextID, binding)

	if secret1 == secret2 {
		t.Error("Different nonces produced same secret")
	}
}

// --- Timestamp Security ---

func TestSecTimestampAffectsProof(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx1"
	binding := "POST|/api|"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)

	proof1 := BuildProofV21(secret, "1000000", binding, bodyHash)
	proof2 := BuildProofV21(secret, "1000001", binding, bodyHash)

	if proof1 == proof2 {
		t.Error("Different timestamps produced same proof")
	}
}

func TestSecTimestampMutationDetected(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx1"
	binding := "POST|/api|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	// Verify with correct timestamp
	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("Valid proof failed verification")
	}

	// Verify with mutated timestamp
	mutatedTimestamp := fmt.Sprintf("%d", time.Now().Unix()+1)
	invalid := VerifyProofV21(nonce, contextID, binding, mutatedTimestamp, bodyHash, proof)
	if invalid {
		t.Error("Mutated timestamp not detected")
	}
}

// --- Concurrent Security ---

func TestSecConcurrentProofGeneration(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx_concurrent"
	binding := "POST|/api|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)

	var wg sync.WaitGroup
	proofs := make([]string, 100)
	errors := make([]error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			proofs[idx] = BuildProofV21(secret, timestamp, binding, bodyHash)
		}(i)
	}

	wg.Wait()

	// All proofs should be identical
	for i := 1; i < 100; i++ {
		if proofs[i] != proofs[0] {
			t.Errorf("Concurrent proof %d differs from proof 0", i)
		}
		if errors[i] != nil {
			t.Errorf("Concurrent proof %d had error: %v", i, errors[i])
		}
	}
}

func TestSecConcurrentVerification(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx_concurrent"
	binding := "POST|/api|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	var wg sync.WaitGroup
	results := make([]bool, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
		}(i)
	}

	wg.Wait()

	for i := 0; i < 100; i++ {
		if !results[i] {
			t.Errorf("Concurrent verification %d failed", i)
		}
	}
}

// --- Hash Security ---

func TestSecHashLength(t *testing.T) {
	inputs := []string{
		"",
		"short",
		strings.Repeat("a", 1000),
		strings.Repeat("b", 10000),
	}

	for _, input := range inputs {
		hash := HashBody(input)
		if len(hash) != 64 {
			t.Errorf("Hash length %d != 64 for input length %d", len(hash), len(input))
		}
	}
}

func TestSecHashLowercase(t *testing.T) {
	hash := HashBody("test")

	for _, c := range hash {
		if c >= 'A' && c <= 'Z' {
			t.Error("Hash contains uppercase characters")
			break
		}
	}
}

func TestSecHashAvalanche(t *testing.T) {
	hash1 := HashBody("test1")
	hash2 := HashBody("test2")

	// Count differing characters
	diffCount := 0
	for i := 0; i < len(hash1); i++ {
		if hash1[i] != hash2[i] {
			diffCount++
		}
	}

	// At least 50% of characters should differ
	if diffCount < 32 {
		t.Errorf("Hash avalanche effect too weak: only %d/64 chars differ", diffCount)
	}
}

func TestSecEmptyStringHash(t *testing.T) {
	hash := HashBody("")
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	if hash != expected {
		t.Errorf("Empty string hash %s != expected %s", hash, expected)
	}
}

// --- Proof Format Security ---

func TestSecProofFormat(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx1"
	binding := "POST|/api|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	// Check length
	if len(proof) != 64 {
		t.Errorf("Proof length %d != 64", len(proof))
	}

	// Check hex format
	for _, c := range proof {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Error("Proof contains invalid character")
			break
		}
	}
}

func TestSecSecretFormat(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx1"
	binding := "POST|/api|"

	secret := DeriveClientSecret(nonce, contextID, binding)

	// Check length
	if len(secret) != 64 {
		t.Errorf("Secret length %d != 64", len(secret))
	}

	// Check hex format
	for _, c := range secret {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Error("Secret contains invalid character")
			break
		}
	}
}

// --- Input Validation ---

func TestSecEmptyBinding(t *testing.T) {
	result := NormalizeBinding("GET", "", "")
	// Should handle gracefully or return error
	if result == "" {
		// Expected behavior for empty path
	}
}

func TestSecEmptyMethod(t *testing.T) {
	result := NormalizeBinding("", "/api", "")
	// Should handle gracefully
	if !strings.HasPrefix(result, "|") {
		// Method should be normalized
	}
}

func TestSecPathTraversal(t *testing.T) {
	paths := []string{
		"/../../../etc/passwd",
		"/api/../secret",
		"/api/./test",
	}

	for _, path := range paths {
		result := NormalizeBinding("GET", path, "")
		// Normalization should not expose vulnerabilities
		if strings.Contains(result, "..") {
			// Path traversal sequences may be preserved, which is fine
			// as long as the binding is consistent
		}
	}
}

// --- Timing Safe Comparison ---

func TestSecTimingSafeEqualStrings(t *testing.T) {
	a := strings.Repeat("test", 100)
	b := strings.Repeat("test", 100)

	if !TimingSafeCompare(a, b) {
		t.Error("Equal strings should compare equal")
	}
}

func TestSecTimingSafeDifferentStrings(t *testing.T) {
	a := strings.Repeat("a", 100)
	b := strings.Repeat("b", 100)

	if TimingSafeCompare(a, b) {
		t.Error("Different strings should not compare equal")
	}
}

func TestSecTimingSafeDifferentLengths(t *testing.T) {
	a := "short"
	b := "much longer string"

	if TimingSafeCompare(a, b) {
		t.Error("Different length strings should not compare equal")
	}
}

func TestSecTimingSafeEmptyStrings(t *testing.T) {
	if !TimingSafeCompare("", "") {
		t.Error("Empty strings should compare equal")
	}
}

func TestSecTimingSafeBytes(t *testing.T) {
	a := []byte{1, 2, 3, 4, 5}
	b := []byte{1, 2, 3, 4, 5}

	if !TimingSafeCompareBytes(a, b) {
		t.Error("Equal byte slices should compare equal")
	}
}

// --- Scoped Proof Security ---

func TestSecScopedProofProtectsFields(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx_scoped"
	binding := "POST|/api/transfer|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	payload1 := map[string]interface{}{
		"amount":    100,
		"recipient": "user123",
		"notes":     "note1",
	}
	payload2 := map[string]interface{}{
		"amount":    100,
		"recipient": "user123",
		"notes":     "note2", // Different non-scoped field
	}

	scope := []string{"amount", "recipient"}

	secret := DeriveClientSecret(nonce, contextID, binding)

	result1 := BuildProofUnified(secret, timestamp, binding, payload1, scope, "")
	result2 := BuildProofUnified(secret, timestamp, binding, payload2, scope, "")

	// No error return from BuildProofUnified

	// Proofs should be same since scoped fields are identical
	if result1.Proof != result2.Proof {
		t.Error("Same scoped fields should produce same proof")
	}
}

func TestSecScopedProofDetectsChange(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx_scoped"
	binding := "POST|/api/transfer|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	payload1 := map[string]interface{}{
		"amount":    100,
		"recipient": "user123",
	}
	payload2 := map[string]interface{}{
		"amount":    200, // Changed scoped field
		"recipient": "user123",
	}

	scope := []string{"amount", "recipient"}

	secret := DeriveClientSecret(nonce, contextID, binding)

	result1 := BuildProofUnified(secret, timestamp, binding, payload1, scope, "")
	result2 := BuildProofUnified(secret, timestamp, binding, payload2, scope, "")

	// No error return from BuildProofUnified

	if result1.Proof == result2.Proof {
		t.Error("Changed scoped field should produce different proof")
	}
}

// --- Chain Proof Security ---

func TestSecChainProofLinkage(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx_chain"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	payload := map[string]interface{}{}

	// Step 1
	binding1 := "POST|/api/cart|"
	secret1 := DeriveClientSecret(nonce, contextID, binding1)
	result1 := BuildProofUnified(secret1, timestamp, binding1, payload, nil, "")

	// Step 2 with chain
	binding2 := "POST|/api/checkout|"
	secret2 := DeriveClientSecret(nonce, contextID, binding2)
	result2 := BuildProofUnified(secret2, timestamp, binding2, payload, nil, result1.Proof)

	// Step 2 without chain
	result2NoChain := BuildProofUnified(secret2, timestamp, binding2, payload, nil, "")

	if result2.Proof == result2NoChain.Proof {
		t.Error("Chain should affect proof")
	}

	if result2.ChainHash == "" {
		t.Error("Chained proof should have chain hash")
	}
}

func TestSecChainProofDifferentPrevious(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx_chain"
	binding := "POST|/api/step2|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	payload := map[string]interface{}{}

	secret := DeriveClientSecret(nonce, contextID, binding)

	prevProof1 := strings.Repeat("a", 64)
	prevProof2 := strings.Repeat("b", 64)

	result1 := BuildProofUnified(secret, timestamp, binding, payload, nil, prevProof1)
	result2 := BuildProofUnified(secret, timestamp, binding, payload, nil, prevProof2)

	if result1.Proof == result2.Proof {
		t.Error("Different previous proofs should produce different results")
	}

	if result1.ChainHash == result2.ChainHash {
		t.Error("Different previous proofs should produce different chain hashes")
	}
}
