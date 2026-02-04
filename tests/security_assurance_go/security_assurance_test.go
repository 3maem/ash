// Package security_assurance_test implements the ASH Security Assurance Pack for Go.
//
// Test Categories:
// A. Unit Tests - Deterministic signature generation, mutation detection
// B. Integration Tests - Full request flow verification
// C. Security Tests - Anti-replay, timing attacks, context expiration
// D. Cryptographic Tests - Constant-time comparison, algorithm strength
package security_assurance_test

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"sync"
	"testing"
	"time"

	ash "github.com/3maem/ash-go/v2"
)

// ============================================================================
// A. UNIT TESTS
// ============================================================================

// TestDeterministicCanonicalizeJSON verifies JSON canonicalization is deterministic
func TestDeterministicCanonicalizeJSON(t *testing.T) {
	input := map[string]interface{}{"z": 1.0, "a": 2.0, "m": 3.0}

	results := make([]string, 100)
	for i := 0; i < 100; i++ {
		result, err := ash.CanonicalizeJSON(input)
		if err != nil {
			t.Fatalf("Canonicalization failed: %v", err)
		}
		results[i] = result
	}

	for i := 1; i < 100; i++ {
		if results[i] != results[0] {
			t.Errorf("Canonicalization is not deterministic: %s != %s", results[i], results[0])
		}
	}

	expected := `{"a":2,"m":3,"z":1}`
	if results[0] != expected {
		t.Errorf("Expected %s, got %s", expected, results[0])
	}
}

// TestDeterministicKeyOrder verifies keys are sorted consistently
func TestDeterministicKeyOrder(t *testing.T) {
	input1 := map[string]interface{}{"z": 1.0, "a": 2.0}
	input2 := map[string]interface{}{"a": 2.0, "z": 1.0}

	result1, _ := ash.CanonicalizeJSON(input1)
	result2, _ := ash.CanonicalizeJSON(input2)

	if result1 != result2 {
		t.Errorf("Different input orders produce different outputs: %s != %s", result1, result2)
	}
}

// TestDeterministicBuildProof verifies proof generation is deterministic
func TestDeterministicBuildProof(t *testing.T) {
	input := ash.BuildProofInput{
		Mode:             ash.ModeBalanced,
		Binding:          "POST /api/test",
		ContextID:        "ctx_test_123",
		Nonce:            "nonce123",
		CanonicalPayload: `{"amount":100}`,
	}

	proofs := make([]string, 100)
	for i := 0; i < 100; i++ {
		proofs[i] = ash.BuildProof(input)
	}

	for i := 1; i < 100; i++ {
		if proofs[i] != proofs[0] {
			t.Errorf("Proof generation is not deterministic")
		}
	}
}

// TestDeterministicBuildProofV21 verifies v2.1 proof generation is deterministic
func TestDeterministicBuildProofV21(t *testing.T) {
	clientSecret := repeatString("a", 64)
	timestamp := "1704067200000"
	binding := "POST|/api/test|"
	bodyHash := ash.HashBody(`{"test":1}`)

	proofs := make([]string, 100)
	for i := 0; i < 100; i++ {
		proofs[i] = ash.BuildProofV21(clientSecret, timestamp, binding, bodyHash)
	}

	for i := 1; i < 100; i++ {
		if proofs[i] != proofs[0] {
			t.Errorf("v2.1 proof generation is not deterministic")
		}
	}
}

// TestDeterministicDeriveClientSecret verifies client secret derivation is deterministic
func TestDeterministicDeriveClientSecret(t *testing.T) {
	nonce := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	contextID := "ash_test_ctx"
	binding := "POST|/api/test|"

	secrets := make([]string, 100)
	for i := 0; i < 100; i++ {
		secrets[i] = ash.DeriveClientSecret(nonce, contextID, binding)
	}

	for i := 1; i < 100; i++ {
		if secrets[i] != secrets[0] {
			t.Errorf("Client secret derivation is not deterministic")
		}
	}
}

// TestDeterministicNormalizeBinding verifies binding normalization is deterministic
func TestDeterministicNormalizeBinding(t *testing.T) {
	method := "post"
	path := "/api//test/"
	query := "z=1&a=2"

	results := make([]string, 100)
	for i := 0; i < 100; i++ {
		results[i] = ash.NormalizeBinding(method, path, query)
	}

	for i := 1; i < 100; i++ {
		if results[i] != results[0] {
			t.Errorf("Binding normalization is not deterministic")
		}
	}
}

// TestDeterministicHashBody verifies body hashing is deterministic
func TestDeterministicHashBody(t *testing.T) {
	body := `{"critical":"data"}`

	hashes := make([]string, 100)
	for i := 0; i < 100; i++ {
		hashes[i] = ash.HashBody(body)
	}

	for i := 1; i < 100; i++ {
		if hashes[i] != hashes[0] {
			t.Errorf("Body hashing is not deterministic")
		}
	}
}

// ============================================================================
// Single-Byte Mutation Detection Tests
// ============================================================================

// TestSingleByteMutationInPayload verifies single byte changes are detected
func TestSingleByteMutationInPayload(t *testing.T) {
	original := `{"amount":100}`
	mutated := `{"amount":101}`

	proof1 := ash.BuildProof(ash.BuildProofInput{
		Mode: ash.ModeBalanced, Binding: "POST /test", ContextID: "ctx1", Nonce: "nonce", CanonicalPayload: original,
	})
	proof2 := ash.BuildProof(ash.BuildProofInput{
		Mode: ash.ModeBalanced, Binding: "POST /test", ContextID: "ctx1", Nonce: "nonce", CanonicalPayload: mutated,
	})

	if proof1 == proof2 {
		t.Error("Single byte mutation not detected")
	}
}

// TestSingleCharMutationInKey verifies key mutations are detected
func TestSingleCharMutationInKey(t *testing.T) {
	original := `{"amount":100}`
	mutated := `{"amounT":100}`

	proof1 := ash.BuildProof(ash.BuildProofInput{
		Mode: ash.ModeBalanced, Binding: "POST /test", ContextID: "ctx1", Nonce: "nonce", CanonicalPayload: original,
	})
	proof2 := ash.BuildProof(ash.BuildProofInput{
		Mode: ash.ModeBalanced, Binding: "POST /test", ContextID: "ctx1", Nonce: "nonce", CanonicalPayload: mutated,
	})

	if proof1 == proof2 {
		t.Error("Key mutation not detected")
	}
}

// TestSingleByteInContextID verifies context ID mutations are detected
func TestSingleByteInContextID(t *testing.T) {
	proof1 := ash.BuildProof(ash.BuildProofInput{
		Mode: ash.ModeBalanced, Binding: "POST /test", ContextID: "ctx_abc123", Nonce: "nonce", CanonicalPayload: "{}",
	})
	proof2 := ash.BuildProof(ash.BuildProofInput{
		Mode: ash.ModeBalanced, Binding: "POST /test", ContextID: "ctx_abc124", Nonce: "nonce", CanonicalPayload: "{}",
	})

	if proof1 == proof2 {
		t.Error("Context ID mutation not detected")
	}
}

// TestV21BodyHashMutationDetected verifies v2.1 body hash mutations are detected
func TestV21BodyHashMutationDetected(t *testing.T) {
	nonce := repeatString("a", 64)
	contextID := "ash_test"
	binding := "POST|/api|"
	timestamp := "1704067200000"

	bodyHash1 := ash.HashBody(`{"amount":100}`)
	bodyHash2 := ash.HashBody(`{"amount":101}`)

	clientSecret := ash.DeriveClientSecret(nonce, contextID, binding)
	proof := ash.BuildProofV21(clientSecret, timestamp, binding, bodyHash1)

	// Verify with correct hash should pass
	if !ash.VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash1, proof) {
		t.Error("Valid proof should verify")
	}

	// Verify with mutated hash should fail
	if ash.VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash2, proof) {
		t.Error("Mutated body hash should fail verification")
	}
}

// ============================================================================
// Missing/Invalid Header Rejection Tests
// ============================================================================

// TestEmptyContextIDDifferentiated verifies empty context ID produces different proof
func TestEmptyContextIDDifferentiated(t *testing.T) {
	proofValid := ash.BuildProof(ash.BuildProofInput{
		Mode: ash.ModeBalanced, Binding: "POST /test", ContextID: "valid_ctx", CanonicalPayload: "{}",
	})
	proofEmpty := ash.BuildProof(ash.BuildProofInput{
		Mode: ash.ModeBalanced, Binding: "POST /test", ContextID: "", CanonicalPayload: "{}",
	})

	if proofValid == proofEmpty {
		t.Error("Empty context ID not differentiated")
	}
}

// TestDifferentModesProduceDifferentProofs verifies modes produce different proofs
func TestDifferentModesProduceDifferentProofs(t *testing.T) {
	proofBalanced := ash.BuildProof(ash.BuildProofInput{
		Mode: ash.ModeBalanced, Binding: "POST /test", ContextID: "ctx1", CanonicalPayload: "{}",
	})
	proofMinimal := ash.BuildProof(ash.BuildProofInput{
		Mode: ash.ModeMinimal, Binding: "POST /test", ContextID: "ctx1", CanonicalPayload: "{}",
	})
	proofStrict := ash.BuildProof(ash.BuildProofInput{
		Mode: ash.ModeStrict, Binding: "POST /test", ContextID: "ctx1", CanonicalPayload: "{}",
	})

	if proofBalanced == proofMinimal {
		t.Error("balanced and minimal should produce different proofs")
	}
	if proofBalanced == proofStrict {
		t.Error("balanced and strict should produce different proofs")
	}
	if proofMinimal == proofStrict {
		t.Error("minimal and strict should produce different proofs")
	}
}

// TestWrongNonceFailsV21Verification verifies wrong nonce fails verification
func TestWrongNonceFailsV21Verification(t *testing.T) {
	nonceCorrect := repeatString("a", 64)
	nonceWrong := repeatString("b", 64)
	contextID := "ash_test"
	binding := "POST|/api|"
	timestamp := "1704067200000"
	bodyHash := ash.HashBody("{}")

	clientSecret := ash.DeriveClientSecret(nonceCorrect, contextID, binding)
	proof := ash.BuildProofV21(clientSecret, timestamp, binding, bodyHash)

	// Correct nonce should verify
	if !ash.VerifyProofV21(nonceCorrect, contextID, binding, timestamp, bodyHash, proof) {
		t.Error("Correct nonce should verify")
	}

	// Wrong nonce should fail
	if ash.VerifyProofV21(nonceWrong, contextID, binding, timestamp, bodyHash, proof) {
		t.Error("Wrong nonce should fail verification")
	}
}

// ============================================================================
// D. CRYPTOGRAPHIC TESTS
// ============================================================================

// TestConstantTimeCompareEqual verifies equal strings return true
func TestConstantTimeCompareEqual(t *testing.T) {
	if !ash.TimingSafeCompare("test123", "test123") {
		t.Error("Equal strings should return true")
	}
	if !ash.TimingSafeCompare(repeatString("a", 1000), repeatString("a", 1000)) {
		t.Error("Long equal strings should return true")
	}
	if !ash.TimingSafeCompare("", "") {
		t.Error("Empty strings should return true")
	}
}

// TestConstantTimeCompareUnequal verifies unequal strings return false
func TestConstantTimeCompareUnequal(t *testing.T) {
	if ash.TimingSafeCompare("test123", "test124") {
		t.Error("Unequal strings should return false")
	}
	if ash.TimingSafeCompare("short", "longer") {
		t.Error("Different length strings should return false")
	}
	if ash.TimingSafeCompare("", "nonempty") {
		t.Error("Empty vs non-empty should return false")
	}
}

// TestConstantTimeBehavior verifies timing doesn't leak information
func TestConstantTimeBehavior(t *testing.T) {
	iterations := 1000
	base := repeatString("a", 64)
	earlyDiff := "b" + repeatString("a", 63)
	lateDiff := repeatString("a", 63) + "b"

	// Measure early difference timing
	earlyTimes := make([]int64, iterations)
	for i := 0; i < iterations; i++ {
		start := time.Now().UnixNano()
		ash.TimingSafeCompare(base, earlyDiff)
		earlyTimes[i] = time.Now().UnixNano() - start
	}

	// Measure late difference timing
	lateTimes := make([]int64, iterations)
	for i := 0; i < iterations; i++ {
		start := time.Now().UnixNano()
		ash.TimingSafeCompare(base, lateDiff)
		lateTimes[i] = time.Now().UnixNano() - start
	}

	earlyMedian := median(earlyTimes)
	lateMedian := median(lateTimes)

	ratio := float64(max(earlyMedian, lateMedian)) / float64(min(earlyMedian, lateMedian))

	// Allow up to 3x variance due to system noise
	if ratio > 3.0 {
		t.Errorf("Timing ratio %.2f suggests non-constant-time comparison", ratio)
	}
}

// TestProofUsesSHA256 verifies proof uses SHA-256
func TestProofUsesSHA256(t *testing.T) {
	proof := ash.BuildProof(ash.BuildProofInput{
		Mode: ash.ModeBalanced, Binding: "POST /test", ContextID: "ctx123", CanonicalPayload: "{}",
	})

	// Base64URL encoded SHA-256 should be 43 characters (no padding)
	if len(proof) != 43 {
		t.Errorf("Unexpected proof length: %d (expected 43 for SHA-256)", len(proof))
	}
}

// TestV21ProofUsesHMACSHA256 verifies v2.1 proof uses HMAC-SHA256
func TestV21ProofUsesHMACSHA256(t *testing.T) {
	clientSecret := repeatString("a", 64)
	timestamp := "1704067200000"
	binding := "POST|/api/test|"
	bodyHash := ash.HashBody("{}")

	proof := ash.BuildProofV21(clientSecret, timestamp, binding, bodyHash)

	// HMAC-SHA256 output is 32 bytes = 64 hex chars
	if len(proof) != 64 {
		t.Errorf("Unexpected v2.1 proof length: %d (expected 64)", len(proof))
	}

	// Should be lowercase hex
	hexPattern := regexp.MustCompile(`^[0-9a-f]+$`)
	if !hexPattern.MatchString(proof) {
		t.Error("Proof should be lowercase hex")
	}
}

// TestBodyHashUsesSHA256 verifies body hash uses SHA-256
func TestBodyHashUsesSHA256(t *testing.T) {
	bodyHash := ash.HashBody(`{"test":"data"}`)

	if len(bodyHash) != 64 {
		t.Errorf("Unexpected hash length: %d (expected 64)", len(bodyHash))
	}

	hexPattern := regexp.MustCompile(`^[0-9a-f]+$`)
	if !hexPattern.MatchString(bodyHash) {
		t.Error("Hash should be lowercase hex")
	}
}

// TestDifferentInputsProduceDifferentOutputs verifies crypto outputs are unique
func TestDifferentInputsProduceDifferentOutputs(t *testing.T) {
	// Test hashBody
	hash1 := ash.HashBody(`{"a":1}`)
	hash2 := ash.HashBody(`{"a":2}`)
	if hash1 == hash2 {
		t.Error("Different payloads produce same hash")
	}

	// Test deriveClientSecret
	secret1 := ash.DeriveClientSecret(repeatString("a", 64), "ctx1", "POST|/a|")
	secret2 := ash.DeriveClientSecret(repeatString("a", 64), "ctx2", "POST|/a|")
	if secret1 == secret2 {
		t.Error("Different context IDs produce same secret")
	}

	// Test buildProofV21
	proof1 := ash.BuildProofV21(repeatString("a", 64), "100", "POST|/a|", hash1)
	proof2 := ash.BuildProofV21(repeatString("a", 64), "100", "POST|/a|", hash2)
	if proof1 == proof2 {
		t.Error("Different body hashes produce same proof")
	}
}

// TestEntropyInOutputs verifies outputs have high entropy
func TestEntropyInOutputs(t *testing.T) {
	hashes := make([]string, 100)
	for i := 0; i < 100; i++ {
		// Use fmt.Sprintf to generate unique inputs (0-99, not just 0-9)
		hashes[i] = ash.HashBody(`{"n":` + fmt.Sprintf("%d", i) + `}`)
	}

	unique := make(map[string]bool)
	for _, h := range hashes {
		unique[h] = true
	}

	if len(unique) != 100 {
		t.Error("Hash collision detected")
	}

	// Check character distribution
	allChars := ""
	for _, h := range hashes {
		allChars += h
	}

	charCounts := make(map[rune]int)
	for _, c := range allChars {
		charCounts[c]++
	}

	totalChars := len(allChars)
	for char, count := range charCounts {
		percentage := float64(count) / float64(totalChars) * 100
		if percentage < 2 || percentage > 12 {
			t.Errorf("Character '%c' appears %.1f%% - suspicious distribution", char, percentage)
		}
	}
}

// TestNoSecretExposure verifies secrets don't appear in outputs
func TestNoSecretExposure(t *testing.T) {
	nonce := "supersecretnoncevalue1234567890123456789012345678901234"
	contextID := "ash_test"
	binding := "POST|/api/test|"

	clientSecret := ash.DeriveClientSecret(nonce, contextID, binding)
	bodyHash := ash.HashBody("{}")
	proof := ash.BuildProofV21(clientSecret, "1234567890", binding, bodyHash)

	if containsSubstring(proof, nonce) {
		t.Error("Nonce appears in proof")
	}
	if containsSubstring(clientSecret, nonce) {
		t.Error("Nonce appears in client secret")
	}
}

// TestV21ProofIncludesAllComponents verifies all security-relevant components are included
func TestV21ProofIncludesAllComponents(t *testing.T) {
	clientSecret := repeatString("a", 64)
	bodyHash := ash.HashBody(`{"amount":100}`)

	// Same secret, different timestamps = different proofs
	proof1 := ash.BuildProofV21(clientSecret, "1000", "POST|/api|", bodyHash)
	proof2 := ash.BuildProofV21(clientSecret, "2000", "POST|/api|", bodyHash)
	if proof1 == proof2 {
		t.Error("Timestamp not included in proof")
	}

	// Same secret, different bindings = different proofs
	proof3 := ash.BuildProofV21(clientSecret, "1000", "POST|/api/a|", bodyHash)
	proof4 := ash.BuildProofV21(clientSecret, "1000", "POST|/api/b|", bodyHash)
	if proof3 == proof4 {
		t.Error("Binding not included in proof")
	}

	// Same everything, different body = different proofs
	hash1 := ash.HashBody(`{"a":1}`)
	hash2 := ash.HashBody(`{"a":2}`)
	proof5 := ash.BuildProofV21(clientSecret, "1000", "POST|/api|", hash1)
	proof6 := ash.BuildProofV21(clientSecret, "1000", "POST|/api|", hash2)
	if proof5 == proof6 {
		t.Error("Body hash not included in proof")
	}
}

// ============================================================================
// C. SECURITY TESTS
// ============================================================================

// TestAntiReplayUniqueContextIDs verifies context IDs are unique
func TestAntiReplayUniqueContextIDs(t *testing.T) {
	ids := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		id, err := ash.GenerateContextID()
		if err != nil {
			t.Fatalf("Failed to generate context ID: %v", err)
		}
		ids[i] = id
	}

	unique := make(map[string]bool)
	for _, id := range ids {
		unique[id] = true
	}

	if len(unique) != 1000 {
		t.Error("Context ID collision detected")
	}
}

// TestAntiReplayUniqueNonces verifies nonces are unique
func TestAntiReplayUniqueNonces(t *testing.T) {
	nonces := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		nonce, err := ash.GenerateNonce(32)
		if err != nil {
			t.Fatalf("Failed to generate nonce: %v", err)
		}
		nonces[i] = nonce
	}

	unique := make(map[string]bool)
	for _, nonce := range nonces {
		unique[nonce] = true
	}

	if len(unique) != 1000 {
		t.Error("Nonce collision detected")
	}
}

// TestProofBindingDifferentEndpoint verifies endpoint binding
func TestProofBindingDifferentEndpoint(t *testing.T) {
	nonce, _ := ash.GenerateNonce(32)
	contextID, _ := ash.GenerateContextID()
	bindingOriginal := "POST|/api/transfer|"
	bindingDifferent := "POST|/api/payment|"
	timestamp := "1704067200000"
	bodyHash := ash.HashBody("{}")

	clientSecret := ash.DeriveClientSecret(nonce, contextID, bindingOriginal)
	proof := ash.BuildProofV21(clientSecret, timestamp, bindingOriginal, bodyHash)

	// Verify with original binding should pass
	if !ash.VerifyProofV21(nonce, contextID, bindingOriginal, timestamp, bodyHash, proof) {
		t.Error("Valid binding should verify")
	}

	// Verify with different binding should fail
	if ash.VerifyProofV21(nonce, contextID, bindingDifferent, timestamp, bodyHash, proof) {
		t.Error("Different binding should fail verification")
	}
}

// TestProofBindingDifferentMethod verifies HTTP method binding
func TestProofBindingDifferentMethod(t *testing.T) {
	nonce, _ := ash.GenerateNonce(32)
	contextID, _ := ash.GenerateContextID()
	timestamp := "1704067200000"
	bodyHash := ash.HashBody("{}")

	bindingPost := ash.NormalizeBinding("POST", "/api/test", "")
	bindingPut := ash.NormalizeBinding("PUT", "/api/test", "")

	clientSecret := ash.DeriveClientSecret(nonce, contextID, bindingPost)
	proof := ash.BuildProofV21(clientSecret, timestamp, bindingPost, bodyHash)

	// Verify with POST should pass
	if !ash.VerifyProofV21(nonce, contextID, bindingPost, timestamp, bodyHash, proof) {
		t.Error("Valid method should verify")
	}

	// Verify with PUT should fail
	if ash.VerifyProofV21(nonce, contextID, bindingPut, timestamp, bodyHash, proof) {
		t.Error("Different method should fail verification")
	}
}

// TestProofBindingDifferentBody verifies body binding
func TestProofBindingDifferentBody(t *testing.T) {
	nonce, _ := ash.GenerateNonce(32)
	contextID, _ := ash.GenerateContextID()
	binding := "POST|/api/transfer|"
	timestamp := "1704067200000"

	bodyHash1 := ash.HashBody(`{"amount":100}`)
	bodyHash2 := ash.HashBody(`{"amount":999999}`)

	clientSecret := ash.DeriveClientSecret(nonce, contextID, binding)
	proof := ash.BuildProofV21(clientSecret, timestamp, binding, bodyHash1)

	// Verify with original body should pass
	if !ash.VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash1, proof) {
		t.Error("Valid body should verify")
	}

	// Verify with different body should fail
	if ash.VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash2, proof) {
		t.Error("Different body should fail verification")
	}
}

// TestReplayWithModifiedTimestamp verifies timestamp binding
func TestReplayWithModifiedTimestamp(t *testing.T) {
	nonce, _ := ash.GenerateNonce(32)
	contextID, _ := ash.GenerateContextID()
	binding := "POST|/api/test|"
	bodyHash := ash.HashBody("{}")

	timestamp1 := "1704067200000"
	timestamp2 := "1704067200001"

	clientSecret := ash.DeriveClientSecret(nonce, contextID, binding)
	proof := ash.BuildProofV21(clientSecret, timestamp1, binding, bodyHash)

	// Verify with original timestamp should pass
	if !ash.VerifyProofV21(nonce, contextID, binding, timestamp1, bodyHash, proof) {
		t.Error("Valid timestamp should verify")
	}

	// Verify with different timestamp should fail
	if ash.VerifyProofV21(nonce, contextID, binding, timestamp2, bodyHash, proof) {
		t.Error("Different timestamp should fail verification")
	}
}

// TestBindingNormalizationMethod verifies method normalization
func TestBindingNormalizationMethod(t *testing.T) {
	binding1 := ash.NormalizeBinding("post", "/api/test", "")
	binding2 := ash.NormalizeBinding("POST", "/api/test", "")
	binding3 := ash.NormalizeBinding("Post", "/api/test", "")

	if binding1 != binding2 || binding2 != binding3 {
		t.Error("Method should be normalized to uppercase")
	}
}

// TestBindingNormalizationPath verifies path normalization
func TestBindingNormalizationPath(t *testing.T) {
	binding1 := ash.NormalizeBinding("POST", "/api//test", "")
	binding2 := ash.NormalizeBinding("POST", "/api/test", "")

	if binding1 != binding2 {
		t.Error("Duplicate slashes should be collapsed")
	}
}

// TestBindingNormalizationQuery verifies query sorting
func TestBindingNormalizationQuery(t *testing.T) {
	binding1 := ash.NormalizeBinding("GET", "/api/search", "z=1&a=2")
	binding2 := ash.NormalizeBinding("GET", "/api/search", "a=2&z=1")

	if binding1 != binding2 {
		t.Error("Query parameters should be sorted")
	}
}

// TestConcurrentProofGeneration verifies thread safety
func TestConcurrentProofGeneration(t *testing.T) {
	var wg sync.WaitGroup
	results := make([]string, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = ash.BuildProof(ash.BuildProofInput{
				Mode:             ash.ModeBalanced,
				Binding:          "POST /test",
				ContextID:        "ctx1",
				CanonicalPayload: "{}",
			})
		}(i)
	}

	wg.Wait()

	// All results should be the same (deterministic)
	for i := 1; i < 100; i++ {
		if results[i] != results[0] {
			t.Error("Concurrent proof generation is not deterministic")
		}
	}
}

// ============================================================================
// Canonicalization Tests
// ============================================================================

// TestUnicodeNFCNormalization verifies Unicode NFC normalization
func TestUnicodeNFCNormalization(t *testing.T) {
	// e\u0301 as single char vs e + combining accent
	input1 := map[string]interface{}{"caf\u00e9": 1.0} // e with acute as single codepoint
	input2 := map[string]interface{}{"cafe\u0301": 1.0} // e + combining acute accent

	result1, _ := ash.CanonicalizeJSON(input1)
	result2, _ := ash.CanonicalizeJSON(input2)

	if result1 != result2 {
		t.Error("Unicode NFC normalization not applied")
	}
}

// TestNegativeZeroNormalized verifies negative zero becomes positive zero
func TestNegativeZeroNormalized(t *testing.T) {
	input := map[string]interface{}{"value": math.Copysign(0, -1)}
	result, _ := ash.CanonicalizeJSON(input)

	expected := `{"value":0}`
	if result != expected {
		t.Errorf("Negative zero not normalized: got %s, expected %s", result, expected)
	}
}

// TestNestedObjectKeySorting verifies nested object keys are sorted
func TestNestedObjectKeySorting(t *testing.T) {
	input := map[string]interface{}{
		"z": map[string]interface{}{"z": 1.0, "a": 2.0},
		"a": map[string]interface{}{"z": 3.0, "a": 4.0},
	}

	result, _ := ash.CanonicalizeJSON(input)
	expected := `{"a":{"a":4,"z":3},"z":{"a":2,"z":1}}`

	if result != expected {
		t.Errorf("Nested sorting failed: got %s, expected %s", result, expected)
	}
}

// TestArrayOrderPreserved verifies array order is preserved
func TestArrayOrderPreserved(t *testing.T) {
	input := map[string]interface{}{"arr": []interface{}{3.0, 1.0, 2.0}}
	result, _ := ash.CanonicalizeJSON(input)

	if !containsSubstring(result, `"arr":[3,1,2]`) {
		t.Errorf("Array order not preserved: %s", result)
	}
}

// TestURLEncodedSorting verifies URL-encoded data is sorted
func TestURLEncodedSorting(t *testing.T) {
	result, _ := ash.CanonicalizeURLEncoded("z=1&a=2&m=3")

	if result != "a=2&m=3&z=1" {
		t.Errorf("URL encoding not sorted: %s", result)
	}
}

// ============================================================================
// Edge Case Tests
// ============================================================================

// TestEmptyInputHashing verifies empty input produces valid hash
func TestEmptyInputHashing(t *testing.T) {
	hashEmpty := ash.HashBody("")
	if len(hashEmpty) != 64 {
		t.Errorf("Empty input hash has wrong length: %d", len(hashEmpty))
	}
}

// TestVeryLongInputHashing verifies long inputs are handled
func TestVeryLongInputHashing(t *testing.T) {
	longInput := `{"data":"` + repeatString("x", 100000) + `"}`
	hashLong := ash.HashBody(longInput)
	if len(hashLong) != 64 {
		t.Errorf("Long input hash has wrong length: %d", len(hashLong))
	}
}

// TestUnicodeInputHashing verifies unicode inputs are handled
func TestUnicodeInputHashing(t *testing.T) {
	unicodeInput := `{"emoji":"🎉","chinese":"中文","arabic":"العربية"}`
	hashUnicode := ash.HashBody(unicodeInput)
	if len(hashUnicode) != 64 {
		t.Errorf("Unicode input hash has wrong length: %d", len(hashUnicode))
	}
}

// TestSpecialJSONValues verifies special JSON values are hashed correctly
func TestSpecialJSONValues(t *testing.T) {
	hashNull := ash.HashBody(`{"value":null}`)
	hashBool := ash.HashBody(`{"value":true}`)
	hashZero := ash.HashBody(`{"value":0}`)

	if len(hashNull) != 64 || len(hashBool) != 64 || len(hashZero) != 64 {
		t.Error("Special values hash has wrong length")
	}

	unique := make(map[string]bool)
	unique[hashNull] = true
	unique[hashBool] = true
	unique[hashZero] = true

	if len(unique) != 3 {
		t.Error("Different values produce same hash")
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

func repeatString(s string, n int) string {
	result := make([]byte, len(s)*n)
	for i := 0; i < n; i++ {
		copy(result[i*len(s):], s)
	}
	return string(result)
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 &&
			func() bool {
				for i := 0; i <= len(s)-len(substr); i++ {
					if s[i:i+len(substr)] == substr {
						return true
					}
				}
				return false
			}()))
}

func median(values []int64) int64 {
	n := len(values)
	if n == 0 {
		return 0
	}
	// Simple insertion sort for small arrays
	sorted := make([]int64, n)
	copy(sorted, values)
	for i := 1; i < n; i++ {
		key := sorted[i]
		j := i - 1
		for j >= 0 && sorted[j] > key {
			sorted[j+1] = sorted[j]
			j--
		}
		sorted[j+1] = key
	}
	return sorted[n/2]
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func generateRandomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
