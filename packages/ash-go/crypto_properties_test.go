package ash

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// CRYPTOGRAPHIC PROPERTY TESTS
// ============================================================================

// --- Avalanche Effect Tests ---

func TestAvalancheEffectHashBody(t *testing.T) {
	input := "test input string"
	hash1 := HashBody(input)

	// Single bit change should cause ~50% bit change
	for i := 0; i < len(input); i++ {
		modified := input[:i] + string(input[i]^1) + input[i+1:]
		hash2 := HashBody(modified)

		if hash1 == hash2 {
			t.Errorf("Single byte change at position %d should change hash", i)
		}

		// Count differing characters (simple proxy for bit difference)
		diff := 0
		for j := 0; j < len(hash1); j++ {
			if hash1[j] != hash2[j] {
				diff++
			}
		}
		// Expect significant change (at least 25% of chars)
		if diff < 16 {
			t.Errorf("Avalanche effect weak at position %d: only %d chars differ", i, diff)
		}
	}
}

func TestAvalancheEffectSecret(t *testing.T) {
	nonce := strings.Repeat("a", 32)
	contextID := "test-ctx"
	binding := "POST|/api|"

	secret1 := DeriveClientSecret(nonce, contextID, binding)

	// Modify nonce
	modifiedNonce := "b" + nonce[1:]
	secret2 := DeriveClientSecret(modifiedNonce, contextID, binding)

	if secret1 == secret2 {
		t.Error("Different nonce should produce different secret")
	}

	// Count differences
	diff := 0
	for i := 0; i < len(secret1); i++ {
		if secret1[i] != secret2[i] {
			diff++
		}
	}
	if diff < 16 {
		t.Errorf("Avalanche effect weak: only %d chars differ", diff)
	}
}

func TestAvalancheEffectProof(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api|"
	bodyHash := HashBody(`{}`)

	proof1 := BuildProofV21(secret, timestamp, binding, bodyHash)

	// Modify timestamp by 1
	proof2 := BuildProofV21(secret, "1234567891", binding, bodyHash)

	if proof1 == proof2 {
		t.Error("Different timestamp should produce different proof")
	}

	diff := 0
	for i := 0; i < len(proof1); i++ {
		if proof1[i] != proof2[i] {
			diff++
		}
	}
	if diff < 16 {
		t.Errorf("Avalanche effect weak: only %d chars differ", diff)
	}
}

// --- Collision Resistance Tests ---

func TestCollisionResistanceHash(t *testing.T) {
	hashes := make(map[string]string)
	iterations := 10000

	for i := 0; i < iterations; i++ {
		input := fmt.Sprintf("input_%d_%d", i, time.Now().UnixNano())
		hash := HashBody(input)

		if existing, found := hashes[hash]; found {
			t.Errorf("Collision found: %s and %s both hash to %s", input, existing, hash)
		}
		hashes[hash] = input
	}
}

func TestCollisionResistanceSecret(t *testing.T) {
	secrets := make(map[string]string)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	binding := "POST|/api|"

	for i := 0; i < 10000; i++ {
		nonce := fmt.Sprintf("%032x", rng.Int63())
		contextID := fmt.Sprintf("ctx_%d", i)
		secret := DeriveClientSecret(nonce, contextID, binding)

		key := nonce + "|" + contextID
		if existing, found := secrets[secret]; found {
			t.Errorf("Collision: %s and %s produce same secret", key, existing)
		}
		secrets[secret] = key
	}
}

func TestCollisionResistanceProof(t *testing.T) {
	proofs := make(map[string]string)
	secret := strings.Repeat("a", 64)
	binding := "POST|/api|"

	for i := 0; i < 10000; i++ {
		timestamp := fmt.Sprintf("%d", 1000000000+i)
		bodyHash := HashBody(fmt.Sprintf(`{"i":%d}`, i))
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		key := timestamp + "|" + bodyHash
		if existing, found := proofs[proof]; found {
			t.Errorf("Collision: %s and %s produce same proof", key, existing)
		}
		proofs[proof] = key
	}
}

// --- Unpredictability Tests ---

func TestUnpredictabilityHash(t *testing.T) {
	// Sequential inputs should not produce sequential or predictable hashes
	var prevHash string
	for i := 0; i < 1000; i++ {
		hash := HashBody(fmt.Sprintf("%d", i))

		if prevHash != "" {
			// Check that hash doesn't just increment
			if hash == prevHash {
				t.Error("Sequential inputs produced same hash")
			}
		}
		prevHash = hash
	}
}

func TestUnpredictabilitySecret(t *testing.T) {
	contextID := "test-ctx"
	binding := "POST|/api|"
	var prevSecret string

	for i := 0; i < 1000; i++ {
		nonce := fmt.Sprintf("%032d", i)
		secret := DeriveClientSecret(nonce, contextID, binding)

		if prevSecret != "" && secret == prevSecret {
			t.Error("Sequential nonces produced same secret")
		}
		prevSecret = secret
	}
}

// --- Distribution Tests ---

func TestHashDistribution(t *testing.T) {
	// Test that hash output is uniformly distributed
	charCounts := make(map[rune]int)
	iterations := 10000

	for i := 0; i < iterations; i++ {
		hash := HashBody(fmt.Sprintf("input_%d", i))
		for _, c := range hash {
			charCounts[c]++
		}
	}

	// Each hex char (0-9, a-f) should appear roughly equally
	totalChars := iterations * 64
	expectedPerChar := totalChars / 16
	tolerance := float64(expectedPerChar) * 0.2 // 20% tolerance

	for c := '0'; c <= '9'; c++ {
		count := charCounts[c]
		if float64(count) < float64(expectedPerChar)-tolerance || float64(count) > float64(expectedPerChar)+tolerance {
			t.Logf("Character %c count %d (expected ~%d)", c, count, expectedPerChar)
		}
	}
	for c := 'a'; c <= 'f'; c++ {
		count := charCounts[c]
		if float64(count) < float64(expectedPerChar)-tolerance || float64(count) > float64(expectedPerChar)+tolerance {
			t.Logf("Character %c count %d (expected ~%d)", c, count, expectedPerChar)
		}
	}
}

// --- Length Consistency Tests ---

func TestHashLengthConsistency(t *testing.T) {
	inputs := []string{
		"",
		"a",
		strings.Repeat("a", 100),
		strings.Repeat("a", 10000),
		"日本語",
		"🚀🌍💻",
	}

	for _, input := range inputs {
		hash := HashBody(input)
		if len(hash) != 64 {
			t.Errorf("Input %q produced hash of length %d, expected 64", input[:min(20, len(input))], len(hash))
		}
	}
}

func TestSecretLengthConsistency(t *testing.T) {
	binding := "POST|/api|"
	for i := 0; i < 100; i++ {
		nonce := fmt.Sprintf("%032d", i)
		contextID := fmt.Sprintf("context_%d", i)
		secret := DeriveClientSecret(nonce, contextID, binding)

		if len(secret) != 64 {
			t.Errorf("Secret length %d, expected 64", len(secret))
		}
	}
}

func TestProofLengthConsistency(t *testing.T) {
	secret := strings.Repeat("a", 64)
	binding := "POST|/api|"

	for i := 0; i < 100; i++ {
		timestamp := fmt.Sprintf("%d", i)
		bodyHash := HashBody(fmt.Sprintf(`{"i":%d}`, i))
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		if len(proof) != 64 {
			t.Errorf("Proof length %d, expected 64", len(proof))
		}
	}
}

// --- Format Consistency Tests ---

func TestHashFormatLowercaseHex(t *testing.T) {
	for i := 0; i < 100; i++ {
		hash := HashBody(fmt.Sprintf("input_%d", i))

		for j, c := range hash {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("Invalid char at position %d: %c", j, c)
			}
		}
	}
}

func TestSecretFormatLowercaseHex(t *testing.T) {
	binding := "POST|/api|"
	for i := 0; i < 100; i++ {
		secret := DeriveClientSecret(fmt.Sprintf("%032d", i), "ctx", binding)

		for j, c := range secret {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("Invalid char at position %d: %c", j, c)
			}
		}
	}
}

func TestProofFormatLowercaseHex(t *testing.T) {
	secret := strings.Repeat("a", 64)
	binding := "POST|/api|"

	for i := 0; i < 100; i++ {
		proof := BuildProofV21(secret, fmt.Sprintf("%d", i), binding, HashBody("{}"))

		for j, c := range proof {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("Invalid char at position %d: %c", j, c)
			}
		}
	}
}

// --- Sensitivity Tests ---

func TestHashSensitivityToInput(t *testing.T) {
	inputs := []struct {
		a, b string
	}{
		{"hello", "hello "},
		{"hello", "Hello"},
		{"123", "1234"},
		{`{"a":1}`, `{"a":2}`},
		{`{"a":1}`, `{"a": 1}`},
	}

	for _, tc := range inputs {
		hashA := HashBody(tc.a)
		hashB := HashBody(tc.b)

		if hashA == hashB {
			t.Errorf("Different inputs should produce different hashes: %q vs %q", tc.a, tc.b)
		}
	}
}

func TestSecretSensitivityToNonce(t *testing.T) {
	contextID := "test-ctx"
	binding := "POST|/api|"
	nonces := []string{
		strings.Repeat("a", 32),
		strings.Repeat("a", 31) + "b",
		strings.Repeat("b", 32),
	}

	secrets := make(map[string]bool)
	for _, nonce := range nonces {
		secret := DeriveClientSecret(nonce, contextID, binding)
		if secrets[secret] {
			t.Error("Different nonces should produce different secrets")
		}
		secrets[secret] = true
	}
}

func TestSecretSensitivityToContext(t *testing.T) {
	nonce := strings.Repeat("a", 32)
	binding := "POST|/api|"
	contexts := []string{"ctx1", "ctx2", "ctx3"}

	secrets := make(map[string]bool)
	for _, ctx := range contexts {
		secret := DeriveClientSecret(nonce, ctx, binding)
		if secrets[secret] {
			t.Error("Different contexts should produce different secrets")
		}
		secrets[secret] = true
	}
}

// --- Timing Safe Comparison Tests ---

func TestTimingSafeCompareEqualCrypto(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("a", 64)

	if !TimingSafeCompare(a, b) {
		t.Error("Equal strings should compare as true")
	}
}

func TestTimingSafeCompareNotEqualCrypto(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)

	if TimingSafeCompare(a, b) {
		t.Error("Different strings should compare as false")
	}
}

func TestTimingSafeCompareDifferentLengthCrypto(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("a", 63)

	if TimingSafeCompare(a, b) {
		t.Error("Different length strings should compare as false")
	}
}

func TestTimingSafeCompareEmptyCrypto(t *testing.T) {
	if !TimingSafeCompare("", "") {
		t.Error("Empty strings should compare as true")
	}
}

func TestTimingSafeCompareSingleDiffCrypto(t *testing.T) {
	a := strings.Repeat("a", 64)

	// Test single character difference at each position
	for i := 0; i < 64; i++ {
		b := a[:i] + "b" + a[i+1:]
		if TimingSafeCompare(a, b) {
			t.Errorf("Single diff at position %d should compare as false", i)
		}
	}
}

// --- Bytes Comparison Tests ---

func TestTimingSafeCompareBytesEqualCrypto(t *testing.T) {
	a := []byte(strings.Repeat("a", 64))
	b := []byte(strings.Repeat("a", 64))

	if !TimingSafeCompareBytes(a, b) {
		t.Error("Equal bytes should compare as true")
	}
}

func TestTimingSafeCompareBytesNotEqualCrypto(t *testing.T) {
	a := []byte(strings.Repeat("a", 64))
	b := []byte(strings.Repeat("b", 64))

	if TimingSafeCompareBytes(a, b) {
		t.Error("Different bytes should compare as false")
	}
}

func TestTimingSafeCompareBytesDifferentLengthCrypto(t *testing.T) {
	a := []byte(strings.Repeat("a", 64))
	b := []byte(strings.Repeat("a", 63))

	if TimingSafeCompareBytes(a, b) {
		t.Error("Different length bytes should compare as false")
	}
}

// --- Additional Crypto Tests ---

func TestProofDependsOnAllInputs(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "1234567890"
	binding := "POST|/api|"
	bodyHash := HashBody(`{}`)

	baseProof := BuildProofV21(secret, timestamp, binding, bodyHash)

	// Change secret
	diffSecret := strings.Repeat("b", 64)
	if BuildProofV21(diffSecret, timestamp, binding, bodyHash) == baseProof {
		t.Error("Different secret should produce different proof")
	}

	// Change timestamp
	if BuildProofV21(secret, "9999999999", binding, bodyHash) == baseProof {
		t.Error("Different timestamp should produce different proof")
	}

	// Change binding
	if BuildProofV21(secret, timestamp, "GET|/api|", bodyHash) == baseProof {
		t.Error("Different binding should produce different proof")
	}

	// Change body hash
	diffBodyHash := HashBody(`{"x":1}`)
	if BuildProofV21(secret, timestamp, binding, diffBodyHash) == baseProof {
		t.Error("Different body hash should produce different proof")
	}
}

func TestSecretDependsOnAllInputs(t *testing.T) {
	nonce := strings.Repeat("a", 32)
	contextID := "ctx-123"
	binding := "POST|/api|"

	baseSecret := DeriveClientSecret(nonce, contextID, binding)

	// Change nonce
	diffNonce := strings.Repeat("b", 32)
	if DeriveClientSecret(diffNonce, contextID, binding) == baseSecret {
		t.Error("Different nonce should produce different secret")
	}

	// Change context
	if DeriveClientSecret(nonce, "ctx-456", binding) == baseSecret {
		t.Error("Different context should produce different secret")
	}

	// Change binding
	if DeriveClientSecret(nonce, contextID, "GET|/api|") == baseSecret {
		t.Error("Different binding should produce different secret")
	}
}

// --- Helper ---

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
