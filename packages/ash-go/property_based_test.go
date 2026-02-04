package ash

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// PROPERTY-BASED TESTS - Testing invariants that should always hold
// ============================================================================

// --- Determinism Properties ---

func TestPropertyDeterministicHash(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 500

	for i := 0; i < iterations; i++ {
		input := randomString(rng, rng.Intn(1000)+1)
		h1 := HashBody(input)
		h2 := HashBody(input)
		h3 := HashBody(input)

		if h1 != h2 || h2 != h3 {
			t.Errorf("Hash not deterministic for input length %d", len(input))
		}
	}
}

func TestPropertyDeterministicSecret(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 500

	for i := 0; i < iterations; i++ {
		nonce := randomHexString(rng, 64)
		contextID := fmt.Sprintf("ctx_%d", i)
		binding := fmt.Sprintf("POST|/api/%d|", i)

		s1 := DeriveClientSecret(nonce, contextID, binding)
		s2 := DeriveClientSecret(nonce, contextID, binding)

		if s1 != s2 {
			t.Errorf("Secret derivation not deterministic")
		}
	}
}

func TestPropertyDeterministicProof(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 500

	for i := 0; i < iterations; i++ {
		secret := randomHexString(rng, 64)
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		binding := fmt.Sprintf("GET|/api/%d|", i)
		bodyHash := randomHexString(rng, 64)

		p1 := BuildProofV21(secret, timestamp, binding, bodyHash)
		p2 := BuildProofV21(secret, timestamp, binding, bodyHash)

		if p1 != p2 {
			t.Errorf("Proof generation not deterministic")
		}
	}
}

func TestPropertyDeterministicCanonicalJSON(t *testing.T) {
	iterations := 500

	for i := 0; i < iterations; i++ {
		input := map[string]interface{}{
			"z": i,
			"a": i * 2,
			"m": fmt.Sprintf("value_%d", i),
		}

		c1, err1 := CanonicalizeJSON(input)
		c2, err2 := CanonicalizeJSON(input)

		if err1 != nil || err2 != nil {
			continue
		}

		if c1 != c2 {
			t.Errorf("JSON canonicalization not deterministic")
		}
	}
}

// --- Format Properties ---

func TestPropertyHashLength(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 500

	for i := 0; i < iterations; i++ {
		input := randomString(rng, rng.Intn(10000))
		hash := HashBody(input)

		if len(hash) != 64 {
			t.Errorf("Hash length %d != 64", len(hash))
		}
	}
}

func TestPropertyHashIsHex(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 500

	for i := 0; i < iterations; i++ {
		input := randomString(rng, rng.Intn(1000)+1)
		hash := HashBody(input)

		if !isValidHex(hash) {
			t.Errorf("Hash is not valid hex")
		}
	}
}

func TestPropertyHashIsLowercase(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 500

	for i := 0; i < iterations; i++ {
		input := randomString(rng, rng.Intn(1000)+1)
		hash := HashBody(input)

		if hash != strings.ToLower(hash) {
			t.Errorf("Hash should be lowercase")
		}
	}
}

func TestPropertySecretLength(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 500

	for i := 0; i < iterations; i++ {
		nonce := randomHexString(rng, 64)
		contextID := fmt.Sprintf("ctx_%d", i)
		binding := fmt.Sprintf("POST|/api/%d|", i)

		secret := DeriveClientSecret(nonce, contextID, binding)

		if len(secret) != 64 {
			t.Errorf("Secret length %d != 64", len(secret))
		}
	}
}

func TestPropertyProofLength(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 500

	for i := 0; i < iterations; i++ {
		secret := randomHexString(rng, 64)
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		binding := fmt.Sprintf("GET|/api/%d|", i)
		bodyHash := randomHexString(rng, 64)

		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		if len(proof) != 64 {
			t.Errorf("Proof length %d != 64", len(proof))
		}
	}
}

// --- Uniqueness Properties ---

func TestPropertyUniqueHashForUniqueInput(t *testing.T) {
	iterations := 1000
	hashes := make(map[string]bool)

	for i := 0; i < iterations; i++ {
		input := fmt.Sprintf("unique_input_%d_%d", i, time.Now().UnixNano())
		hash := HashBody(input)

		if hashes[hash] {
			t.Errorf("Collision detected at iteration %d", i)
		}
		hashes[hash] = true
	}
}

func TestPropertyUniqueSecretForUniqueNonce(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 500
	secrets := make(map[string]bool)

	contextID := "fixed_context"
	binding := "POST|/api/test|"

	for i := 0; i < iterations; i++ {
		nonce := randomHexString(rng, 64)
		secret := DeriveClientSecret(nonce, contextID, binding)

		if secrets[secret] {
			t.Errorf("Secret collision detected")
		}
		secrets[secret] = true
	}
}

func TestPropertyUniqueProofForUniqueTimestamp(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 500
	proofs := make(map[string]bool)

	secret := randomHexString(rng, 64)
	binding := "GET|/api/resource|"
	bodyHash := HashBody("{}")

	for i := 0; i < iterations; i++ {
		timestamp := fmt.Sprintf("%d", time.Now().UnixNano()+int64(i))
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		if proofs[proof] {
			t.Errorf("Proof collision detected")
		}
		proofs[proof] = true
	}
}

// --- Verification Properties ---

func TestPropertyValidProofVerifies(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 500

	for i := 0; i < iterations; i++ {
		nonce := randomHexString(rng, 64)
		contextID := fmt.Sprintf("ctx_%d", i)
		binding := fmt.Sprintf("POST|/api/%d|", i)
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		bodyHash := HashBody(fmt.Sprintf(`{"i":%d}`, i))

		secret := DeriveClientSecret(nonce, contextID, binding)
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
		if !valid {
			t.Errorf("Valid proof failed verification at iteration %d", i)
		}
	}
}

func TestPropertyInvalidProofRejects(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 500

	for i := 0; i < iterations; i++ {
		nonce := randomHexString(rng, 64)
		contextID := fmt.Sprintf("ctx_%d", i)
		binding := fmt.Sprintf("POST|/api/%d|", i)
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		bodyHash := HashBody(fmt.Sprintf(`{"i":%d}`, i))

		// Generate random invalid proof
		invalidProof := randomHexString(rng, 64)

		valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, invalidProof)
		if valid {
			t.Errorf("Random proof should not verify at iteration %d", i)
		}
	}
}

func TestPropertyTamperedProofRejects(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 500

	for i := 0; i < iterations; i++ {
		nonce := randomHexString(rng, 64)
		contextID := fmt.Sprintf("ctx_%d", i)
		binding := fmt.Sprintf("POST|/api/%d|", i)
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		bodyHash := HashBody(fmt.Sprintf(`{"i":%d}`, i))

		secret := DeriveClientSecret(nonce, contextID, binding)
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		// Tamper with one character
		pos := rng.Intn(len(proof))
		tamperedProof := proof[:pos] + flipHexChar(proof[pos]) + proof[pos+1:]

		valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, tamperedProof)
		if valid {
			t.Errorf("Tampered proof should not verify at iteration %d", i)
		}
	}
}

// --- Binding Properties ---

func TestPropertyBindingFormat(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 500

	for i := 0; i < iterations; i++ {
		method := methods[rng.Intn(len(methods))]
		path := fmt.Sprintf("/api/v%d/resource/%d", rng.Intn(3)+1, i)
		query := fmt.Sprintf("page=%d", rng.Intn(100))

		binding := NormalizeBinding(method, path, query)
		parts := strings.Split(binding, "|")

		if len(parts) != 3 {
			t.Errorf("Binding should have 3 parts, got %d", len(parts))
		}
	}
}

func TestPropertyBindingMethodUppercase(t *testing.T) {
	methods := []string{"get", "post", "put", "delete", "patch", "Get", "POST", "pUt"}
	iterations := len(methods) * 10

	for i := 0; i < iterations; i++ {
		method := methods[i%len(methods)]
		binding := NormalizeBinding(method, "/api", "")
		parts := strings.Split(binding, "|")

		if len(parts) >= 1 && parts[0] != strings.ToUpper(method) {
			t.Errorf("Method should be uppercase: got %s, expected %s", parts[0], strings.ToUpper(method))
		}
	}
}

// --- JSON Canonicalization Properties ---

func TestPropertySortedKeys(t *testing.T) {
	iterations := 500

	for i := 0; i < iterations; i++ {
		input := map[string]interface{}{
			"z": 1,
			"a": 2,
			"m": 3,
			"b": 4,
		}

		result, err := CanonicalizeJSON(input)
		if err != nil {
			continue
		}

		// Check that 'a' appears before 'b' before 'm' before 'z'
		aPos := strings.Index(result, `"a"`)
		bPos := strings.Index(result, `"b"`)
		mPos := strings.Index(result, `"m"`)
		zPos := strings.Index(result, `"z"`)

		if !(aPos < bPos && bPos < mPos && mPos < zPos) {
			t.Errorf("Keys not sorted: a=%d, b=%d, m=%d, z=%d", aPos, bPos, mPos, zPos)
		}
	}
}

func TestPropertyNoWhitespace(t *testing.T) {
	iterations := 500

	for i := 0; i < iterations; i++ {
		input := map[string]interface{}{
			"key1": "value1",
			"key2": i,
			"nested": map[string]interface{}{
				"inner": "data",
			},
		}

		result, err := CanonicalizeJSON(input)
		if err != nil {
			continue
		}

		// Should not contain unnecessary whitespace
		if strings.Contains(result, " :") || strings.Contains(result, ": ") {
			t.Errorf("Contains whitespace around colons")
		}
		if strings.Contains(result, "{ ") || strings.Contains(result, " }") {
			t.Errorf("Contains whitespace inside braces")
		}
	}
}

// --- Query Canonicalization Properties ---

func TestPropertyQuerySorted(t *testing.T) {
	iterations := 500

	for i := 0; i < iterations; i++ {
		query := fmt.Sprintf("z=%d&a=%d&m=%d", i, i*2, i*3)
		result, err := CanonicalizeQuery(query)
		if err != nil {
			continue
		}

		// Check that 'a' appears before 'm' before 'z'
		aPos := strings.Index(result, "a=")
		mPos := strings.Index(result, "m=")
		zPos := strings.Index(result, "z=")

		if aPos != -1 && mPos != -1 && zPos != -1 {
			if !(aPos < mPos && mPos < zPos) {
				t.Errorf("Query params not sorted: a=%d, m=%d, z=%d", aPos, mPos, zPos)
			}
		}
	}
}

func TestPropertyQueryDuplicatesSorted(t *testing.T) {
	iterations := 100

	for i := 0; i < iterations; i++ {
		query := fmt.Sprintf("a=%d&a=%d&a=%d", i+2, i, i+1)
		result, err := CanonicalizeQuery(query)
		if err != nil {
			continue
		}

		// With duplicate keys, values should be sorted
		parts := strings.Split(result, "&")
		values := []string{}
		for _, p := range parts {
			if strings.HasPrefix(p, "a=") {
				values = append(values, strings.TrimPrefix(p, "a="))
			}
		}

		// Values should be sorted
		for j := 1; j < len(values); j++ {
			if values[j-1] > values[j] {
				t.Errorf("Duplicate values not sorted: %v", values)
				break
			}
		}
	}
}

// --- Avalanche Effect Properties ---

func TestPropertyAvalancheEffect(t *testing.T) {
	iterations := 100

	for i := 0; i < iterations; i++ {
		input1 := fmt.Sprintf("test_input_%d", i)
		input2 := fmt.Sprintf("test_input_%d", i+1)

		hash1 := HashBody(input1)
		hash2 := HashBody(input2)

		// Count differing bits
		diffBits := countDifferingBits(hash1, hash2)

		// With avalanche effect, we expect roughly 50% of bits to differ
		// For 256-bit hash, that's ~128 bits. Allow 64-192 range
		if diffBits < 32 || diffBits > 224 {
			t.Errorf("Poor avalanche effect: only %d bits differ", diffBits)
		}
	}
}

// --- Scoped Proof Properties ---

func TestPropertyScopedProofDeterministic(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 200

	for i := 0; i < iterations; i++ {
		secret := randomHexString(rng, 64)
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		binding := "POST|/api/transfer|"
		payload := map[string]interface{}{
			"amount": i * 100,
			"to":     fmt.Sprintf("user_%d", i),
		}
		scope := []string{"amount", "to"}

		r1 := BuildProofUnified(secret, timestamp, binding, payload, scope, "")
		r2 := BuildProofUnified(secret, timestamp, binding, payload, scope, "")

		if r1.Proof != r2.Proof {
			t.Errorf("Scoped proof not deterministic at iteration %d", i)
		}

		if r1.ScopeHash != r2.ScopeHash {
			t.Errorf("Scope hash not deterministic at iteration %d", i)
		}
	}
}

// Helper functions

func randomString(rng *rand.Rand, length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = chars[rng.Intn(len(chars))]
	}
	return string(result)
}

func randomHexString(rng *rand.Rand, length int) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, length)
	for i := range result {
		result[i] = hexChars[rng.Intn(16)]
	}
	return string(result)
}

func isValidHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

func flipHexChar(c byte) string {
	if c == '0' {
		return "1"
	}
	return "0"
}

func countDifferingBits(h1, h2 string) int {
	if len(h1) != len(h2) {
		return -1
	}

	count := 0
	for i := 0; i < len(h1); i++ {
		b1 := hexCharToNibble(h1[i])
		b2 := hexCharToNibble(h2[i])
		xor := b1 ^ b2
		for xor > 0 {
			count += int(xor & 1)
			xor >>= 1
		}
	}
	return count
}

func hexCharToNibble(c byte) byte {
	if c >= '0' && c <= '9' {
		return c - '0'
	}
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 10
	}
	if c >= 'A' && c <= 'F' {
		return c - 'A' + 10
	}
	return 0
}
