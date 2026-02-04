package ash

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// ============================================================================
// DEEP FUZZER TESTS - High iteration fuzzing for robustness
// ============================================================================

func TestFuzzProofGeneration(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 1000

	for i := 0; i < iterations; i++ {
		nonce := randomHex(rng, 64)
		contextID := fmt.Sprintf("ctx_%d", i)
		binding := fmt.Sprintf("POST|/api/test/%d|", i)
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		bodyHash := HashBody(fmt.Sprintf(`{"i":%d}`, i))

		secret := DeriveClientSecret(nonce, contextID, binding)
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		if len(proof) != 64 {
			t.Errorf("Iteration %d: proof length %d != 64", i, len(proof))
		}
		if !isHexString(proof) {
			t.Errorf("Iteration %d: proof not hex", i)
		}
	}
}

func TestFuzzProofVerification(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 1000

	for i := 0; i < iterations; i++ {
		nonce := randomHex(rng, 64)
		contextID := fmt.Sprintf("ctx_%d", i)
		binding := fmt.Sprintf("GET|/api/resource/%d|", i)
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		bodyHash := HashBody("")

		secret := DeriveClientSecret(nonce, contextID, binding)
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
		if !valid {
			t.Errorf("Iteration %d: valid proof failed verification", i)
		}

		// Tamper with proof
		tamperedProof := proof[:len(proof)-1] + "0"
		if tamperedProof == proof {
			tamperedProof = proof[:len(proof)-1] + "1"
		}
		invalid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, tamperedProof)
		if invalid {
			t.Errorf("Iteration %d: tampered proof passed verification", i)
		}
	}
}

func TestFuzzJSONCanonicalizations(t *testing.T) {
	iterations := 1000

	for i := 0; i < iterations; i++ {
		// Test various JSON structures
		testCases := []interface{}{
			map[string]interface{}{"a": i, "b": i * 2},
			map[string]interface{}{"z": i, "a": i, "m": i},
			[]interface{}{i, i + 1, i + 2},
			map[string]interface{}{
				"nested": map[string]interface{}{
					"value": i,
				},
			},
		}

		for _, tc := range testCases {
			result1, err1 := CanonicalizeJSON(tc)
			result2, err2 := CanonicalizeJSON(tc)

			if err1 != nil || err2 != nil {
				continue // Skip invalid inputs
			}

			if result1 != result2 {
				t.Errorf("Iteration %d: non-deterministic canonicalization", i)
			}
		}
	}
}

func TestFuzzQueryCanonicalization(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 1000

	for i := 0; i < iterations; i++ {
		// Generate random query strings
		numParams := rng.Intn(10) + 1
		params := make([]string, numParams)
		for j := 0; j < numParams; j++ {
			key := fmt.Sprintf("key%d", rng.Intn(100))
			value := fmt.Sprintf("value%d", rng.Intn(100))
			params[j] = key + "=" + value
		}
		query := strings.Join(params, "&")

		result1, err1 := CanonicalizeQuery(query)
		result2, err2 := CanonicalizeQuery(query)

		if err1 != nil || err2 != nil {
			continue // Skip errors
		}

		if result1 != result2 {
			t.Errorf("Iteration %d: non-deterministic query canonicalization", i)
		}
	}
}

func TestFuzzBindingNormalization(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 1000

	for i := 0; i < iterations; i++ {
		method := methods[rng.Intn(len(methods))]
		path := fmt.Sprintf("/api/v%d/resource/%d", rng.Intn(3)+1, i)
		query := fmt.Sprintf("page=%d&limit=%d", rng.Intn(100), rng.Intn(50))

		result1 := NormalizeBinding(method, path, query)
		result2 := NormalizeBinding(method, path, query)

		if result1 != result2 {
			t.Errorf("Iteration %d: non-deterministic binding normalization", i)
		}

		// Verify format
		parts := strings.Split(result1, "|")
		if len(parts) != 3 {
			t.Errorf("Iteration %d: binding should have 3 parts", i)
		}
	}
}

func TestFuzzHashBodyConsistency(t *testing.T) {
	iterations := 1000

	for i := 0; i < iterations; i++ {
		body := fmt.Sprintf(`{"index":%d,"data":"test_%d"}`, i, i*2)

		hash1 := HashBody(body)
		hash2 := HashBody(body)

		if hash1 != hash2 {
			t.Errorf("Iteration %d: non-deterministic hashing", i)
		}

		if len(hash1) != 64 {
			t.Errorf("Iteration %d: hash length %d != 64", i, len(hash1))
		}
	}
}

func TestFuzzClientSecretDerivation(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 1000

	for i := 0; i < iterations; i++ {
		nonce := randomHex(rng, 64)
		contextID := fmt.Sprintf("ash_ctx_%d", i)
		binding := fmt.Sprintf("POST|/api/action/%d|", i)

		secret1 := DeriveClientSecret(nonce, contextID, binding)
		secret2 := DeriveClientSecret(nonce, contextID, binding)

		if secret1 != secret2 {
			t.Errorf("Iteration %d: non-deterministic secret derivation", i)
		}

		if len(secret1) != 64 {
			t.Errorf("Iteration %d: secret length %d != 64", i, len(secret1))
		}
	}
}

func TestFuzzTimingSafeCompare(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 1000

	for i := 0; i < iterations; i++ {
		length := rng.Intn(100) + 10
		a := randomHex(rng, length)
		b := randomHex(rng, length)

		// Same strings should be equal
		if !TimingSafeCompare(a, a) {
			t.Errorf("Iteration %d: same string comparison failed", i)
		}

		// Different strings should not be equal (usually)
		if a != b && TimingSafeCompare(a, b) {
			t.Errorf("Iteration %d: different strings compared equal", i)
		}
	}
}

func TestFuzzScopedProofGeneration(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 500

	for i := 0; i < iterations; i++ {
		nonce := randomHex(rng, 64)
		contextID := fmt.Sprintf("ctx_%d", i)
		binding := "POST|/api/transfer|"
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		payload := map[string]interface{}{
			"amount":    i * 100,
			"recipient": fmt.Sprintf("user_%d", i),
			"memo":      fmt.Sprintf("test_%d", i),
		}
		scope := []string{"amount", "recipient"}

		secret := DeriveClientSecret(nonce, contextID, binding)
		result := BuildProofUnified(secret, timestamp, binding, payload, scope, "")

		if len(result.Proof) != 64 {
			t.Errorf("Iteration %d: proof length %d != 64", i, len(result.Proof))
		}

		if len(scope) > 0 && len(result.ScopeHash) != 64 {
			t.Errorf("Iteration %d: scope hash length %d != 64", i, len(result.ScopeHash))
		}
	}
}

func TestFuzzURLEncodedCanonicalization(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 1000

	for i := 0; i < iterations; i++ {
		numParams := rng.Intn(5) + 1
		params := make([]string, numParams)
		for j := 0; j < numParams; j++ {
			key := fmt.Sprintf("field%d", rng.Intn(20))
			value := fmt.Sprintf("val%d", rng.Intn(100))
			params[j] = key + "=" + value
		}
		input := strings.Join(params, "&")

		result1, err1 := CanonicalizeURLEncoded(input)
		result2, err2 := CanonicalizeURLEncoded(input)

		if err1 != nil || err2 != nil {
			continue // Skip errors
		}

		if result1 != result2 {
			t.Errorf("Iteration %d: non-deterministic URL encoding", i)
		}
	}
}

func TestFuzzUnicodeHandling(t *testing.T) {
	unicodeStrings := []string{
		"hello",
		"héllo",
		"日本語",
		"emoji 😀",
		"mixed café 日本",
		"special\t\n\r",
		"quotes\"and'stuff",
	}

	for i, s := range unicodeStrings {
		input := map[string]interface{}{"text": s}
		result1, err1 := CanonicalizeJSON(input)
		result2, err2 := CanonicalizeJSON(input)

		if err1 != nil || err2 != nil {
			continue
		}

		if result1 != result2 {
			t.Errorf("Unicode test %d: non-deterministic for %q", i, s)
		}

		if !utf8.ValidString(result1) {
			t.Errorf("Unicode test %d: invalid UTF-8 output", i)
		}
	}
}

func TestFuzzEmptyAndNullValues(t *testing.T) {
	testCases := []interface{}{
		map[string]interface{}{},
		map[string]interface{}{"empty": ""},
		map[string]interface{}{"null": nil},
		[]interface{}{},
		map[string]interface{}{"arr": []interface{}{}},
	}

	for i, tc := range testCases {
		result1, err1 := CanonicalizeJSON(tc)
		result2, err2 := CanonicalizeJSON(tc)

		if err1 != nil || err2 != nil {
			continue
		}

		if result1 != result2 {
			t.Errorf("Empty/null test %d: non-deterministic", i)
		}
	}
}

func TestFuzzLargePayloads(t *testing.T) {
	iterations := 100

	for i := 0; i < iterations; i++ {
		// Create large nested structure
		size := (i + 1) * 10
		data := make(map[string]interface{})
		for j := 0; j < size; j++ {
			data[fmt.Sprintf("key_%d", j)] = fmt.Sprintf("value_%d", j)
		}

		result1, err1 := CanonicalizeJSON(data)
		result2, err2 := CanonicalizeJSON(data)

		if err1 != nil || err2 != nil {
			continue
		}

		if result1 != result2 {
			t.Errorf("Large payload test %d: non-deterministic", i)
		}
	}
}

func TestFuzzSpecialCharactersInQuery(t *testing.T) {
	specialChars := []string{
		"a=1&b=2",
		"key=hello%20world",
		"name=John+Doe",
		"path=%2Ffoo%2Fbar",
		"unicode=%E6%97%A5%E6%9C%AC",
	}

	for i, query := range specialChars {
		result1, err1 := CanonicalizeQuery(query)
		result2, err2 := CanonicalizeQuery(query)

		if err1 != nil || err2 != nil {
			continue // Skip errors
		}

		if result1 != result2 {
			t.Errorf("Special char test %d: non-deterministic for %q", i, query)
		}
	}
}

func TestFuzzProofDifferentInputs(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	iterations := 500

	proofs := make(map[string]bool)

	for i := 0; i < iterations; i++ {
		nonce := randomHex(rng, 64)
		contextID := fmt.Sprintf("ctx_%d_%d", i, rng.Intn(1000))
		binding := fmt.Sprintf("POST|/api/%d|", i)
		timestamp := fmt.Sprintf("%d", time.Now().Unix()+int64(i))
		bodyHash := HashBody(fmt.Sprintf(`{"unique":%d}`, i))

		secret := DeriveClientSecret(nonce, contextID, binding)
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		if proofs[proof] {
			t.Errorf("Iteration %d: duplicate proof generated", i)
		}
		proofs[proof] = true
	}
}

// Helper functions
func randomHex(rng *rand.Rand, length int) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, length)
	for i := range result {
		result[i] = hexChars[rng.Intn(16)]
	}
	return string(result)
}

func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
