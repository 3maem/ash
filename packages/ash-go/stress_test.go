package ash

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// STRESS TESTS - High volume and concurrent operation testing
// ============================================================================

// --- High Volume Tests ---

func TestStressHighVolumeHashing(t *testing.T) {
	iterations := 10000

	for i := 0; i < iterations; i++ {
		input := fmt.Sprintf(`{"index":%d,"timestamp":%d}`, i, time.Now().UnixNano())
		hash := HashBody(input)

		if len(hash) != 64 {
			t.Errorf("Iteration %d: hash length %d != 64", i, len(hash))
		}
	}
}

func TestStressHighVolumeSecretDerivation(t *testing.T) {
	iterations := 5000
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < iterations; i++ {
		nonce := makeRandomHex(rng, 64)
		contextID := fmt.Sprintf("ctx_%d", i)
		binding := fmt.Sprintf("POST|/api/%d|", i)

		secret := DeriveClientSecret(nonce, contextID, binding)

		if len(secret) != 64 {
			t.Errorf("Iteration %d: secret length %d != 64", i, len(secret))
		}
	}
}

func TestStressHighVolumeProofGeneration(t *testing.T) {
	iterations := 5000
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < iterations; i++ {
		secret := makeRandomHex(rng, 64)
		timestamp := fmt.Sprintf("%d", time.Now().UnixNano())
		binding := fmt.Sprintf("GET|/api/%d|", i)
		bodyHash := makeRandomHex(rng, 64)

		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		if len(proof) != 64 {
			t.Errorf("Iteration %d: proof length %d != 64", i, len(proof))
		}
	}
}

func TestStressHighVolumeVerification(t *testing.T) {
	iterations := 5000
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < iterations; i++ {
		nonce := makeRandomHex(rng, 64)
		contextID := fmt.Sprintf("ctx_%d", i)
		binding := fmt.Sprintf("POST|/api/%d|", i)
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		bodyHash := HashBody(fmt.Sprintf(`{"i":%d}`, i))

		secret := DeriveClientSecret(nonce, contextID, binding)
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
		if !valid {
			t.Errorf("Iteration %d: valid proof failed verification", i)
		}
	}
}

func TestStressHighVolumeCanonicalizeJSON(t *testing.T) {
	iterations := 5000

	for i := 0; i < iterations; i++ {
		input := map[string]interface{}{
			"z": i,
			"a": i * 2,
			"m": fmt.Sprintf("value_%d", i),
			"nested": map[string]interface{}{
				"b": i,
				"a": i,
			},
		}

		result, err := CanonicalizeJSON(input)
		if err != nil {
			continue
		}

		if result == "" {
			t.Errorf("Iteration %d: empty result", i)
		}
	}
}

func TestStressHighVolumeQueryCanonicalization(t *testing.T) {
	iterations := 5000
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < iterations; i++ {
		numParams := rng.Intn(10) + 1
		params := make([]string, numParams)
		for j := 0; j < numParams; j++ {
			params[j] = fmt.Sprintf("key%d=value%d", rng.Intn(100), rng.Intn(100))
		}
		query := strings.Join(params, "&")

		result, err := CanonicalizeQuery(query)
		if err == nil && result == "" && query != "" {
			t.Errorf("Iteration %d: empty result for non-empty query", i)
		}
	}
}

// --- Concurrent Tests ---

func TestStressConcurrentHashing(t *testing.T) {
	numGoroutines := 100
	iterationsPerGoroutine := 100

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*iterationsPerGoroutine)

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < iterationsPerGoroutine; i++ {
				input := fmt.Sprintf(`{"goroutine":%d,"iteration":%d}`, gid, i)
				hash := HashBody(input)

				if len(hash) != 64 {
					errors <- fmt.Errorf("goroutine %d, iteration %d: hash length %d != 64", gid, i, len(hash))
				}
			}
		}(g)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

func TestStressConcurrentSecretDerivation(t *testing.T) {
	numGoroutines := 50
	iterationsPerGoroutine := 100

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*iterationsPerGoroutine)

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(gid)))

			for i := 0; i < iterationsPerGoroutine; i++ {
				nonce := makeRandomHex(rng, 64)
				contextID := fmt.Sprintf("ctx_%d_%d", gid, i)
				binding := fmt.Sprintf("POST|/api/%d/%d|", gid, i)

				secret := DeriveClientSecret(nonce, contextID, binding)

				if len(secret) != 64 {
					errors <- fmt.Errorf("goroutine %d, iteration %d: secret length %d != 64", gid, i, len(secret))
				}
			}
		}(g)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

func TestStressConcurrentProofGeneration(t *testing.T) {
	numGoroutines := 50
	iterationsPerGoroutine := 100

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*iterationsPerGoroutine)

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(gid)))

			for i := 0; i < iterationsPerGoroutine; i++ {
				secret := makeRandomHex(rng, 64)
				timestamp := fmt.Sprintf("%d", time.Now().UnixNano())
				binding := fmt.Sprintf("GET|/api/%d/%d|", gid, i)
				bodyHash := makeRandomHex(rng, 64)

				proof := BuildProofV21(secret, timestamp, binding, bodyHash)

				if len(proof) != 64 {
					errors <- fmt.Errorf("goroutine %d, iteration %d: proof length %d != 64", gid, i, len(proof))
				}
			}
		}(g)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

func TestStressConcurrentVerification(t *testing.T) {
	numGoroutines := 50
	iterationsPerGoroutine := 100

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*iterationsPerGoroutine)

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(gid)))

			for i := 0; i < iterationsPerGoroutine; i++ {
				nonce := makeRandomHex(rng, 64)
				contextID := fmt.Sprintf("ctx_%d_%d", gid, i)
				binding := fmt.Sprintf("POST|/api/%d/%d|", gid, i)
				timestamp := fmt.Sprintf("%d", time.Now().Unix())
				bodyHash := HashBody(fmt.Sprintf(`{"g":%d,"i":%d}`, gid, i))

				secret := DeriveClientSecret(nonce, contextID, binding)
				proof := BuildProofV21(secret, timestamp, binding, bodyHash)

				valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
				if !valid {
					errors <- fmt.Errorf("goroutine %d, iteration %d: valid proof failed verification", gid, i)
				}
			}
		}(g)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

func TestStressConcurrentJSONCanonicalizations(t *testing.T) {
	numGoroutines := 50
	iterationsPerGoroutine := 100

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*iterationsPerGoroutine)

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < iterationsPerGoroutine; i++ {
				input := map[string]interface{}{
					"goroutine": gid,
					"iteration": i,
					"data":      fmt.Sprintf("value_%d_%d", gid, i),
				}

				result, err := CanonicalizeJSON(input)
				if err != nil {
					continue
				}

				if result == "" {
					errors <- fmt.Errorf("goroutine %d, iteration %d: empty result", gid, i)
				}
			}
		}(g)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

// --- Mixed Operation Tests ---

func TestStressMixedOperations(t *testing.T) {
	numGoroutines := 20
	iterationsPerGoroutine := 50

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*iterationsPerGoroutine*5)

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(gid)))

			for i := 0; i < iterationsPerGoroutine; i++ {
				// Operation 1: Hash
				hash := HashBody(fmt.Sprintf(`{"g":%d,"i":%d}`, gid, i))
				if len(hash) != 64 {
					errors <- fmt.Errorf("hash error at %d:%d", gid, i)
				}

				// Operation 2: Secret derivation
				nonce := makeRandomHex(rng, 64)
				secret := DeriveClientSecret(nonce, fmt.Sprintf("ctx_%d", gid), "POST|/api|")
				if len(secret) != 64 {
					errors <- fmt.Errorf("secret error at %d:%d", gid, i)
				}

				// Operation 3: Proof generation
				proof := BuildProofV21(secret, fmt.Sprintf("%d", time.Now().UnixNano()), "POST|/api|", hash)
				if len(proof) != 64 {
					errors <- fmt.Errorf("proof error at %d:%d", gid, i)
				}

				// Operation 4: JSON canonicalization
				_, err := CanonicalizeJSON(map[string]interface{}{"g": gid, "i": i})
				if err != nil {
					// Skip errors
				}

				// Operation 5: Query canonicalization
				_, _ = CanonicalizeQuery(fmt.Sprintf("g=%d&i=%d", gid, i))
			}
		}(g)
	}

	wg.Wait()
	close(errors)

	errorCount := 0
	for err := range errors {
		errorCount++
		if errorCount <= 10 {
			t.Error(err)
		}
	}

	if errorCount > 10 {
		t.Errorf("... and %d more errors", errorCount-10)
	}
}

// --- Determinism Under Stress ---

func TestStressDeterminismUnderLoad(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "stress_test"
	binding := "POST|/api/stress|"
	timestamp := "1234567890"
	body := `{"stress":"test"}`
	bodyHash := HashBody(body)

	secret := DeriveClientSecret(nonce, contextID, binding)
	expectedProof := BuildProofV21(secret, timestamp, binding, bodyHash)

	numGoroutines := 100
	iterationsPerGoroutine := 100

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*iterationsPerGoroutine)

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < iterationsPerGoroutine; i++ {
				// All goroutines should get same result
				localSecret := DeriveClientSecret(nonce, contextID, binding)
				localProof := BuildProofV21(localSecret, timestamp, binding, bodyHash)

				if localProof != expectedProof {
					errors <- fmt.Errorf("goroutine %d, iteration %d: proof mismatch", gid, i)
				}
			}
		}(g)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

// --- Large Payload Stress ---

func TestStressLargePayloads(t *testing.T) {
	iterations := 100
	sizes := []int{1024, 10240, 102400} // 1KB, 10KB, 100KB

	for _, size := range sizes {
		for i := 0; i < iterations; i++ {
			payload := strings.Repeat("x", size)
			hash := HashBody(payload)

			if len(hash) != 64 {
				t.Errorf("Size %d, iteration %d: hash length %d != 64", size, i, len(hash))
			}
		}
	}
}

func TestStressLargeJSONPayloads(t *testing.T) {
	iterations := 50

	for i := 0; i < iterations; i++ {
		// Create payload with many keys
		numKeys := 100 + i
		payload := make(map[string]interface{})
		for j := 0; j < numKeys; j++ {
			payload[fmt.Sprintf("key_%d", j)] = fmt.Sprintf("value_%d", j)
		}

		result, err := CanonicalizeJSON(payload)
		if err != nil {
			continue
		}

		if result == "" {
			t.Errorf("Iteration %d: empty result for payload with %d keys", i, numKeys)
		}
	}
}

// --- Rapid Fire Tests ---

func TestStressRapidFireHashing(t *testing.T) {
	start := time.Now()
	iterations := 50000

	for i := 0; i < iterations; i++ {
		HashBody(fmt.Sprintf("%d", i))
	}

	elapsed := time.Since(start)
	t.Logf("Completed %d hash operations in %v", iterations, elapsed)
}

func TestStressRapidFireProofGeneration(t *testing.T) {
	secret := strings.Repeat("a", 64)
	binding := "POST|/api|"
	bodyHash := strings.Repeat("b", 64)

	start := time.Now()
	iterations := 50000

	for i := 0; i < iterations; i++ {
		BuildProofV21(secret, fmt.Sprintf("%d", i), binding, bodyHash)
	}

	elapsed := time.Since(start)
	t.Logf("Completed %d proof generations in %v", iterations, elapsed)
}

// --- Memory Pressure Tests ---

func TestStressMemoryPressure(t *testing.T) {
	// Generate many unique hashes
	hashes := make(map[string]bool)
	iterations := 10000

	for i := 0; i < iterations; i++ {
		hash := HashBody(fmt.Sprintf("unique_input_%d_%d", i, time.Now().UnixNano()))
		hashes[hash] = true
	}

	if len(hashes) != iterations {
		t.Logf("Generated %d unique hashes out of %d iterations", len(hashes), iterations)
	}
}

// --- Edge Case Stress ---

func TestStressEmptyInputs(t *testing.T) {
	iterations := 1000

	for i := 0; i < iterations; i++ {
		hash := HashBody("")
		if len(hash) != 64 {
			t.Errorf("Iteration %d: empty hash length %d != 64", i, len(hash))
		}

		result, _ := CanonicalizeJSON(map[string]interface{}{})
		if result != "{}" {
			t.Errorf("Iteration %d: empty object mismatch", i)
		}

		query, _ := CanonicalizeQuery("")
		if query != "" {
			t.Errorf("Iteration %d: empty query should be empty", i)
		}
	}
}

func TestStressSpecialCharacters(t *testing.T) {
	specialInputs := []string{
		"\x00\x01\x02\x03",
		"unicode: 日本語",
		"emoji: 😀🎉",
		"newlines:\n\r\n",
		"tabs:\t\t\t",
		"mixed: \x00日本😀\n\t",
	}

	iterations := 500

	for i := 0; i < iterations; i++ {
		for _, input := range specialInputs {
			hash := HashBody(input)
			if len(hash) != 64 {
				t.Errorf("Special input hash length %d != 64", len(hash))
			}
		}
	}
}

// --- Scoped Proof Stress ---

func TestStressScopedProofs(t *testing.T) {
	iterations := 1000
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < iterations; i++ {
		secret := makeRandomHex(rng, 64)
		timestamp := fmt.Sprintf("%d", time.Now().UnixNano())
		binding := fmt.Sprintf("POST|/api/%d|", i)
		payload := map[string]interface{}{
			"field1": i,
			"field2": i * 2,
			"field3": fmt.Sprintf("value_%d", i),
		}
		scope := []string{"field1", "field2"}

		result := BuildProofUnified(secret, timestamp, binding, payload, scope, "")

		if len(result.Proof) != 64 {
			t.Errorf("Iteration %d: scoped proof length %d != 64", i, len(result.Proof))
		}
	}
}

// --- Chain Proof Stress ---

func TestStressChainProofs(t *testing.T) {
	iterations := 500
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < iterations; i++ {
		secret := makeRandomHex(rng, 64)
		timestamp := fmt.Sprintf("%d", time.Now().UnixNano())
		binding := fmt.Sprintf("POST|/api/%d|", i)
		payload := map[string]interface{}{"i": i}
		previousProof := makeRandomHex(rng, 64)

		result := BuildProofUnified(secret, timestamp, binding, payload, nil, previousProof)

		if len(result.Proof) != 64 {
			t.Errorf("Iteration %d: chain proof length %d != 64", i, len(result.Proof))
		}
	}
}

// Helper
func makeRandomHex(rng *rand.Rand, length int) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, length)
	for i := range result {
		result[i] = hexChars[rng.Intn(16)]
	}
	return string(result)
}
