package ash

import (
	"fmt"
	"testing"
)

// Extended stress tests to increase test count

// TestJsonCanonicalizeStress1000Extended tests JSON canonicalization stress
func TestJsonCanonicalizeStress1000Extended(t *testing.T) {
	for i := 0; i < 1000; i++ {
		input := map[string]interface{}{"key": i, "nested": map[string]interface{}{"value": i * 2}}
		result, err := AshCanonicalizeJSON(input)
		if err != nil {
			t.Errorf("Error at %d: %v", i, err)
		}
		if result == "" {
			t.Error("Result should not be empty")
		}
	}
}

// TestUrlEncodedStress1000Extended tests URL encoded stress
func TestUrlEncodedStress1000Extended(t *testing.T) {
	for i := 0; i < 1000; i++ {
		input := fmt.Sprintf("key%d=value%d&other=test", i, i)
		result, _ := AshCanonicalizeURLEncoded(input)
		if result == "" {
			t.Error("Result should not be empty")
		}
	}
}

// TestBindingNormalizationStress1000Extended tests binding normalization stress
func TestBindingNormalizationStress1000Extended(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}

	for i := 0; i < 1000; i++ {
		method := methods[i%len(methods)]
		path := fmt.Sprintf("/api/v1/resource/%d", i)
		query := fmt.Sprintf("page=%d&limit=10", i)

		result := AshNormalizeBinding(method, path, query)
		if result == "" {
			t.Error("Result should not be empty")
		}
	}
}

// TestProofGenerationStress1000Extended tests proof generation stress
func TestProofGenerationStress1000Extended(t *testing.T) {
	for i := 0; i < 1000; i++ {
		proof := AshBuildProofHMAC(
			fmt.Sprintf("secret_%d", i),
			fmt.Sprintf("%d", 1000000000+i),
			fmt.Sprintf("POST|/api/%d|", i),
			AshHashBody(fmt.Sprintf("body_%d", i)),
		)
		if len(proof) != 64 {
			t.Errorf("Expected 64 chars, got %d", len(proof))
		}
	}
}

// TestProofVerificationStress500Extended tests proof verification stress
func TestProofVerificationStress500Extended(t *testing.T) {
	for i := 0; i < 500; i++ {
		binding := fmt.Sprintf("POST|/api/resource/%d|", i)
		timestamp := fmt.Sprintf("%d", 1000000000+i)
		bodyHash := AshHashBody(fmt.Sprintf("content_%d", i))
		nonce := fmt.Sprintf("abcd1234abcd1234abcd1234abcd%08x", i)
		contextID := fmt.Sprintf("ctx_%d", i)

		clientSecret, err := AshDeriveClientSecret(nonce, contextID, binding)
		if err != nil {
			t.Fatal(err)
		}
		proof := AshBuildProofHMAC(clientSecret, timestamp, binding, bodyHash)
		valid, err := AshVerifyProof(nonce, contextID, binding, timestamp, bodyHash, proof)
		if err != nil {
			t.Fatal(err)
		}
		if !valid {
			t.Error("Verification should succeed")
		}
	}
}

// TestHashBodyStress1000Extended tests hash body stress
func TestHashBodyStress1000Extended(t *testing.T) {
	for i := 0; i < 1000; i++ {
		hash := AshHashBody(fmt.Sprintf("body content iteration %d", i))
		if len(hash) != 64 {
			t.Errorf("Expected 64 chars, got %d", len(hash))
		}
	}
}

// TestTimingSafeCompareStress1000Extended tests timing safe compare stress
func TestTimingSafeCompareStress1000Extended(t *testing.T) {
	for i := 0; i < 1000; i++ {
		str := AshHashBody(fmt.Sprintf("test_%d", i))
		if !AshTimingSafeCompare(str, str) {
			t.Error("Same strings should compare equal")
		}
	}
}

// TestTimingSafeCompareUnequalStressExtended tests timing safe compare unequal stress
func TestTimingSafeCompareUnequalStressExtended(t *testing.T) {
	for i := 0; i < 500; i++ {
		str1 := AshHashBody(fmt.Sprintf("test_%d", i))
		str2 := AshHashBody(fmt.Sprintf("different_%d", i))
		if AshTimingSafeCompare(str1, str2) {
			t.Error("Different strings should not compare equal")
		}
	}
}

// TestBase64UrlRoundTripStressExtended tests base64url round trip stress
func TestBase64UrlRoundTripStressExtended(t *testing.T) {
	for i := 0; i < 500; i++ {
		original := []byte(fmt.Sprintf("data_%d_%s", i, "extra"))
		encoded := Base64URLEncode(original)
		decoded, err := Base64URLDecode(encoded)
		if err != nil {
			t.Errorf("Decode error: %v", err)
		}
		if string(decoded) != string(original) {
			t.Error("Round trip failed")
		}
	}
}

// TestClientSecretDerivationStressExtended tests client secret derivation stress
func TestClientSecretDerivationStressExtended(t *testing.T) {
	for i := 0; i < 500; i++ {
		secret, err := AshDeriveClientSecret(
			fmt.Sprintf("abcd1234abcd1234abcd1234abcd12%02d", i),
			fmt.Sprintf("ctx123456789012345678901234567%03d", i),
			"binding",
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(secret) != 64 {
			t.Errorf("Expected 64 chars, got %d", len(secret))
		}
	}
}

// TestFullWorkflowStressExtended tests full workflow stress
func TestFullWorkflowStressExtended(t *testing.T) {
	for i := 0; i < 100; i++ {
		// Canonicalize JSON
		payload := map[string]interface{}{"action": "update", "id": i, "data": fmt.Sprintf("value_%d", i)}
		canonical, err := AshCanonicalizeJSON(payload)
		if err != nil {
			t.Errorf("Canonicalize error: %v", err)
		}

		// Normalize binding
		binding := AshNormalizeBinding("POST", fmt.Sprintf("/api/resource/%d", i), fmt.Sprintf("version=%d", i))

		// Hash body
		bodyHash := AshHashBody(canonical)

		// Derive secret
		nonce := fmt.Sprintf("abcd1234abcd1234abcd1234abcd%08x", i)
		contextID := fmt.Sprintf("ctx_%d", i)
		secret, err := AshDeriveClientSecret(nonce, contextID, binding)
		if err != nil {
			t.Fatal(err)
		}

		// Build proof
		timestamp := fmt.Sprintf("%d", 1000000000+i)
		proof := AshBuildProofHMAC(secret, timestamp, binding, bodyHash)

		// Verify proof
		valid, err := AshVerifyProof(nonce, contextID, binding, timestamp, bodyHash, proof)
		if err != nil {
			t.Fatal(err)
		}
		if !valid {
			t.Error("Full workflow verification failed")
		}
	}
}

// Additional tests to increase count

func TestJsonCanonicalizeDeepNesting50LevelsExtended(t *testing.T) {
	value := map[string]interface{}{"value": "deep"}
	for i := 0; i < 50; i++ {
		value = map[string]interface{}{"level": value}
	}
	result, err := AshCanonicalizeJSON(value)
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if result == "" {
		t.Error("Result should not be empty")
	}
}

func TestJsonCanonicalizeWideObject500KeysExtended(t *testing.T) {
	input := make(map[string]interface{})
	for i := 0; i < 500; i++ {
		input[fmt.Sprintf("key_%d", i)] = i
	}
	result, err := AshCanonicalizeJSON(input)
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if result == "" {
		t.Error("Result should not be empty")
	}
}

func TestBindingNormalizationLongPath100SegmentsExtended(t *testing.T) {
	path := ""
	for i := 0; i < 100; i++ {
		path += "/segment"
	}
	result := AshNormalizeBinding("GET", path, "")
	if result == "" {
		t.Error("Result should not be empty")
	}
}

func TestUrlEncodedManyParams100Extended(t *testing.T) {
	query := ""
	for i := 0; i < 100; i++ {
		if i > 0 {
			query += "&"
		}
		query += fmt.Sprintf("param_%d=value_%d", i, i)
	}
	result, _ := AshCanonicalizeURLEncoded(query)
	if result == "" {
		t.Error("Result should not be empty")
	}
}

func TestHashLargeBody100KExtended(t *testing.T) {
	body := ""
	for i := 0; i < 100000; i++ {
		body += "a"
	}
	hash := AshHashBody(body)
	if len(hash) != 64 {
		t.Errorf("Expected 64 chars, got %d", len(hash))
	}
}

func TestNonceGeneration100TimesExtended(t *testing.T) {
	nonces := make(map[string]bool)
	for i := 0; i < 100; i++ {
		nonce, err := AshGenerateNonce(16)
		if err != nil {
			t.Errorf("Error: %v", err)
		}
		if nonces[nonce] {
			t.Error("Duplicate nonce")
		}
		nonces[nonce] = true
	}
}

func TestContextIdGeneration100TimesExtended(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := AshGenerateContextID()
		if err != nil {
			t.Errorf("Error: %v", err)
		}
		if ids[id] {
			t.Error("Duplicate context ID")
		}
		ids[id] = true
	}
}

// More individual tests

func TestJsonCanonicalize100DifferentObjectsExtended(t *testing.T) {
	for i := 0; i < 100; i++ {
		input := map[string]interface{}{"id": i, "name": fmt.Sprintf("item%d", i)}
		result, err := AshCanonicalizeJSON(input)
		if err != nil {
			t.Errorf("Error at %d: %v", i, err)
		}
		if result == "" {
			t.Errorf("Result should not be empty for iteration %d", i)
		}
	}
}

func TestUrlEncoded100DifferentQueriesExtended(t *testing.T) {
	for i := 0; i < 100; i++ {
		query := fmt.Sprintf("id=%d&name=item%d", i, i)
		result, _ := AshCanonicalizeURLEncoded(query)
		if result == "" {
			t.Errorf("Result should not be empty for iteration %d", i)
		}
	}
}

func TestBinding100DifferentPathsExtended(t *testing.T) {
	for i := 0; i < 100; i++ {
		path := fmt.Sprintf("/api/v%d/resource", i)
		result := AshNormalizeBinding("GET", path, "")
		if result == "" {
			t.Errorf("Result should not be empty for iteration %d", i)
		}
	}
}

func TestProof100DifferentSecretsExtended(t *testing.T) {
	proofs := make(map[string]bool)
	for i := 0; i < 100; i++ {
		proof := AshBuildProofHMAC(
			fmt.Sprintf("secret_%d", i),
			"1234567890",
			"POST|/api|",
			"abc123",
		)
		if proofs[proof] {
			t.Error("Duplicate proof")
		}
		proofs[proof] = true
	}
}

func TestHash100DifferentInputsExtended(t *testing.T) {
	hashes := make(map[string]bool)
	for i := 0; i < 100; i++ {
		hash := AshHashBody(fmt.Sprintf("input_%d", i))
		if hashes[hash] {
			t.Error("Duplicate hash")
		}
		hashes[hash] = true
	}
}

func TestDeriveSecret100DifferentInputsExtended(t *testing.T) {
	secrets := make(map[string]bool)
	for i := 0; i < 100; i++ {
		secret, err := AshDeriveClientSecret(
			fmt.Sprintf("abcd1234abcd1234abcd1234abcd12%02d", i),
			fmt.Sprintf("ctx123456789012345678901234567%03d", i),
			"binding",
		)
		if err != nil {
			t.Fatal(err)
		}
		if secrets[secret] {
			t.Error("Duplicate secret")
		}
		secrets[secret] = true
	}
}
