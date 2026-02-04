package ash

import (
	"fmt"
	"strings"
	"testing"
)

// Security-focused tests

// TestTimingAttackResistanceFirstCharDiff tests timing safe compare with first char different
func TestTimingAttackResistanceFirstCharDiff(t *testing.T) {
	secret := AshHashBody("actual_secret")
	modified := "x" + secret[1:]
	if AshTimingSafeCompare(secret, modified) {
		t.Error("Should detect first char difference")
	}
}

// TestTimingAttackResistanceLastCharDiff tests timing safe compare with last char different
func TestTimingAttackResistanceLastCharDiff(t *testing.T) {
	secret := AshHashBody("actual_secret")
	modified := secret[:len(secret)-1] + "x"
	if AshTimingSafeCompare(secret, modified) {
		t.Error("Should detect last char difference")
	}
}

// TestTimingAttackResistanceMiddleCharDiff tests timing safe compare with middle char different
func TestTimingAttackResistanceMiddleCharDiff(t *testing.T) {
	secret := AshHashBody("actual_secret")
	modified := secret[:32] + "x" + secret[33:]
	if AshTimingSafeCompare(secret, modified) {
		t.Error("Should detect middle char difference")
	}
}

// TestDetectsSingleBitChangeInProof tests detection of single bit change
func TestDetectsSingleBitChangeInProofSecurity(t *testing.T) {
	secret := "test-secret"
	timestamp := "1234567890"
	binding := "POST|/api|"
	bodyHash := AshHashBody("data")

	proof := AshBuildProofHMAC(secret, timestamp, binding, bodyHash)

	chars := []byte(proof)
	for i := 0; i < len(proof); i++ {
		tampered := make([]byte, len(chars))
		copy(tampered, chars)
		if tampered[i] == 'a' {
			tampered[i] = 'b'
		} else {
			tampered[i] = 'a'
		}
		tamperedProof := string(tampered)

		valid, err := AshVerifyProof("abcd1234abcd1234abcd1234abcd1234", "ctx123456789012345678901234567890", binding, timestamp, bodyHash, tamperedProof)
		if err != nil {
			t.Fatal(err)
		}
		if valid {
			t.Errorf("Should detect tampering at position %d", i)
		}
	}
}

// TestDetectsTimestampTamperingSecurity tests detection of timestamp tampering
func TestDetectsTimestampTamperingSecurity(t *testing.T) {
	binding := "POST|/api|"
	bodyHash := AshHashBody("data")

	originalTimestamp := "1234567890"
	nonce := "abcd1234abcd1234abcd1234abcd1234"
	contextID := "ctx123"
	clientSecret, err := AshDeriveClientSecret(nonce, contextID, binding)
	if err != nil {
		t.Fatal(err)
	}
	proof := AshBuildProofHMAC(clientSecret, originalTimestamp, binding, bodyHash)

	tamperedTimestamps := []string{
		"1234567891",
		"0000000000",
		"9999999999",
	}

	for _, tampered := range tamperedTimestamps {
		valid, err := AshVerifyProof(nonce, contextID, binding, tampered, bodyHash, proof)
		if err != nil {
			t.Fatal(err)
		}
		if valid {
			t.Errorf("Should detect timestamp tampering: %s", tampered)
		}
	}
}

// TestDetectsBindingTamperingSecurity tests detection of binding tampering
func TestDetectsBindingTamperingSecurity(t *testing.T) {
	timestamp := "1234567890"
	bodyHash := AshHashBody("data")

	originalBinding := "POST|/api/users|"
	nonce := "abcd1234abcd1234abcd1234abcd1234"
	contextID := "ctx123"
	clientSecret, err := AshDeriveClientSecret(nonce, contextID, originalBinding)
	if err != nil {
		t.Fatal(err)
	}
	proof := AshBuildProofHMAC(clientSecret, timestamp, originalBinding, bodyHash)

	tamperedBindings := []string{
		"GET|/api/users|",
		"POST|/api/admin|",
		"POST|/api/users|extra",
	}

	for _, tampered := range tamperedBindings {
		valid, err := AshVerifyProof(nonce, contextID, tampered, timestamp, bodyHash, proof)
		if err != nil {
			t.Fatal(err)
		}
		if valid {
			t.Errorf("Should detect binding tampering: %s", tampered)
		}
	}
}

// TestDetectsBodyTamperingSecurity tests detection of body tampering
func TestDetectsBodyTamperingSecurity(t *testing.T) {
	timestamp := "1234567890"
	binding := "POST|/api|"

	originalBody := `{"name":"John","action":"transfer"}`
	originalHash := AshHashBody(originalBody)
	nonce := "abcd1234abcd1234abcd1234abcd1234"
	contextID := "ctx123"
	clientSecret, err := AshDeriveClientSecret(nonce, contextID, binding)
	if err != nil {
		t.Fatal(err)
	}
	proof := AshBuildProofHMAC(clientSecret, timestamp, binding, originalHash)

	tamperedBodies := []string{
		`{"name":"Jane","action":"transfer"}`,
		`{"name":"John","action":"delete"}`,
		`{"name":"John","action":"transfer","extra":true}`,
	}

	for _, tampered := range tamperedBodies {
		tamperedHash := AshHashBody(tampered)
		valid, err := AshVerifyProof(nonce, contextID, binding, timestamp, tamperedHash, proof)
		if err != nil {
			t.Fatal(err)
		}
		if valid {
			t.Error("Should detect body tampering")
		}
	}
}

// TestReplayAttackSameInputsSameProofSecurity tests that same inputs produce same proof
func TestReplayAttackSameInputsSameProofSecurity(t *testing.T) {
	secret := "secret"
	timestamp := "1234567890"
	binding := "POST|/api|"
	bodyHash := "abc123"

	proof1 := AshBuildProofHMAC(secret, timestamp, binding, bodyHash)
	proof2 := AshBuildProofHMAC(secret, timestamp, binding, bodyHash)

	if proof1 != proof2 {
		t.Error("Same inputs should produce same proof")
	}
}

// TestDifferentContextsDifferentProofsSecurity tests different contexts produce different proofs
func TestDifferentContextsDifferentProofsSecurity(t *testing.T) {
	timestamp := "1234567890"
	binding := "POST|/api|"
	bodyHash := "abc123"

	secret1, err := AshDeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "ctx123456789012345678901234567890", binding)
	if err != nil {
		t.Fatal(err)
	}
	secret2, err := AshDeriveClientSecret("bcde2345bcde2345bcde2345bcde2345", "ctx234567890123456789012345678901", binding)
	if err != nil {
		t.Fatal(err)
	}

	proof1 := AshBuildProofHMAC(secret1, timestamp, binding, bodyHash)
	proof2 := AshBuildProofHMAC(secret2, timestamp, binding, bodyHash)

	if proof1 == proof2 {
		t.Error("Different contexts should produce different proofs")
	}
}

// TestClientSecretIsNotReversibleSecurity tests client secret is not reversible
func TestClientSecretIsNotReversibleSecurity(t *testing.T) {
	secret, err := AshDeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "ctx456789012345678901234567890123", "binding")
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(secret, "nonce123") {
		t.Error("Secret should not contain nonce")
	}
	if strings.Contains(secret, "ctx456") {
		t.Error("Secret should not contain context")
	}
}

// TestClientSecretHasHighEntropySecurity tests client secret has high entropy
func TestClientSecretHasHighEntropySecurity(t *testing.T) {
	secrets := make(map[string]bool)

	for i := 0; i < 100; i++ {
		secret, err := AshDeriveClientSecret(fmt.Sprintf("abcd1234abcd1234abcd1234abcd12%02d", i), fmt.Sprintf("ctx123456789012345678901234567%03d", i), "binding")
		if err != nil {
			t.Fatal(err)
		}
		if secrets[secret] {
			t.Error("Duplicate secret found")
		}
		secrets[secret] = true
	}

	if len(secrets) != 100 {
		t.Error("All secrets should be unique")
	}
}

// TestHashResistsCollisionsSecurity tests hash resists collisions
func TestHashResistsCollisionsSecurity(t *testing.T) {
	hashes := make(map[string]bool)

	for i := 0; i < 1000; i++ {
		hash := AshHashBody(fmt.Sprintf("input_%d", i))
		if hashes[hash] {
			t.Error("Hash collision found")
		}
		hashes[hash] = true
	}
}

// TestHashAvalancheEffectSecurity tests hash avalanche effect
func TestHashAvalancheEffectSecurity(t *testing.T) {
	hash1 := AshHashBody("test")
	hash2 := AshHashBody("test1")

	diffCount := 0
	for i := 0; i < 64; i++ {
		if hash1[i] != hash2[i] {
			diffCount++
		}
	}

	if diffCount < 20 {
		t.Errorf("Avalanche effect not sufficient: only %d chars different", diffCount)
	}
}

// TestHashPreimageResistanceSecurity tests hash preimage resistance
func TestHashPreimageResistanceSecurity(t *testing.T) {
	hash := AshHashBody("secret_data")

	if strings.Contains(hash, "secret") {
		t.Error("Hash should not reveal input")
	}
	if strings.Contains(hash, "data") {
		t.Error("Hash should not reveal input")
	}
}

// TestNullByteAttackSecurity tests null byte attack
func TestNullByteAttackSecurity(t *testing.T) {
	hash1 := AshHashBody("test\x00data")
	hash2 := AshHashBody("test")

	if hash1 == hash2 {
		t.Error("Null byte should not truncate")
	}
}

// TestNonceHasSufficientEntropySecurity tests nonce has sufficient entropy
func TestNonceHasSufficientEntropySecurity(t *testing.T) {
	nonces := make(map[string]bool)

	for i := 0; i < 1000; i++ {
		nonce, err := AshGenerateNonce(16)
		if err != nil {
			t.Errorf("Error generating nonce: %v", err)
		}
		if nonces[nonce] {
			t.Error("Duplicate nonce found")
		}
		nonces[nonce] = true
	}
}

// TestNonceHasMinimumLengthSecurity tests nonce has minimum length
func TestNonceHasMinimumLengthSecurity(t *testing.T) {
	for i := 0; i < 100; i++ {
		nonce, err := AshGenerateNonce(16)
		if err != nil {
			t.Errorf("Error generating nonce: %v", err)
		}
		if len(nonce) < 32 {
			t.Errorf("Nonce too short: %d", len(nonce))
		}
	}
}

// TestContextIdIsUniqueSecurity tests context ID is unique
func TestContextIdIsUniqueSecurity(t *testing.T) {
	ids := make(map[string]bool)

	for i := 0; i < 1000; i++ {
		id, err := AshGenerateContextID()
		if err != nil {
			t.Errorf("Error generating context ID: %v", err)
		}
		if ids[id] {
			t.Error("Duplicate context ID found")
		}
		ids[id] = true
	}
}

// TestBase64UrlIsUrlSafeSecurity tests base64url is url safe
func TestBase64UrlIsUrlSafeSecurity(t *testing.T) {
	testData := [][]byte{
		{0xfb, 0xff, 0xfe},
		{0x00, 0xff, 0x7f, 0x80},
	}

	for _, data := range testData {
		encoded := Base64URLEncode(data)

		if strings.Contains(encoded, "+") {
			t.Error("Base64URL should not contain +")
		}
		if strings.Contains(encoded, "/") {
			t.Error("Base64URL should not contain /")
		}
		if strings.Contains(encoded, "=") {
			t.Error("Base64URL should not contain =")
		}

		decoded, err := Base64URLDecode(encoded)
		if err != nil {
			t.Errorf("Decode error: %v", err)
		}
		if string(decoded) != string(data) {
			t.Error("Round trip failed")
		}
	}
}

// TestProofHasGoodDistributionSecurity tests proof has good distribution
func TestProofHasGoodDistributionSecurity(t *testing.T) {
	charCounts := make(map[rune]int)
	for _, c := range "0123456789abcdef" {
		charCounts[c] = 0
	}

	for i := 0; i < 100; i++ {
		proof := AshBuildProofHMAC(
			fmt.Sprintf("secret_%d", i),
			"1000000000",
			fmt.Sprintf("POST|/api/%d|", i),
			fmt.Sprintf("body_%d", i),
		)

		for _, c := range proof {
			charCounts[c]++
		}
	}

	for c, count := range charCounts {
		if count < 200 {
			t.Errorf("Character %c appears too infrequently: %d", c, count)
		}
		if count > 600 {
			t.Errorf("Character %c appears too frequently: %d", c, count)
		}
	}
}

// TestHmacProducesFixedLengthOutputSecurity tests HMAC produces fixed length output
func TestHmacProducesFixedLengthOutputSecurity(t *testing.T) {
	lengths := []int{1, 10, 100, 1000, 10000}

	for _, l := range lengths {
		proof := AshBuildProofHMAC(
			strings.Repeat("s", l),
			"1234567890",
			"POST|/api|",
			strings.Repeat("a", 64),
		)
		if len(proof) != 64 {
			t.Errorf("Expected 64 chars for secret length %d, got %d", l, len(proof))
		}
	}
}

// TestSmallInputChangeProducesDifferentOutputSecurity tests small input change produces different output
func TestSmallInputChangeProducesDifferentOutputSecurity(t *testing.T) {
	proof1 := AshBuildProofHMAC("secret", "1234567890", "POST|/api|", "abc123")
	proof2 := AshBuildProofHMAC("secret", "1234567891", "POST|/api|", "abc123")

	if proof1 == proof2 {
		t.Error("Different inputs should produce different outputs")
	}

	diffCount := 0
	for i := 0; i < len(proof1); i++ {
		if proof1[i] != proof2[i] {
			diffCount++
		}
	}

	if diffCount < 20 {
		t.Errorf("Avalanche effect not sufficient: %d chars different", diffCount)
	}
}
