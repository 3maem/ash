package ash

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// COMPREHENSIVE VERIFICATION TESTS
// ============================================================================

// --- Basic Verification Tests ---

func TestVerifyValidProofComprehensive(t *testing.T) {
	nonce := strings.Repeat("b", 32)
	contextID := "test-context"
	binding := "POST|/api/test|"
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
	bodyHash := HashBody(`{"key":"value"}`)

	// Derive secret and build proof
	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	// Verify using VerifyProofV21
	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)

	if !valid {
		t.Error("Valid proof should verify")
	}
}

func TestVerifyInvalidProofComprehensive(t *testing.T) {
	nonce := strings.Repeat("b", 32)
	contextID := "test-context"
	binding := "POST|/api/test|"
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
	bodyHash := HashBody(`{"key":"value"}`)

	proof := strings.Repeat("x", 64) // Invalid proof
	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)

	if valid {
		t.Error("Invalid proof should not verify")
	}
}

// --- Tampered Input Tests ---

func TestVerifyTamperedNonceComprehensive(t *testing.T) {
	nonce := strings.Repeat("b", 32)
	contextID := "test-context"
	binding := "POST|/api/test|"
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
	bodyHash := HashBody(`{"key":"value"}`)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	// Verify with different nonce
	wrongNonce := strings.Repeat("x", 32)
	valid := VerifyProofV21(wrongNonce, contextID, binding, timestamp, bodyHash, proof)

	if valid {
		t.Error("Proof should not verify with wrong nonce")
	}
}

func TestVerifyTamperedContextIDComprehensive(t *testing.T) {
	nonce := strings.Repeat("b", 32)
	contextID := "test-context"
	binding := "POST|/api/test|"
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
	bodyHash := HashBody(`{"key":"value"}`)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	// Verify with different context
	valid := VerifyProofV21(nonce, "wrong-context", binding, timestamp, bodyHash, proof)

	if valid {
		t.Error("Proof should not verify with wrong context ID")
	}
}

func TestVerifyTamperedTimestampComprehensive(t *testing.T) {
	nonce := strings.Repeat("b", 32)
	contextID := "test-context"
	binding := "POST|/api/test|"
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
	bodyHash := HashBody(`{"key":"value"}`)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	// Verify with different timestamp
	wrongTimestamp := fmt.Sprintf("%d", time.Now().UnixMilli()+10000)
	valid := VerifyProofV21(nonce, contextID, binding, wrongTimestamp, bodyHash, proof)

	if valid {
		t.Error("Proof should not verify with wrong timestamp")
	}
}

func TestVerifyTamperedBindingComprehensive(t *testing.T) {
	nonce := strings.Repeat("b", 32)
	contextID := "test-context"
	binding := "POST|/api/test|"
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
	bodyHash := HashBody(`{"key":"value"}`)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	// Verify with different binding
	valid := VerifyProofV21(nonce, contextID, "GET|/api/test|", timestamp, bodyHash, proof)

	if valid {
		t.Error("Proof should not verify with wrong binding")
	}
}

func TestVerifyTamperedBodyHashComprehensive(t *testing.T) {
	nonce := strings.Repeat("b", 32)
	contextID := "test-context"
	binding := "POST|/api/test|"
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
	bodyHash := HashBody(`{"key":"value"}`)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	// Verify with different body hash
	wrongBodyHash := HashBody(`{"key":"modified"}`)
	valid := VerifyProofV21(nonce, contextID, binding, timestamp, wrongBodyHash, proof)

	if valid {
		t.Error("Proof should not verify with wrong body hash")
	}
}

// --- Single Character Change Tests ---

func TestVerifySingleCharChangeInProofComprehensive(t *testing.T) {
	nonce := strings.Repeat("b", 32)
	contextID := "test-context"
	binding := "POST|/api/test|"
	timestamp := "1234567890"
	bodyHash := HashBody(`{"key":"value"}`)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	// Change single character in proof
	for i := 0; i < len(proof); i++ {
		newChar := "0"
		if proof[i] == '0' {
			newChar = "1"
		}
		wrongProof := proof[:i] + newChar + proof[i+1:]
		valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, wrongProof)
		if valid {
			t.Errorf("Proof should not verify with changed char at position %d", i)
		}
	}
}

// --- Empty and Edge Cases ---

func TestVerifyEmptyBodyComprehensive(t *testing.T) {
	nonce := strings.Repeat("b", 32)
	contextID := "test-context"
	binding := "POST|/api/test|"
	timestamp := "1234567890"
	bodyHash := HashBody("")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)
	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)

	if !valid {
		t.Error("Valid proof with empty body should verify")
	}
}

func TestVerifyEmptyObjectComprehensive(t *testing.T) {
	nonce := strings.Repeat("b", 32)
	contextID := "test-context"
	binding := "POST|/api/test|"
	timestamp := "1234567890"
	bodyHash := HashBody("{}")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)
	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)

	if !valid {
		t.Error("Valid proof with empty object should verify")
	}
}

// --- Multiple Verifications ---

func TestVerifyMultipleTimesComprehensive(t *testing.T) {
	nonce := strings.Repeat("b", 32)
	contextID := "test-context"
	binding := "POST|/api/test|"
	timestamp := "1234567890"
	bodyHash := HashBody(`{"key":"value"}`)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	// Verify multiple times
	for i := 0; i < 100; i++ {
		valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
		if !valid {
			t.Errorf("Verification %d failed unexpectedly", i)
		}
	}
}

// --- Different HTTP Methods ---

func TestVerifyDifferentMethodsComprehensive(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
	nonce := strings.Repeat("b", 32)
	contextID := "test-context"
	timestamp := "1234567890"
	bodyHash := HashBody(`{}`)

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			binding := method + "|/api/test|"
			secret := DeriveClientSecret(nonce, contextID, binding)
			proof := BuildProofV21(secret, timestamp, binding, bodyHash)
			valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)

			if !valid {
				t.Errorf("Proof for %s should verify", method)
			}

			// Verify wrong method fails
			wrongBinding := "OPTIONS|/api/test|"
			if method != "OPTIONS" {
				valid = VerifyProofV21(nonce, contextID, wrongBinding, timestamp, bodyHash, proof)
				if valid {
					t.Errorf("Proof should not verify with wrong method")
				}
			}
		})
	}
}

// --- Different Paths ---

func TestVerifyDifferentPathsComprehensive(t *testing.T) {
	paths := []string{
		"/api",
		"/api/users",
		"/api/users/123",
		"/api/v1/data",
		"/",
	}
	nonce := strings.Repeat("b", 32)
	contextID := "test-context"
	timestamp := "1234567890"
	bodyHash := HashBody(`{}`)

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			binding := "GET|" + path + "|"
			secret := DeriveClientSecret(nonce, contextID, binding)
			proof := BuildProofV21(secret, timestamp, binding, bodyHash)
			valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)

			if !valid {
				t.Errorf("Proof for path %s should verify", path)
			}
		})
	}
}

// --- Different Payloads ---

func TestVerifyDifferentPayloadsComprehensive(t *testing.T) {
	payloads := []string{
		`{}`,
		`{"a":1}`,
		`{"a":1,"b":2}`,
		`{"nested":{"key":"value"}}`,
		`[1,2,3]`,
		`"string"`,
		`null`,
		`true`,
		`false`,
		`123`,
	}
	nonce := strings.Repeat("b", 32)
	contextID := "test-context"
	binding := "POST|/api|"
	timestamp := "1234567890"

	for i, payload := range payloads {
		t.Run(fmt.Sprintf("payload_%d", i), func(t *testing.T) {
			bodyHash := HashBody(payload)
			secret := DeriveClientSecret(nonce, contextID, binding)
			proof := BuildProofV21(secret, timestamp, binding, bodyHash)
			valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)

			if !valid {
				t.Error("Proof should verify")
			}
		})
	}
}

// --- Unicode Content ---

func TestVerifyUnicodeContentComprehensive(t *testing.T) {
	payloads := []string{
		`{"name":"日本語"}`,
		`{"emoji":"🚀"}`,
		`{"mixed":"Hello 世界"}`,
		`{"arabic":"العربية"}`,
	}
	nonce := strings.Repeat("b", 32)
	contextID := "test-context"
	binding := "POST|/api|"
	timestamp := "1234567890"

	for i, payload := range payloads {
		t.Run(fmt.Sprintf("unicode_%d", i), func(t *testing.T) {
			bodyHash := HashBody(payload)
			secret := DeriveClientSecret(nonce, contextID, binding)
			proof := BuildProofV21(secret, timestamp, binding, bodyHash)
			valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)

			if !valid {
				t.Error("Proof with unicode should verify")
			}
		})
	}
}

// --- Large Payloads ---

func TestVerifyLargePayloadComprehensive(t *testing.T) {
	sizes := []int{1000, 10000, 100000}
	nonce := strings.Repeat("b", 32)
	contextID := "test-context"
	binding := "POST|/api|"
	timestamp := "1234567890"

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			payload := `{"data":"` + strings.Repeat("x", size) + `"}`
			bodyHash := HashBody(payload)
			secret := DeriveClientSecret(nonce, contextID, binding)
			proof := BuildProofV21(secret, timestamp, binding, bodyHash)
			valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)

			if !valid {
				t.Error("Proof with large payload should verify")
			}
		})
	}
}

// --- Concurrent Verification ---

func TestVerifyConcurrentComprehensive(t *testing.T) {
	nonce := strings.Repeat("b", 32)
	contextID := "test-context"
	binding := "POST|/api|"
	timestamp := "1234567890"
	bodyHash := HashBody(`{"key":"value"}`)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func() {
			valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
			if !valid {
				t.Error("Concurrent verification failed")
			}
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}

// --- Proof Format Verification ---

func TestVerifyProofFormatComprehensive(t *testing.T) {
	nonce := strings.Repeat("b", 32)
	contextID := "test-context"
	binding := "POST|/api|"
	timestamp := "1234567890"
	bodyHash := HashBody(`{}`)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	// Verify format
	if len(proof) != 64 {
		t.Errorf("Proof should be 64 chars, got %d", len(proof))
	}

	// Verify lowercase hex
	for _, c := range proof {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("Proof should be lowercase hex, found char: %c", c)
		}
	}
}

// --- Cross-Verification Tests ---

func TestVerifyDifferentNoncesProduceDifferentProofs(t *testing.T) {
	nonces := []string{
		strings.Repeat("a", 32),
		strings.Repeat("b", 32),
		strings.Repeat("c", 32),
	}
	contextID := "test-context"
	binding := "POST|/api|"
	timestamp := "1234567890"
	bodyHash := HashBody(`{}`)

	proofs := make(map[string]bool)
	for _, nonce := range nonces {
		secret := DeriveClientSecret(nonce, contextID, binding)
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)
		if proofs[proof] {
			t.Error("Different nonces should produce different proofs")
		}
		proofs[proof] = true
	}
}

func TestVerifyDifferentContextsProduceDifferentProofs(t *testing.T) {
	nonce := strings.Repeat("a", 32)
	contexts := []string{"ctx-1", "ctx-2", "ctx-3"}
	binding := "POST|/api|"
	timestamp := "1234567890"
	bodyHash := HashBody(`{}`)

	proofs := make(map[string]bool)
	for _, ctx := range contexts {
		secret := DeriveClientSecret(nonce, ctx, binding)
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)
		if proofs[proof] {
			t.Error("Different contexts should produce different proofs")
		}
		proofs[proof] = true
	}
}
