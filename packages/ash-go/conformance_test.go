package ash

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// CONFORMANCE TESTS - ASH v2.3.1 Specification Compliance
// ============================================================================

// --- JCS Vectors (JSON Canonicalization Scheme - RFC 8785) ---

func TestJCSSimpleObject(t *testing.T) {
	input := map[string]interface{}{"b": 2, "a": 1}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"a":1,"b":2}`
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestJCSNestedObject(t *testing.T) {
	input := map[string]interface{}{
		"z": map[string]interface{}{"b": 2, "a": 1},
		"a": 0,
	}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"a":0,"z":{"a":1,"b":2}}`
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestJCSArrayPreservesOrder(t *testing.T) {
	input := map[string]interface{}{"items": []interface{}{3, 1, 2}}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"items":[3,1,2]}`
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestJCSUnicodeEmoji(t *testing.T) {
	input := map[string]interface{}{"emoji": "😀", "text": "hello"}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"emoji":"😀","text":"hello"}`
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestJCSNumberFormats(t *testing.T) {
	input := map[string]interface{}{
		"int":      42,
		"float":    3.14,
		"negative": -5,
		"zero":     0,
	}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"float":3.14,"int":42,"negative":-5,"zero":0}`
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestJCSEmptyObject(t *testing.T) {
	input := map[string]interface{}{}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{}`
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestJCSNullAndBooleans(t *testing.T) {
	input := map[string]interface{}{
		"null_val":  nil,
		"true_val":  true,
		"false_val": false,
	}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"false_val":false,"null_val":null,"true_val":true}`
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestJCSEmptyString(t *testing.T) {
	input := map[string]interface{}{"empty": "", "space": " "}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"empty":"","space":" "}`
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestJCSDeepNesting(t *testing.T) {
	input := map[string]interface{}{
		"a": map[string]interface{}{
			"b": map[string]interface{}{
				"c": map[string]interface{}{"d": 1},
			},
		},
	}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"a":{"b":{"c":{"d":1}}}}`
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestJCSMixedArray(t *testing.T) {
	input := map[string]interface{}{
		"arr": []interface{}{1, "two", true, nil, map[string]interface{}{"x": 1}},
	}
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"arr":[1,"two",true,null,{"x":1}]}`
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

// --- Query Vectors ---

func TestQuerySimpleSort(t *testing.T) {
	result, err := CanonicalizeQuery("b=2&a=1")
	if err != nil {
		t.Fatalf("CanonicalizeQuery failed: %v", err)
	}
	expected := "a=1&b=2"
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestQueryDuplicateKeysSorted(t *testing.T) {
	result, err := CanonicalizeQuery("z=3&a=1&z=2&z=1")
	if err != nil {
		t.Fatalf("CanonicalizeQuery failed: %v", err)
	}
	expected := "a=1&z=1&z=2&z=3"
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestQueryPercentEncodingUppercase(t *testing.T) {
	result, err := CanonicalizeQuery("path=%2ffoo%2fbar")
	if err != nil {
		t.Fatalf("CanonicalizeQuery failed: %v", err)
	}
	expected := "path=%2Ffoo%2Fbar"
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestQueryEmptyValue(t *testing.T) {
	result, err := CanonicalizeQuery("a=&b=1")
	if err != nil {
		t.Fatalf("CanonicalizeQuery failed: %v", err)
	}
	expected := "a=&b=1"
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestQueryNoValue(t *testing.T) {
	result, err := CanonicalizeQuery("flag&name=test")
	if err != nil {
		t.Fatalf("CanonicalizeQuery failed: %v", err)
	}
	expected := "flag=&name=test"
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestQueryEmptyString(t *testing.T) {
	result, err := CanonicalizeQuery("")
	if err != nil {
		t.Fatalf("CanonicalizeQuery failed: %v", err)
	}
	expected := ""
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestQueryCaseSensitiveKeys(t *testing.T) {
	result, err := CanonicalizeQuery("A=1&a=2&B=3")
	if err != nil {
		t.Fatalf("CanonicalizeQuery failed: %v", err)
	}
	expected := "A=1&B=3&a=2"
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

// --- Binding Vectors ---

func TestBindingPostNoQuery(t *testing.T) {
	result := NormalizeBinding("POST", "/api/users", "")
	expected := "POST|/api/users|"
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestBindingGetWithQuery(t *testing.T) {
	result := NormalizeBinding("GET", "/api/users", "limit=10&offset=0")
	expected := "GET|/api/users|limit=10&offset=0"
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestBindingDeleteWithId(t *testing.T) {
	result := NormalizeBinding("DELETE", "/api/users/123", "")
	expected := "DELETE|/api/users/123|"
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestBindingQueryMustBeCanonical(t *testing.T) {
	result := NormalizeBinding("GET", "/search", "z=1&a=2")
	expected := "GET|/search|a=2&z=1"
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestBindingPutWithQuery(t *testing.T) {
	result := NormalizeBinding("PUT", "/api/items/456", "force=true")
	expected := "PUT|/api/items/456|force=true"
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestBindingPatch(t *testing.T) {
	result := NormalizeBinding("PATCH", "/api/config", "")
	expected := "PATCH|/api/config|"
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestBindingMethodUppercase(t *testing.T) {
	result := NormalizeBinding("post", "/api/data", "")
	expected := "POST|/api/data|"
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

// --- Proof Vectors ---

func TestProofBasic(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx_test_001"
	binding := "POST|/api/login|"
	timestamp := "1737331200"
	bodyHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	if len(proof) != 64 {
		t.Errorf("Proof length %d != 64", len(proof))
	}

	// Verify roundtrip
	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("Valid proof failed verification")
	}
}

func TestProofScoped(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx_test_002"
	binding := "POST|/api/transfer|"
	timestamp := "1737331200"
	payload := map[string]interface{}{
		"amount":    100,
		"recipient": "user123",
		"notes":     "ignore this",
	}
	scope := []string{"amount", "recipient"}

	secret := DeriveClientSecret(nonce, contextID, binding)
	result := BuildProofUnified(secret, timestamp, binding, payload, scope, "")

	if len(result.Proof) != 64 {
		t.Errorf("Proof length %d != 64", len(result.Proof))
	}

	if len(result.ScopeHash) != 64 {
		t.Errorf("Scope hash length %d != 64", len(result.ScopeHash))
	}
}

func TestProofChained(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx_test_003"
	binding := "POST|/api/checkout|"
	timestamp := "1737331200"
	payload := map[string]interface{}{}
	prevProof := strings.Repeat("c", 64)

	secret := DeriveClientSecret(nonce, contextID, binding)
	result := BuildProofUnified(secret, timestamp, binding, payload, nil, prevProof)

	if len(result.Proof) != 64 {
		t.Errorf("Proof length %d != 64", len(result.Proof))
	}

	if len(result.ChainHash) != 64 {
		t.Errorf("Chain hash length %d != 64", len(result.ChainHash))
	}
}

func TestProofUnified(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx_test_004"
	binding := "POST|/api/payment|"
	timestamp := "1737331200"
	payload := map[string]interface{}{
		"amount":   500,
		"currency": "USD",
	}
	scope := []string{"amount", "currency"}
	prevProof := strings.Repeat("c", 64)

	secret := DeriveClientSecret(nonce, contextID, binding)
	result := BuildProofUnified(secret, timestamp, binding, payload, scope, prevProof)

	if len(result.Proof) != 64 {
		t.Errorf("Proof length %d != 64", len(result.Proof))
	}

	if len(result.ScopeHash) != 64 {
		t.Errorf("Scope hash length %d != 64", len(result.ScopeHash))
	}

	if len(result.ChainHash) != 64 {
		t.Errorf("Chain hash length %d != 64", len(result.ChainHash))
	}
}

// --- Hash Vectors ---

func TestHashEmptyObject(t *testing.T) {
	canonical, _ := CanonicalizeJSON(map[string]interface{}{})
	hash := HashBody(canonical)
	expected := "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	if hash != expected {
		t.Errorf("Got %s, expected %s", hash, expected)
	}
}

func TestHashEmptyString(t *testing.T) {
	hash := HashBody("")
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hash != expected {
		t.Errorf("Got %s, expected %s", hash, expected)
	}
}

// --- Mode Vectors ---

func TestModeStrict(t *testing.T) {
	if !IsValidMode("strict") {
		t.Error("strict should be valid mode")
	}
}

func TestModeBalanced(t *testing.T) {
	if !IsValidMode("balanced") {
		t.Error("balanced should be valid mode")
	}
}

func TestModeMinimal(t *testing.T) {
	if !IsValidMode("minimal") {
		t.Error("minimal should be valid mode")
	}
}

func TestModeInvalid(t *testing.T) {
	if IsValidMode("invalid") {
		t.Error("invalid should not be valid mode")
	}
}

// --- Chain Vectors ---

func TestChainFirstRequest(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx_chain"
	binding := "POST|/api/cart|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	payload := map[string]interface{}{}

	secret := DeriveClientSecret(nonce, contextID, binding)
	result := BuildProofUnified(secret, timestamp, binding, payload, nil, "")

	if len(result.Proof) != 64 {
		t.Errorf("Proof length %d != 64", len(result.Proof))
	}

	if result.ChainHash != "" {
		t.Error("First step should have empty chain hash")
	}
}

func TestChainSecondRequest(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx_chain"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	payload := map[string]interface{}{}

	// Step 1
	binding1 := "POST|/api/cart|"
	secret1 := DeriveClientSecret(nonce, contextID, binding1)
	result1 := BuildProofUnified(secret1, timestamp, binding1, payload, nil, "")

	// Step 2
	binding2 := "POST|/api/checkout|"
	secret2 := DeriveClientSecret(nonce, contextID, binding2)
	result2 := BuildProofUnified(secret2, timestamp, binding2, payload, nil, result1.Proof)

	if result2.ChainHash == "" {
		t.Error("Second step should have chain hash")
	}

	if len(result2.ChainHash) != 64 {
		t.Errorf("Chain hash length %d != 64", len(result2.ChainHash))
	}
}

func TestChainCompleteFlow(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx_flow"
	payload := map[string]interface{}{}

	// Step 1: Cart
	binding1 := "POST|/api/cart|"
	secret1 := DeriveClientSecret(nonce, contextID, binding1)
	result1 := BuildProofUnified(secret1, "12345", binding1, payload, nil, "")

	// Step 2: Checkout
	binding2 := "POST|/api/checkout|"
	secret2 := DeriveClientSecret(nonce, contextID, binding2)
	result2 := BuildProofUnified(secret2, "12346", binding2, payload, nil, result1.Proof)

	// Step 3: Payment
	binding3 := "POST|/api/payment|"
	secret3 := DeriveClientSecret(nonce, contextID, binding3)
	result3 := BuildProofUnified(secret3, "12347", binding3, payload, nil, result2.Proof)

	// Verify chain progression
	if result1.ChainHash != "" {
		t.Error("Step 1 should have empty chain hash")
	}
	if result2.ChainHash == "" {
		t.Error("Step 2 should have chain hash")
	}
	if result3.ChainHash == "" {
		t.Error("Step 3 should have chain hash")
	}

	// All proofs should be valid
	if len(result1.Proof) != 64 || len(result2.Proof) != 64 || len(result3.Proof) != 64 {
		t.Error("All proofs should be 64 characters")
	}
}

// --- Scope Vectors ---

func TestScopeExtractFields(t *testing.T) {
	payload := map[string]interface{}{
		"amount":    100,
		"recipient": "user123",
		"notes":     "test",
		"metadata":  map[string]interface{}{"ip": "1.2.3.4"},
	}
	scope := []string{"amount", "recipient"}

	extracted := ExtractScopedFields(payload, scope)

	if _, ok := extracted["amount"]; !ok {
		t.Error("Should extract amount")
	}
	if _, ok := extracted["recipient"]; !ok {
		t.Error("Should extract recipient")
	}
	if _, ok := extracted["notes"]; ok {
		t.Error("Should not extract notes")
	}
	if _, ok := extracted["metadata"]; ok {
		t.Error("Should not extract metadata")
	}
}

func TestScopeEmptyScope(t *testing.T) {
	payload := map[string]interface{}{"a": 1, "b": 2}
	scope := []string{}

	extracted := ExtractScopedFields(payload, scope)

	// Empty scope should return full payload
	if len(extracted) != 2 {
		t.Error("Empty scope should return full payload")
	}
}

func TestScopeScopeHash(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ctx_scope"
	binding := "POST|/api/test|"
	timestamp := "12345"
	payload := map[string]interface{}{
		"amount":    100,
		"recipient": "user123",
	}
	scope := []string{"amount", "recipient"}

	secret := DeriveClientSecret(nonce, contextID, binding)
	result := BuildProofUnified(secret, timestamp, binding, payload, scope, "")

	if len(result.ScopeHash) != 64 {
		t.Errorf("Scope hash length %d != 64", len(result.ScopeHash))
	}

	// Scope hash should be hex
	for _, c := range result.ScopeHash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Error("Scope hash should be lowercase hex")
			break
		}
	}
}

// --- URL Encoded Vectors ---

func TestURLEncodedSimpleSort(t *testing.T) {
	result, err := CanonicalizeURLEncoded("z=1&a=2")
	if err != nil {
		t.Fatalf("CanonicalizeURLEncoded failed: %v", err)
	}
	expected := "a=2&z=1"
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestURLEncodedDuplicateKeys(t *testing.T) {
	result, err := CanonicalizeURLEncoded("a=1&b=2&a=3")
	if err != nil {
		t.Fatalf("CanonicalizeURLEncoded failed: %v", err)
	}
	expected := "a=1&a=3&b=2"
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestURLEncodedEmptyValue(t *testing.T) {
	result, err := CanonicalizeURLEncoded("key=")
	if err != nil {
		t.Fatalf("CanonicalizeURLEncoded failed: %v", err)
	}
	expected := "key="
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestURLEncodedKeyWithoutValue(t *testing.T) {
	result, err := CanonicalizeURLEncoded("flag")
	if err != nil {
		t.Fatalf("CanonicalizeURLEncoded failed: %v", err)
	}
	expected := "flag="
	if result != expected {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

// --- Timing Safe Vectors ---

func TestTimingSafeEqual(t *testing.T) {
	if !TimingSafeCompare("abc123", "abc123") {
		t.Error("Equal strings should compare equal")
	}
}

func TestTimingSafeDifferentLastChar(t *testing.T) {
	if TimingSafeCompare("abc123", "abc124") {
		t.Error("Different strings should not compare equal")
	}
}

func TestTimingSafeDifferentLength(t *testing.T) {
	if TimingSafeCompare("abc123", "abc12") {
		t.Error("Different length strings should not compare equal")
	}
}

func TestTimingSafeEmpty(t *testing.T) {
	if !TimingSafeCompare("", "") {
		t.Error("Empty strings should compare equal")
	}
}

func TestTimingSafeCompletelyDifferent(t *testing.T) {
	if TimingSafeCompare("abc", "xyz") {
		t.Error("Completely different strings should not compare equal")
	}
}
