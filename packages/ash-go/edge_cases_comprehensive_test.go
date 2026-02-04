package ash

import (
	"strings"
	"testing"
)

// TestJsonNullTopLevel tests null at top level
func TestJsonNullTopLevel(t *testing.T) {
	result, err := AshCanonicalizeJSON(nil)
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if result != "null" {
		t.Errorf("Expected 'null', got %q", result)
	}
}

// TestJsonNullInObject tests null in object
func TestJsonNullInObject(t *testing.T) {
	result, err := AshCanonicalizeJSON(map[string]interface{}{"key": nil})
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if result != `{"key":null}` {
		t.Errorf("Expected '{\"key\":null}', got %q", result)
	}
}

// TestJsonNullInArray tests null in array
func TestJsonNullInArray(t *testing.T) {
	result, err := AshCanonicalizeJSON([]interface{}{nil, nil, nil})
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if result != `[null,null,null]` {
		t.Errorf("Expected '[null,null,null]', got %q", result)
	}
}

// TestJsonEmptyString tests empty string
func TestJsonEmptyString(t *testing.T) {
	result, err := AshCanonicalizeJSON("")
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if result != `""` {
		t.Errorf("Expected '\"\"', got %q", result)
	}
}

// TestJsonEmptyArray tests empty array
func TestJsonEmptyArray(t *testing.T) {
	result, err := AshCanonicalizeJSON([]interface{}{})
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if result != `[]` {
		t.Errorf("Expected '[]', got %q", result)
	}
}

// TestJsonEmptyObject tests empty object
func TestJsonEmptyObject(t *testing.T) {
	result, err := AshCanonicalizeJSON(map[string]interface{}{})
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if result != `{}` {
		t.Errorf("Expected '{}', got %q", result)
	}
}

// TestJsonTrueStandalone tests standalone true
func TestJsonTrueStandalone(t *testing.T) {
	result, err := AshCanonicalizeJSON(true)
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if result != `true` {
		t.Errorf("Expected 'true', got %q", result)
	}
}

// TestJsonFalseStandalone tests standalone false
func TestJsonFalseStandalone(t *testing.T) {
	result, err := AshCanonicalizeJSON(false)
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if result != `false` {
		t.Errorf("Expected 'false', got %q", result)
	}
}

// TestJsonZero tests zero
func TestJsonZero(t *testing.T) {
	result, err := AshCanonicalizeJSON(0)
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if result != `0` {
		t.Errorf("Expected '0', got %q", result)
	}
}

// TestJsonNegativeZero tests negative zero
func TestJsonNegativeZero(t *testing.T) {
	result, err := AshCanonicalizeJSON(-0.0)
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if result != `0` {
		t.Errorf("Expected '0', got %q", result)
	}
}

// TestJsonOnePointZero tests 1.0
func TestJsonOnePointZero(t *testing.T) {
	result, err := AshCanonicalizeJSON(1.0)
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if result != `1` {
		t.Errorf("Expected '1', got %q", result)
	}
}

// TestBindingRootPath tests root path
func TestBindingRootPath(t *testing.T) {
	result := AshNormalizeBinding("GET", "/", "")
	if result != "GET|/|" {
		t.Errorf("Expected 'GET|/|', got %q", result)
	}
}

// TestBindingPathWithOnlySlashes tests path with only slashes
func TestBindingPathWithOnlySlashes(t *testing.T) {
	result := AshNormalizeBinding("GET", "///", "")
	if result != "GET|/|" {
		t.Errorf("Expected 'GET|/|', got %q", result)
	}
}

// TestProofWithEmptySecret tests proof with empty secret
func TestProofWithEmptySecret(t *testing.T) {
	proof := AshBuildProofHMAC("", "1234567890", "POST|/api|", "abc123")
	if len(proof) != 64 {
		t.Errorf("Expected 64 chars, got %d", len(proof))
	}
}

// TestProofWithEmptyTimestamp tests proof with empty timestamp
func TestProofWithEmptyTimestamp(t *testing.T) {
	proof := AshBuildProofHMAC("secret", "", "POST|/api|", "abc123")
	if len(proof) != 64 {
		t.Errorf("Expected 64 chars, got %d", len(proof))
	}
}

// TestProofWithEmptyBinding tests proof with empty binding
func TestProofWithEmptyBinding(t *testing.T) {
	proof := AshBuildProofHMAC("secret", "1234567890", "", "abc123")
	if len(proof) != 64 {
		t.Errorf("Expected 64 chars, got %d", len(proof))
	}
}

// TestProofWithEmptyBodyHash tests proof with empty body hash
func TestProofWithEmptyBodyHash(t *testing.T) {
	proof := AshBuildProofHMAC("secret", "1234567890", "POST|/api|", "")
	if len(proof) != 64 {
		t.Errorf("Expected 64 chars, got %d", len(proof))
	}
}

// TestProofWithAllEmpty tests proof with all empty
func TestProofWithAllEmpty(t *testing.T) {
	proof := AshBuildProofHMAC("", "", "", "")
	if len(proof) != 64 {
		t.Errorf("Expected 64 chars, got %d", len(proof))
	}
}

// TestProofWithUnicodeSecret tests proof with unicode secret
func TestProofWithUnicodeSecret(t *testing.T) {
	proof := AshBuildProofHMAC("密码🔐", "1234567890", "POST|/api|", "abc123")
	if len(proof) != 64 {
		t.Errorf("Expected 64 chars, got %d", len(proof))
	}
}

// TestHashEmptyBody tests hash of empty body
func TestHashEmptyBody(t *testing.T) {
	hash := AshHashBody("")
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hash != expected {
		t.Errorf("Expected %q, got %q", expected, hash)
	}
}

// TestHashSingleByte tests hash of single byte
func TestHashSingleByte(t *testing.T) {
	hash := AshHashBody("a")
	if len(hash) != 64 {
		t.Errorf("Expected 64 chars, got %d", len(hash))
	}
}

// TestBase64UrlEncodeEmpty tests base64url encode empty
func TestBase64UrlEncodeEmpty(t *testing.T) {
	encoded := Base64URLEncode([]byte{})
	if encoded != "" {
		t.Errorf("Expected empty, got %q", encoded)
	}
}

// TestBase64UrlEncodeSingleByte tests base64url encode single byte
func TestBase64UrlEncodeSingleByte(t *testing.T) {
	encoded := Base64URLEncode([]byte{0x61})
	decoded, _ := Base64URLDecode(encoded)
	if string(decoded) != "a" {
		t.Errorf("Expected 'a', got %q", string(decoded))
	}
}

// TestTimingSafeCompareEmptyStrings tests timing safe compare empty strings
func TestTimingSafeCompareEmptyStrings(t *testing.T) {
	if !AshTimingSafeCompare("", "") {
		t.Error("Expected true for empty strings")
	}
}

// TestTimingSafeCompareOneEmpty tests timing safe compare one empty
func TestTimingSafeCompareOneEmpty(t *testing.T) {
	if AshTimingSafeCompare("", "notempty") {
		t.Error("Expected false")
	}
	if AshTimingSafeCompare("notempty", "") {
		t.Error("Expected false")
	}
}

// TestTimingSafeCompareSingleChar tests timing safe compare single char
func TestTimingSafeCompareSingleChar(t *testing.T) {
	if !AshTimingSafeCompare("a", "a") {
		t.Error("Expected true")
	}
	if AshTimingSafeCompare("a", "b") {
		t.Error("Expected false")
	}
}

// TestUrlEncodedEmptyString tests url encoded empty string
func TestUrlEncodedEmptyString(t *testing.T) {
	result, _ := AshCanonicalizeURLEncoded("")
	if result != "" {
		t.Errorf("Expected empty, got %q", result)
	}
}

// TestUrlEncodedSingleParam tests url encoded single param
func TestUrlEncodedSingleParam(t *testing.T) {
	result, _ := AshCanonicalizeURLEncoded("key=value")
	if result != "key=value" {
		t.Errorf("Expected 'key=value', got %q", result)
	}
}

// TestJsonStringWithOnlySpaces tests string with only spaces
func TestJsonStringWithOnlySpaces(t *testing.T) {
	result, err := AshCanonicalizeJSON("   ")
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if result != `"   "` {
		t.Errorf("Expected '\"   \"', got %q", result)
	}
}

// TestJsonSingleElementArray tests single element array
func TestJsonSingleElementArray(t *testing.T) {
	result, err := AshCanonicalizeJSON([]interface{}{1})
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if result != `[1]` {
		t.Errorf("Expected '[1]', got %q", result)
	}
}

// TestJsonArrayWithAllTypes tests array with all types
func TestJsonArrayWithAllTypes(t *testing.T) {
	result, err := AshCanonicalizeJSON([]interface{}{1, "string", true, false, nil, []interface{}{}, map[string]interface{}{}})
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if result != `[1,"string",true,false,null,[],{}]` {
		t.Errorf("Unexpected result: %q", result)
	}
}

// TestBindingEmptyQueryString tests empty query string
func TestBindingEmptyQueryString(t *testing.T) {
	result := AshNormalizeBinding("GET", "/path", "")
	if result != "GET|/path|" {
		t.Errorf("Expected 'GET|/path|', got %q", result)
	}
}

// TestJsonNumericStringKeys tests numeric string keys
func TestJsonNumericStringKeys(t *testing.T) {
	result, err := AshCanonicalizeJSON(map[string]interface{}{"10": "ten", "2": "two", "1": "one"})
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	expected := `{"1":"one","10":"ten","2":"two"}`
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

// TestJsonMixedCaseKeys tests mixed case keys
func TestJsonMixedCaseKeys(t *testing.T) {
	result, err := AshCanonicalizeJSON(map[string]interface{}{"B": 2, "a": 1, "A": 3, "b": 4})
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	expected := `{"A":3,"B":2,"a":1,"b":4}`
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

// TestBindingAllHttpMethods tests all HTTP methods
func TestBindingAllHttpMethods(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
	for _, method := range methods {
		result := AshNormalizeBinding(method, "/path", "")
		if !strings.HasPrefix(result, method+"|") {
			t.Errorf("Expected %s at start, got %q", method, result)
		}
	}
}

// TestBindingLowercaseMethods tests lowercase methods
func TestBindingLowercaseMethods(t *testing.T) {
	methods := []string{"get", "post", "put", "delete", "patch"}
	for _, method := range methods {
		result := AshNormalizeBinding(method, "/path", "")
		expected := strings.ToUpper(method) + "|/path|"
		if result != expected {
			t.Errorf("Expected %q, got %q", expected, result)
		}
	}
}

// TestUrlEncodedSortsDuplicateKeys tests duplicate key sorting
func TestUrlEncodedSortsDuplicateKeys(t *testing.T) {
	result, _ := AshCanonicalizeURLEncoded("a=3&a=1&a=2")
	if result != "a=1&a=2&a=3" {
		t.Errorf("Expected 'a=1&a=2&a=3', got %q", result)
	}
}

// TestUrlEncodedSortsParameters tests parameter sorting
func TestUrlEncodedSortsParameters(t *testing.T) {
	result, _ := AshCanonicalizeURLEncoded("z=3&a=1&m=2")
	if result != "a=1&m=2&z=3" {
		t.Errorf("Expected 'a=1&m=2&z=3', got %q", result)
	}
}

// TestUrlEncodedEncodesSpace tests space encoding
func TestUrlEncodedEncodesSpace(t *testing.T) {
	result, _ := AshCanonicalizeURLEncoded("key=hello world")
	if !strings.Contains(result, "%20") {
		t.Errorf("Expected %%20, got %q", result)
	}
}

// TestProofDeterminism100Times tests proof determinism
func TestProofDeterminism100Times(t *testing.T) {
	proofs := make([]string, 100)
	for i := 0; i < 100; i++ {
		proofs[i] = AshBuildProofHMAC("secret", "1234567890", "POST|/api|", "abc123")
	}
	for i := 1; i < 100; i++ {
		if proofs[i] != proofs[0] {
			t.Error("Proof is not deterministic")
		}
	}
}

// TestHashDeterminism100Times tests hash determinism
func TestHashDeterminism100Times(t *testing.T) {
	hashes := make([]string, 100)
	for i := 0; i < 100; i++ {
		hashes[i] = AshHashBody("test")
	}
	for i := 1; i < 100; i++ {
		if hashes[i] != hashes[0] {
			t.Error("Hash is not deterministic")
		}
	}
}

// TestBindingDeterminism100Times tests binding determinism
func TestBindingDeterminism100Times(t *testing.T) {
	bindings := make([]string, 100)
	for i := 0; i < 100; i++ {
		bindings[i] = AshNormalizeBinding("POST", "/api/update", "z=3&a=1")
	}
	for i := 1; i < 100; i++ {
		if bindings[i] != bindings[0] {
			t.Error("Binding normalization is not deterministic")
		}
	}
}

// TestJsonCanonicalizeDeterminism100Times tests JSON canonicalization determinism
func TestJsonCanonicalizeDeterminism100Times(t *testing.T) {
	results := make([]string, 100)
	for i := 0; i < 100; i++ {
		results[i], _ = AshCanonicalizeJSON(map[string]interface{}{"z": 26, "a": 1, "m": 13})
	}
	for i := 1; i < 100; i++ {
		if results[i] != results[0] {
			t.Error("JSON canonicalization is not deterministic")
		}
	}
}
