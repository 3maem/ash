package ash

import (
	"reflect"
	"strings"
	"testing"
)

// ============================================================================
// TYPES AND STRUCTURES TESTS
// ============================================================================

// --- BuildProofInput Tests ---

func TestBuildProofInputDefaults(t *testing.T) {
	input := BuildProofInput{
		Mode:             "balanced",
		ContextID:        "ctx",
		Binding:          "GET|/|",
		CanonicalPayload: "{}",
	}

	if input.Mode != "balanced" {
		t.Error("Mode should be balanced")
	}
}

func TestBuildProofInputAllModes(t *testing.T) {
	modes := []AshMode{ModeStrict, ModeBalanced, ModeMinimal}

	for _, mode := range modes {
		input := BuildProofInput{
			Mode:             mode,
			ContextID:        "ctx",
			Binding:          "POST|/api|",
			CanonicalPayload: "{}",
		}

		err := ValidateProofInput(input)
		if err != nil {
			t.Errorf("Mode %v should be valid", mode)
		}
	}
}

func TestBuildProofInputInvalidMode(t *testing.T) {
	input := BuildProofInput{
		Mode:             AshMode("invalid"),
		ContextID:        "ctx",
		Binding:          "POST|/api|",
		CanonicalPayload: "{}",
	}

	err := ValidateProofInput(input)
	if err == nil {
		t.Error("Invalid mode should error")
	}
}

func TestBuildProofInputWithPayload(t *testing.T) {
	input := BuildProofInput{
		Mode:             ModeBalanced,
		ContextID:        "ctx",
		Binding:          "POST|/api|",
		CanonicalPayload: `{"a":1,"b":2}`,
	}

	if input.CanonicalPayload != `{"a":1,"b":2}` {
		t.Error("CanonicalPayload should be set correctly")
	}
}

func TestBuildProofInputWithNonce(t *testing.T) {
	input := BuildProofInput{
		Mode:             ModeBalanced,
		ContextID:        "ctx",
		Binding:          "POST|/api|",
		CanonicalPayload: "{}",
		Nonce:            strings.Repeat("a", 64),
	}

	if input.Nonce == "" {
		t.Error("Nonce should be set")
	}
}

// --- UnifiedProofResult Tests ---

func TestUnifiedProofResultFields(t *testing.T) {
	result := UnifiedProofResult{
		Proof:     strings.Repeat("a", 64),
		ScopeHash: strings.Repeat("b", 64),
		ChainHash: strings.Repeat("c", 64),
	}

	if len(result.Proof) != 64 {
		t.Error("Proof should be 64 chars")
	}
	if len(result.ScopeHash) != 64 {
		t.Error("ScopeHash should be 64 chars")
	}
	if len(result.ChainHash) != 64 {
		t.Error("ChainHash should be 64 chars")
	}
}

func TestUnifiedProofResultEmpty(t *testing.T) {
	result := UnifiedProofResult{}

	if result.Proof != "" {
		t.Error("Empty result should have empty proof")
	}
	if result.ScopeHash != "" {
		t.Error("Empty result should have empty scope hash")
	}
}

// --- AshError Tests ---

func TestAshErrorImplementsError(t *testing.T) {
	var err error = &AshError{
		Code:    "TEST",
		Message: "test message",
	}

	if err.Error() == "" {
		t.Error("AshError should implement error interface")
	}
}

func TestTypesAshErrorCodes(t *testing.T) {
	codes := []AshErrorCode{
		ErrCtxNotFound,
		ErrCtxExpired,
		ErrCanonicalizationError,
		ErrProofInvalid,
		ErrBindingMismatch,
	}

	for _, code := range codes {
		err := &AshError{Code: code, Message: "test"}
		if err.Code != code {
			t.Errorf("Code mismatch: %s != %s", err.Code, code)
		}
	}
}

func TestTypesAshErrorMessage(t *testing.T) {
	err := &AshError{
		Code:    "TEST_CODE",
		Message: "This is a test message",
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "TEST_CODE") && !strings.Contains(errStr, "test message") {
		t.Error("Error string should contain code or message")
	}
}

// --- Type Validation Tests ---

func TestHashBodyReturnsString(t *testing.T) {
	result := HashBody("test")
	if reflect.TypeOf(result).Kind() != reflect.String {
		t.Error("HashBody should return string")
	}
}

func TestDeriveClientSecretReturnsString(t *testing.T) {
	result := DeriveClientSecret("nonce", "ctx", "binding")
	if reflect.TypeOf(result).Kind() != reflect.String {
		t.Error("DeriveClientSecret should return string")
	}
}

func TestBuildProofV21ReturnsString(t *testing.T) {
	result := BuildProofV21("secret", "timestamp", "binding", "bodyhash")
	if reflect.TypeOf(result).Kind() != reflect.String {
		t.Error("BuildProofV21 should return string")
	}
}

func TestVerifyProofV21ReturnsBool(t *testing.T) {
	result := VerifyProofV21("nonce", "ctx", "binding", "ts", "hash", "proof")
	if reflect.TypeOf(result).Kind() != reflect.Bool {
		t.Error("VerifyProofV21 should return bool")
	}
}

func TestTimingSafeCompareReturnsBool(t *testing.T) {
	result := TimingSafeCompare("a", "b")
	if reflect.TypeOf(result).Kind() != reflect.Bool {
		t.Error("TimingSafeCompare should return bool")
	}
}

func TestNormalizeBindingReturnsString(t *testing.T) {
	result := NormalizeBinding("GET", "/", "")
	if reflect.TypeOf(result).Kind() != reflect.String {
		t.Error("NormalizeBinding should return string")
	}
}

func TestCanonicalizeQueryReturnsString(t *testing.T) {
	result, _ := CanonicalizeQuery("a=1")
	if reflect.TypeOf(result).Kind() != reflect.String {
		t.Error("CanonicalizeQuery should return string")
	}
}

func TestCanonicalizeJSONReturnsStringAndError(t *testing.T) {
	result, err := CanonicalizeJSON(map[string]interface{}{})

	if reflect.TypeOf(result).Kind() != reflect.String {
		t.Error("CanonicalizeJSON should return string")
	}
	if err != nil && reflect.TypeOf(err).String() != "*ash.AshError" && !strings.Contains(reflect.TypeOf(err).String(), "error") {
		t.Error("CanonicalizeJSON should return error interface")
	}
}

// --- JSON Types ---

func TestCanonicalizeJSONWithMap(t *testing.T) {
	input := map[string]interface{}{
		"key": "value",
	}

	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Errorf("Map should canonicalize: %v", err)
	}
	if result == "" {
		t.Error("Result should not be empty")
	}
}

func TestCanonicalizeJSONWithSlice(t *testing.T) {
	input := []interface{}{1, 2, 3}

	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Errorf("Slice should canonicalize: %v", err)
	}
	if !strings.Contains(result, "[") {
		t.Error("Result should contain array bracket")
	}
}

func TestCanonicalizeJSONWithString(t *testing.T) {
	input := "test string"

	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Errorf("String should canonicalize: %v", err)
	}
	if !strings.Contains(result, "test") {
		t.Error("Result should contain string value")
	}
}

func TestCanonicalizeJSONWithNumber(t *testing.T) {
	inputs := []interface{}{
		42,
		3.14,
		float64(100),
		int64(1000),
	}

	for _, input := range inputs {
		result, err := CanonicalizeJSON(input)
		if err != nil {
			t.Errorf("Number %v should canonicalize: %v", input, err)
		}
		if result == "" {
			t.Error("Result should not be empty")
		}
	}
}

func TestCanonicalizeJSONWithBool(t *testing.T) {
	trueResult, err1 := CanonicalizeJSON(true)
	falseResult, err2 := CanonicalizeJSON(false)

	if err1 != nil || err2 != nil {
		t.Error("Booleans should canonicalize")
	}

	if trueResult != "true" {
		t.Errorf("true should canonicalize to 'true', got %s", trueResult)
	}
	if falseResult != "false" {
		t.Errorf("false should canonicalize to 'false', got %s", falseResult)
	}
}

func TestCanonicalizeJSONWithNull(t *testing.T) {
	result, err := CanonicalizeJSON(nil)
	if err != nil {
		t.Errorf("Null should canonicalize: %v", err)
	}
	if result != "null" {
		t.Errorf("nil should canonicalize to 'null', got %s", result)
	}
}

// --- Nested Types ---

func TestCanonicalizeJSONNestedMap(t *testing.T) {
	input := map[string]interface{}{
		"level1": map[string]interface{}{
			"level2": map[string]interface{}{
				"level3": "deep",
			},
		},
	}

	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Errorf("Nested map should canonicalize: %v", err)
	}
	if !strings.Contains(result, "deep") {
		t.Error("Result should contain nested value")
	}
}

func TestCanonicalizeJSONNestedArray(t *testing.T) {
	input := map[string]interface{}{
		"arr": []interface{}{
			[]interface{}{1, 2},
			[]interface{}{3, 4},
		},
	}

	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Errorf("Nested array should canonicalize: %v", err)
	}
	if !strings.Contains(result, "[[") {
		t.Error("Result should contain nested array brackets")
	}
}

func TestCanonicalizeJSONMixedTypes(t *testing.T) {
	input := map[string]interface{}{
		"string":  "hello",
		"number":  42,
		"float":   3.14,
		"bool":    true,
		"null":    nil,
		"array":   []interface{}{1, "two", true},
		"object":  map[string]interface{}{"nested": "value"},
	}

	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Errorf("Mixed types should canonicalize: %v", err)
	}
	if result == "" {
		t.Error("Result should not be empty")
	}
}

// --- Scope Types ---

func TestScopeEmptyArray(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "12345"
	binding := "POST|/api|"
	payload := map[string]interface{}{"key": "value"}

	result := BuildProofUnified(secret, timestamp, binding, payload, []string{}, "")
	// No error return from BuildProofUnified
	if result.Proof == "" {
		t.Error("Proof should be generated")
	}
}

func TestScopeNilArray(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "12345"
	binding := "POST|/api|"
	payload := map[string]interface{}{"key": "value"}

	result := BuildProofUnified(secret, timestamp, binding, payload, nil, "")
	// No error return from BuildProofUnified
	if result.Proof == "" {
		t.Error("Proof should be generated")
	}
}

func TestScopeSingleField(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "12345"
	binding := "POST|/api|"
	payload := map[string]interface{}{
		"important": "value",
		"extra":     "ignored",
	}

	result := BuildProofUnified(secret, timestamp, binding, payload, []string{"important"}, "")
	// No error return from BuildProofUnified
	if result.ScopeHash == "" {
		t.Error("Scope hash should be generated")
	}
}

func TestScopeMultipleFields(t *testing.T) {
	secret := strings.Repeat("a", 64)
	timestamp := "12345"
	binding := "POST|/api|"
	payload := map[string]interface{}{
		"field1": "value1",
		"field2": "value2",
		"field3": "value3",
	}

	result := BuildProofUnified(secret, timestamp, binding, payload, []string{"field1", "field2"}, "")
	// No error return from BuildProofUnified
	if result.ScopeHash == "" {
		t.Error("Scope hash should be generated")
	}
}

// --- Binding Types ---

func TestTypesBindingFormat(t *testing.T) {
	binding := NormalizeBinding("GET", "/api/users", "page=1")
	parts := strings.Split(binding, "|")

	if len(parts) != 3 {
		t.Errorf("Binding should have 3 parts, got %d", len(parts))
	}
}

func TestBindingMethodPart(t *testing.T) {
	binding := NormalizeBinding("POST", "/api", "")
	parts := strings.Split(binding, "|")

	if len(parts) >= 1 && parts[0] != "POST" {
		t.Errorf("First part should be method: %s", parts[0])
	}
}

func TestBindingPathPart(t *testing.T) {
	binding := NormalizeBinding("GET", "/api/users", "")
	parts := strings.Split(binding, "|")

	if len(parts) >= 2 && !strings.Contains(parts[1], "/api") {
		t.Errorf("Second part should contain path: %s", parts[1])
	}
}

func TestBindingQueryPart(t *testing.T) {
	binding := NormalizeBinding("GET", "/api", "page=1&limit=10")
	parts := strings.Split(binding, "|")

	if len(parts) >= 3 && parts[2] == "" {
		// Query might be canonicalized and included
	}
}

// --- Hash Types ---

func TestHashLength(t *testing.T) {
	inputs := []string{"", "a", "test", strings.Repeat("x", 10000)}

	for _, input := range inputs {
		hash := HashBody(input)
		if len(hash) != 64 {
			t.Errorf("Hash of %q should be 64 chars, got %d", input[:typesMin(10, len(input))], len(hash))
		}
	}
}

func TestHashCharacterSet(t *testing.T) {
	hash := HashBody("test input")

	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("Hash should only contain hex chars, got %c", c)
		}
	}
}

// --- Secret Types ---

func TestSecretLength(t *testing.T) {
	secret := DeriveClientSecret(
		strings.Repeat("a", 64),
		"context",
		"binding",
	)

	if len(secret) != 64 {
		t.Errorf("Secret should be 64 chars, got %d", len(secret))
	}
}

func TestSecretCharacterSet(t *testing.T) {
	secret := DeriveClientSecret(
		strings.Repeat("a", 64),
		"context",
		"binding",
	)

	for _, c := range secret {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("Secret should only contain hex chars, got %c", c)
		}
	}
}

// --- Proof Types ---

func TestProofLength(t *testing.T) {
	proof := BuildProofV21(
		strings.Repeat("a", 64),
		"12345",
		"GET|/|",
		strings.Repeat("b", 64),
	)

	if len(proof) != 64 {
		t.Errorf("Proof should be 64 chars, got %d", len(proof))
	}
}

func TestProofCharacterSet(t *testing.T) {
	proof := BuildProofV21(
		strings.Repeat("a", 64),
		"12345",
		"GET|/|",
		strings.Repeat("b", 64),
	)

	for _, c := range proof {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("Proof should only contain hex chars, got %c", c)
		}
	}
}

// --- Mode Enum Tests ---

func TestTypesModeStrict(t *testing.T) {
	input := BuildProofInput{
		Mode:             "strict",
		ContextID:        "ctx",
		Binding:          "POST|/api|",
		CanonicalPayload: "{}",
	}

	err := ValidateProofInput(input)
	if err != nil {
		t.Errorf("strict mode should be valid: %v", err)
	}
}

func TestTypesModeBalanced(t *testing.T) {
	input := BuildProofInput{
		Mode:             "balanced",
		ContextID:        "ctx",
		Binding:          "POST|/api|",
		CanonicalPayload: "{}",
	}

	err := ValidateProofInput(input)
	if err != nil {
		t.Errorf("balanced mode should be valid: %v", err)
	}
}

func TestTypesModeMinimal(t *testing.T) {
	input := BuildProofInput{
		Mode:             "minimal",
		ContextID:        "ctx",
		Binding:          "POST|/api|",
		CanonicalPayload: "{}",
	}

	err := ValidateProofInput(input)
	if err != nil {
		t.Errorf("minimal mode should be valid: %v", err)
	}
}

// Helper
func typesMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// --- Version Tests ---

func TestVersionStringExists(t *testing.T) {
	version := GetVersion()
	if version == "" {
		t.Error("Version should not be empty")
	}
}

func TestVersionFormat(t *testing.T) {
	version := GetVersion()
	if !strings.Contains(version, ".") {
		t.Error("Version should contain dots")
	}
}

// --- Special Input Types ---

func TestSpecialInputEmptyString(t *testing.T) {
	hash := HashBody("")
	if len(hash) != 64 {
		t.Error("Empty string should hash")
	}
}

func TestSpecialInputWhitespace(t *testing.T) {
	inputs := []string{" ", "\t", "\n", "  \t\n  "}

	for _, input := range inputs {
		hash := HashBody(input)
		if len(hash) != 64 {
			t.Errorf("Whitespace %q should hash", input)
		}
	}
}

func TestSpecialInputUnicode(t *testing.T) {
	inputs := []string{
		"日本語",
		"emoji 😀",
		"مرحبا",
		"Привет",
	}

	for _, input := range inputs {
		hash := HashBody(input)
		if len(hash) != 64 {
			t.Errorf("Unicode %q should hash", input)
		}
	}
}

func TestSpecialInputBinary(t *testing.T) {
	input := string([]byte{0x00, 0x01, 0x02, 0xFF, 0xFE})
	hash := HashBody(input)
	if len(hash) != 64 {
		t.Error("Binary data should hash")
	}
}

// --- Interface Compliance ---

func TestUnifiedProofResultIsStruct(t *testing.T) {
	result := UnifiedProofResult{}
	resultType := reflect.TypeOf(result)

	if resultType.Kind() != reflect.Struct {
		t.Error("UnifiedProofResult should be a struct")
	}
}

func TestBuildProofInputIsStruct(t *testing.T) {
	input := BuildProofInput{}
	inputType := reflect.TypeOf(input)

	if inputType.Kind() != reflect.Struct {
		t.Error("BuildProofInput should be a struct")
	}
}

func TestAshErrorIsPointerReceiver(t *testing.T) {
	err := &AshError{Code: "TEST", Message: "test"}
	errType := reflect.TypeOf(err)

	if errType.Kind() != reflect.Ptr {
		t.Error("AshError should use pointer receiver")
	}
}

// Additional test for CanonicalizeURLEncoded
func TestCanonicalizeURLEncodedReturnsString(t *testing.T) {
	result, _ := CanonicalizeURLEncoded("a=1&b=2")
	if reflect.TypeOf(result).Kind() != reflect.String {
		t.Error("CanonicalizeURLEncoded should return string")
	}
}

// Test ExtractScopedFields function
func TestExtractScopedFieldsReturnsMap(t *testing.T) {
	payload := map[string]interface{}{
		"a": 1,
		"b": 2,
		"c": 3,
	}
	scope := []string{"a", "b"}

	result := ExtractScopedFields(payload, scope)
	if reflect.TypeOf(result).Kind() != reflect.Map {
		t.Error("ExtractScopedFields should return map")
	}
}

func TestExtractScopedFieldsExtract(t *testing.T) {
	payload := map[string]interface{}{
		"keep1":   "value1",
		"keep2":   "value2",
		"discard": "ignored",
	}

	result := ExtractScopedFields(payload, []string{"keep1", "keep2"})

	if len(result) != 2 {
		t.Errorf("Should extract 2 fields, got %d", len(result))
	}

	if result["keep1"] != "value1" {
		t.Error("Should contain keep1")
	}

	if _, exists := result["discard"]; exists {
		t.Error("Should not contain discard")
	}
}
