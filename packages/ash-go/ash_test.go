package ash

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// TestVersionConstants tests that version constants are correctly set.
func TestVersionConstants(t *testing.T) {
	if Version != "2.3.4" {
		t.Errorf("Expected Version to be \"2.3.4\", got %q", Version)
	}
	if AshVersionPrefix != "ASHv1" {
		t.Errorf("Expected AshVersionPrefix to be \"ASHv1\", got %q", AshVersionPrefix)
	}
	if AshVersionPrefixV21 != "ASHv2.1" {
		t.Errorf("Expected AshVersionPrefixV21 to be \"ASHv2.1\", got %q", AshVersionPrefixV21)
	}
}

// TestBuildProof tests the BuildProof function.
func TestBuildProof(t *testing.T) {
	tests := []struct {
		name  string
		input BuildProofInput
	}{
		{
			name: "basic proof without nonce",
			input: BuildProofInput{
				Mode:             ModeBalanced,
				Binding:          "POST /api/login",
				ContextID:        "ctx_12345",
				CanonicalPayload: `{"password":"secret","username":"test"}`,
			},
		},
		{
			name: "proof with nonce",
			input: BuildProofInput{
				Mode:             ModeBalanced,
				Binding:          "POST /api/submit",
				ContextID:        "ctx_67890",
				Nonce:            "nonce_abc123",
				CanonicalPayload: `{"data":"test"}`,
			},
		},
		{
			name: "empty payload",
			input: BuildProofInput{
				Mode:             ModeMinimal,
				Binding:          "GET /api/data",
				ContextID:        "ctx_empty",
				CanonicalPayload: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof := BuildProof(tt.input)

			// Proof should be a valid Base64URL string
			if proof == "" {
				t.Error("BuildProof returned empty string")
			}

			// Should be decodable
			decoded, err := Base64URLDecode(proof)
			if err != nil {
				t.Errorf("Failed to decode proof: %v", err)
			}

			// SHA256 produces 32 bytes
			if len(decoded) != 32 {
				t.Errorf("Expected 32 bytes, got %d", len(decoded))
			}

			// Same input should produce same proof (determinism)
			proof2 := BuildProof(tt.input)
			if proof != proof2 {
				t.Error("BuildProof is not deterministic")
			}
		})
	}
}

// TestBuildProofDeterminism tests that proof generation is deterministic.
func TestBuildProofDeterminism(t *testing.T) {
	input := BuildProofInput{
		Mode:             ModeBalanced,
		Binding:          "POST /api/test",
		ContextID:        "ctx_determinism",
		Nonce:            "nonce_test",
		CanonicalPayload: `{"key":"value"}`,
	}

	proofs := make([]string, 100)
	for i := 0; i < 100; i++ {
		proofs[i] = BuildProof(input)
	}

	for i := 1; i < len(proofs); i++ {
		if proofs[i] != proofs[0] {
			t.Error("BuildProof produced different results for same input")
		}
	}
}

// TestBase64URLEncode tests Base64URL encoding.
func TestBase64URLEncode(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "hello",
			input:    []byte("hello"),
			expected: "aGVsbG8",
		},
		{
			name:     "binary data",
			input:    []byte{0x00, 0xFF, 0x7F, 0x80},
			expected: "AP9_gA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Base64URLEncode(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestBase64URLDecode tests Base64URL decoding.
func TestBase64URLDecode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
		wantErr  bool
	}{
		{
			name:     "empty",
			input:    "",
			expected: []byte{},
		},
		{
			name:     "hello",
			input:    "aGVsbG8",
			expected: []byte("hello"),
		},
		{
			name:     "with padding",
			input:    "aGVsbG8=",
			expected: []byte("hello"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Base64URLDecode(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if string(result) != string(tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestCanonicalizeJSON tests JSON canonicalization.
func TestCanonicalizeJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
		wantErr  bool
	}{
		{
			name:     "null",
			input:    nil,
			expected: "null",
		},
		{
			name:     "boolean true",
			input:    true,
			expected: "true",
		},
		{
			name:     "boolean false",
			input:    false,
			expected: "false",
		},
		{
			name:     "string",
			input:    "hello",
			expected: `"hello"`,
		},
		{
			name:     "number integer",
			input:    float64(42),
			expected: "42",
		},
		{
			name:     "number float",
			input:    float64(3.14),
			expected: "3.14",
		},
		{
			name:     "number zero",
			input:    float64(0),
			expected: "0",
		},
		{
			name:     "empty array",
			input:    []interface{}{},
			expected: "[]",
		},
		{
			name:     "array with values",
			input:    []interface{}{"a", float64(1), true},
			expected: `["a",1,true]`,
		},
		{
			name:     "empty object",
			input:    map[string]interface{}{},
			expected: "{}",
		},
		{
			name: "object with sorted keys",
			input: map[string]interface{}{
				"zebra": float64(1),
				"apple": float64(2),
				"mango": float64(3),
			},
			expected: `{"apple":2,"mango":3,"zebra":1}`,
		},
		{
			name: "nested object",
			input: map[string]interface{}{
				"outer": map[string]interface{}{
					"inner": "value",
				},
			},
			expected: `{"outer":{"inner":"value"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CanonicalizeJSON(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestCanonicalizeJSONKeyOrder tests that keys are sorted lexicographically.
func TestCanonicalizeJSONKeyOrder(t *testing.T) {
	input := map[string]interface{}{
		"z":  float64(1),
		"a":  float64(2),
		"m":  float64(3),
		"1":  float64(4),
		"10": float64(5),
		"2":  float64(6),
	}

	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expected := `{"1":4,"10":5,"2":6,"a":2,"m":3,"z":1}`
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

// TestCanonicalizeJSONRFC8785Escaping tests RFC 8785 (JCS) string escaping.
func TestCanonicalizeJSONRFC8785Escaping(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name:     "backspace",
			input:    "a\bb",
			expected: `"a\bb"`,
		},
		{
			name:     "tab",
			input:    "a\tb",
			expected: `"a\tb"`,
		},
		{
			name:     "newline",
			input:    "a\nb",
			expected: `"a\nb"`,
		},
		{
			name:     "form feed",
			input:    "a\fb",
			expected: `"a\fb"`,
		},
		{
			name:     "carriage return",
			input:    "a\rb",
			expected: `"a\rb"`,
		},
		{
			name:     "double quote",
			input:    `a"b`,
			expected: `"a\"b"`,
		},
		{
			name:     "backslash",
			input:    `a\b`,
			expected: `"a\\b"`,
		},
		{
			name:     "null char (control)",
			input:    "a\x00b",
			expected: `"a\u0000b"`,
		},
		{
			name:     "other control char (0x01)",
			input:    "a\x01b",
			expected: `"a\u0001b"`,
		},
		{
			name:     "control char 0x1F",
			input:    "a\x1Fb",
			expected: `"a\u001fb"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CanonicalizeJSON(tt.input)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestCanonicalizeJSONRejectsNaNAndInfinity tests that NaN and Infinity are rejected.
func TestCanonicalizeJSONRejectsNaNAndInfinity(t *testing.T) {
	tests := []struct {
		name  string
		input float64
	}{
		{"NaN", math.NaN()},           // Creates NaN
		{"positive infinity", math.Inf(1)},  // Creates +Inf
		{"negative infinity", math.Inf(-1)}, // Creates -Inf
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CanonicalizeJSON(tt.input)
			if err == nil {
				t.Errorf("Expected error for %s, got nil", tt.name)
			}
		})
	}
}

// TestCanonicalizeJSONMinusZero tests that -0 becomes 0.
func TestCanonicalizeJSONMinusZero(t *testing.T) {
	// Create -0
	minusZero := -0.0

	result, err := CanonicalizeJSON(minusZero)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}

	if result != "0" {
		t.Errorf("Expected \"0\", got %q", result)
	}
}

// TestParseJSON tests JSON parsing and canonicalization.
func TestParseJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "simple object",
			input:    `{"b": 2, "a": 1}`,
			expected: `{"a":1,"b":2}`,
		},
		{
			name:     "with whitespace",
			input:    `{  "key"  :  "value"  }`,
			expected: `{"key":"value"}`,
		},
		{
			name:    "invalid json",
			input:   `{invalid}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseJSON(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestCanonicalizeURLEncoded tests URL-encoded canonicalization.
func TestCanonicalizeURLEncoded(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "empty",
			input:    "",
			expected: "",
		},
		{
			name:     "single pair",
			input:    "key=value",
			expected: "key=value",
		},
		{
			name:     "multiple pairs sorted",
			input:    "b=2&a=1",
			expected: "a=1&b=2",
		},
		{
			name:     "duplicate keys sorted by value",
			input:    "a=3&a=1&a=2",
			expected: "a=1&a=2&a=3",
		},
		{
			name:     "plus as literal",
			input:    "key=hello+world",
			expected: "key=hello%2Bworld",
		},
		{
			name:     "percent encoded",
			input:    "key=hello%20world",
			expected: "key=hello%20world",
		},
		{
			name:     "key without value",
			input:    "key",
			expected: "key=",
		},
		{
			name:     "empty parts skipped",
			input:    "a=1&&b=2",
			expected: "a=1&b=2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CanonicalizeURLEncoded(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestCanonicalizeQueryUppercaseHex tests uppercase percent-encoding in query strings.
func TestCanonicalizeQueryUppercaseHex(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase hex converted to uppercase",
			input:    "key=%c3%a9", // e with acute in lowercase hex
			expected: "key=%C3%A9", // should be uppercase
		},
		{
			name:     "space as %20 not plus",
			input:    "key=hello%20world",
			expected: "key=hello%20world",
		},
		{
			name:     "mixed case hex",
			input:    "key=%aB%Cd",
			expected: "key=%AB%CD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CanonicalizeQuery(tt.input)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestCanonicalizeQueryFragmentStripping tests that fragments are stripped.
func TestCanonicalizeQueryFragmentStripping(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "strip fragment",
			input:    "a=1&b=2#section",
			expected: "a=1&b=2",
		},
		{
			name:     "fragment with query",
			input:    "?foo=bar#anchor",
			expected: "foo=bar",
		},
		{
			name:     "fragment only",
			input:    "#anchor",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CanonicalizeQuery(tt.input)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestCanonicalizeQueryEmptyValues tests that empty values are preserved.
func TestCanonicalizeQueryEmptyValues(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "key with empty value",
			input:    "a=",
			expected: "a=",
		},
		{
			name:     "mixed empty and non-empty",
			input:    "a=&b=value",
			expected: "a=&b=value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CanonicalizeQuery(tt.input)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestNormalizeBinding tests binding normalization (v2.3.1+ format: METHOD|PATH|QUERY).
func TestNormalizeBinding(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		path     string
		query    string
		expected string
	}{
		{
			name:     "simple",
			method:   "POST",
			path:     "/api/login",
			query:    "",
			expected: "POST|/api/login|",
		},
		{
			name:     "lowercase method",
			method:   "post",
			path:     "/api/login",
			query:    "",
			expected: "POST|/api/login|",
		},
		{
			name:     "mixed case method",
			method:   "PoSt",
			path:     "/api/login",
			query:    "",
			expected: "POST|/api/login|",
		},
		{
			name:     "path without leading slash",
			method:   "GET",
			path:     "api/data",
			query:    "",
			expected: "GET|/api/data|",
		},
		{
			name:     "with query string",
			method:   "GET",
			path:     "/api/data",
			query:    "foo=bar",
			expected: "GET|/api/data|foo=bar",
		},
		{
			name:     "query sorted",
			method:   "GET",
			path:     "/api/data",
			query:    "z=1&a=2",
			expected: "GET|/api/data|a=2&z=1",
		},
		{
			name:     "path with fragment",
			method:   "GET",
			path:     "/api/data#section",
			query:    "",
			expected: "GET|/api/data|",
		},
		{
			name:     "duplicate slashes",
			method:   "GET",
			path:     "/api//data///test",
			query:    "",
			expected: "GET|/api/data/test|",
		},
		{
			name:     "trailing slash removed",
			method:   "GET",
			path:     "/api/data/",
			query:    "",
			expected: "GET|/api/data|",
		},
		{
			name:     "root path preserved",
			method:   "GET",
			path:     "/",
			query:    "",
			expected: "GET|/|",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeBinding(tt.method, tt.path, tt.query)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestTimingSafeCompare tests constant-time string comparison.
func TestTimingSafeCompare(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected bool
	}{
		{
			name:     "equal strings",
			a:        "hello",
			b:        "hello",
			expected: true,
		},
		{
			name:     "different strings",
			a:        "hello",
			b:        "world",
			expected: false,
		},
		{
			name:     "different lengths",
			a:        "hello",
			b:        "hello world",
			expected: false,
		},
		{
			name:     "empty strings",
			a:        "",
			b:        "",
			expected: true,
		},
		{
			name:     "one empty",
			a:        "hello",
			b:        "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TimingSafeCompare(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestTimingSafeCompareBytes tests constant-time byte comparison.
func TestTimingSafeCompareBytes(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected bool
	}{
		{
			name:     "equal bytes",
			a:        []byte{1, 2, 3},
			b:        []byte{1, 2, 3},
			expected: true,
		},
		{
			name:     "different bytes",
			a:        []byte{1, 2, 3},
			b:        []byte{1, 2, 4},
			expected: false,
		},
		{
			name:     "different lengths",
			a:        []byte{1, 2},
			b:        []byte{1, 2, 3},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TimingSafeCompareBytes(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestIsValidMode tests mode validation.
func TestIsValidMode(t *testing.T) {
	tests := []struct {
		mode     AshMode
		expected bool
	}{
		{ModeMinimal, true},
		{ModeBalanced, true},
		{ModeStrict, true},
		{AshMode("invalid"), false},
		{AshMode(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			result := IsValidMode(tt.mode)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestIsValidHTTPMethod tests HTTP method validation.
func TestIsValidHTTPMethod(t *testing.T) {
	tests := []struct {
		method   HttpMethod
		expected bool
	}{
		{MethodGET, true},
		{MethodPOST, true},
		{MethodPUT, true},
		{MethodPATCH, true},
		{MethodDELETE, true},
		{HttpMethod("OPTIONS"), false},
		{HttpMethod(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.method), func(t *testing.T) {
			result := IsValidHTTPMethod(tt.method)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestAshError tests error handling.
func TestAshError(t *testing.T) {
	err := NewAshError(ErrCanonicalizationError, "test message")

	if err.Code != ErrCanonicalizationError {
		t.Errorf("Expected code %s, got %s", ErrCanonicalizationError, err.Code)
	}

	if err.Message != "test message" {
		t.Errorf("Expected message %q, got %q", "test message", err.Message)
	}

	errStr := err.Error()
	if !strings.Contains(errStr, string(ErrCanonicalizationError)) {
		t.Errorf("Error string should contain code: %s", errStr)
	}
	if !strings.Contains(errStr, "test message") {
		t.Errorf("Error string should contain message: %s", errStr)
	}
}

// TestValidateProofInput tests proof input validation.
func TestValidateProofInput(t *testing.T) {
	tests := []struct {
		name    string
		input   BuildProofInput
		wantErr bool
	}{
		{
			name: "valid input",
			input: BuildProofInput{
				Mode:             ModeBalanced,
				Binding:          "POST /api/test",
				ContextID:        "ctx_123",
				CanonicalPayload: "{}",
			},
			wantErr: false,
		},
		{
			name: "invalid mode",
			input: BuildProofInput{
				Mode:             AshMode("invalid"),
				Binding:          "POST /api/test",
				ContextID:        "ctx_123",
				CanonicalPayload: "{}",
			},
			wantErr: true,
		},
		{
			name: "empty context id",
			input: BuildProofInput{
				Mode:             ModeBalanced,
				Binding:          "POST /api/test",
				ContextID:        "",
				CanonicalPayload: "{}",
			},
			wantErr: true,
		},
		{
			name: "empty binding",
			input: BuildProofInput{
				Mode:             ModeBalanced,
				Binding:          "",
				ContextID:        "ctx_123",
				CanonicalPayload: "{}",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProofInput(tt.input)
			if tt.wantErr && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestIsASCII tests ASCII detection.
func TestIsASCII(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"hello", true},
		{"Hello World 123!", true},
		{"", true},
		{"hello\u0000world", true}, // null is ASCII
		{"hello\u00e9", false},     // e with accent
		{"hello\u4e16\u754c", false}, // Chinese characters
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := IsASCII(tt.input)
			if result != tt.expected {
				t.Errorf("IsASCII(%q) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestContextPublicInfoJSON tests JSON serialization of ContextPublicInfo.
func TestContextPublicInfoJSON(t *testing.T) {
	info := ContextPublicInfo{
		ContextID: "ctx_123",
		ExpiresAt: 1704067200000,
		Mode:      ModeBalanced,
		Nonce:     "nonce_abc",
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded ContextPublicInfo
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.ContextID != info.ContextID {
		t.Errorf("ContextID mismatch: got %s, expected %s", decoded.ContextID, info.ContextID)
	}
	if decoded.ExpiresAt != info.ExpiresAt {
		t.Errorf("ExpiresAt mismatch: got %d, expected %d", decoded.ExpiresAt, info.ExpiresAt)
	}
	if decoded.Mode != info.Mode {
		t.Errorf("Mode mismatch: got %s, expected %s", decoded.Mode, info.Mode)
	}
	if decoded.Nonce != info.Nonce {
		t.Errorf("Nonce mismatch: got %s, expected %s", decoded.Nonce, info.Nonce)
	}
}

// TestCanonicalizeURLEncodedFromMap tests URL encoding from map.
func TestCanonicalizeURLEncodedFromMap(t *testing.T) {
	data := map[string][]string{
		"b": {"2"},
		"a": {"1", "3"},
	}

	result := CanonicalizeURLEncodedFromMap(data)

	// Should have a=1, a=3, b=2 (sorted by key, values in order)
	if !strings.Contains(result, "a=1") {
		t.Error("Result should contain a=1")
	}
	if !strings.Contains(result, "a=3") {
		t.Error("Result should contain a=3")
	}
	if !strings.Contains(result, "b=2") {
		t.Error("Result should contain b=2")
	}

	// Verify a comes before b
	aIdx := strings.Index(result, "a=")
	bIdx := strings.Index(result, "b=")
	if aIdx > bIdx {
		t.Error("a should come before b in sorted result")
	}
}

// TestHashBodyLowercaseHex tests that SHA-256 output is lowercase hex.
func TestHashBodyLowercaseHex(t *testing.T) {
	result := HashBody("test")

	// SHA-256 of "test" is known value
	expected := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}

	// Verify all characters are lowercase hex
	for _, c := range result {
		isLowerHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isLowerHex {
			t.Errorf("Character %c is not lowercase hex", c)
		}
	}

	// Verify length is 64 (32 bytes * 2 hex chars)
	if len(result) != 64 {
		t.Errorf("Expected length 64, got %d", len(result))
	}
}

// TestConstantTimeComparison tests that timing-safe comparison is used.
func TestConstantTimeComparison(t *testing.T) {
	// These tests verify the function works correctly, not the timing properties
	tests := []struct {
		a        string
		b        string
		expected bool
	}{
		{"abc", "abc", true},
		{"abc", "abd", false},
		{"abc", "ab", false},
		{"", "", true},
	}

	for _, tt := range tests {
		result := TimingSafeCompare(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("TimingSafeCompare(%q, %q) = %v, expected %v", tt.a, tt.b, result, tt.expected)
		}
	}
}

// Benchmark tests
func BenchmarkBuildProof(b *testing.B) {
	input := BuildProofInput{
		Mode:             ModeBalanced,
		Binding:          "POST /api/login",
		ContextID:        "ctx_benchmark_12345",
		Nonce:            "nonce_benchmark",
		CanonicalPayload: `{"password":"secret","username":"test"}`,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BuildProof(input)
	}
}

func BenchmarkCanonicalizeJSON(b *testing.B) {
	data := map[string]interface{}{
		"zebra":    float64(1),
		"apple":    float64(2),
		"mango":    float64(3),
		"nested":   map[string]interface{}{"key": "value"},
		"array":    []interface{}{float64(1), float64(2), float64(3)},
		"boolean":  true,
		"nullval":  nil,
		"string":   "hello world",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CanonicalizeJSON(data)
	}
}

func BenchmarkTimingSafeCompare(b *testing.B) {
	a := "this_is_a_test_proof_string_for_benchmarking"
	c := "this_is_a_test_proof_string_for_benchmarking"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		TimingSafeCompare(a, c)
	}
}
