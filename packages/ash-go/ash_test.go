package ash

import (
	"testing"
)

func TestCanonicalizeJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple object key ordering",
			input:    `{"z":1,"a":2}`,
			expected: `{"a":2,"z":1}`,
		},
		{
			name:     "nested object key ordering",
			input:    `{"b":{"d":4,"c":3},"a":1}`,
			expected: `{"a":1,"b":{"c":3,"d":4}}`,
		},
		{
			name:     "array order preserved",
			input:    `{"arr":[3,1,2]}`,
			expected: `{"arr":[3,1,2]}`,
		},
		{
			name:     "empty object",
			input:    `{}`,
			expected: `{}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := AshCanonicalizeJSON(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("got %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestCanonicalizeURLEncoded(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple key ordering",
			input:    "z=1&a=2",
			expected: "a=2&z=1",
		},
		{
			name:     "empty input",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := AshCanonicalizeURLEncoded(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("got %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestNormalizeBinding(t *testing.T) {
	tests := []struct {
		method   string
		path     string
		expected string
	}{
		{"post", "/api/test", "POST /api/test"},
		{"GET", "/api//test/", "GET /api/test"},
		{"put", "api/test", "PUT /api/test"},
		{"DELETE", "/", "DELETE /"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			result := AshNormalizeBinding(tt.method, tt.path)
			if result != tt.expected {
				t.Errorf("got %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestBuildAndVerifyProof(t *testing.T) {
	proof1 := AshBuildProof(ModeBalanced, "POST /api/test", "ctx123", "", `{"a":1}`)
	proof2 := AshBuildProof(ModeBalanced, "POST /api/test", "ctx123", "", `{"a":1}`)

	if proof1 != proof2 {
		t.Error("identical inputs should produce identical proofs")
	}

	if !AshVerifyProof(proof1, proof2) {
		t.Error("identical proofs should verify as equal")
	}

	proof3 := AshBuildProof(ModeBalanced, "POST /api/test", "ctx123", "", `{"a":2}`)
	if AshVerifyProof(proof1, proof3) {
		t.Error("different proofs should not verify as equal")
	}
}

func TestTimingSafeEqual(t *testing.T) {
	if !AshTimingSafeEqual("test", "test") {
		t.Error("identical strings should be equal")
	}

	if AshTimingSafeEqual("test", "Test") {
		t.Error("different strings should not be equal")
	}

	if AshTimingSafeEqual("short", "longer") {
		t.Error("different length strings should not be equal")
	}
}

func TestMemoryStore(t *testing.T) {
	store := NewMemoryStore()

	// Create context
	ctx, err := store.Create("POST /api/test", 30000, ModeBalanced, nil)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}

	// Get context
	retrieved, err := store.Get(ctx.ID)
	if err != nil {
		t.Fatalf("failed to get context: %v", err)
	}
	if retrieved.ID != ctx.ID {
		t.Error("retrieved context ID doesn't match")
	}

	// Consume context
	if err := store.Consume(ctx.ID); err != nil {
		t.Fatalf("failed to consume context: %v", err)
	}

	// Try to consume again
	if err := store.Consume(ctx.ID); err == nil {
		t.Error("should not be able to consume context twice")
	}
}

func TestAshVerify(t *testing.T) {
	store := NewMemoryStore()
	ash := New(store, ModeBalanced)

	// Issue context
	ctx, err := ash.AshIssueContext("POST /api/test", 30000, nil)
	if err != nil {
		t.Fatalf("failed to issue context: %v", err)
	}

	// Build proof
	payload := `{"a":1}`
	canonicalPayload, _ := AshCanonicalizeJSON(payload)
	proof := AshBuildProof(ctx.Mode, ctx.Binding, ctx.ID, ctx.Nonce, canonicalPayload)

	// Verify
	result := ash.AshVerify(ctx.ID, proof, "POST /api/test", payload, "application/json")
	if !result.Valid {
		t.Errorf("verification should succeed: %s", result.ErrorMessage)
	}

	// Try to verify again (replay)
	result = ash.AshVerify(ctx.ID, proof, "POST /api/test", payload, "application/json")
	if result.Valid {
		t.Error("replay should be detected")
	}
}
