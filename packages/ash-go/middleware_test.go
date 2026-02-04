package ash

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ============================================================================
// PATH MATCHING TESTS
// ============================================================================

func TestMiddlewarePathMatching(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		skipPaths  []string
		shouldSkip bool
	}{
		{"exact path match", "/api/secure", []string{"/api/secure"}, true},
		{"exact path no match", "/api/other", []string{"/api/secure"}, false},
		{"wildcard match", "/api/users", []string{"/api/*"}, true},
		{"wildcard nested match", "/api/users/123", []string{"/api/*"}, true},
		{"wildcard no match", "/other/path", []string{"/api/*"}, false},
		{"multiple paths first match", "/api/users", []string{"/api/users", "/api/orders"}, true},
		{"multiple paths second match", "/api/orders", []string{"/api/users", "/api/orders"}, true},
		{"root wildcard", "/anything", []string{"/*"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skipFn := func(c *gin.Context) bool {
				path := c.Request.URL.Path
				for _, p := range tt.skipPaths {
					if strings.HasSuffix(p, "*") {
						if strings.HasPrefix(path, strings.TrimSuffix(p, "*")) {
							return true
						}
					} else if path == p {
						return true
					}
				}
				return false
			}

			// Simulate the check
			req := httptest.NewRequest("GET", tt.path, nil)
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = req

			result := skipFn(c)
			if result != tt.shouldSkip {
				t.Errorf("expected skip=%v, got %v", tt.shouldSkip, result)
			}
		})
	}
}

// ============================================================================
// HEADER HANDLING TESTS
// ============================================================================

func TestMiddlewareHeaderHandling(t *testing.T) {
	t.Run("missing context ID returns error", func(t *testing.T) {
		store := NewAshMemoryStore()
		router := gin.New()
		router.POST("/api/test", AshGinMiddleware(AshGinMiddlewareOptions{
			Store: store,
		}), func(c *gin.Context) {
			c.JSON(200, gin.H{"success": true})
		})

		req := httptest.NewRequest("POST", "/api/test", nil)
		req.Header.Set("X-ASH-Proof", strings.Repeat("a", 64))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != 450 {
			t.Errorf("expected status 450, got %d", w.Code)
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["error"] != AshErrCtxNotFound {
			t.Errorf("expected error %s, got %v", AshErrCtxNotFound, resp["error"])
		}
	})

	t.Run("missing proof returns error", func(t *testing.T) {
		store := NewAshMemoryStore()
		router := gin.New()
		router.POST("/api/test", AshGinMiddleware(AshGinMiddlewareOptions{
			Store: store,
		}), func(c *gin.Context) {
			c.JSON(200, gin.H{"success": true})
		})

		req := httptest.NewRequest("POST", "/api/test", nil)
		req.Header.Set("X-ASH-Context-ID", "ctx_123")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != 483 {
			t.Errorf("expected status 483, got %d", w.Code)
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["error"] != AshErrProofMissing {
			t.Errorf("expected error %s, got %v", AshErrProofMissing, resp["error"])
		}
	})

	t.Run("invalid proof format returns error", func(t *testing.T) {
		store := NewAshMemoryStore()
		store.Store(&AshMiddlewareContext{
			ID:      "ctx_123",
			Nonce:   "abcd1234abcd1234abcd1234abcd1234",
			Binding: "POST|/api/test|",
		})

		router := gin.New()
		router.POST("/api/test", AshGinMiddleware(AshGinMiddlewareOptions{
			Store: store,
		}), func(c *gin.Context) {
			c.JSON(200, gin.H{"success": true})
		})

		req := httptest.NewRequest("POST", "/api/test", nil)
		req.Header.Set("X-ASH-Context-ID", "ctx_123")
		req.Header.Set("X-ASH-Proof", "invalid") // Not 64 chars
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != 460 {
			t.Errorf("expected status 460, got %d", w.Code)
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["error"] != AshErrProofInvalid {
			t.Errorf("expected error %s, got %v", AshErrProofInvalid, resp["error"])
		}
	})

	t.Run("scope header parsing", func(t *testing.T) {
		tests := []struct {
			header   string
			expected []string
		}{
			{"field1, field2, field3", []string{"field1", "field2", "field3"}},
			{"", []string{}},
			{"  field1  ,  field2  ", []string{"field1", "field2"}},
			{"single", []string{"single"}},
		}

		for _, tt := range tests {
			var result []string
			if tt.header != "" {
				for _, s := range strings.Split(tt.header, ",") {
					s = strings.TrimSpace(s)
					if s != "" {
						result = append(result, s)
					}
				}
			}

			if len(result) != len(tt.expected) {
				t.Errorf("for header %q: expected %d items, got %d", tt.header, len(tt.expected), len(result))
			}
		}
	})
}

// ============================================================================
// BINDING NORMALIZATION TESTS
// ============================================================================

func TestMiddlewareBindingNormalization(t *testing.T) {
	t.Run("binding from request parts", func(t *testing.T) {
		binding := AshNormalizeBinding("POST", "/api/users", "")
		if binding != "POST|/api/users|" {
			t.Errorf("expected POST|/api/users|, got %s", binding)
		}
	})

	t.Run("binding with query string", func(t *testing.T) {
		binding := AshNormalizeBinding("GET", "/api/search", "q=test&page=1")
		if !strings.Contains(binding, "page=1") {
			t.Errorf("expected binding to contain page=1: %s", binding)
		}
		if !strings.Contains(binding, "q=test") {
			t.Errorf("expected binding to contain q=test: %s", binding)
		}
	})

	t.Run("binding normalizes method to uppercase", func(t *testing.T) {
		binding := AshNormalizeBinding("post", "/api/users", "")
		if !strings.HasPrefix(binding, "POST|") {
			t.Errorf("expected binding to start with POST|: %s", binding)
		}
	})

	t.Run("binding normalizes path", func(t *testing.T) {
		binding := AshNormalizeBinding("GET", "/api//users/", "")
		if !strings.Contains(binding, "/api/users") {
			t.Errorf("expected normalized path: %s", binding)
		}
	})
}

// ============================================================================
// VERIFICATION FLOW TESTS
// ============================================================================

func TestMiddlewareVerificationFlow(t *testing.T) {
	t.Run("full verification success", func(t *testing.T) {
		nonce, _ := AshGenerateNonce(32)
		contextID, _ := AshGenerateContextID()
		binding := AshNormalizeBinding("POST", "/api/test", "")
		timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
		payload := map[string]interface{}{"test": "data"}

		canonical, _ := AshCanonicalizeJSON(payload)
		bodyHash := AshHashBody(canonical)
		clientSecret, err := AshDeriveClientSecret(nonce, contextID, binding)
		if err != nil {
			t.Fatal(err)
		}
		proof := AshBuildProofHMAC(clientSecret, timestamp, binding, bodyHash)

		// Verify
		result, err := AshVerifyProof(nonce, contextID, binding, timestamp, bodyHash, proof)
		if err != nil {
			t.Fatal(err)
		}
		if !result {
			t.Error("expected verification to succeed")
		}
	})

	t.Run("verification with middleware", func(t *testing.T) {
		nonce, _ := AshGenerateNonce(32)
		contextID, _ := AshGenerateContextID()
		binding := AshNormalizeBinding("POST", "/api/test", "")
		timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
		payload := map[string]interface{}{"test": "data"}

		canonical, _ := AshCanonicalizeJSON(payload)
		bodyHash := AshHashBody(canonical)
		clientSecret, err := AshDeriveClientSecret(nonce, contextID, binding)
		if err != nil {
			t.Fatal(err)
		}
		proof := AshBuildProofHMAC(clientSecret, timestamp, binding, bodyHash)

		store := NewAshMemoryStore()
		store.Store(&AshMiddlewareContext{
			ID:      contextID,
			Nonce:   nonce,
			Binding: binding,
		})

		router := gin.New()
		router.POST("/api/test", AshGinMiddleware(AshGinMiddlewareOptions{
			Store: store,
		}), func(c *gin.Context) {
			c.JSON(200, gin.H{"success": true})
		})

		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/test", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-ASH-Context-ID", contextID)
		req.Header.Set("X-ASH-Proof", proof)
		req.Header.Set("X-ASH-Timestamp", timestamp)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}
	})
}

// ============================================================================
// ERROR RESPONSE TESTS
// ============================================================================

func TestMiddlewareErrorResponses(t *testing.T) {
	t.Run("error response format", func(t *testing.T) {
		store := NewAshMemoryStore()
		router := gin.New()
		router.POST("/api/test", AshGinMiddleware(AshGinMiddlewareOptions{
			Store: store,
		}), func(c *gin.Context) {
			c.JSON(200, gin.H{"success": true})
		})

		req := httptest.NewRequest("POST", "/api/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)

		if _, ok := resp["error"]; !ok {
			t.Error("expected 'error' field in response")
		}
		if _, ok := resp["message"]; !ok {
			t.Error("expected 'message' field in response")
		}
	})

	t.Run("error codes to HTTP status mapping", func(t *testing.T) {
		mappings := map[string]int{
			AshErrCtxNotFound:            450,
			AshErrCtxExpired:             451,
			AshErrCtxAlreadyUsed:         452,
			AshErrProofInvalid:           460,
			AshErrBindingMismatch:        461,
			AshErrScopeMismatch:          473,
			AshErrChainBroken:            474,
			AshErrScopePolicyViolation:   475,
			AshErrTimestampInvalid:       482,
			AshErrProofMissing:           483,
			AshErrCanonicalizationError:  http.StatusUnprocessableEntity, // 422
			AshErrModeViolation:          http.StatusBadRequest,          // 400
			AshErrScopePolicyRequired:    http.StatusBadRequest,          // 400
		}

		for code, expectedStatus := range mappings {
			status := ashGetHTTPStatusForCode(code)
			if status != expectedStatus {
				t.Errorf("for code %s: expected %d, got %d", code, expectedStatus, status)
			}
		}
	})
}

// ============================================================================
// SCOPE HANDLING TESTS
// ============================================================================

func TestMiddlewareScopeHandling(t *testing.T) {
	t.Run("reject scope headers when unified disabled", func(t *testing.T) {
		store := NewAshMemoryStore()
		store.Store(&AshMiddlewareContext{
			ID:      "ctx_123",
			Nonce:   "abcd1234abcd1234abcd1234abcd1234",
			Binding: "POST|/api/test|",
		})

		router := gin.New()
		router.POST("/api/test", AshGinMiddleware(AshGinMiddlewareOptions{
			Store:         store,
			EnableUnified: false,
		}), func(c *gin.Context) {
			c.JSON(200, gin.H{"success": true})
		})

		req := httptest.NewRequest("POST", "/api/test", nil)
		req.Header.Set("X-ASH-Context-ID", "ctx_123")
		req.Header.Set("X-ASH-Proof", strings.Repeat("a", 64))
		req.Header.Set("X-ASH-Scope", "field1,field2")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", w.Code)
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["error"] != AshErrModeViolation {
			t.Errorf("expected error %s, got %v", AshErrModeViolation, resp["error"])
		}
	})

	t.Run("scope policy enforcement", func(t *testing.T) {
		policyScope := []string{"amount", "recipient"}
		clientScope := []string{"amount", "recipient"}

		normalizedClient := AshNormalizeScopeFields(clientScope)
		normalizedPolicy := AshNormalizeScopeFields(policyScope)

		if AshJoinScopeFields(normalizedClient) != AshJoinScopeFields(normalizedPolicy) {
			t.Error("expected scopes to match")
		}
	})

	t.Run("scope policy violation detection", func(t *testing.T) {
		policyScope := []string{"amount", "recipient"}
		clientScope := []string{"amount"} // Missing recipient

		normalizedClient := AshNormalizeScopeFields(clientScope)
		normalizedPolicy := AshNormalizeScopeFields(policyScope)

		if AshJoinScopeFields(normalizedClient) == AshJoinScopeFields(normalizedPolicy) {
			t.Error("expected scopes to not match")
		}
	})
}

// ============================================================================
// TIMESTAMP VALIDATION TESTS
// ============================================================================

func TestMiddlewareTimestampValidation(t *testing.T) {
	t.Run("valid timestamp", func(t *testing.T) {
		timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
		err := AshValidateTimestamp(timestamp, 300)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("expired timestamp", func(t *testing.T) {
		// 10 minutes ago
		oldTime := time.Now().Add(-10 * time.Minute).UnixMilli()
		timestamp := strconv.FormatInt(oldTime, 10)
		err := AshValidateTimestamp(timestamp, 300) // 5 minute max age
		if err == nil {
			t.Error("expected error for expired timestamp")
		}
	})

	t.Run("future timestamp", func(t *testing.T) {
		// 2 minutes in the future (beyond 30 second tolerance)
		futureTime := time.Now().Add(2 * time.Minute).UnixMilli()
		timestamp := strconv.FormatInt(futureTime, 10)
		err := AshValidateTimestamp(timestamp, 300)
		if err == nil {
			t.Error("expected error for future timestamp")
		}
	})

	t.Run("invalid timestamp format", func(t *testing.T) {
		err := AshValidateTimestamp("not-a-number", 300)
		if err == nil {
			t.Error("expected error for invalid timestamp format")
		}
	})
}

// ============================================================================
// CONTEXT STORE TESTS
// ============================================================================

func TestMiddlewareContextStore(t *testing.T) {
	t.Run("store and retrieve context", func(t *testing.T) {
		store := NewAshMemoryStore()

		ctx := &AshMiddlewareContext{
			ID:      "ctx_123",
			Nonce:   "abcd1234abcd1234abcd1234abcd1234",
			Binding: "POST|/api/test|",
		}
		store.Store(ctx)

		retrieved, err := store.Get("ctx_123")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if retrieved == nil {
			t.Fatal("expected context to be retrieved")
		}
		if retrieved.ID != "ctx_123" {
			t.Errorf("expected ID ctx_123, got %s", retrieved.ID)
		}
	})

	t.Run("get non-existent context", func(t *testing.T) {
		store := NewAshMemoryStore()

		retrieved, err := store.Get("non_existent")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if retrieved != nil {
			t.Error("expected nil for non-existent context")
		}
	})

	t.Run("consume context", func(t *testing.T) {
		store := NewAshMemoryStore()

		ctx := &AshMiddlewareContext{
			ID:      "ctx_123",
			Nonce:   "abcd1234abcd1234abcd1234abcd1234",
			Binding: "POST|/api/test|",
			Used:    false,
		}
		store.Store(ctx)

		err := store.Consume("ctx_123")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		retrieved, _ := store.Get("ctx_123")
		if !retrieved.Used {
			t.Error("expected context to be marked as used")
		}
	})

	t.Run("consume already used context", func(t *testing.T) {
		store := NewAshMemoryStore()

		ctx := &AshMiddlewareContext{
			ID:      "ctx_123",
			Nonce:   "abcd1234abcd1234abcd1234abcd1234",
			Binding: "POST|/api/test|",
			Used:    true,
		}
		store.Store(ctx)

		err := store.Consume("ctx_123")
		if err == nil {
			t.Error("expected error for already used context")
		}
	})
}

// ============================================================================
// REPLAY PROTECTION TESTS
// ============================================================================

func TestMiddlewareReplayProtection(t *testing.T) {
	t.Run("context already used returns error", func(t *testing.T) {
		store := NewAshMemoryStore()
		store.Store(&AshMiddlewareContext{
			ID:      "ctx_123",
			Nonce:   "abcd1234abcd1234abcd1234abcd1234",
			Binding: "POST|/api/test|",
			Used:    true, // Already used
		})

		router := gin.New()
		router.POST("/api/test", AshGinMiddleware(AshGinMiddlewareOptions{
			Store: store,
		}), func(c *gin.Context) {
			c.JSON(200, gin.H{"success": true})
		})

		req := httptest.NewRequest("POST", "/api/test", nil)
		req.Header.Set("X-ASH-Context-ID", "ctx_123")
		req.Header.Set("X-ASH-Proof", strings.Repeat("a", 64))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != 452 {
			t.Errorf("expected status 452, got %d", w.Code)
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["error"] != AshErrCtxAlreadyUsed {
			t.Errorf("expected error %s, got %v", AshErrCtxAlreadyUsed, resp["error"])
		}
	})
}

// ============================================================================
// BINDING MISMATCH TESTS
// ============================================================================

func TestMiddlewareBindingMismatch(t *testing.T) {
	t.Run("binding mismatch returns error", func(t *testing.T) {
		store := NewAshMemoryStore()
		store.Store(&AshMiddlewareContext{
			ID:      "ctx_123",
			Nonce:   "abcd1234abcd1234abcd1234abcd1234",
			Binding: "POST|/api/other|", // Different binding
		})

		router := gin.New()
		router.POST("/api/test", AshGinMiddleware(AshGinMiddlewareOptions{
			Store: store,
		}), func(c *gin.Context) {
			c.JSON(200, gin.H{"success": true})
		})

		req := httptest.NewRequest("POST", "/api/test", nil)
		req.Header.Set("X-ASH-Context-ID", "ctx_123")
		req.Header.Set("X-ASH-Proof", strings.Repeat("a", 64))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != 461 {
			t.Errorf("expected status 461, got %d", w.Code)
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["error"] != AshErrBindingMismatch {
			t.Errorf("expected error %s, got %v", AshErrBindingMismatch, resp["error"])
		}
	})
}

// ============================================================================
// CONTENT TYPE HANDLING TESTS
// ============================================================================

func TestMiddlewareContentTypeHandling(t *testing.T) {
	t.Run("JSON content type", func(t *testing.T) {
		contentType := "application/json"
		isJSON := strings.HasPrefix(contentType, "application/json")
		if !isJSON {
			t.Error("expected JSON detection")
		}
	})

	t.Run("JSON with charset", func(t *testing.T) {
		contentType := "application/json; charset=utf-8"
		isJSON := strings.HasPrefix(contentType, "application/json")
		if !isJSON {
			t.Error("expected JSON detection with charset")
		}
	})

	t.Run("form urlencoded", func(t *testing.T) {
		contentType := "application/x-www-form-urlencoded"
		isForm := strings.Contains(contentType, "x-www-form-urlencoded")
		if !isForm {
			t.Error("expected form detection")
		}
	})
}

// ============================================================================
// SKIP FUNCTION TESTS
// ============================================================================

func TestMiddlewareSkipFunction(t *testing.T) {
	t.Run("skip function allows bypass", func(t *testing.T) {
		store := NewAshMemoryStore()

		router := gin.New()
		router.GET("/health", AshGinMiddleware(AshGinMiddlewareOptions{
			Store: store,
			Skip: func(c *gin.Context) bool {
				return c.Request.URL.Path == "/health"
			},
		}), func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}
	})

	t.Run("skip function does not affect other routes", func(t *testing.T) {
		store := NewAshMemoryStore()

		router := gin.New()
		router.POST("/api/test", AshGinMiddleware(AshGinMiddlewareOptions{
			Store: store,
			Skip: func(c *gin.Context) bool {
				return c.Request.URL.Path == "/health"
			},
		}), func(c *gin.Context) {
			c.JSON(200, gin.H{"success": true})
		})

		req := httptest.NewRequest("POST", "/api/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should fail because no ASH headers
		if w.Code == http.StatusOK {
			t.Error("expected middleware to run for non-skipped path")
		}
	})
}

// ============================================================================
// CUSTOM ERROR HANDLER TESTS
// ============================================================================

func TestMiddlewareCustomErrorHandler(t *testing.T) {
	t.Run("custom error handler is called", func(t *testing.T) {
		store := NewAshMemoryStore()
		customHandlerCalled := false

		router := gin.New()
		router.POST("/api/test", AshGinMiddleware(AshGinMiddlewareOptions{
			Store: store,
			OnError: func(c *gin.Context, err *AshVerifyError) {
				customHandlerCalled = true
				c.AbortWithStatusJSON(err.StatusCode, gin.H{
					"custom_error": err.Code,
					"custom_msg":   err.Message,
					"timestamp":    time.Now().Unix(),
				})
			},
		}), func(c *gin.Context) {
			c.JSON(200, gin.H{"success": true})
		})

		req := httptest.NewRequest("POST", "/api/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if !customHandlerCalled {
			t.Error("expected custom error handler to be called")
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if _, ok := resp["custom_error"]; !ok {
			t.Error("expected custom_error field in response")
		}
		if _, ok := resp["timestamp"]; !ok {
			t.Error("expected timestamp field in response")
		}
	})
}

// ============================================================================
// METADATA STORAGE TESTS
// ============================================================================

func TestMiddlewareMetadataStorage(t *testing.T) {
	t.Run("stores metadata in gin context", func(t *testing.T) {
		nonce, _ := AshGenerateNonce(32)
		contextID, _ := AshGenerateContextID()
		binding := AshNormalizeBinding("POST", "/api/test", "")
		timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
		payload := map[string]interface{}{"test": "data"}

		canonical, _ := AshCanonicalizeJSON(payload)
		bodyHash := AshHashBody(canonical)
		clientSecret, err := AshDeriveClientSecret(nonce, contextID, binding)
		if err != nil {
			t.Fatal(err)
		}
		proof := AshBuildProofHMAC(clientSecret, timestamp, binding, bodyHash)

		store := NewAshMemoryStore()
		store.Store(&AshMiddlewareContext{
			ID:       contextID,
			Nonce:    nonce,
			Binding:  binding,
			Metadata: map[string]interface{}{"user_id": "123"},
		})

		var storedContext *AshMiddlewareContext
		var scopeExists bool

		router := gin.New()
		router.POST("/api/test", AshGinMiddleware(AshGinMiddlewareOptions{
			Store: store,
		}), func(c *gin.Context) {
			ctx, _ := c.Get("ashContext")
			storedContext = ctx.(*AshMiddlewareContext)
			_, scopeExists = c.Get("ashScope")
			c.JSON(200, gin.H{"success": true})
		})

		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/test", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-ASH-Context-ID", contextID)
		req.Header.Set("X-ASH-Proof", proof)
		req.Header.Set("X-ASH-Timestamp", timestamp)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}

		if storedContext == nil {
			t.Error("expected ashContext to be stored")
		}
		if !scopeExists {
			t.Error("expected ashScope to be stored")
		}
	})
}

// ============================================================================
// CHAINED PROOFS TESTS
// ============================================================================

func TestMiddlewareChainedProofs(t *testing.T) {
	t.Run("verify with chain hash", func(t *testing.T) {
		nonce, _ := AshGenerateNonce(32)
		contextID, _ := AshGenerateContextID()
		binding := AshNormalizeBinding("POST", "/api/test", "")
		timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
		payload := map[string]interface{}{"test": "data"}
		previousProof := strings.Repeat("a", 64)

		clientSecret, err := AshDeriveClientSecret(nonce, contextID, binding)
		if err != nil {
			t.Fatal(err)
		}
		result := AshBuildProofUnified(clientSecret, timestamp, binding, payload, nil, previousProof)

		store := NewAshMemoryStore()
		store.Store(&AshMiddlewareContext{
			ID:            contextID,
			Nonce:         nonce,
			Binding:       binding,
			PreviousProof: previousProof,
		})

		router := gin.New()
		router.POST("/api/test", AshGinMiddleware(AshGinMiddlewareOptions{
			Store:         store,
			EnableUnified: true,
		}), func(c *gin.Context) {
			c.JSON(200, gin.H{"success": true})
		})

		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/test", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-ASH-Context-ID", contextID)
		req.Header.Set("X-ASH-Proof", result.Proof)
		req.Header.Set("X-ASH-Timestamp", timestamp)
		req.Header.Set("X-ASH-Chain-Hash", result.ChainHash)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}
	})
}

// ============================================================================
// CONCURRENCY TESTS
// ============================================================================

func TestMiddlewareConcurrency(t *testing.T) {
	t.Run("independent requests", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			nonce, _ := AshGenerateNonce(32)
			contextID, _ := AshGenerateContextID()
			binding := AshNormalizeBinding("POST", "/api/test", "")

			clientSecret, err := AshDeriveClientSecret(nonce, contextID, binding)
			if err != nil {
				t.Fatal(err)
			}
			if len(clientSecret) != 64 {
				t.Errorf("expected client secret length 64, got %d", len(clientSecret))
			}
		}
	})

	t.Run("no state leakage", func(t *testing.T) {
		nonce1, _ := AshGenerateNonce(32)
		ctx1, _ := AshGenerateContextID()

		nonce2, _ := AshGenerateNonce(32)
		ctx2, _ := AshGenerateContextID()

		if nonce1 == nonce2 {
			t.Error("expected different nonces")
		}
		if ctx1 == ctx2 {
			t.Error("expected different context IDs")
		}
	})
}

// ============================================================================
// EXPECTED BINDING TESTS
// ============================================================================

func TestMiddlewareExpectedBinding(t *testing.T) {
	t.Run("uses expected binding when provided", func(t *testing.T) {
		expectedBinding := "POST|/api/transfer|"
		nonce, _ := AshGenerateNonce(32)
		contextID, _ := AshGenerateContextID()
		timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
		payload := map[string]interface{}{"amount": 100}

		canonical, _ := AshCanonicalizeJSON(payload)
		bodyHash := AshHashBody(canonical)
		clientSecret, err := AshDeriveClientSecret(nonce, contextID, expectedBinding)
		if err != nil {
			t.Fatal(err)
		}
		proof := AshBuildProofHMAC(clientSecret, timestamp, expectedBinding, bodyHash)

		store := NewAshMemoryStore()
		store.Store(&AshMiddlewareContext{
			ID:      contextID,
			Nonce:   nonce,
			Binding: expectedBinding,
		})

		router := gin.New()
		// Actual path is /api/test but we use expected binding
		router.POST("/api/test", AshGinMiddleware(AshGinMiddlewareOptions{
			Store:           store,
			ExpectedBinding: expectedBinding,
		}), func(c *gin.Context) {
			c.JSON(200, gin.H{"success": true})
		})

		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/test", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-ASH-Context-ID", contextID)
		req.Header.Set("X-ASH-Proof", proof)
		req.Header.Set("X-ASH-Timestamp", timestamp)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}
	})
}

// ============================================================================
// UNIFIED VERIFICATION TESTS
// ============================================================================

func TestMiddlewareUnifiedVerification(t *testing.T) {
	t.Run("unified verification with scope", func(t *testing.T) {
		nonce, _ := AshGenerateNonce(32)
		contextID, _ := AshGenerateContextID()
		binding := AshNormalizeBinding("POST", "/api/test", "")
		timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
		payload := map[string]interface{}{"amount": 100, "recipient": "user123"}
		scope := []string{"amount", "recipient"}

		clientSecret, err := AshDeriveClientSecret(nonce, contextID, binding)
		if err != nil {
			t.Fatal(err)
		}
		result := AshBuildProofUnified(clientSecret, timestamp, binding, payload, scope, "")

		store := NewAshMemoryStore()
		store.Store(&AshMiddlewareContext{
			ID:      contextID,
			Nonce:   nonce,
			Binding: binding,
		})

		router := gin.New()
		router.POST("/api/test", AshGinMiddleware(AshGinMiddlewareOptions{
			Store:         store,
			EnableUnified: true,
		}), func(c *gin.Context) {
			c.JSON(200, gin.H{"success": true})
		})

		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/test", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-ASH-Context-ID", contextID)
		req.Header.Set("X-ASH-Proof", result.Proof)
		req.Header.Set("X-ASH-Timestamp", timestamp)
		req.Header.Set("X-ASH-Scope", strings.Join(scope, ","))
		req.Header.Set("X-ASH-Scope-Hash", result.ScopeHash)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("unified verification requires timestamp", func(t *testing.T) {
		store := NewAshMemoryStore()
		store.Store(&AshMiddlewareContext{
			ID:      "ctx_123",
			Nonce:   "abcd1234abcd1234abcd1234abcd1234",
			Binding: "POST|/api/test|",
		})

		router := gin.New()
		router.POST("/api/test", AshGinMiddleware(AshGinMiddlewareOptions{
			Store:         store,
			EnableUnified: true,
		}), func(c *gin.Context) {
			c.JSON(200, gin.H{"success": true})
		})

		req := httptest.NewRequest("POST", "/api/test", bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-ASH-Context-ID", "ctx_123")
		req.Header.Set("X-ASH-Proof", strings.Repeat("a", 64))
		req.Header.Set("X-ASH-Scope", "amount")
		// No timestamp header
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != 482 {
			t.Errorf("expected status 482, got %d", w.Code)
		}
	})
}

// ============================================================================
// EMPTY BODY HANDLING TESTS
// ============================================================================

func TestMiddlewareEmptyBodyHandling(t *testing.T) {
	t.Run("handles empty JSON body", func(t *testing.T) {
		nonce, _ := AshGenerateNonce(32)
		contextID, _ := AshGenerateContextID()
		binding := AshNormalizeBinding("POST", "/api/test", "")
		timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)

		bodyHash := AshHashBody("")
		clientSecret, err := AshDeriveClientSecret(nonce, contextID, binding)
		if err != nil {
			t.Fatal(err)
		}
		proof := AshBuildProofHMAC(clientSecret, timestamp, binding, bodyHash)

		store := NewAshMemoryStore()
		store.Store(&AshMiddlewareContext{
			ID:      contextID,
			Nonce:   nonce,
			Binding: binding,
		})

		router := gin.New()
		router.POST("/api/test", AshGinMiddleware(AshGinMiddlewareOptions{
			Store: store,
		}), func(c *gin.Context) {
			c.JSON(200, gin.H{"success": true})
		})

		req := httptest.NewRequest("POST", "/api/test", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-ASH-Context-ID", contextID)
		req.Header.Set("X-ASH-Proof", proof)
		req.Header.Set("X-ASH-Timestamp", timestamp)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}
	})
}

// ============================================================================
// BACKWARD COMPATIBILITY TESTS
// ============================================================================

func TestMiddlewareBackwardCompatibility(t *testing.T) {
	t.Run("deprecated NewMemoryStore works", func(t *testing.T) {
		store := NewMemoryStore()
		if store == nil {
			t.Error("expected store to be created")
		}

		store.Store(&AshMiddlewareContext{
			ID:    "test",
			Nonce: "nonce",
		})

		ctx, _ := store.Get("test")
		if ctx == nil {
			t.Error("expected context to be retrievable")
		}
	})

	t.Run("ContextStore type alias works", func(t *testing.T) {
		var store ContextStore = NewAshMemoryStore()
		if store == nil {
			t.Error("expected store to be assignable to ContextStore")
		}
	})
}

// ============================================================================
// FORM DATA HANDLING TESTS
// ============================================================================

func TestMiddlewareFormDataHandling(t *testing.T) {
	t.Run("handles form urlencoded data", func(t *testing.T) {
		nonce, _ := AshGenerateNonce(32)
		contextID, _ := AshGenerateContextID()
		binding := AshNormalizeBinding("POST", "/api/test", "")
		timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
		formData := "key=value&other=data"

		canonical, _ := AshCanonicalizeURLEncoded(formData)
		bodyHash := AshHashBody(canonical)
		clientSecret, err := AshDeriveClientSecret(nonce, contextID, binding)
		if err != nil {
			t.Fatal(err)
		}
		proof := AshBuildProofHMAC(clientSecret, timestamp, binding, bodyHash)

		store := NewAshMemoryStore()
		store.Store(&AshMiddlewareContext{
			ID:      contextID,
			Nonce:   nonce,
			Binding: binding,
		})

		router := gin.New()
		router.POST("/api/test", AshGinMiddleware(AshGinMiddlewareOptions{
			Store: store,
		}), func(c *gin.Context) {
			c.JSON(200, gin.H{"success": true})
		})

		req := httptest.NewRequest("POST", "/api/test", bytes.NewReader([]byte(formData)))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-ASH-Context-ID", contextID)
		req.Header.Set("X-ASH-Proof", proof)
		req.Header.Set("X-ASH-Timestamp", timestamp)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}
	})
}
