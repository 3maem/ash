package ash

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// HTTPMiddleware creates an HTTP middleware for ASH verification.
func HTTPMiddleware(ash *Ash, protectedPaths []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if path should be protected
			path := r.URL.Path
			shouldVerify := false

			for _, p := range protectedPaths {
				if strings.HasSuffix(p, "*") {
					if strings.HasPrefix(path, strings.TrimSuffix(p, "*")) {
						shouldVerify = true
						break
					}
				} else if path == p {
					shouldVerify = true
					break
				}
			}

			if !shouldVerify {
				next.ServeHTTP(w, r)
				return
			}

			// Get headers
			contextID := r.Header.Get("X-ASH-Context-ID")
			proof := r.Header.Get("X-ASH-Proof")

			if contextID == "" {
				writeError(w, "MISSING_CONTEXT_ID", "Missing X-ASH-Context-ID header", 403)
				return
			}

			if proof == "" {
				writeError(w, "MISSING_PROOF", "Missing X-ASH-Proof header", 403)
				return
			}

			// Normalize binding
			binding := ash.AshNormalizeBinding(r.Method, path)

			// Get payload
			var payload string
			if r.Body != nil {
				body, err := io.ReadAll(r.Body)
				if err == nil {
					payload = string(body)
				}
				// Restore body for downstream handlers
				r.Body = io.NopCloser(strings.NewReader(payload))
			}

			contentType := r.Header.Get("Content-Type")

			// Verify
			result := ash.AshVerify(contextID, proof, binding, payload, contentType)

			if !result.Valid {
				writeError(w, string(result.ErrorCode), result.ErrorMessage, 403)
				return
			}

			// Store metadata in request context (via header for simplicity)
			if result.Metadata != nil {
				if metaJSON, err := json.Marshal(result.Metadata); err == nil {
					r.Header.Set("X-ASH-Metadata", string(metaJSON))
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GinMiddleware creates a Gin middleware for ASH verification.
// Usage:
//
//	router.Use(ash.GinMiddleware(ashInstance, []string{"/api/*"}))
func GinMiddleware(ash *Ash, protectedPaths []string) interface{} {
	// Returns a function compatible with Gin's HandlerFunc
	return func(c interface{}) {
		// This is a placeholder - actual implementation would use gin.Context
		// Users should adapt this for their Gin version
	}
}

// EchoMiddleware creates an Echo middleware for ASH verification.
// Usage:
//
//	e.Use(ash.EchoMiddleware(ashInstance, []string{"/api/*"}))
func EchoMiddleware(ash *Ash, protectedPaths []string) interface{} {
	// Returns a function compatible with Echo's MiddlewareFunc
	return func(next interface{}) interface{} {
		// This is a placeholder - actual implementation would use echo.Context
		// Users should adapt this for their Echo version
		return nil
	}
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, code, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}

// ContextHandler is an HTTP handler for issuing contexts.
type ContextHandler struct {
	ash *Ash
}

// NewContextHandler creates a new context handler.
func NewContextHandler(ash *Ash) *ContextHandler {
	return &ContextHandler{ash: ash}
}

// ServeHTTP handles context issuance requests.
func (h *ContextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	binding := r.URL.Query().Get("binding")
	if binding == "" {
		binding = "POST /api/update"
	}

	modeStr := r.URL.Query().Get("mode")
	mode := ModeBalanced
	switch modeStr {
	case "minimal":
		mode = ModeMinimal
	case "strict":
		mode = ModeStrict
	}

	ctx, err := h.ash.AshIssueContextWithMode(binding, 30000, mode, nil)
	if err != nil {
		writeError(w, "CONTEXT_CREATION_FAILED", "Failed to create context", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"contextId": ctx.ID,
		"binding":   ctx.Binding,
		"expiresAt": ctx.ExpiresAt,
		"mode":      ctx.Mode,
		"nonce":     ctx.Nonce,
	})
}
