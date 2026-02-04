package ash

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// isProduction detects if the application is running in production mode.
// Checks GIN_MODE, APP_ENV, and ENV environment variables.
func isProduction() bool {
	env := os.Getenv("GIN_MODE")
	if env == "release" {
		return true
	}
	env = os.Getenv("APP_ENV")
	if env == "production" || env == "prod" {
		return true
	}
	env = os.Getenv("ENV")
	return env == "production" || env == "prod"
}

// AshGinMiddlewareOptions configures the ASH Gin middleware.
type AshGinMiddlewareOptions struct {
	// Store is the context store instance (required)
	Store AshContextStore

	// ExpectedBinding is the expected endpoint binding (optional)
	// If not set, binding is computed from the request
	ExpectedBinding string

	// EnableUnified enables v2.3 unified verification (scoping + chaining)
	EnableUnified bool

	// MaxTimestampAgeSeconds is the maximum age for timestamps in seconds
	// Set to 0 to disable timestamp freshness validation (not recommended)
	// Default: 300 (5 minutes)
	MaxTimestampAgeSeconds int

	// Skip is a function to skip verification for certain requests
	Skip func(c *gin.Context) bool

	// OnError is a custom error handler (optional)
	// If not set, returns JSON error response
	OnError func(c *gin.Context, err *AshVerifyError)

	// EnforceIp enables IP address binding verification (v2.3.4)
	// Verifies that the request IP matches the context IP
	EnforceIp bool

	// EnforceUser enables user binding verification (v2.3.4)
	// Verifies that the authenticated user matches the context user_id
	// Use UserIDExtractor to customize user ID extraction
	EnforceUser bool

	// UserIDExtractor extracts user ID from gin context for user binding (v2.3.4)
	// If nil, looks for "user_id" in context using c.Get("user_id")
	UserIDExtractor func(c *gin.Context) (string, error)
}

// AshVerifyError represents a verification error.
type AshVerifyError struct {
	Code       string
	Message    string
	StatusCode int
}

// Error implements the error interface.
func (e *AshVerifyError) Error() string {
	return e.Message
}

// ASH error codes per SDK Implementation Reference Section 8.
const (
	AshErrCtxNotFound            = "ASH_CTX_NOT_FOUND"
	AshErrCtxExpired             = "ASH_CTX_EXPIRED"
	AshErrCtxAlreadyUsed         = "ASH_CTX_ALREADY_USED"
	AshErrBindingMismatch        = "ASH_BINDING_MISMATCH"
	AshErrProofMissing           = "ASH_PROOF_MISSING"
	AshErrProofInvalid           = "ASH_PROOF_INVALID"
	AshErrCanonicalizationError  = "ASH_CANONICALIZATION_ERROR"
	AshErrMalformedRequest       = "ASH_MALFORMED_REQUEST"
	AshErrModeViolation          = "ASH_MODE_VIOLATION"
	AshErrUnsupportedContentType = "ASH_UNSUPPORTED_CONTENT_TYPE"
	AshErrScopeMismatch          = "ASH_SCOPE_MISMATCH"
	AshErrChainBroken            = "ASH_CHAIN_BROKEN"
	AshErrInternalError          = "ASH_INTERNAL_ERROR"
	AshErrTimestampInvalid       = "ASH_TIMESTAMP_INVALID"
	AshErrScopePolicyRequired    = "ASH_SCOPE_POLICY_REQUIRED"
	AshErrScopePolicyViolation   = "ASH_SCOPE_POLICY_VIOLATION"
)

// ASH header names for v2.3 unified proof.
const (
	HeaderContextID = "X-ASH-Context-ID"
	HeaderProof     = "X-ASH-Proof"
	HeaderTimestamp = "X-ASH-Timestamp"
	HeaderScope     = "X-ASH-Scope"
	HeaderScopeHash = "X-ASH-Scope-Hash"
	HeaderChainHash = "X-ASH-Chain-Hash"
)

// ashGetHTTPStatusForCode returns the recommended HTTP status code for an ASH error code.
//
// v2.3.4: Uses unique HTTP status codes in the 450-499 range for ASH-specific errors.
// This enables precise error identification, better monitoring, and targeted retry logic.
//
// Error Categories:
// - 450-459: Context errors
// - 460-469: Seal/Proof errors
// - 461: Binding errors
// - 473-479: Verification errors
// - 480-489: Format/Protocol errors
func ashGetHTTPStatusForCode(code string) int {
	statusMap := map[string]int{
		// Context errors (450-459)
		AshErrCtxNotFound:    450,
		AshErrCtxExpired:     451,
		AshErrCtxAlreadyUsed: 452,
		// Seal/Proof errors (460-469)
		AshErrProofInvalid: 460,
		// Binding errors (461)
		AshErrBindingMismatch:      461,
		AshErrScopeMismatch:        473,
		AshErrChainBroken:          474,
		AshErrScopePolicyViolation: 475,
		// Format/Protocol errors (480-489)
		AshErrTimestampInvalid: 482,
		AshErrProofMissing:     483,
		// Standard HTTP codes (preserved for semantic clarity)
		AshErrCanonicalizationError:  http.StatusUnprocessableEntity, // 422
		AshErrMalformedRequest:       http.StatusBadRequest,          // 400
		AshErrModeViolation:          http.StatusBadRequest,          // 400
		AshErrUnsupportedContentType: http.StatusUnsupportedMediaType, // 415
		AshErrScopePolicyRequired:    http.StatusBadRequest,          // 400
		AshErrInternalError:          http.StatusInternalServerError, // 500
	}
	if status, ok := statusMap[code]; ok {
		return status
	}
	return http.StatusInternalServerError
}

// AshGinMiddleware creates a Gin middleware for ASH verification.
//
// Example:
//
//	r := gin.Default()
//	store := ash.NewAshMemoryStore()
//
//	r.POST("/api/update", ash.AshGinMiddleware(ash.AshGinMiddlewareOptions{
//		Store: store,
//	}), func(c *gin.Context) {
//		c.JSON(200, gin.H{"success": true})
//	})
//
//	// With v2.3 unified features (scoping + chaining)
//	r.POST("/api/transfer", ash.AshGinMiddleware(ash.AshGinMiddlewareOptions{
//		Store:         store,
//		EnableUnified: true,
//	}), func(c *gin.Context) {
//		scope := c.GetStringSlice("ashScope")
//		c.JSON(200, gin.H{"success": true, "scope": scope})
//	})
func AshGinMiddleware(options AshGinMiddlewareOptions) gin.HandlerFunc {
	// Set defaults
	if options.MaxTimestampAgeSeconds == 0 {
		options.MaxTimestampAgeSeconds = 300 // 5 minutes
	}

	defaultErrorHandler := func(c *gin.Context, err *AshVerifyError) {
		c.AbortWithStatusJSON(err.StatusCode, gin.H{
			"error":   err.Code,
			"message": err.Message,
		})
	}

	if options.OnError == nil {
		options.OnError = defaultErrorHandler
	}

	return func(c *gin.Context) {
		// Check skip condition
		if options.Skip != nil && options.Skip(c) {
			c.Next()
			return
		}

		// Get required headers
		contextID := c.GetHeader(HeaderContextID)
		proof := c.GetHeader(HeaderProof)

		// Get optional v2.3 headers
		timestamp := c.GetHeader(HeaderTimestamp)
		scopeHeader := c.GetHeader(HeaderScope)
		scopeHash := c.GetHeader(HeaderScopeHash)
		chainHash := c.GetHeader(HeaderChainHash)

		// Parse client scope fields
		var clientScope []string
		if scopeHeader != "" {
			for _, s := range strings.Split(scopeHeader, ",") {
				s = strings.TrimSpace(s)
				if s != "" {
					clientScope = append(clientScope, s)
				}
			}
		}

		// Reject scope headers when unified mode is disabled
		if !options.EnableUnified && (len(clientScope) > 0 || scopeHash != "" || chainHash != "") {
			message := "Invalid request"
			if !isProduction() {
				message = "Scope/chain headers are not supported without EnableUnified=true"
			}
			options.OnError(c, &AshVerifyError{
				Code:       AshErrModeViolation,
				Message:    message,
				StatusCode: ashGetHTTPStatusForCode(AshErrModeViolation),
			})
			return
		}

		// Normalize binding
		binding := AshNormalizeBinding(c.Request.Method, c.Request.URL.Path, c.Request.URL.RawQuery)
		effectiveBinding := binding
		if options.ExpectedBinding != "" {
			effectiveBinding = options.ExpectedBinding
		}

		// Check server-side scope policy (ENH-003)
		policyScope := AshGetScopePolicy(effectiveBinding)
		hasPolicyScope := len(policyScope) > 0

		// If server has a scope policy but unified mode is disabled, configuration is invalid
		if hasPolicyScope && !options.EnableUnified {
			message := "Invalid request"
			if !isProduction() {
				message = "Server has a scope policy but EnableUnified=false"
			}
			options.OnError(c, &AshVerifyError{
				Code:       AshErrModeViolation,
				Message:    message,
				StatusCode: ashGetHTTPStatusForCode(AshErrModeViolation),
			})
			return
		}

		// Determine effective scope
		scope := clientScope
		if hasPolicyScope {
			// If server has a policy, client MUST use it
			if len(clientScope) == 0 {
				message := "Invalid request"
				if !isProduction() {
					message = "This endpoint requires scope headers per server policy"
				}
				options.OnError(c, &AshVerifyError{
					Code:       AshErrScopePolicyRequired,
					Message:    message,
					StatusCode: ashGetHTTPStatusForCode(AshErrScopePolicyRequired),
				})
				return
			}

			// Verify client scope matches server policy
			normalizedClientScope := AshNormalizeScopeFields(clientScope)
			normalizedPolicyScope := AshNormalizeScopeFields(policyScope)

			if AshJoinScopeFields(normalizedClientScope) != AshJoinScopeFields(normalizedPolicyScope) {
				message := "Invalid request"
				if !isProduction() {
					message = fmt.Sprintf("Request scope does not match server policy: expected %v, got %v", policyScope, clientScope)
				}
				options.OnError(c, &AshVerifyError{
					Code:       AshErrScopePolicyViolation,
					Message:    message,
					StatusCode: ashGetHTTPStatusForCode(AshErrScopePolicyViolation),
				})
				return
			}

			scope = policyScope
		}

		// Validate required headers
		if contextID == "" {
			options.OnError(c, &AshVerifyError{
				Code:       AshErrCtxNotFound,
				Message:    "Missing X-ASH-Context-ID header",
				StatusCode: ashGetHTTPStatusForCode(AshErrCtxNotFound),
			})
			return
		}

		if proof == "" {
			options.OnError(c, &AshVerifyError{
				Code:       AshErrProofMissing,
				Message:    "Missing X-ASH-Proof header",
				StatusCode: ashGetHTTPStatusForCode(AshErrProofMissing),
			})
			return
		}

		// Validate proof format
		if len(proof) != 64 {
			options.OnError(c, &AshVerifyError{
				Code:       AshErrProofInvalid,
				Message:    "Invalid proof format",
				StatusCode: ashGetHTTPStatusForCode(AshErrProofInvalid),
			})
			return
		}

		// Validate timestamp freshness
		if timestamp != "" && options.MaxTimestampAgeSeconds > 0 {
			if err := AshValidateTimestamp(timestamp, options.MaxTimestampAgeSeconds); err != nil {
				options.OnError(c, &AshVerifyError{
					Code:       AshErrTimestampInvalid,
					Message:    err.Error(),
					StatusCode: ashGetHTTPStatusForCode(AshErrTimestampInvalid),
				})
				return
			}
		}

		// Get context from store
		ctx, err := options.Store.Get(contextID)
		if err != nil || ctx == nil {
			options.OnError(c, &AshVerifyError{
				Code:       AshErrCtxNotFound,
				Message:    "Invalid or expired context",
				StatusCode: ashGetHTTPStatusForCode(AshErrCtxNotFound),
			})
			return
		}

		// Check if context was already used
		if ctx.Used {
			options.OnError(c, &AshVerifyError{
				Code:       AshErrCtxAlreadyUsed,
				Message:    "Context already used (replay detected)",
				StatusCode: ashGetHTTPStatusForCode(AshErrCtxAlreadyUsed),
			})
			return
		}

		// Check binding match
		if ctx.Binding != effectiveBinding {
			message := "Request binding does not match context"
			if !isProduction() {
				message = fmt.Sprintf("Binding mismatch: expected %s, got %s", ctx.Binding, effectiveBinding)
			}
			options.OnError(c, &AshVerifyError{
				Code:       AshErrBindingMismatch,
				Message:    message,
				StatusCode: ashGetHTTPStatusForCode(AshErrBindingMismatch),
			})
			return
		}

		// Read and canonicalize body
		var canonicalPayload string
		var payloadMap map[string]interface{}
		contentType := c.ContentType()

		body, err := c.GetRawData()
		if err != nil {
			options.OnError(c, &AshVerifyError{
				Code:       AshErrCanonicalizationError,
				Message:    "Failed to read request body",
				StatusCode: ashGetHTTPStatusForCode(AshErrCanonicalizationError),
			})
			return
		}

		// Canonicalize based on content type
		if strings.HasPrefix(contentType, "application/json") {
			if len(body) > 0 {
				if err := json.Unmarshal(body, &payloadMap); err != nil {
					options.OnError(c, &AshVerifyError{
						Code:       AshErrCanonicalizationError,
						Message:    "Failed to parse JSON body",
						StatusCode: ashGetHTTPStatusForCode(AshErrCanonicalizationError),
					})
					return
				}
				canonicalPayload, err = AshCanonicalizeJSON(payloadMap)
				if err != nil {
					options.OnError(c, &AshVerifyError{
						Code:       AshErrCanonicalizationError,
						Message:    "Failed to canonicalize JSON body",
						StatusCode: ashGetHTTPStatusForCode(AshErrCanonicalizationError),
					})
					return
				}
			} else {
				canonicalPayload = ""
				payloadMap = make(map[string]interface{})
			}
		} else if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
			canonicalPayload, err = AshCanonicalizeURLEncoded(string(body))
			if err != nil {
				options.OnError(c, &AshVerifyError{
					Code:       AshErrCanonicalizationError,
					Message:    "Failed to canonicalize form body",
					StatusCode: ashGetHTTPStatusForCode(AshErrCanonicalizationError),
				})
				return
			}
			payloadMap = make(map[string]interface{})
		} else {
			// For other content types, use empty string
			canonicalPayload = ""
			payloadMap = make(map[string]interface{})
		}

		// Verify proof
		var verificationPassed bool

		if options.EnableUnified && (len(scope) > 0 || chainHash != "") {
			// v2.3 unified verification
			if timestamp == "" {
				options.OnError(c, &AshVerifyError{
					Code:       AshErrTimestampInvalid,
					Message:    "Timestamp is required for unified proof verification",
					StatusCode: ashGetHTTPStatusForCode(AshErrTimestampInvalid),
				})
				return
			}

			var verifyErr error
			verificationPassed, verifyErr = AshVerifyProofUnified(
				ctx.Nonce,
				contextID,
				ctx.Binding,
				timestamp,
				payloadMap,
				proof,
				scope,
				scopeHash,
				ctx.PreviousProof,
				chainHash,
			)
			if verifyErr != nil {
				options.OnError(c, &AshVerifyError{
					Code:       AshErrProofInvalid,
					Message:    verifyErr.Error(),
					StatusCode: ashGetHTTPStatusForCode(AshErrProofInvalid),
				})
				return
			}
		} else {
			// v2.1 standard verification
			bodyHash := AshHashBody(canonicalPayload)
			var verifyErr error
			verificationPassed, verifyErr = AshVerifyProof(
				ctx.Nonce,
				contextID,
				ctx.Binding,
				timestamp,
				bodyHash,
				proof,
			)
			if verifyErr != nil {
				options.OnError(c, &AshVerifyError{
					Code:       AshErrProofInvalid,
					Message:    verifyErr.Error(),
					StatusCode: ashGetHTTPStatusForCode(AshErrProofInvalid),
				})
				return
			}
		}

		if !verificationPassed {
			errCode := AshErrProofInvalid
			errMsg := "Proof verification failed"

			if len(scope) > 0 && scopeHash != "" {
				errCode = AshErrScopeMismatch
				if isProduction() {
					errMsg = "Invalid request"
				} else {
					errMsg = "Scope hash verification failed"
				}
			} else if chainHash != "" {
				errCode = AshErrChainBroken
				if isProduction() {
					errMsg = "Invalid request"
				} else {
					errMsg = "Chain hash verification failed"
				}
			}

			options.OnError(c, &AshVerifyError{
				Code:       errCode,
				Message:    errMsg,
				StatusCode: ashGetHTTPStatusForCode(errCode),
			})
			return
		}

		// v2.3.4: Verify IP binding if requested
		if options.EnforceIp {
			clientIP := GetClientIP(
				c.GetHeader("X-Forwarded-For"),
				c.GetHeader("X-Real-IP"),
				c.ClientIP(),
			)
			// Strip port if present
			if host, _, err := net.SplitHostPort(clientIP); err == nil {
				clientIP = host
			}

			contextIP := ""
			if ctx.Metadata != nil {
				if ip, ok := ctx.Metadata["ip"].(string); ok {
					contextIP = ip
				}
			}

			if contextIP != "" && contextIP != clientIP {
				message := "Request binding does not match context"
				if !isProduction() {
					message = fmt.Sprintf("IP address mismatch: expected %s, got %s", contextIP, clientIP)
				}
				options.OnError(c, &AshVerifyError{
					Code:       AshErrBindingMismatch,
					Message:    message,
					StatusCode: ashGetHTTPStatusForCode(AshErrBindingMismatch),
				})
				return
			}
		}

		// v2.3.4: Verify user binding if requested
		if options.EnforceUser {
			var currentUserID string
			var err error

			if options.UserIDExtractor != nil {
				currentUserID, err = options.UserIDExtractor(c)
				if err != nil {
					options.OnError(c, &AshVerifyError{
						Code:       AshErrInternalError,
						Message:    "Failed to extract user ID",
						StatusCode: ashGetHTTPStatusForCode(AshErrInternalError),
					})
					return
				}
			} else {
				// Default: look for user_id in context
				if uid, exists := c.Get("user_id"); exists {
					if uidStr, ok := uid.(string); ok {
						currentUserID = uidStr
					} else if uidInt, ok := uid.(int); ok {
						currentUserID = strconv.Itoa(uidInt)
					} else if uidInt64, ok := uid.(int64); ok {
						currentUserID = strconv.FormatInt(uidInt64, 10)
					}
				}
			}

			contextUserID := ""
			if ctx.Metadata != nil {
				if uid, ok := ctx.Metadata["user_id"].(string); ok {
					contextUserID = uid
				} else if uidFloat, ok := ctx.Metadata["user_id"].(float64); ok {
					contextUserID = strconv.FormatFloat(uidFloat, 'f', 0, 64)
				}
			}

			if contextUserID != "" && currentUserID != contextUserID {
				message := "Request binding does not match context"
				if !isProduction() {
					message = fmt.Sprintf("User mismatch: expected %s, got %s", contextUserID, currentUserID)
				}
				options.OnError(c, &AshVerifyError{
					Code:       AshErrBindingMismatch,
					Message:    message,
					StatusCode: ashGetHTTPStatusForCode(AshErrBindingMismatch),
				})
				return
			}
		}

		// Mark context as used
		if err := options.Store.Consume(contextID); err != nil {
			options.OnError(c, &AshVerifyError{
				Code:       AshErrCtxAlreadyUsed,
				Message:    "Context already used (replay detected)",
				StatusCode: ashGetHTTPStatusForCode(AshErrCtxAlreadyUsed),
			})
			return
		}

		// Store metadata in context for downstream handlers
		c.Set("ashContext", ctx)
		c.Set("ashScope", scope)
		c.Set("ashChainHash", chainHash)
		c.Set("ashScopePolicy", policyScope)
		c.Set("ashClientIP", GetClientIP(
			c.GetHeader("X-Forwarded-For"),
			c.GetHeader("X-Real-IP"),
			c.ClientIP(),
		))

		c.Next()
	}
}

// AshContextStore is the interface for ASH context storage (middleware-specific).
type AshContextStore interface {
	// Get retrieves a context by ID
	Get(id string) (*AshMiddlewareContext, error)
	// Consume marks a context as used
	Consume(id string) error
	// Store saves a new context
	Store(ctx *AshMiddlewareContext) error
}

// AshMiddlewareContext represents a stored ASH context for middleware use.
type AshMiddlewareContext struct {
	ID            string
	Nonce         string
	Binding       string
	ClientSecret  string
	Used          bool
	CreatedAt     int64
	ExpiresAt     int64
	PreviousProof string
	Metadata      map[string]interface{}
}

// storedContext wraps AshMiddlewareContext with expiration tracking.
type storedContext struct {
	ctx       *AshMiddlewareContext
	expiresAt time.Time
}

// AshMemoryStore is an in-memory implementation of AshContextStore with TTL support.
type AshMemoryStore struct {
	contexts        map[string]*storedContext
	mu              sync.RWMutex
	ttl             time.Duration
	cleanupInterval time.Duration
	stopCh          chan struct{}
}

// NewAshMemoryStore creates a new in-memory context store with TTL.
// Uses default TTL of 5 minutes and cleanup interval of 1 minute.
func NewAshMemoryStore() *AshMemoryStore {
	return NewAshMemoryStoreWithTTL(5*time.Minute, 1*time.Minute)
}

// NewAshMemoryStoreWithTTL creates a new in-memory context store with custom TTL.
// ttl is the duration after which contexts expire.
// cleanupInterval is the interval between cleanup runs.
func NewAshMemoryStoreWithTTL(ttl, cleanupInterval time.Duration) *AshMemoryStore {
	store := &AshMemoryStore{
		contexts:        make(map[string]*storedContext),
		ttl:             ttl,
		cleanupInterval: cleanupInterval,
		stopCh:          make(chan struct{}),
	}
	go store.cleanupLoop()
	return store
}

// Get retrieves a context by ID. Returns nil if not found or expired.
func (s *AshMemoryStore) Get(id string) (*AshMiddlewareContext, error) {
	s.mu.RLock()
	stored, ok := s.contexts[id]
	s.mu.RUnlock()

	if !ok {
		return nil, nil
	}

	// Check if context has expired
	if time.Now().After(stored.expiresAt) {
		s.mu.Lock()
		// Double-check after acquiring write lock
		if stored, ok := s.contexts[id]; ok && time.Now().After(stored.expiresAt) {
			delete(s.contexts, id)
		}
		s.mu.Unlock()
		return nil, nil
	}

	return stored.ctx, nil
}

// Consume marks a context as used.
func (s *AshMemoryStore) Consume(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	stored, ok := s.contexts[id]
	if !ok {
		return nil
	}

	// Check if context has expired
	if time.Now().After(stored.expiresAt) {
		delete(s.contexts, id)
		return nil
	}

	if stored.ctx.Used {
		return &AshVerifyError{
			Code:    AshErrCtxAlreadyUsed,
			Message: "Context already used",
		}
	}
	stored.ctx.Used = true
	return nil
}

// Store saves a new context with expiration time.
func (s *AshMemoryStore) Store(ctx *AshMiddlewareContext) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.contexts[ctx.ID] = &storedContext{
		ctx:       ctx,
		expiresAt: time.Now().Add(s.ttl),
	}
	return nil
}

// Stop stops the cleanup goroutine.
// Should be called when the store is no longer needed to prevent goroutine leaks.
func (s *AshMemoryStore) Stop() {
	close(s.stopCh)
}

// cleanupLoop periodically removes expired contexts.
func (s *AshMemoryStore) cleanupLoop() {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.stopCh:
			return
		}
	}
}

// cleanup removes all expired contexts.
func (s *AshMemoryStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, stored := range s.contexts {
		if now.After(stored.expiresAt) {
			delete(s.contexts, id)
		}
	}
}

// AshValidateTimestamp validates timestamp freshness.
func AshValidateTimestamp(timestamp string, maxAgeSeconds int) error {
	// Parse timestamp (milliseconds since epoch)
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return &AshVerifyError{
			Code:    AshErrTimestampInvalid,
			Message: "Invalid timestamp format",
		}
	}

	// Convert to time
	tsTime := time.Unix(ts/1000, (ts%1000)*int64(time.Millisecond))
	now := time.Now()

	// Check if timestamp is too old
	age := now.Sub(tsTime)
	if age > time.Duration(maxAgeSeconds)*time.Second {
		return &AshVerifyError{
			Code:    AshErrTimestampInvalid,
			Message: "Timestamp is too old",
		}
	}

	// Check if timestamp is in the future (with 30 second tolerance)
	if tsTime.After(now.Add(30 * time.Second)) {
		return &AshVerifyError{
			Code:    AshErrTimestampInvalid,
			Message: "Timestamp is in the future",
		}
	}

	return nil
}

// ============================================================================
// BACKWARD COMPATIBILITY ALIASES (Deprecated)
// ============================================================================

// Deprecated: Use AshContextStore instead.
type ContextStore = AshContextStore

// Deprecated: Use NewAshMemoryStore instead.
func NewMemoryStore() *AshMemoryStore {
	return NewAshMemoryStore()
}

// Deprecated: Use AshMiddlewareContext instead.
type MiddlewareContext = AshMiddlewareContext
