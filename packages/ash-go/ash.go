// Package ash provides request integrity and anti-replay protection.
//
// ASH (Anti-tamper Security Hash) protects HTTP requests from tampering
// and replay attacks through cryptographic proofs and one-time contexts.
//
// Example:
//
//	store := ash.NewMemoryStore()
//	a := ash.New(store, ash.ModeBalanced)
//
//	// Issue a context
//	ctx, err := a.AshIssueContext("POST /api/update", 30000, nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Verify a request
//	result := a.AshVerify(contextID, proof, "POST /api/update", payload, "application/json")
//	if !result.Valid {
//	    log.Printf("Verification failed: %s", result.ErrorMessage)
//	}
package ash

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

const (
	// AshVersion is the protocol version.
	AshVersion = "ASHv1"

	// LibraryVersion is the library version.
	LibraryVersion = "1.0.0"
)

// Mode represents ASH security modes.
type Mode string

const (
	// ModeMinimal provides basic integrity protection.
	ModeMinimal Mode = "minimal"

	// ModeBalanced provides recommended protection for most operations.
	ModeBalanced Mode = "balanced"

	// ModeStrict provides maximum security with server nonce.
	ModeStrict Mode = "strict"
)

// ErrorCode represents ASH error codes.
type ErrorCode string

const (
	ErrInvalidContext       ErrorCode = "INVALID_CONTEXT"
	ErrContextExpired       ErrorCode = "CONTEXT_EXPIRED"
	ErrReplayDetected       ErrorCode = "REPLAY_DETECTED"
	ErrIntegrityFailed      ErrorCode = "INTEGRITY_FAILED"
	ErrEndpointMismatch     ErrorCode = "ENDPOINT_MISMATCH"
	ErrModeViolation        ErrorCode = "MODE_VIOLATION"
	ErrUnsupportedContent   ErrorCode = "UNSUPPORTED_CONTENT_TYPE"
	ErrMalformedRequest     ErrorCode = "MALFORMED_REQUEST"
	ErrCanonicalizeFailed   ErrorCode = "CANONICALIZATION_FAILED"
)

// Context represents an ASH context.
type Context struct {
	ID        string                 `json:"id"`
	Binding   string                 `json:"binding"`
	ExpiresAt int64                  `json:"expires_at"`
	Mode      Mode                   `json:"mode"`
	Used      bool                   `json:"used"`
	Nonce     string                 `json:"nonce,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// IsExpired checks if the context has expired.
func (c *Context) IsExpired() bool {
	return time.Now().UnixMilli() > c.ExpiresAt
}

// VerifyResult represents the result of verification.
type VerifyResult struct {
	Valid        bool
	ErrorCode    ErrorCode
	ErrorMessage string
	Metadata     map[string]interface{}
}

// Success creates a successful result.
func Success(metadata map[string]interface{}) VerifyResult {
	return VerifyResult{Valid: true, Metadata: metadata}
}

// Failure creates a failed result.
func Failure(code ErrorCode, message string) VerifyResult {
	return VerifyResult{
		Valid:        false,
		ErrorCode:    code,
		ErrorMessage: message,
	}
}

// Ash is the main ASH instance.
type Ash struct {
	store       ContextStore
	defaultMode Mode
}

// New creates a new ASH instance.
func New(store ContextStore, defaultMode Mode) *Ash {
	return &Ash{
		store:       store,
		defaultMode: defaultMode,
	}
}

// AshIssueContext issues a new context for a request.
func (a *Ash) AshIssueContext(binding string, ttlMs int64, metadata map[string]interface{}) (*Context, error) {
	return a.AshIssueContextWithMode(binding, ttlMs, a.defaultMode, metadata)
}

// AshIssueContextWithMode issues a new context with a specific mode.
func (a *Ash) AshIssueContextWithMode(binding string, ttlMs int64, mode Mode, metadata map[string]interface{}) (*Context, error) {
	return a.store.Create(binding, ttlMs, mode, metadata)
}

// AshVerify verifies a request against its context and proof.
func (a *Ash) AshVerify(contextID, proof, binding, payload, contentType string) VerifyResult {
	// Get context
	ctx, err := a.store.Get(contextID)
	if err != nil || ctx == nil {
		return Failure(ErrInvalidContext, "Invalid or expired context")
	}

	// Check if already used
	if ctx.Used {
		return Failure(ErrReplayDetected, "Context already used (replay detected)")
	}

	// Check binding
	if ctx.Binding != binding {
		return Failure(ErrEndpointMismatch,
			fmt.Sprintf("Binding mismatch: expected %s, got %s", ctx.Binding, binding))
	}

	// Canonicalize payload
	canonicalPayload, err := a.AshCanonicalize(payload, contentType)
	if err != nil {
		return Failure(ErrCanonicalizeFailed, "Failed to canonicalize payload: "+err.Error())
	}

	// Build expected proof
	expectedProof := AshBuildProof(ctx.Mode, ctx.Binding, contextID, ctx.Nonce, canonicalPayload)

	// Verify proof
	if !AshVerifyProof(expectedProof, proof) {
		return Failure(ErrIntegrityFailed, "Proof verification failed")
	}

	// Consume context
	if err := a.store.Consume(contextID); err != nil {
		return Failure(ErrReplayDetected, "Context already used (replay detected)")
	}

	return Success(ctx.Metadata)
}

// AshCanonicalize canonicalizes a payload based on content type.
func (a *Ash) AshCanonicalize(payload, contentType string) (string, error) {
	if strings.Contains(contentType, "application/json") {
		return AshCanonicalizeJSON(payload)
	}
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		return AshCanonicalizeURLEncoded(payload)
	}
	return payload, nil
}

// AshNormalizeBinding normalizes a binding string.
func (a *Ash) AshNormalizeBinding(method, path string) string {
	return AshNormalizeBinding(method, path)
}

// AshVersion returns the protocol version.
func (a *Ash) AshVersion() string {
	return AshVersion
}

// AshLibraryVersion returns the library version.
func (a *Ash) AshLibraryVersion() string {
	return LibraryVersion
}

// Store returns the context store.
func (a *Ash) Store() ContextStore {
	return a.store
}

// AshCanonicalizeJSON canonicalizes JSON to deterministic form.
func AshCanonicalizeJSON(input string) (string, error) {
	var data interface{}
	if err := json.Unmarshal([]byte(input), &data); err != nil {
		return "", err
	}

	normalized := normalizeValue(data)
	result, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}

	return string(result), nil
}

// AshCanonicalizeURLEncoded canonicalizes URL-encoded data.
func AshCanonicalizeURLEncoded(input string) (string, error) {
	if input == "" {
		return "", nil
	}

	values, err := url.ParseQuery(input)
	if err != nil {
		return "", err
	}

	// Get sorted keys
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build result
	var pairs []string
	for _, k := range keys {
		for _, v := range values[k] {
			// NFC normalize
			k = norm.NFC.String(k)
			v = norm.NFC.String(v)
			pairs = append(pairs, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}

	return strings.Join(pairs, "&"), nil
}

// AshBuildProof builds a cryptographic proof.
func AshBuildProof(mode Mode, binding, contextID, nonce, canonicalPayload string) string {
	var input string
	if nonce != "" {
		input = fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
			AshVersion, mode, binding, contextID, nonce, canonicalPayload)
	} else {
		input = fmt.Sprintf("%s\n%s\n%s\n%s\n%s",
			AshVersion, mode, binding, contextID, canonicalPayload)
	}

	hash := sha256.Sum256([]byte(input))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// AshVerifyProof verifies two proofs using constant-time comparison.
func AshVerifyProof(expected, actual string) bool {
	return AshTimingSafeEqual(expected, actual)
}

// AshTimingSafeEqual performs constant-time string comparison.
func AshTimingSafeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// AshNormalizeBinding normalizes a binding string.
func AshNormalizeBinding(method, path string) string {
	// Uppercase method
	method = strings.ToUpper(method)

	// Remove query string
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}

	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Collapse duplicate slashes
	re := regexp.MustCompile(`/+`)
	path = re.ReplaceAllString(path, "/")

	// Remove trailing slash (except for root)
	if path != "/" {
		path = strings.TrimSuffix(path, "/")
	}

	return method + " " + path
}

// normalizeValue recursively normalizes a JSON value.
func normalizeValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		return normalizeObject(val)
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = normalizeValue(item)
		}
		return result
	case string:
		return norm.NFC.String(val)
	default:
		return val
	}
}

// normalizeObject normalizes an object with sorted keys.
func normalizeObject(obj map[string]interface{}) map[string]interface{} {
	// Get sorted keys
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build ordered map (Go maps maintain insertion order in JSON encoding)
	result := make(map[string]interface{})
	for _, k := range keys {
		normalizedKey := norm.NFC.String(k)
		result[normalizedKey] = normalizeValue(obj[k])
	}

	return result
}
