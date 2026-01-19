// Package ash provides the ASH Protocol SDK for Go.
//
// ASH (Authenticated Secure Hash) is a deterministic integrity verification
// protocol for web requests. This package provides canonicalization, proof
// generation, and secure comparison utilities.
//
// Developed by 3maem Co. | شركة عمائم
package ash

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Version is the ASH protocol version.
const Version = "1.0.0"

// ASH protocol version prefix used in proof generation.
const ashVersionPrefix = "ASHv1"

// AshMode represents security modes for ASH protocol.
type AshMode string

const (
	// ModeMinimal is the minimal security mode.
	ModeMinimal AshMode = "minimal"
	// ModeBalanced is the balanced security mode.
	ModeBalanced AshMode = "balanced"
	// ModeStrict is the strict security mode.
	ModeStrict AshMode = "strict"
)

// AshErrorCode represents error codes returned by ASH verification.
type AshErrorCode string

const (
	// ErrInvalidContext indicates an invalid context.
	ErrInvalidContext AshErrorCode = "ASH_INVALID_CONTEXT"
	// ErrContextExpired indicates an expired context.
	ErrContextExpired AshErrorCode = "ASH_CONTEXT_EXPIRED"
	// ErrReplayDetected indicates a replay attack detected.
	ErrReplayDetected AshErrorCode = "ASH_REPLAY_DETECTED"
	// ErrIntegrityFailed indicates integrity verification failed.
	ErrIntegrityFailed AshErrorCode = "ASH_INTEGRITY_FAILED"
	// ErrEndpointMismatch indicates endpoint mismatch.
	ErrEndpointMismatch AshErrorCode = "ASH_ENDPOINT_MISMATCH"
	// ErrModeViolation indicates mode violation.
	ErrModeViolation AshErrorCode = "ASH_MODE_VIOLATION"
	// ErrUnsupportedContentType indicates unsupported content type.
	ErrUnsupportedContentType AshErrorCode = "ASH_UNSUPPORTED_CONTENT_TYPE"
	// ErrMalformedRequest indicates a malformed request.
	ErrMalformedRequest AshErrorCode = "ASH_MALFORMED_REQUEST"
	// ErrCanonicalizationFailed indicates canonicalization failed.
	ErrCanonicalizationFailed AshErrorCode = "ASH_CANONICALIZATION_FAILED"
)

// AshError represents an error in the ASH protocol.
type AshError struct {
	Code    AshErrorCode
	Message string
}

func (e *AshError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// NewAshError creates a new AshError.
func NewAshError(code AshErrorCode, message string) *AshError {
	return &AshError{Code: code, Message: message}
}

// BuildProofInput contains input for building a proof.
type BuildProofInput struct {
	// Mode is the ASH mode (currently only 'balanced' in v1).
	Mode AshMode
	// Binding is the canonical binding: "METHOD /path".
	Binding string
	// ContextID is the server-issued context ID.
	ContextID string
	// Nonce is the optional server-issued nonce.
	Nonce string
	// CanonicalPayload is the canonicalized payload string.
	CanonicalPayload string
}

// StoredContext represents context as stored on server.
type StoredContext struct {
	// ContextID is the unique context identifier (CSPRNG).
	ContextID string
	// Binding is the canonical binding: "METHOD /path".
	Binding string
	// Mode is the security mode.
	Mode AshMode
	// IssuedAt is the timestamp when context was issued (ms epoch).
	IssuedAt int64
	// ExpiresAt is the timestamp when context expires (ms epoch).
	ExpiresAt int64
	// Nonce is the optional nonce for server-assisted mode.
	Nonce string
	// ConsumedAt is the timestamp when context was consumed (0 if not consumed).
	ConsumedAt int64
}

// ContextPublicInfo represents public context info returned to client.
type ContextPublicInfo struct {
	// ContextID is the opaque context ID.
	ContextID string `json:"contextId"`
	// ExpiresAt is the expiration timestamp (ms epoch).
	ExpiresAt int64 `json:"expiresAt"`
	// Mode is the security mode.
	Mode AshMode `json:"mode"`
	// Nonce is the optional nonce (if server-assisted mode).
	Nonce string `json:"nonce,omitempty"`
}

// HttpMethod represents HTTP methods.
type HttpMethod string

const (
	MethodGET    HttpMethod = "GET"
	MethodPOST   HttpMethod = "POST"
	MethodPUT    HttpMethod = "PUT"
	MethodPATCH  HttpMethod = "PATCH"
	MethodDELETE HttpMethod = "DELETE"
)

// SupportedContentType represents supported content types.
type SupportedContentType string

const (
	ContentTypeJSON       SupportedContentType = "application/json"
	ContentTypeURLEncoded SupportedContentType = "application/x-www-form-urlencoded"
)

// BuildProof builds a deterministic proof from the given inputs.
//
// Proof structure (from ASH-Spec-v1.0):
//
//	proof = SHA256(
//	  "ASHv1" + "\n" +
//	  mode + "\n" +
//	  binding + "\n" +
//	  contextId + "\n" +
//	  (nonce? + "\n" : "") +
//	  canonicalPayload
//	)
//
// Output: Base64URL encoded (no padding)
func BuildProof(input BuildProofInput) string {
	// Build the proof input string
	var sb strings.Builder
	sb.WriteString(ashVersionPrefix)
	sb.WriteByte('\n')
	sb.WriteString(string(input.Mode))
	sb.WriteByte('\n')
	sb.WriteString(input.Binding)
	sb.WriteByte('\n')
	sb.WriteString(input.ContextID)
	sb.WriteByte('\n')

	// Add nonce if present (server-assisted mode)
	if input.Nonce != "" {
		sb.WriteString(input.Nonce)
		sb.WriteByte('\n')
	}

	// Add canonical payload
	sb.WriteString(input.CanonicalPayload)

	// Compute SHA-256 hash
	hash := sha256.Sum256([]byte(sb.String()))

	// Encode as Base64URL (no padding)
	return Base64URLEncode(hash[:])
}

// Base64URLEncode encodes data as Base64URL (no padding).
// RFC 4648 Section 5: Base 64 Encoding with URL and Filename Safe Alphabet
func Base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// Base64URLDecode decodes a Base64URL string to bytes.
// Handles both padded and unpadded input.
func Base64URLDecode(input string) ([]byte, error) {
	// Remove any padding characters
	input = strings.TrimRight(input, "=")
	return base64.RawURLEncoding.DecodeString(input)
}

// CanonicalizeJSON canonicalizes a JSON value to a deterministic string.
//
// Rules (from ASH-Spec-v1.0):
//   - JSON minified (no whitespace)
//   - Object keys sorted lexicographically (ascending)
//   - Arrays preserve order
//   - Unicode normalization: NFC
//   - Numbers: no scientific notation, remove trailing zeros, -0 becomes 0
//   - Unsupported values REJECT: NaN, Infinity
func CanonicalizeJSON(value interface{}) (string, error) {
	canonicalized, err := canonicalizeValue(value)
	if err != nil {
		return "", err
	}
	return buildCanonicalJSON(canonicalized)
}

// canonicalizeValue recursively canonicalizes a value.
func canonicalizeValue(value interface{}) (interface{}, error) {
	if value == nil {
		return nil, nil
	}

	switch v := value.(type) {
	case string:
		// Apply NFC normalization to strings
		return norm.NFC.String(v), nil

	case bool:
		return v, nil

	case float64:
		return canonicalizeNumber(v)

	case float32:
		return canonicalizeNumber(float64(v))

	case int:
		return float64(v), nil

	case int8:
		return float64(v), nil

	case int16:
		return float64(v), nil

	case int32:
		return float64(v), nil

	case int64:
		return float64(v), nil

	case uint:
		return float64(v), nil

	case uint8:
		return float64(v), nil

	case uint16:
		return float64(v), nil

	case uint32:
		return float64(v), nil

	case uint64:
		return float64(v), nil

	case json.Number:
		f, err := v.Float64()
		if err != nil {
			return nil, NewAshError(ErrCanonicalizationFailed, "invalid json.Number")
		}
		return canonicalizeNumber(f)

	case []interface{}:
		result := make([]interface{}, len(v))
		for i, item := range v {
			canonicalized, err := canonicalizeValue(item)
			if err != nil {
				return nil, err
			}
			result[i] = canonicalized
		}
		return result, nil

	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, val := range v {
			// Normalize key using NFC
			normalizedKey := norm.NFC.String(key)
			canonicalized, err := canonicalizeValue(val)
			if err != nil {
				return nil, err
			}
			result[normalizedKey] = canonicalized
		}
		return result, nil

	default:
		return nil, NewAshError(ErrCanonicalizationFailed, fmt.Sprintf("unsupported type: %T", value))
	}
}

// canonicalizeNumber canonicalizes a number according to ASH spec.
func canonicalizeNumber(num float64) (float64, error) {
	// Check for NaN
	if num != num { // NaN is the only value that's not equal to itself
		return 0, NewAshError(ErrCanonicalizationFailed, "NaN values are not allowed")
	}

	// Check for Infinity
	if num > 1e308 || num < -1e308 {
		return 0, NewAshError(ErrCanonicalizationFailed, "Infinity values are not allowed")
	}

	// Convert -0 to 0
	if num == 0 {
		return 0, nil
	}

	return num, nil
}

// buildCanonicalJSON builds canonical JSON string with sorted keys.
func buildCanonicalJSON(value interface{}) (string, error) {
	if value == nil {
		return "null", nil
	}

	switch v := value.(type) {
	case string:
		bytes, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(bytes), nil

	case bool:
		if v {
			return "true", nil
		}
		return "false", nil

	case float64:
		return formatNumber(v), nil

	case []interface{}:
		var sb strings.Builder
		sb.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				sb.WriteByte(',')
			}
			itemStr, err := buildCanonicalJSON(item)
			if err != nil {
				return "", err
			}
			sb.WriteString(itemStr)
		}
		sb.WriteByte(']')
		return sb.String(), nil

	case map[string]interface{}:
		// Get keys and sort them
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		var sb strings.Builder
		sb.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			keyBytes, err := json.Marshal(key)
			if err != nil {
				return "", err
			}
			sb.Write(keyBytes)
			sb.WriteByte(':')

			valStr, err := buildCanonicalJSON(v[key])
			if err != nil {
				return "", err
			}
			sb.WriteString(valStr)
		}
		sb.WriteByte('}')
		return sb.String(), nil

	default:
		return "", NewAshError(ErrCanonicalizationFailed, fmt.Sprintf("cannot serialize type: %T", value))
	}
}

// formatNumber formats a number without scientific notation.
func formatNumber(num float64) string {
	// Handle special case of 0
	if num == 0 {
		return "0"
	}

	// Check if it's an integer
	if num == float64(int64(num)) {
		return strconv.FormatInt(int64(num), 10)
	}

	// Format with enough precision, then clean up
	str := strconv.FormatFloat(num, 'f', -1, 64)
	return str
}

// CanonicalizeURLEncoded canonicalizes URL-encoded form data.
//
// Rules (from ASH-Spec-v1.0):
//   - Parse into key-value pairs
//   - Percent-decode consistently
//   - Sort keys lexicographically
//   - For duplicate keys: preserve value order per key
//   - Output format: k1=v1&k1=v2&k2=v3
//   - Unicode NFC applies after decoding
func CanonicalizeURLEncoded(input string) (string, error) {
	pairs, err := parseURLEncoded(input)
	if err != nil {
		return "", err
	}

	// Normalize all keys and values with NFC
	for i := range pairs {
		pairs[i].Key = norm.NFC.String(pairs[i].Key)
		pairs[i].Value = norm.NFC.String(pairs[i].Value)
	}

	// Sort by key (stable sort preserves value order for same keys)
	sort.SliceStable(pairs, func(i, j int) bool {
		return pairs[i].Key < pairs[j].Key
	})

	// Encode and join
	var parts []string
	for _, pair := range pairs {
		parts = append(parts, url.QueryEscape(pair.Key)+"="+url.QueryEscape(pair.Value))
	}

	return strings.Join(parts, "&"), nil
}

// keyValuePair represents a key-value pair for URL encoding.
type keyValuePair struct {
	Key   string
	Value string
}

// parseURLEncoded parses URL-encoded string into key-value pairs.
func parseURLEncoded(input string) ([]keyValuePair, error) {
	if input == "" {
		return nil, nil
	}

	var pairs []keyValuePair

	for _, part := range strings.Split(input, "&") {
		// Skip empty parts
		if part == "" {
			continue
		}

		// Replace + with space before decoding
		part = strings.ReplaceAll(part, "+", " ")

		eqIndex := strings.Index(part, "=")
		if eqIndex == -1 {
			// Key with no value
			key, err := url.QueryUnescape(part)
			if err != nil {
				return nil, NewAshError(ErrCanonicalizationFailed, "invalid URL encoding")
			}
			if key != "" {
				pairs = append(pairs, keyValuePair{Key: key, Value: ""})
			}
		} else {
			key, err := url.QueryUnescape(part[:eqIndex])
			if err != nil {
				return nil, NewAshError(ErrCanonicalizationFailed, "invalid URL encoding")
			}
			value, err := url.QueryUnescape(part[eqIndex+1:])
			if err != nil {
				return nil, NewAshError(ErrCanonicalizationFailed, "invalid URL encoding")
			}
			if key != "" {
				pairs = append(pairs, keyValuePair{Key: key, Value: value})
			}
		}
	}

	return pairs, nil
}

// CanonicalizeURLEncodedFromMap canonicalizes URL-encoded data from a map.
func CanonicalizeURLEncodedFromMap(data map[string][]string) string {
	var pairs []keyValuePair

	for key, values := range data {
		for _, value := range values {
			pairs = append(pairs, keyValuePair{Key: key, Value: value})
		}
	}

	// Normalize all keys and values with NFC
	for i := range pairs {
		pairs[i].Key = norm.NFC.String(pairs[i].Key)
		pairs[i].Value = norm.NFC.String(pairs[i].Value)
	}

	// Sort by key (stable sort preserves value order for same keys)
	sort.SliceStable(pairs, func(i, j int) bool {
		return pairs[i].Key < pairs[j].Key
	})

	// Encode and join
	var parts []string
	for _, pair := range pairs {
		parts = append(parts, url.QueryEscape(pair.Key)+"="+url.QueryEscape(pair.Value))
	}

	return strings.Join(parts, "&")
}

// NormalizeBinding normalizes a binding string.
//
// Rules (from ASH-Spec-v1.0):
//   - Format: "METHOD /path"
//   - Method uppercased
//   - Path must start with /
//   - Path excludes query string
//   - Collapse duplicate slashes
func NormalizeBinding(method, path string) string {
	// Uppercase method
	normalizedMethod := strings.ToUpper(method)

	// Remove fragment (#...) first
	if fragIndex := strings.Index(path, "#"); fragIndex != -1 {
		path = path[:fragIndex]
	}

	// Remove query string
	if queryIndex := strings.Index(path, "?"); queryIndex != -1 {
		path = path[:queryIndex]
	}

	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Collapse duplicate slashes
	var sb strings.Builder
	prevSlash := false
	for _, r := range path {
		if r == '/' {
			if !prevSlash {
				sb.WriteRune(r)
			}
			prevSlash = true
		} else {
			sb.WriteRune(r)
			prevSlash = false
		}
	}
	path = sb.String()

	// Remove trailing slash (except for root)
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = path[:len(path)-1]
	}

	return normalizedMethod + " " + path
}

// TimingSafeCompare compares two strings in constant time.
//
// This prevents timing attacks where an attacker could determine
// partial matches based on comparison duration.
func TimingSafeCompare(a, b string) bool {
	aBytes := []byte(a)
	bBytes := []byte(b)

	// If lengths differ, we still need constant-time behavior
	if len(aBytes) != len(bBytes) {
		// Compare aBytes with itself to maintain constant time
		subtle.ConstantTimeCompare(aBytes, aBytes)
		return false
	}

	return subtle.ConstantTimeCompare(aBytes, bBytes) == 1
}

// TimingSafeCompareBytes compares two byte slices in constant time.
func TimingSafeCompareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		// Compare a with itself to maintain constant time
		subtle.ConstantTimeCompare(a, a)
		return false
	}

	return subtle.ConstantTimeCompare(a, b) == 1
}

// IsValidMode checks if a mode is valid.
func IsValidMode(mode AshMode) bool {
	switch mode {
	case ModeMinimal, ModeBalanced, ModeStrict:
		return true
	default:
		return false
	}
}

// IsValidHTTPMethod checks if an HTTP method is valid.
func IsValidHTTPMethod(method HttpMethod) bool {
	switch method {
	case MethodGET, MethodPOST, MethodPUT, MethodPATCH, MethodDELETE:
		return true
	default:
		return false
	}
}

// ParseJSON parses a JSON string and canonicalizes it.
func ParseJSON(jsonStr string) (string, error) {
	var data interface{}
	decoder := json.NewDecoder(strings.NewReader(jsonStr))
	decoder.UseNumber()
	if err := decoder.Decode(&data); err != nil {
		return "", NewAshError(ErrCanonicalizationFailed, "invalid JSON: "+err.Error())
	}
	return CanonicalizeJSON(data)
}

// Common errors
var (
	// ErrNilInput is returned when nil input is provided.
	ErrNilInput = errors.New("nil input")
	// ErrEmptyContextID is returned when context ID is empty.
	ErrEmptyContextID = errors.New("empty context ID")
	// ErrEmptyBinding is returned when binding is empty.
	ErrEmptyBinding = errors.New("empty binding")
)

// ValidateProofInput validates the proof input.
func ValidateProofInput(input BuildProofInput) error {
	if !IsValidMode(input.Mode) {
		return NewAshError(ErrModeViolation, "invalid mode")
	}
	if input.ContextID == "" {
		return ErrEmptyContextID
	}
	if input.Binding == "" {
		return ErrEmptyBinding
	}
	return nil
}

// IsASCII checks if a string contains only ASCII characters.
func IsASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}
