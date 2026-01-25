// Package ash provides the ASH Protocol SDK for Go.
//
// ASH (Authenticated Secure Hash) is a deterministic integrity verification
// protocol for web requests. This package provides canonicalization, proof
// generation, and secure comparison utilities.
//
// Developed by 3maem Co. | شركة عمائم
package ash

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Version is the ASH protocol version.
const Version = "2.3.2"

// AshVersionPrefix is the ASH v1 protocol version prefix used in proof generation.
const AshVersionPrefix = "ASHv1"

// AshVersionPrefixV21 is the ASH v2.1 protocol version prefix.
// Exported for API consistency across SDKs.
const AshVersionPrefixV21 = "ASHv2.1"

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
	sb.WriteString(AshVersionPrefix)
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
	if math.IsNaN(num) {
		return 0, NewAshError(ErrCanonicalizationFailed, "NaN values are not allowed")
	}

	// Check for Infinity (both positive and negative)
	if math.IsInf(num, 0) {
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
		return escapeJSONStringRFC8785(v), nil

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
		// Get keys and sort them lexicographically (byte-wise, NOT locale-dependent)
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
			sb.WriteString(escapeJSONStringRFC8785(key))
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

// escapeJSONStringRFC8785 escapes a string according to RFC 8785 (JCS).
//
// Minimal JSON escaping rules:
//   - 0x08 -> \b (backspace)
//   - 0x09 -> \t (tab)
//   - 0x0A -> \n (newline)
//   - 0x0C -> \f (form feed)
//   - 0x0D -> \r (carriage return)
//   - 0x22 -> \" (double quote)
//   - 0x5C -> \\ (backslash)
//   - 0x00-0x1F (other control chars) -> \uXXXX (lowercase hex)
func escapeJSONStringRFC8785(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')

	for _, r := range s {
		switch r {
		case '\b': // 0x08
			sb.WriteString(`\b`)
		case '\t': // 0x09
			sb.WriteString(`\t`)
		case '\n': // 0x0A
			sb.WriteString(`\n`)
		case '\f': // 0x0C
			sb.WriteString(`\f`)
		case '\r': // 0x0D
			sb.WriteString(`\r`)
		case '"': // 0x22
			sb.WriteString(`\"`)
		case '\\': // 0x5C
			sb.WriteString(`\\`)
		default:
			if r >= 0x00 && r <= 0x1F {
				// Other control characters: use \uXXXX with lowercase hex
				sb.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else {
				sb.WriteRune(r)
			}
		}
	}

	sb.WriteByte('"')
	return sb.String()
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

	// Encode and join (use %20 for spaces instead of +, uppercase hex)
	var parts []string
	for _, pair := range pairs {
		key := percentEncodeUppercase(pair.Key)
		value := percentEncodeUppercase(pair.Value)
		parts = append(parts, key+"="+value)
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

	// Encode and join (use %20 for spaces instead of +, uppercase hex)
	var parts []string
	for _, pair := range pairs {
		key := percentEncodeUppercase(pair.Key)
		value := percentEncodeUppercase(pair.Value)
		parts = append(parts, key+"="+value)
	}

	return strings.Join(parts, "&")
}

// CanonicalizeQuery canonicalizes a URL query string according to ASH specification.
//
// 9 MUST Rules:
//  1. MUST parse query string after ? (or use full string if no ?)
//  2. MUST split on & to get key=value pairs
//  3. MUST handle keys without values (treat as empty string)
//  4. MUST percent-decode all keys and values
//  5. MUST apply Unicode NFC normalization
//  6. MUST sort pairs by key lexicographically (byte order), then by value
//  7. MUST preserve order of duplicate keys
//  8. MUST re-encode with uppercase hex (%XX)
//  9. MUST join with & separator
func CanonicalizeQuery(query string) (string, error) {
	// Rule 1: Remove leading ? if present
	query = strings.TrimPrefix(query, "?")

	// Strip fragment (#...) if present
	if fragIndex := strings.Index(query, "#"); fragIndex != -1 {
		query = query[:fragIndex]
	}

	if query == "" {
		return "", nil
	}

	// Rule 2 & 3: Parse pairs
	values, err := url.ParseQuery(query)
	if err != nil {
		return "", NewAshError(ErrCanonicalizationFailed, "invalid query string: "+err.Error())
	}

	// Collect all pairs
	type kvPair struct {
		key   string
		value string
	}
	var pairs []kvPair

	for key, vals := range values {
		// Rule 4 & 5: NFC normalize (already decoded by ParseQuery)
		normalizedKey := norm.NFC.String(key)
		for _, val := range vals {
			normalizedVal := norm.NFC.String(val)
			pairs = append(pairs, kvPair{key: normalizedKey, value: normalizedVal})
		}
	}

	// Rule 6 & 7: Sort by key (byte-wise), then by value for stable ordering
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i].key != pairs[j].key {
			return pairs[i].key < pairs[j].key
		}
		return pairs[i].value < pairs[j].value
	})

	// Rule 8 & 9: Re-encode with uppercase hex and join
	var parts []string
	for _, p := range pairs {
		encodedKey := percentEncodeUppercase(p.key)
		encodedValue := percentEncodeUppercase(p.value)
		parts = append(parts, encodedKey+"="+encodedValue)
	}

	return strings.Join(parts, "&"), nil
}

// percentEncodeUppercase encodes a string with uppercase percent-encoding.
// Uses %20 for spaces (not +), and uppercase hex (A-F not a-f).
func percentEncodeUppercase(s string) string {
	encoded := url.QueryEscape(s)
	// Replace + with %20
	encoded = strings.ReplaceAll(encoded, "+", "%20")
	// Convert lowercase hex to uppercase in percent-encoding
	return uppercasePercentEncoding(encoded)
}

// uppercasePercentEncoding converts lowercase hex in percent-encoding to uppercase.
func uppercasePercentEncoding(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			sb.WriteByte('%')
			sb.WriteByte(toUpperHex(s[i+1]))
			sb.WriteByte(toUpperHex(s[i+2]))
			i += 2
		} else {
			sb.WriteByte(s[i])
		}
	}
	return sb.String()
}

// toUpperHex converts a hex character to uppercase.
func toUpperHex(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - 32 // Convert to uppercase
	}
	return c
}

// NormalizeBinding normalizes a binding string to canonical form (v2.3.2+ format).
//
// Format: METHOD|PATH|CANONICAL_QUERY
//
// Rules:
//   - Method uppercased
//   - Path must start with /
//   - Duplicate slashes collapsed
//   - Trailing slash removed (except for root)
//   - Query string canonicalized
//   - Parts joined with | (pipe)
func NormalizeBinding(method, path, query string) string {
	// Uppercase method
	normalizedMethod := strings.ToUpper(method)

	// Remove fragment (#...) first
	if fragIndex := strings.Index(path, "#"); fragIndex != -1 {
		path = path[:fragIndex]
	}

	// Extract path without query string (in case path contains ?)
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

	// Canonicalize query string
	canonicalQuery := ""
	if query != "" {
		canonicalQuery, _ = CanonicalizeQuery(query)
	}

	// v2.3.2 format: METHOD|PATH|CANONICAL_QUERY
	return normalizedMethod + "|" + path + "|" + canonicalQuery
}

// NormalizeBindingFromURL normalizes a binding from a full URL path (including query string).
//
// This is a convenience function that extracts the query from the path.
func NormalizeBindingFromURL(method, fullPath string) string {
	path := fullPath
	query := ""

	if queryIndex := strings.Index(fullPath, "?"); queryIndex != -1 {
		path = fullPath[:queryIndex]
		query = fullPath[queryIndex+1:]
	}

	return NormalizeBinding(method, path, query)
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

// =========================================================================
// ASH v2.1 - Derived Client Secret & Cryptographic Proof
// =========================================================================

// GenerateNonce generates a cryptographically secure random nonce.
// Returns hex-encoded nonce (64 chars for 32 bytes).
func GenerateNonce(bytes int) (string, error) {
	if bytes <= 0 {
		bytes = 32
	}
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateContextID generates a unique context ID with "ash_" prefix.
func GenerateContextID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "ash_" + hex.EncodeToString(b), nil
}

// DeriveClientSecret derives client secret from server nonce (v2.1).
//
// SECURITY PROPERTIES:
// - One-way: Cannot derive nonce from clientSecret (HMAC is irreversible)
// - Context-bound: Unique per contextId + binding combination
// - Safe to expose: Client can use it but cannot forge other contexts
//
// Formula: clientSecret = HMAC-SHA256(nonce, contextId + "|" + binding)
func DeriveClientSecret(nonce, contextID, binding string) string {
	h := hmac.New(sha256.New, []byte(nonce))
	h.Write([]byte(contextID + "|" + binding))
	return hex.EncodeToString(h.Sum(nil))
}

// BuildProofV21 builds a v2.1 cryptographic proof (client-side).
//
// Formula: proof = HMAC-SHA256(clientSecret, timestamp + "|" + binding + "|" + bodyHash)
func BuildProofV21(clientSecret, timestamp, binding, bodyHash string) string {
	message := timestamp + "|" + binding + "|" + bodyHash
	h := hmac.New(sha256.New, []byte(clientSecret))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyProofV21 verifies a v2.1 proof (server-side).
func VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, clientProof string) bool {
	// Derive the same client secret server-side
	clientSecret := DeriveClientSecret(nonce, contextID, binding)

	// Compute expected proof
	expectedProof := BuildProofV21(clientSecret, timestamp, binding, bodyHash)

	// Constant-time comparison
	return TimingSafeCompare(expectedProof, clientProof)
}

// HashBody computes SHA-256 hash of canonical body.
func HashBody(canonicalBody string) string {
	hash := sha256.Sum256([]byte(canonicalBody))
	return hex.EncodeToString(hash[:])
}

// StoredContextV21 represents context as stored on server (v2.1).
type StoredContextV21 struct {
	StoredContext
	// ClientSecret is the v2.1 derived secret (safe to expose to client).
	ClientSecret string
	// Fingerprint is the optional device fingerprint hash.
	Fingerprint string
	// IPAddress is the client IP address for binding.
	IPAddress string
	// UserID is the optional user ID for binding.
	UserID int64
}

// ToClientInfo converts to client-safe format (v2.1).
// SECURITY: nonce is NEVER included, only clientSecret.
func (c *StoredContextV21) ToClientInfo() map[string]interface{} {
	return map[string]interface{}{
		"contextId":    c.ContextID,
		"binding":      c.Binding,
		"mode":         c.Mode,
		"expiresAt":    c.ExpiresAt,
		"clientSecret": c.ClientSecret,
	}
}

// =========================================================================
// ASH v2.2 - Context Scoping (Selective Field Protection)
// =========================================================================

// ScopedProofResult contains proof and scope hash
type ScopedProofResult struct {
	Proof     string
	ScopeHash string
}

// ExtractScopedFields extracts specified fields from a payload map.
// Supports dot notation for nested fields (e.g., "user.address.city").
func ExtractScopedFields(payload map[string]interface{}, scope []string) map[string]interface{} {
	if len(scope) == 0 {
		return payload
	}

	result := make(map[string]interface{})
	for _, fieldPath := range scope {
		value := getNestedValue(payload, fieldPath)
		if value != nil {
			setNestedValue(result, fieldPath, value)
		}
	}
	return result
}

func getNestedValue(obj map[string]interface{}, path string) interface{} {
	keys := strings.Split(path, ".")
	var current interface{} = obj

	for _, key := range keys {
		if currentMap, ok := current.(map[string]interface{}); ok {
			current = currentMap[key]
		} else {
			return nil
		}
	}

	return current
}

func setNestedValue(obj map[string]interface{}, path string, value interface{}) {
	keys := strings.Split(path, ".")
	current := obj

	for i := 0; i < len(keys)-1; i++ {
		key := keys[i]
		if _, exists := current[key]; !exists {
			current[key] = make(map[string]interface{})
		}
		current = current[key].(map[string]interface{})
	}

	current[keys[len(keys)-1]] = value
}

// BuildProofV21Scoped builds a v2.2 proof with scoped fields.
func BuildProofV21Scoped(clientSecret, timestamp, binding string, payload map[string]interface{}, scope []string) ScopedProofResult {
	scopedPayload := ExtractScopedFields(payload, scope)

	// Canonicalize (JSON encode)
	canonicalBytes, _ := json.Marshal(scopedPayload)
	bodyHash := HashBody(string(canonicalBytes))

	scopeStr := strings.Join(scope, ",")
	scopeHash := HashBody(scopeStr)

	message := timestamp + "|" + binding + "|" + bodyHash + "|" + scopeHash
	h := hmac.New(sha256.New, []byte(clientSecret))
	h.Write([]byte(message))
	proof := hex.EncodeToString(h.Sum(nil))

	return ScopedProofResult{Proof: proof, ScopeHash: scopeHash}
}

// VerifyProofV21Scoped verifies a v2.2 proof with scoped fields.
func VerifyProofV21Scoped(nonce, contextID, binding, timestamp string, payload map[string]interface{}, scope []string, scopeHash, clientProof string) bool {
	// Verify scope hash
	scopeStr := strings.Join(scope, ",")
	expectedScopeHash := HashBody(scopeStr)
	if !TimingSafeCompare(expectedScopeHash, scopeHash) {
		return false
	}

	clientSecret := DeriveClientSecret(nonce, contextID, binding)
	result := BuildProofV21Scoped(clientSecret, timestamp, binding, payload, scope)

	return TimingSafeCompare(result.Proof, clientProof)
}

// HashScopedBody hashes the scoped payload fields.
func HashScopedBody(payload map[string]interface{}, scope []string) string {
	scopedPayload := ExtractScopedFields(payload, scope)
	canonicalBytes, _ := json.Marshal(scopedPayload)
	return HashBody(string(canonicalBytes))
}

// =========================================================================
// ASH v2.3 - Unified Proof Functions (Scoping + Chaining)
// =========================================================================

// UnifiedProofResult contains proof, scope hash, and chain hash.
type UnifiedProofResult struct {
	Proof     string
	ScopeHash string
	ChainHash string
}

// HashProof hashes a proof for chaining purposes.
func HashProof(proof string) string {
	hash := sha256.Sum256([]byte(proof))
	return hex.EncodeToString(hash[:])
}

// BuildProofUnified builds a unified v2.3 proof with optional scoping and chaining.
//
// Formula:
//   scopeHash  = len(scope) > 0 ? SHA256(scope.join(",")) : ""
//   bodyHash   = SHA256(canonicalize(scopedPayload))
//   chainHash  = previousProof != "" ? SHA256(previousProof) : ""
//   proof      = HMAC-SHA256(clientSecret, timestamp|binding|bodyHash|scopeHash|chainHash)
func BuildProofUnified(clientSecret, timestamp, binding string, payload map[string]interface{}, scope []string, previousProof string) UnifiedProofResult {
	// Extract and hash scoped payload
	scopedPayload := ExtractScopedFields(payload, scope)
	canonicalBytes, _ := json.Marshal(scopedPayload)
	bodyHash := HashBody(string(canonicalBytes))

	// Compute scope hash (empty string if no scope)
	scopeHash := ""
	if len(scope) > 0 {
		scopeStr := strings.Join(scope, ",")
		scopeHash = HashBody(scopeStr)
	}

	// Compute chain hash (empty string if no previous proof)
	chainHash := ""
	if previousProof != "" {
		chainHash = HashProof(previousProof)
	}

	// Build proof message: timestamp|binding|bodyHash|scopeHash|chainHash
	message := timestamp + "|" + binding + "|" + bodyHash + "|" + scopeHash + "|" + chainHash
	h := hmac.New(sha256.New, []byte(clientSecret))
	h.Write([]byte(message))
	proof := hex.EncodeToString(h.Sum(nil))

	return UnifiedProofResult{
		Proof:     proof,
		ScopeHash: scopeHash,
		ChainHash: chainHash,
	}
}

// VerifyProofUnified verifies a unified v2.3 proof with optional scoping and chaining.
func VerifyProofUnified(nonce, contextID, binding, timestamp string, payload map[string]interface{}, clientProof string, scope []string, scopeHash, previousProof, chainHash string) bool {
	// Validate scope hash if scoping is used
	if len(scope) > 0 {
		scopeStr := strings.Join(scope, ",")
		expectedScopeHash := HashBody(scopeStr)
		if !TimingSafeCompare(expectedScopeHash, scopeHash) {
			return false
		}
	}

	// Validate chain hash if chaining is used
	if previousProof != "" {
		expectedChainHash := HashProof(previousProof)
		if !TimingSafeCompare(expectedChainHash, chainHash) {
			return false
		}
	}

	// Derive client secret and compute expected proof
	clientSecret := DeriveClientSecret(nonce, contextID, binding)
	result := BuildProofUnified(clientSecret, timestamp, binding, payload, scope, previousProof)

	return TimingSafeCompare(result.Proof, clientProof)
}
