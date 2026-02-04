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
const Version = "2.3.4"

// AshVersionPrefix is the ASH v1 protocol version prefix used in proof generation.
const AshVersionPrefix = "ASHv1"

// AshVersionPrefixV21 is the ASH v2.1 protocol version prefix.
// Exported for API consistency across SDKs.
const AshVersionPrefixV21 = "ASHv2.1"

// ScopeFieldDelimiter is the delimiter for joining scope fields.
// BUG-002: Uses U+001F unit separator to prevent collision when field names contain commas.
// Must match Rust ash-core SCOPE_FIELD_DELIMITER.
const ScopeFieldDelimiter = "\x1F"

// ============================================================================
// SECURITY CONSTANTS (Must match Rust ash-core)
// ============================================================================

// MinNonceHexChars is the minimum hex characters for nonce.
// SEC-014: Ensures adequate entropy (32 hex chars = 16 bytes = 128 bits).
const MinNonceHexChars = 32

// MaxNonceLength is the maximum nonce length.
// SEC-NONCE-001: Limits nonce beyond minimum entropy requirement.
const MaxNonceLength = 128

// MaxContextIDLength is the maximum context_id length.
// SEC-CTX-001: Limits context_id to reasonable size for headers and storage.
const MaxContextIDLength = 256

// MaxBindingLength is the maximum binding length.
// SEC-AUDIT-004: Prevents DoS via extremely long bindings.
const MaxBindingLength = 8192 // 8KB

// ============================================================================
// SCOPE POLICY FUNCTIONS
// ============================================================================

// AshNormalizeScopeFields normalizes scope fields by sorting and deduplicating.
// BUG-023: Ensures deterministic scope hash across all SDKs.
func AshNormalizeScopeFields(scope []string) []string {
	if len(scope) == 0 {
		return scope
	}
	// Deduplicate using map
	seen := make(map[string]bool)
	result := make([]string, 0, len(scope))
	for _, s := range scope {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	// Sort lexicographically
	sort.Strings(result)
	return result
}

// AshJoinScopeFields joins scope fields with the proper delimiter after normalization.
// BUG-002, BUG-023: Uses unit separator and normalizes for cross-SDK compatibility.
func AshJoinScopeFields(scope []string) string {
	normalized := AshNormalizeScopeFields(scope)
	return strings.Join(normalized, ScopeFieldDelimiter)
}

// ============================================================================
// TYPES AND CONSTANTS
// ============================================================================

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
	// ErrCtxNotFound indicates context not found.
	ErrCtxNotFound AshErrorCode = "ASH_CTX_NOT_FOUND"
	// ErrCtxExpired indicates an expired context.
	ErrCtxExpired AshErrorCode = "ASH_CTX_EXPIRED"
	// ErrCtxAlreadyUsed indicates context already consumed (replay).
	ErrCtxAlreadyUsed AshErrorCode = "ASH_CTX_ALREADY_USED"
	// ErrBindingMismatch indicates endpoint binding mismatch.
	ErrBindingMismatch AshErrorCode = "ASH_BINDING_MISMATCH"
	// ErrProofMissing indicates proof not provided.
	ErrProofMissing AshErrorCode = "ASH_PROOF_MISSING"
	// ErrProofInvalid indicates proof verification failed.
	ErrProofInvalid AshErrorCode = "ASH_PROOF_INVALID"
	// ErrCanonicalizationError indicates canonicalization failed.
	ErrCanonicalizationError AshErrorCode = "ASH_CANONICALIZATION_ERROR"
	// ErrModeViolation indicates mode violation.
	ErrModeViolation AshErrorCode = "ASH_MODE_VIOLATION"
	// ErrUnsupportedContentType indicates unsupported content type.
	ErrUnsupportedContentType AshErrorCode = "ASH_UNSUPPORTED_CONTENT_TYPE"
	// ErrScopeMismatch indicates scope hash mismatch (v2.2+).
	ErrScopeMismatch AshErrorCode = "ASH_SCOPE_MISMATCH"
	// ErrChainBroken indicates chain verification failed (v2.3+).
	ErrChainBroken AshErrorCode = "ASH_CHAIN_BROKEN"
	// ErrTimestampInvalid indicates timestamp validation failed (SEC-005).
	ErrTimestampInvalid AshErrorCode = "ASH_TIMESTAMP_INVALID"
)

// HTTPStatus returns the recommended HTTP status code for this error code.
//
// v2.3.4: Uses unique HTTP status codes in the 450-499 range for ASH-specific errors.
// This enables precise error identification, better monitoring, and targeted retry logic.
func (c AshErrorCode) HTTPStatus() int {
	switch c {
	// Context errors (450-459)
	case ErrCtxNotFound:
		return 450
	case ErrCtxExpired:
		return 451
	case ErrCtxAlreadyUsed:
		return 452
	// Seal/Proof errors (460-469)
	case ErrProofInvalid:
		return 460
	// Verification errors (461, 473-479)
	case ErrBindingMismatch:
		return 461
	case ErrScopeMismatch:
		return 473
	case ErrChainBroken:
		return 474
	// Format/Protocol errors (480-489)
	case ErrTimestampInvalid:
		return 482
	case ErrProofMissing:
		return 483
	// Standard HTTP codes (preserved for semantic clarity)
	case ErrCanonicalizationError:
		return 422
	case ErrModeViolation:
		return 400
	case ErrUnsupportedContentType:
		return 415
	default:
		return 500
	}
}

// AshError represents an error in the ASH protocol.
type AshError struct {
	Code    AshErrorCode
	Message string
}

func (e *AshError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// HTTPStatus returns the recommended HTTP status code for this error.
func (e *AshError) HTTPStatus() int {
	return e.Code.HTTPStatus()
}

// AshNewError creates a new AshError.
func AshNewError(code AshErrorCode, message string) *AshError {
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

// ============================================================================
// CORE PROOF FUNCTIONS
// ============================================================================

// AshBuildProof builds a deterministic proof from the given inputs.
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
func AshBuildProof(input BuildProofInput) string {
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
	return AshBase64URLEncode(hash[:])
}

// ============================================================================
// BASE64 FUNCTIONS
// ============================================================================

// AshBase64URLEncode encodes data as Base64URL (no padding).
// RFC 4648 Section 5: Base 64 Encoding with URL and Filename Safe Alphabet
func AshBase64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// AshBase64URLDecode decodes a Base64URL string to bytes.
// Handles both padded and unpadded input.
func AshBase64URLDecode(input string) ([]byte, error) {
	// Remove any padding characters
	input = strings.TrimRight(input, "=")
	return base64.RawURLEncoding.DecodeString(input)
}

// ============================================================================
// CANONICALIZATION FUNCTIONS
// ============================================================================

// AshCanonicalizeJSON canonicalizes a JSON value to a deterministic string.
//
// Rules (from ASH-Spec-v1.0):
//   - JSON minified (no whitespace)
//   - Object keys sorted lexicographically (ascending)
//   - Arrays preserve order
//   - Unicode normalization: NFC
//   - Numbers: no scientific notation, remove trailing zeros, -0 becomes 0
//   - Unsupported values REJECT: NaN, Infinity
func AshCanonicalizeJSON(value interface{}) (string, error) {
	canonicalized, err := ashCanonicalizeValue(value)
	if err != nil {
		return "", err
	}
	return ashBuildCanonicalJSON(canonicalized)
}

// ashCanonicalizeValue recursively canonicalizes a value.
func ashCanonicalizeValue(value interface{}) (interface{}, error) {
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
		return ashCanonicalizeNumber(v)

	case float32:
		return ashCanonicalizeNumber(float64(v))

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
			return nil, AshNewError(ErrCanonicalizationError, "invalid json.Number")
		}
		return ashCanonicalizeNumber(f)

	case []interface{}:
		result := make([]interface{}, len(v))
		for i, item := range v {
			canonicalized, err := ashCanonicalizeValue(item)
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
			canonicalized, err := ashCanonicalizeValue(val)
			if err != nil {
				return nil, err
			}
			result[normalizedKey] = canonicalized
		}
		return result, nil

	default:
		return nil, AshNewError(ErrCanonicalizationError, fmt.Sprintf("unsupported type: %T", value))
	}
}

// ashCanonicalizeNumber canonicalizes a number according to ASH spec.
func ashCanonicalizeNumber(num float64) (float64, error) {
	// Check for NaN
	if math.IsNaN(num) {
		return 0, AshNewError(ErrCanonicalizationError, "NaN values are not allowed")
	}

	// Check for Infinity (both positive and negative)
	if math.IsInf(num, 0) {
		return 0, AshNewError(ErrCanonicalizationError, "Infinity values are not allowed")
	}

	// Convert -0 to 0
	if num == 0 {
		return 0, nil
	}

	return num, nil
}

// ashBuildCanonicalJSON builds canonical JSON string with sorted keys.
func ashBuildCanonicalJSON(value interface{}) (string, error) {
	if value == nil {
		return "null", nil
	}

	switch v := value.(type) {
	case string:
		return ashEscapeJSONStringRFC8785(v), nil

	case bool:
		if v {
			return "true", nil
		}
		return "false", nil

	case float64:
		return ashFormatNumber(v), nil

	case []interface{}:
		var sb strings.Builder
		sb.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				sb.WriteByte(',')
			}
			itemStr, err := ashBuildCanonicalJSON(item)
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
			sb.WriteString(ashEscapeJSONStringRFC8785(key))
			sb.WriteByte(':')

			valStr, err := ashBuildCanonicalJSON(v[key])
			if err != nil {
				return "", err
			}
			sb.WriteString(valStr)
		}
		sb.WriteByte('}')
		return sb.String(), nil

	default:
		return "", AshNewError(ErrCanonicalizationError, fmt.Sprintf("cannot serialize type: %T", value))
	}
}

// ashEscapeJSONStringRFC8785 escapes a string according to RFC 8785 (JCS).
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
func ashEscapeJSONStringRFC8785(s string) string {
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

// ashFormatNumber formats a number without scientific notation.
func ashFormatNumber(num float64) string {
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

// AshCanonicalizeURLEncoded canonicalizes URL-encoded form data.
//
// Rules (from ASH-Spec-v1.0):
//   - Parse into key-value pairs
//   - Percent-decode consistently
//   - Sort keys lexicographically
//   - For duplicate keys: sort by value (byte-wise)
//   - Output format: k1=v1&k1=v2&k2=v3
//   - Unicode NFC applies after decoding
func AshCanonicalizeURLEncoded(input string) (string, error) {
	pairs, err := ashParseURLEncoded(input)
	if err != nil {
		return "", err
	}

	// Normalize all keys and values with NFC
	for i := range pairs {
		pairs[i].Key = norm.NFC.String(pairs[i].Key)
		pairs[i].Value = norm.NFC.String(pairs[i].Value)
	}

	// Sort by key first, then by value for duplicate keys (byte-wise)
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i].Key != pairs[j].Key {
			return pairs[i].Key < pairs[j].Key
		}
		return pairs[i].Value < pairs[j].Value
	})

	// Encode and join (use %20 for spaces instead of +, uppercase hex)
	var parts []string
	for _, pair := range pairs {
		key := ashPercentEncodeUppercase(pair.Key)
		value := ashPercentEncodeUppercase(pair.Value)
		parts = append(parts, key+"="+value)
	}

	return strings.Join(parts, "&"), nil
}

// keyValuePair represents a key-value pair for URL encoding.
type keyValuePair struct {
	Key   string
	Value string
}

// ashParseURLEncoded parses URL-encoded string into key-value pairs.
func ashParseURLEncoded(input string) ([]keyValuePair, error) {
	if input == "" {
		return nil, nil
	}

	var pairs []keyValuePair

	for _, part := range strings.Split(input, "&") {
		// Skip empty parts
		if part == "" {
			continue
		}

		// Note: Do NOT replace + with space. ASH treats + as literal plus.
		// Space should be encoded as %20.
		// url.QueryUnescape treats + as space, so we preserve + by encoding it first.
		part = strings.ReplaceAll(part, "+", "%2B")

		eqIndex := strings.Index(part, "=")
		if eqIndex == -1 {
			// Key with no value
			key, err := url.QueryUnescape(part)
			if err != nil {
				return nil, AshNewError(ErrCanonicalizationError, "invalid URL encoding")
			}
			if key != "" {
				pairs = append(pairs, keyValuePair{Key: key, Value: ""})
			}
		} else {
			key, err := url.QueryUnescape(part[:eqIndex])
			if err != nil {
				return nil, AshNewError(ErrCanonicalizationError, "invalid URL encoding")
			}
			value, err := url.QueryUnescape(part[eqIndex+1:])
			if err != nil {
				return nil, AshNewError(ErrCanonicalizationError, "invalid URL encoding")
			}
			if key != "" {
				pairs = append(pairs, keyValuePair{Key: key, Value: value})
			}
		}
	}

	return pairs, nil
}

// AshCanonicalizeURLEncodedFromMap canonicalizes URL-encoded data from a map.
func AshCanonicalizeURLEncodedFromMap(data map[string][]string) string {
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

	// Sort by key first, then by value for duplicate keys (byte-wise)
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i].Key != pairs[j].Key {
			return pairs[i].Key < pairs[j].Key
		}
		return pairs[i].Value < pairs[j].Value
	})

	// Encode and join (use %20 for spaces instead of +, uppercase hex)
	var parts []string
	for _, pair := range pairs {
		key := ashPercentEncodeUppercase(pair.Key)
		value := ashPercentEncodeUppercase(pair.Value)
		parts = append(parts, key+"="+value)
	}

	return strings.Join(parts, "&")
}

// AshCanonicalizeQuery canonicalizes a URL query string according to ASH specification.
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
func AshCanonicalizeQuery(query string) (string, error) {
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
		return "", AshNewError(ErrCanonicalizationError, "invalid query string: "+err.Error())
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
		encodedKey := ashPercentEncodeUppercase(p.key)
		encodedValue := ashPercentEncodeUppercase(p.value)
		parts = append(parts, encodedKey+"="+encodedValue)
	}

	return strings.Join(parts, "&"), nil
}

// ashPercentEncodeUppercase encodes a string with uppercase percent-encoding.
// Uses %20 for spaces (not +), and uppercase hex (A-F not a-f).
func ashPercentEncodeUppercase(s string) string {
	encoded := url.QueryEscape(s)
	// Replace + with %20
	encoded = strings.ReplaceAll(encoded, "+", "%20")
	// Convert lowercase hex to uppercase in percent-encoding
	return ashUppercasePercentEncoding(encoded)
}

// ashUppercasePercentEncoding converts lowercase hex in percent-encoding to uppercase.
func ashUppercasePercentEncoding(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			sb.WriteByte('%')
			sb.WriteByte(ashToUpperHex(s[i+1]))
			sb.WriteByte(ashToUpperHex(s[i+2]))
			i += 2
		} else {
			sb.WriteByte(s[i])
		}
	}
	return sb.String()
}

// ashToUpperHex converts a hex character to uppercase.
func ashToUpperHex(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - 32 // Convert to uppercase
	}
	return c
}

// ============================================================================
// BINDING FUNCTIONS
// ============================================================================

// AshNormalizeBinding normalizes a binding string to canonical form (v2.3.2+ format).
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
func AshNormalizeBinding(method, path, query string) string {
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
		canonicalQuery, _ = AshCanonicalizeQuery(query)
	}

	// v2.3.2 format: METHOD|PATH|CANONICAL_QUERY
	return normalizedMethod + "|" + path + "|" + canonicalQuery
}

// AshNormalizeBindingFromURL normalizes a binding from a full URL path (including query string).
//
// This is a convenience function that extracts the query from the path.
func AshNormalizeBindingFromURL(method, fullPath string) string {
	path := fullPath
	query := ""

	if queryIndex := strings.Index(fullPath, "?"); queryIndex != -1 {
		path = fullPath[:queryIndex]
		query = fullPath[queryIndex+1:]
	}

	return AshNormalizeBinding(method, path, query)
}

// ============================================================================
// COMPARISON FUNCTIONS
// ============================================================================

// AshTimingSafeCompare compares two strings in constant time.
//
// This prevents timing attacks where an attacker could determine
// partial matches based on comparison duration.
func AshTimingSafeCompare(a, b string) bool {
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

// AshTimingSafeCompareBytes compares two byte slices in constant time.
func AshTimingSafeCompareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		// Compare a with itself to maintain constant time
		subtle.ConstantTimeCompare(a, a)
		return false
	}

	return subtle.ConstantTimeCompare(a, b) == 1
}

// ============================================================================
// VALIDATION FUNCTIONS
// ============================================================================

// AshIsValidMode checks if a mode is valid.
func AshIsValidMode(mode AshMode) bool {
	switch mode {
	case ModeMinimal, ModeBalanced, ModeStrict:
		return true
	default:
		return false
	}
}

// AshIsValidHTTPMethod checks if an HTTP method is valid.
func AshIsValidHTTPMethod(method HttpMethod) bool {
	switch method {
	case MethodGET, MethodPOST, MethodPUT, MethodPATCH, MethodDELETE:
		return true
	default:
		return false
	}
}

// AshParseJSON parses a JSON string and canonicalizes it.
func AshParseJSON(jsonStr string) (string, error) {
	var data interface{}
	decoder := json.NewDecoder(strings.NewReader(jsonStr))
	decoder.UseNumber()
	if err := decoder.Decode(&data); err != nil {
		return "", AshNewError(ErrCanonicalizationError, "invalid JSON: "+err.Error())
	}
	return AshCanonicalizeJSON(data)
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

// AshValidateProofInput validates the proof input.
func AshValidateProofInput(input BuildProofInput) error {
	if !AshIsValidMode(input.Mode) {
		return AshNewError(ErrModeViolation, "invalid mode")
	}
	if input.ContextID == "" {
		return ErrEmptyContextID
	}
	if input.Binding == "" {
		return ErrEmptyBinding
	}
	return nil
}

// AshIsASCII checks if a string contains only ASCII characters.
func AshIsASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// ============================================================================
// ASH v2.1 - Derived Client Secret & Cryptographic Proof
// ============================================================================

// AshGenerateNonce generates a cryptographically secure random nonce.
// Returns hex-encoded nonce (64 chars for 32 bytes).
func AshGenerateNonce(bytes int) (string, error) {
	if bytes <= 0 {
		bytes = 32
	}
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// AshGenerateContextID generates a unique context ID with "ash_" prefix.
func AshGenerateContextID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "ash_" + hex.EncodeToString(b), nil
}

// AshDeriveClientSecret derives client secret from server nonce (v2.1).
//
// SECURITY PROPERTIES:
// - One-way: Cannot derive nonce from clientSecret (HMAC is irreversible)
// - Context-bound: Unique per contextId + binding combination
// - Safe to expose: Client can use it but cannot forge other contexts
//
// Formula: clientSecret = HMAC-SHA256(nonce, contextId + "|" + binding)
//
// Returns error if:
// - nonce has fewer than 32 hex characters (SEC-014: weak key material)
// - nonce exceeds 128 characters (SEC-NONCE-001: DoS prevention)
// - nonce contains non-hexadecimal characters (BUG-004: invalid format)
// - contextID is empty (BUG-041: ambiguous context)
// - contextID exceeds 256 characters (SEC-CTX-001: DoS prevention)
// - contextID contains invalid characters (SEC-CTX-001: must be alphanumeric, _, -, .)
// - binding exceeds 8KB (SEC-AUDIT-004: DoS prevention)
func AshDeriveClientSecret(nonce, contextID, binding string) (string, error) {
	// SEC-014: Validate nonce has sufficient entropy
	if len(nonce) < MinNonceHexChars {
		return "", AshNewError(ErrProofInvalid, fmt.Sprintf(
			"nonce must be at least %d hex characters (%d bytes) for adequate entropy",
			MinNonceHexChars, MinNonceHexChars/2))
	}

	// SEC-NONCE-001: Validate nonce doesn't exceed maximum length
	if len(nonce) > MaxNonceLength {
		return "", AshNewError(ErrProofInvalid, fmt.Sprintf(
			"nonce exceeds maximum length of %d characters", MaxNonceLength))
	}

	// BUG-004: Validate nonce is valid hexadecimal
	for _, c := range nonce {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return "", AshNewError(ErrProofInvalid,
				"nonce must contain only hexadecimal characters (0-9, a-f, A-F)")
		}
	}

	// BUG-041: Validate contextID is not empty
	if contextID == "" {
		return "", AshNewError(ErrProofInvalid, "context_id cannot be empty")
	}

	// SEC-CTX-001: Validate contextID doesn't exceed maximum length
	if len(contextID) > MaxContextIDLength {
		return "", AshNewError(ErrProofInvalid, fmt.Sprintf(
			"context_id exceeds maximum length of %d characters", MaxContextIDLength))
	}

	// SEC-CTX-001: Validate contextID contains only allowed characters (A-Z a-z 0-9 _ - .)
	for _, c := range contextID {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' || c == '.') {
			return "", AshNewError(ErrProofInvalid,
				"context_id must contain only ASCII alphanumeric characters, underscore, hyphen, or dot")
		}
	}

	// SEC-AUDIT-004: Validate binding length to prevent memory exhaustion
	if len(binding) > MaxBindingLength {
		return "", AshNewError(ErrProofInvalid, fmt.Sprintf(
			"binding exceeds maximum length of %d bytes", MaxBindingLength))
	}

	h := hmac.New(sha256.New, []byte(nonce))
	h.Write([]byte(contextID + "|" + binding))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// AshDeriveClientSecretUnsafe derives client secret without validation (for backward compatibility).
// Deprecated: Use AshDeriveClientSecret instead which returns errors for invalid input.
func AshDeriveClientSecretUnsafe(nonce, contextID, binding string) string {
	h := hmac.New(sha256.New, []byte(nonce))
	h.Write([]byte(contextID + "|" + binding))
	return hex.EncodeToString(h.Sum(nil))
}

// AshBuildProofHMAC builds an HMAC-SHA256 cryptographic proof (client-side).
//
// Formula: proof = HMAC-SHA256(clientSecret, timestamp + "|" + binding + "|" + bodyHash)
func AshBuildProofHMAC(clientSecret, timestamp, binding, bodyHash string) string {
	message := timestamp + "|" + binding + "|" + bodyHash
	h := hmac.New(sha256.New, []byte(clientSecret))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// AshVerifyProof verifies an HMAC proof (server-side).
// Returns (valid, error) where error is non-nil for invalid inputs.
func AshVerifyProof(nonce, contextID, binding, timestamp, bodyHash, clientProof string) (bool, error) {
	// Derive the same client secret server-side
	clientSecret, err := AshDeriveClientSecret(nonce, contextID, binding)
	if err != nil {
		return false, err
	}

	// Compute expected proof
	expectedProof := AshBuildProofHMAC(clientSecret, timestamp, binding, bodyHash)

	// Constant-time comparison
	return AshTimingSafeCompare(expectedProof, clientProof), nil
}

// AshVerifyProofUnsafe verifies an HMAC proof without input validation (for backward compatibility).
// Deprecated: Use AshVerifyProof instead which validates inputs.
func AshVerifyProofUnsafe(nonce, contextID, binding, timestamp, bodyHash, clientProof string) bool {
	clientSecret := AshDeriveClientSecretUnsafe(nonce, contextID, binding)
	expectedProof := AshBuildProofHMAC(clientSecret, timestamp, binding, bodyHash)
	return AshTimingSafeCompare(expectedProof, clientProof)
}

// AshHashBody computes SHA-256 hash of canonical body.
func AshHashBody(canonicalBody string) string {
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

// ============================================================================
// ASH v2.2 - Context Scoping (Selective Field Protection)
// ============================================================================

// ScopedProofResult contains proof and scope hash
type ScopedProofResult struct {
	Proof     string
	ScopeHash string
}

// AshExtractScopedFields extracts specified fields from a payload map.
// Supports dot notation for nested fields (e.g., "user.address.city").
func AshExtractScopedFields(payload map[string]interface{}, scope []string) map[string]interface{} {
	if len(scope) == 0 {
		return payload
	}

	result := make(map[string]interface{})
	for _, fieldPath := range scope {
		value := ashGetNestedValue(payload, fieldPath)
		if value != nil {
			ashSetNestedValue(result, fieldPath, value)
		}
	}
	return result
}

func ashGetNestedValue(obj map[string]interface{}, path string) interface{} {
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

func ashSetNestedValue(obj map[string]interface{}, path string, value interface{}) {
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

// AshBuildProofScoped builds a scoped proof with selective field protection.
func AshBuildProofScoped(clientSecret, timestamp, binding string, payload map[string]interface{}, scope []string) ScopedProofResult {
	// BUG-023: Normalize scope for deterministic ordering
	normalizedScope := AshNormalizeScopeFields(scope)
	scopedPayload := AshExtractScopedFields(payload, normalizedScope)

	// Use proper canonicalization (sorted keys, NFC normalization, etc.)
	canonical, _ := AshCanonicalizeJSON(scopedPayload)
	bodyHash := AshHashBody(canonical)

	// BUG-002, BUG-023: Use unit separator and normalized scope
	scopeStr := AshJoinScopeFields(scope)
	scopeHash := AshHashBody(scopeStr)

	message := timestamp + "|" + binding + "|" + bodyHash + "|" + scopeHash
	h := hmac.New(sha256.New, []byte(clientSecret))
	h.Write([]byte(message))
	proof := hex.EncodeToString(h.Sum(nil))

	return ScopedProofResult{Proof: proof, ScopeHash: scopeHash}
}

// AshVerifyProofScoped verifies a scoped proof with selective field protection.
// Returns (valid, error) where error is non-nil for invalid inputs.
func AshVerifyProofScoped(nonce, contextID, binding, timestamp string, payload map[string]interface{}, scope []string, scopeHash, clientProof string) (bool, error) {
	// BUG-002, BUG-023: Verify scope hash with unit separator and normalization
	scopeStr := AshJoinScopeFields(scope)
	expectedScopeHash := AshHashBody(scopeStr)
	if !AshTimingSafeCompare(expectedScopeHash, scopeHash) {
		return false, nil
	}

	clientSecret, err := AshDeriveClientSecret(nonce, contextID, binding)
	if err != nil {
		return false, err
	}
	result := AshBuildProofScoped(clientSecret, timestamp, binding, payload, scope)

	return AshTimingSafeCompare(result.Proof, clientProof), nil
}

// AshVerifyProofScopedUnsafe verifies a scoped proof without input validation (for backward compatibility).
// Deprecated: Use AshVerifyProofScoped instead which validates inputs.
func AshVerifyProofScopedUnsafe(nonce, contextID, binding, timestamp string, payload map[string]interface{}, scope []string, scopeHash, clientProof string) bool {
	scopeStr := AshJoinScopeFields(scope)
	expectedScopeHash := AshHashBody(scopeStr)
	if !AshTimingSafeCompare(expectedScopeHash, scopeHash) {
		return false
	}
	clientSecret := AshDeriveClientSecretUnsafe(nonce, contextID, binding)
	result := AshBuildProofScoped(clientSecret, timestamp, binding, payload, scope)
	return AshTimingSafeCompare(result.Proof, clientProof)
}

// AshHashScopedBody hashes the scoped payload fields.
func AshHashScopedBody(payload map[string]interface{}, scope []string) string {
	scopedPayload := AshExtractScopedFields(payload, scope)
	// Use proper canonicalization (sorted keys, NFC normalization, etc.)
	canonical, _ := AshCanonicalizeJSON(scopedPayload)
	return AshHashBody(canonical)
}

// ============================================================================
// ASH v2.3 - Unified Proof Functions (Scoping + Chaining)
// ============================================================================

// UnifiedProofResult contains proof, scope hash, and chain hash.
type UnifiedProofResult struct {
	Proof     string
	ScopeHash string
	ChainHash string
}

// AshHashProof hashes a proof for chaining purposes.
func AshHashProof(proof string) string {
	hash := sha256.Sum256([]byte(proof))
	return hex.EncodeToString(hash[:])
}

// AshBuildProofUnified builds a unified v2.3 proof with optional scoping and chaining.
//
// Formula:
//
//	scopeHash  = len(scope) > 0 ? SHA256(sorted(scope).join("\x1F")) : ""
//	bodyHash   = SHA256(canonicalize(scopedPayload))
//	chainHash  = previousProof != "" ? SHA256(previousProof) : ""
//	proof      = HMAC-SHA256(clientSecret, timestamp|binding|bodyHash|scopeHash|chainHash)
func AshBuildProofUnified(clientSecret, timestamp, binding string, payload map[string]interface{}, scope []string, previousProof string) UnifiedProofResult {
	// BUG-023: Normalize scope for deterministic ordering
	normalizedScope := AshNormalizeScopeFields(scope)

	// Extract and hash scoped payload
	scopedPayload := AshExtractScopedFields(payload, normalizedScope)
	// Use proper canonicalization (sorted keys, NFC normalization, etc.)
	canonical, _ := AshCanonicalizeJSON(scopedPayload)
	bodyHash := AshHashBody(canonical)

	// BUG-002, BUG-023: Compute scope hash with unit separator and normalization
	scopeHash := ""
	if len(scope) > 0 {
		scopeStr := AshJoinScopeFields(scope)
		scopeHash = AshHashBody(scopeStr)
	}

	// Compute chain hash (empty string if no previous proof)
	chainHash := ""
	if previousProof != "" {
		chainHash = AshHashProof(previousProof)
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

// AshVerifyProofUnified verifies a unified v2.3 proof with optional scoping and chaining.
// Returns (valid, error) where error is non-nil for invalid inputs.
func AshVerifyProofUnified(nonce, contextID, binding, timestamp string, payload map[string]interface{}, clientProof string, scope []string, scopeHash, previousProof, chainHash string) (bool, error) {
	// SEC-013: Validate consistency - scopeHash must be empty when scope is empty
	if len(scope) == 0 && scopeHash != "" {
		return false, nil
	}

	// BUG-002, BUG-023: Validate scope hash with unit separator and normalization
	if len(scope) > 0 {
		scopeStr := AshJoinScopeFields(scope)
		expectedScopeHash := AshHashBody(scopeStr)
		if !AshTimingSafeCompare(expectedScopeHash, scopeHash) {
			return false, nil
		}
	}

	// SEC-013: Validate consistency - chainHash must be empty when previousProof is absent
	if previousProof == "" && chainHash != "" {
		return false, nil
	}

	// Validate chain hash if chaining is used
	if previousProof != "" {
		expectedChainHash := AshHashProof(previousProof)
		if !AshTimingSafeCompare(expectedChainHash, chainHash) {
			return false, nil
		}
	}

	// Derive client secret and compute expected proof
	clientSecret, err := AshDeriveClientSecret(nonce, contextID, binding)
	if err != nil {
		return false, err
	}
	result := AshBuildProofUnified(clientSecret, timestamp, binding, payload, scope, previousProof)

	return AshTimingSafeCompare(result.Proof, clientProof), nil
}

// AshVerifyProofUnifiedUnsafe verifies a unified proof without input validation (for backward compatibility).
// Deprecated: Use AshVerifyProofUnified instead which validates inputs.
func AshVerifyProofUnifiedUnsafe(nonce, contextID, binding, timestamp string, payload map[string]interface{}, clientProof string, scope []string, scopeHash, previousProof, chainHash string) bool {
	if len(scope) == 0 && scopeHash != "" {
		return false
	}
	if len(scope) > 0 {
		scopeStr := AshJoinScopeFields(scope)
		expectedScopeHash := AshHashBody(scopeStr)
		if !AshTimingSafeCompare(expectedScopeHash, scopeHash) {
			return false
		}
	}
	if previousProof == "" && chainHash != "" {
		return false
	}
	if previousProof != "" {
		expectedChainHash := AshHashProof(previousProof)
		if !AshTimingSafeCompare(expectedChainHash, chainHash) {
			return false
		}
	}
	clientSecret := AshDeriveClientSecretUnsafe(nonce, contextID, binding)
	result := AshBuildProofUnified(clientSecret, timestamp, binding, payload, scope, previousProof)
	return AshTimingSafeCompare(result.Proof, clientProof)
}

// AshGetVersion returns the SDK version string.
func AshGetVersion() string {
	return Version
}

// ============================================================================
// BACKWARD COMPATIBILITY ALIASES (Deprecated - use Ash-prefixed versions)
// ============================================================================

// Deprecated: Use AshNormalizeScopeFields instead.
func NormalizeScopeFields(scope []string) []string {
	return AshNormalizeScopeFields(scope)
}

// Deprecated: Use AshJoinScopeFields instead.
func JoinScopeFields(scope []string) string {
	return AshJoinScopeFields(scope)
}

// Deprecated: Use AshNewError instead.
func NewAshError(code AshErrorCode, message string) *AshError {
	return AshNewError(code, message)
}

// Deprecated: Use AshBuildProof instead.
func BuildProof(input BuildProofInput) string {
	return AshBuildProof(input)
}

// Deprecated: Use AshBase64URLEncode instead.
func Base64URLEncode(data []byte) string {
	return AshBase64URLEncode(data)
}

// Deprecated: Use AshBase64URLDecode instead.
func Base64URLDecode(input string) ([]byte, error) {
	return AshBase64URLDecode(input)
}

// Deprecated: Use AshCanonicalizeJSON instead.
func CanonicalizeJSON(value interface{}) (string, error) {
	return AshCanonicalizeJSON(value)
}

// Deprecated: Use AshCanonicalizeURLEncoded instead.
func CanonicalizeURLEncoded(input string) (string, error) {
	return AshCanonicalizeURLEncoded(input)
}

// Deprecated: Use AshCanonicalizeURLEncodedFromMap instead.
func CanonicalizeURLEncodedFromMap(data map[string][]string) string {
	return AshCanonicalizeURLEncodedFromMap(data)
}

// Deprecated: Use AshCanonicalizeQuery instead.
func CanonicalizeQuery(query string) (string, error) {
	return AshCanonicalizeQuery(query)
}

// Deprecated: Use AshNormalizeBinding instead.
func NormalizeBinding(method, path, query string) string {
	return AshNormalizeBinding(method, path, query)
}

// Deprecated: Use AshNormalizeBindingFromURL instead.
func NormalizeBindingFromURL(method, fullPath string) string {
	return AshNormalizeBindingFromURL(method, fullPath)
}

// Deprecated: Use AshTimingSafeCompare instead.
func TimingSafeCompare(a, b string) bool {
	return AshTimingSafeCompare(a, b)
}

// Deprecated: Use AshTimingSafeCompareBytes instead.
func TimingSafeCompareBytes(a, b []byte) bool {
	return AshTimingSafeCompareBytes(a, b)
}

// Deprecated: Use AshIsValidMode instead.
func IsValidMode(mode AshMode) bool {
	return AshIsValidMode(mode)
}

// Deprecated: Use AshIsValidHTTPMethod instead.
func IsValidHTTPMethod(method HttpMethod) bool {
	return AshIsValidHTTPMethod(method)
}

// Deprecated: Use AshParseJSON instead.
func ParseJSON(jsonStr string) (string, error) {
	return AshParseJSON(jsonStr)
}

// Deprecated: Use AshValidateProofInput instead.
func ValidateProofInput(input BuildProofInput) error {
	return AshValidateProofInput(input)
}

// Deprecated: Use AshIsASCII instead.
func IsASCII(s string) bool {
	return AshIsASCII(s)
}

// Deprecated: Use AshGenerateNonce instead.
func GenerateNonce(bytes int) (string, error) {
	return AshGenerateNonce(bytes)
}

// Deprecated: Use AshGenerateContextID instead.
func GenerateContextID() (string, error) {
	return AshGenerateContextID()
}

// Deprecated: Use AshDeriveClientSecret instead.
// This function ignores validation errors for backward compatibility.
func DeriveClientSecret(nonce, contextID, binding string) string {
	return AshDeriveClientSecretUnsafe(nonce, contextID, binding)
}

// Deprecated: Use AshBuildProofHMAC instead.
func BuildProofV21(clientSecret, timestamp, binding, bodyHash string) string {
	return AshBuildProofHMAC(clientSecret, timestamp, binding, bodyHash)
}

// Deprecated: Use AshBuildProofHMAC instead.
func AshBuildProofV21(clientSecret, timestamp, binding, bodyHash string) string {
	return AshBuildProofHMAC(clientSecret, timestamp, binding, bodyHash)
}

// Deprecated: Use AshVerifyProof instead.
// This function ignores validation errors for backward compatibility.
func VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, clientProof string) bool {
	return AshVerifyProofUnsafe(nonce, contextID, binding, timestamp, bodyHash, clientProof)
}

// Deprecated: Use AshVerifyProof instead.
// This function ignores validation errors for backward compatibility.
func AshVerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, clientProof string) bool {
	return AshVerifyProofUnsafe(nonce, contextID, binding, timestamp, bodyHash, clientProof)
}

// Deprecated: Use AshHashBody instead.
func HashBody(canonicalBody string) string {
	return AshHashBody(canonicalBody)
}

// Deprecated: Use AshExtractScopedFields instead.
func ExtractScopedFields(payload map[string]interface{}, scope []string) map[string]interface{} {
	return AshExtractScopedFields(payload, scope)
}

// Deprecated: Use AshBuildProofScoped instead.
func BuildProofV21Scoped(clientSecret, timestamp, binding string, payload map[string]interface{}, scope []string) ScopedProofResult {
	return AshBuildProofScoped(clientSecret, timestamp, binding, payload, scope)
}

// Deprecated: Use AshBuildProofScoped instead.
func AshBuildProofV21Scoped(clientSecret, timestamp, binding string, payload map[string]interface{}, scope []string) ScopedProofResult {
	return AshBuildProofScoped(clientSecret, timestamp, binding, payload, scope)
}

// Deprecated: Use AshVerifyProofScoped instead.
// This function ignores validation errors for backward compatibility.
func VerifyProofV21Scoped(nonce, contextID, binding, timestamp string, payload map[string]interface{}, scope []string, scopeHash, clientProof string) bool {
	return AshVerifyProofScopedUnsafe(nonce, contextID, binding, timestamp, payload, scope, scopeHash, clientProof)
}

// Deprecated: Use AshVerifyProofScoped instead.
// This function ignores validation errors for backward compatibility.
func AshVerifyProofV21Scoped(nonce, contextID, binding, timestamp string, payload map[string]interface{}, scope []string, scopeHash, clientProof string) bool {
	return AshVerifyProofScopedUnsafe(nonce, contextID, binding, timestamp, payload, scope, scopeHash, clientProof)
}

// Deprecated: Use AshHashScopedBody instead.
func HashScopedBody(payload map[string]interface{}, scope []string) string {
	return AshHashScopedBody(payload, scope)
}

// Deprecated: Use AshHashProof instead.
func HashProof(proof string) string {
	return AshHashProof(proof)
}

// Deprecated: Use AshBuildProofUnified instead.
func BuildProofUnified(clientSecret, timestamp, binding string, payload map[string]interface{}, scope []string, previousProof string) UnifiedProofResult {
	return AshBuildProofUnified(clientSecret, timestamp, binding, payload, scope, previousProof)
}

// Deprecated: Use AshVerifyProofUnified instead.
// This function ignores validation errors for backward compatibility.
func VerifyProofUnified(nonce, contextID, binding, timestamp string, payload map[string]interface{}, clientProof string, scope []string, scopeHash, previousProof, chainHash string) bool {
	return AshVerifyProofUnifiedUnsafe(nonce, contextID, binding, timestamp, payload, clientProof, scope, scopeHash, previousProof, chainHash)
}

// Deprecated: Use AshGetVersion instead.
func GetVersion() string {
	return AshGetVersion()
}

// ============================================================================
// INTERNAL BACKWARD COMPATIBILITY (unexported - for internal use only)
// ============================================================================

// Deprecated internal aliases for unexported functions.
// These are kept for any internal code that might still reference them.

func canonicalizeValue(value interface{}) (interface{}, error) {
	return ashCanonicalizeValue(value)
}

func canonicalizeNumber(num float64) (float64, error) {
	return ashCanonicalizeNumber(num)
}

func buildCanonicalJSON(value interface{}) (string, error) {
	return ashBuildCanonicalJSON(value)
}

func escapeJSONStringRFC8785(s string) string {
	return ashEscapeJSONStringRFC8785(s)
}

func formatNumber(num float64) string {
	return ashFormatNumber(num)
}

func parseURLEncoded(input string) ([]keyValuePair, error) {
	return ashParseURLEncoded(input)
}

func percentEncodeUppercase(s string) string {
	return ashPercentEncodeUppercase(s)
}

func uppercasePercentEncoding(s string) string {
	return ashUppercasePercentEncoding(s)
}

func toUpperHex(c byte) byte {
	return ashToUpperHex(c)
}

func getNestedValue(obj map[string]interface{}, path string) interface{} {
	return ashGetNestedValue(obj, path)
}

func setNestedValue(obj map[string]interface{}, path string, value interface{}) {
	ashSetNestedValue(obj, path, value)
}
