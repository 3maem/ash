// Package ash provides the ASH Protocol SDK for Go.
//
// This file implements ENH-003: Server-Side Scope Policies
//
// Allows servers to define which fields must be protected for each route,
// without requiring client-side scope management.
//
// Example:
//
//	// Register policies at application startup
//	ash.AshRegisterScopePolicy("POST|/api/transfer|", []string{"amount", "recipient"})
//	ash.AshRegisterScopePolicy("POST|/api/payment|", []string{"amount", "card_last4"})
//	ash.AshRegisterScopePolicy("PUT|/api/users/:id|", []string{"role", "permissions"})
//
//	// Later, get policy for a binding
//	scope := ash.AshGetScopePolicy("POST|/api/transfer|")
//	// Returns: []string{"amount", "recipient"}
package ash

import (
	"regexp"
	"strings"
	"sync"
)

// scopePolicies holds the internal storage for scope policies
var (
	scopePolicies     = make(map[string][]string)
	scopePoliciesMu   sync.RWMutex
)

// AshRegisterScopePolicy registers a scope policy for a binding pattern.
//
// Parameters:
//   - binding: The binding pattern (supports <param>, :param, {param}, *, ** wildcards)
//   - fields: The fields that must be protected
//
// Example:
//
//	ash.AshRegisterScopePolicy("POST|/api/transfer|", []string{"amount", "recipient"})
//	ash.AshRegisterScopePolicy("PUT|/api/users/:id|", []string{"role", "permissions"})
func AshRegisterScopePolicy(binding string, fields []string) {
	scopePoliciesMu.Lock()
	defer scopePoliciesMu.Unlock()

	// Make a copy of the slice to prevent external modifications
	fieldsCopy := make([]string, len(fields))
	copy(fieldsCopy, fields)
	scopePolicies[binding] = fieldsCopy
}

// AshRegisterScopePolicies registers multiple scope policies at once.
//
// Parameters:
//   - policies: Map of binding => fields
//
// Example:
//
//	ash.AshRegisterScopePolicies(map[string][]string{
//		"POST|/api/transfer|": {"amount", "recipient"},
//		"POST|/api/payment|":  {"amount", "card_last4"},
//	})
func AshRegisterScopePolicies(policies map[string][]string) {
	scopePoliciesMu.Lock()
	defer scopePoliciesMu.Unlock()

	for binding, fields := range policies {
		fieldsCopy := make([]string, len(fields))
		copy(fieldsCopy, fields)
		scopePolicies[binding] = fieldsCopy
	}
}

// AshGetScopePolicy returns the scope policy for a binding.
//
// Returns empty slice if no policy is defined (full payload protection).
//
// Parameters:
//   - binding: The normalized binding string
//
// Returns:
//   - The fields that must be protected
//
// Example:
//
//	scope := ash.AshGetScopePolicy("POST|/api/transfer|")
//	// Returns: []string{"amount", "recipient"}
func AshGetScopePolicy(binding string) []string {
	scopePoliciesMu.RLock()
	defer scopePoliciesMu.RUnlock()

	// Exact match first
	if fields, ok := scopePolicies[binding]; ok {
		result := make([]string, len(fields))
		copy(result, fields)
		return result
	}

	// Pattern match
	for pattern, fields := range scopePolicies {
		if ashMatchesBindingPattern(binding, pattern) {
			result := make([]string, len(fields))
			copy(result, fields)
			return result
		}
	}

	// Default: no scoping (full payload protection)
	return []string{}
}

// AshHasScopePolicy checks if a binding has a scope policy defined.
//
// Parameters:
//   - binding: The normalized binding string
//
// Returns:
//   - True if a policy exists
func AshHasScopePolicy(binding string) bool {
	scopePoliciesMu.RLock()
	defer scopePoliciesMu.RUnlock()

	if _, ok := scopePolicies[binding]; ok {
		return true
	}

	for pattern := range scopePolicies {
		if ashMatchesBindingPattern(binding, pattern) {
			return true
		}
	}

	return false
}

// AshGetAllScopePolicies returns all registered policies.
//
// Returns:
//   - All registered scope policies (copy)
func AshGetAllScopePolicies() map[string][]string {
	scopePoliciesMu.RLock()
	defer scopePoliciesMu.RUnlock()

	result := make(map[string][]string)
	for binding, fields := range scopePolicies {
		fieldsCopy := make([]string, len(fields))
		copy(fieldsCopy, fields)
		result[binding] = fieldsCopy
	}
	return result
}

// AshClearScopePolicies clears all registered policies.
//
// Useful for testing.
func AshClearScopePolicies() {
	scopePoliciesMu.Lock()
	defer scopePoliciesMu.Unlock()

	scopePolicies = make(map[string][]string)
}

// ashMatchesBindingPattern checks if a binding matches a pattern with wildcards.
//
// Supports:
//   - <param> for Flask-style route parameters
//   - :param for Express-style route parameters
//   - {param} for Laravel/OpenAPI-style route parameters
//   - * for single path segment wildcard
//   - ** for multi-segment wildcard
func ashMatchesBindingPattern(binding, pattern string) bool {
	// If no wildcards or params, must be exact match
	if !strings.Contains(pattern, "*") &&
		!strings.Contains(pattern, "<") &&
		!strings.Contains(pattern, ":") &&
		!strings.Contains(pattern, "{") {
		return binding == pattern
	}

	// Convert pattern to regex
	regexStr := regexp.QuoteMeta(pattern)

	// Replace ** first (multi-segment)
	regexStr = strings.ReplaceAll(regexStr, `\*\*`, ".*")

	// Replace * (single segment - not containing | or /)
	regexStr = strings.ReplaceAll(regexStr, `\*`, "[^|/]*")

	// Replace <param> (Flask-style route params)
	// Note: QuoteMeta does NOT escape < and >, so we match them directly
	flaskRe := regexp.MustCompile(`<[a-zA-Z_][a-zA-Z0-9_]*>`)
	regexStr = flaskRe.ReplaceAllString(regexStr, "[^|/]+")

	// Replace :param (Express-style route params) - need to match unescaped colon
	// Since QuoteMeta doesn't escape colons, we match them directly
	expressRe := regexp.MustCompile(`:[a-zA-Z_][a-zA-Z0-9_]*`)
	regexStr = expressRe.ReplaceAllString(regexStr, "[^|/]+")

	// Replace {param} (Laravel/OpenAPI-style route params)
	laravelRe := regexp.MustCompile(`\\{[a-zA-Z_][a-zA-Z0-9_]*\\}`)
	regexStr = laravelRe.ReplaceAllString(regexStr, "[^|/]+")

	// Compile and match
	re, err := regexp.Compile("^" + regexStr + "$")
	if err != nil {
		return false
	}

	return re.MatchString(binding)
}

// ============================================================================
// BACKWARD COMPATIBILITY ALIASES (Deprecated - use Ash-prefixed versions)
// ============================================================================

// Deprecated: Use AshRegisterScopePolicy instead.
func RegisterScopePolicy(binding string, fields []string) {
	AshRegisterScopePolicy(binding, fields)
}

// Deprecated: Use AshRegisterScopePolicies instead.
func RegisterScopePolicies(policies map[string][]string) {
	AshRegisterScopePolicies(policies)
}

// Deprecated: Use AshGetScopePolicy instead.
func GetScopePolicy(binding string) []string {
	return AshGetScopePolicy(binding)
}

// Deprecated: Use AshHasScopePolicy instead.
func HasScopePolicy(binding string) bool {
	return AshHasScopePolicy(binding)
}

// Deprecated: Use AshGetAllScopePolicies instead.
func GetAllScopePolicies() map[string][]string {
	return AshGetAllScopePolicies()
}

// Deprecated: Use AshClearScopePolicies instead.
func ClearScopePolicies() {
	AshClearScopePolicies()
}

// ============================================================================
// INTERNAL BACKWARD COMPATIBILITY (unexported - for internal use only)
// ============================================================================

// Deprecated internal alias for unexported function.
func matchesBindingPattern(binding, pattern string) bool {
	return ashMatchesBindingPattern(binding, pattern)
}
