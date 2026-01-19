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
//	ash.RegisterScopePolicy("POST|/api/transfer|", []string{"amount", "recipient"})
//	ash.RegisterScopePolicy("POST|/api/payment|", []string{"amount", "card_last4"})
//	ash.RegisterScopePolicy("PUT|/api/users/:id|", []string{"role", "permissions"})
//
//	// Later, get policy for a binding
//	scope := ash.GetScopePolicy("POST|/api/transfer|")
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

// RegisterScopePolicy registers a scope policy for a binding pattern.
//
// Parameters:
//   - binding: The binding pattern (supports <param>, :param, {param}, *, ** wildcards)
//   - fields: The fields that must be protected
//
// Example:
//
//	ash.RegisterScopePolicy("POST|/api/transfer|", []string{"amount", "recipient"})
//	ash.RegisterScopePolicy("PUT|/api/users/:id|", []string{"role", "permissions"})
func RegisterScopePolicy(binding string, fields []string) {
	scopePoliciesMu.Lock()
	defer scopePoliciesMu.Unlock()

	// Make a copy of the slice to prevent external modifications
	fieldsCopy := make([]string, len(fields))
	copy(fieldsCopy, fields)
	scopePolicies[binding] = fieldsCopy
}

// RegisterScopePolicies registers multiple scope policies at once.
//
// Parameters:
//   - policies: Map of binding => fields
//
// Example:
//
//	ash.RegisterScopePolicies(map[string][]string{
//		"POST|/api/transfer|": {"amount", "recipient"},
//		"POST|/api/payment|":  {"amount", "card_last4"},
//	})
func RegisterScopePolicies(policies map[string][]string) {
	scopePoliciesMu.Lock()
	defer scopePoliciesMu.Unlock()

	for binding, fields := range policies {
		fieldsCopy := make([]string, len(fields))
		copy(fieldsCopy, fields)
		scopePolicies[binding] = fieldsCopy
	}
}

// GetScopePolicy returns the scope policy for a binding.
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
//	scope := ash.GetScopePolicy("POST|/api/transfer|")
//	// Returns: []string{"amount", "recipient"}
func GetScopePolicy(binding string) []string {
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
		if matchesBindingPattern(binding, pattern) {
			result := make([]string, len(fields))
			copy(result, fields)
			return result
		}
	}

	// Default: no scoping (full payload protection)
	return []string{}
}

// HasScopePolicy checks if a binding has a scope policy defined.
//
// Parameters:
//   - binding: The normalized binding string
//
// Returns:
//   - True if a policy exists
func HasScopePolicy(binding string) bool {
	scopePoliciesMu.RLock()
	defer scopePoliciesMu.RUnlock()

	if _, ok := scopePolicies[binding]; ok {
		return true
	}

	for pattern := range scopePolicies {
		if matchesBindingPattern(binding, pattern) {
			return true
		}
	}

	return false
}

// GetAllScopePolicies returns all registered policies.
//
// Returns:
//   - All registered scope policies (copy)
func GetAllScopePolicies() map[string][]string {
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

// ClearScopePolicies clears all registered policies.
//
// Useful for testing.
func ClearScopePolicies() {
	scopePoliciesMu.Lock()
	defer scopePoliciesMu.Unlock()

	scopePolicies = make(map[string][]string)
}

// matchesBindingPattern checks if a binding matches a pattern with wildcards.
//
// Supports:
//   - <param> for Flask-style route parameters
//   - :param for Express-style route parameters
//   - {param} for Laravel/OpenAPI-style route parameters
//   - * for single path segment wildcard
//   - ** for multi-segment wildcard
func matchesBindingPattern(binding, pattern string) bool {
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
