//! Server-side scope policy registry for ASH.
//!
//! Allows servers to define which fields must be protected for each route,
//! without requiring client-side scope management.
//!
//! # Example
//!
//! ```rust
//! use ash_core::config::{register_scope_policy, get_scope_policy, clear_scope_policies};
//!
//! // Clear any existing policies (useful in tests)
//! clear_scope_policies();
//!
//! // Register policies at application startup
//! register_scope_policy("POST|/api/transfer|", &["amount", "recipient"]);
//! register_scope_policy("POST|/api/payment|", &["amount", "card_last4"]);
//! register_scope_policy("PUT|/api/users/<id>|", &["role", "permissions"]);
//!
//! // Later, get policy for a binding
//! let scope = get_scope_policy("POST|/api/transfer|");
//! assert_eq!(scope, vec!["amount", "recipient"]);
//! ```

use regex::Regex;
use std::collections::HashMap;
use std::sync::RwLock;

lazy_static::lazy_static! {
    /// Internal storage for scope policies
    static ref POLICIES: RwLock<HashMap<String, Vec<String>>> = RwLock::new(HashMap::new());
}

/// Register a scope policy for a binding pattern.
///
/// # Arguments
///
/// * `binding` - The binding pattern (supports `<param>`, `:param`, `{param}`, `*`, `**` wildcards)
/// * `fields` - The fields that must be protected
///
/// # Example
///
/// ```rust
/// use ash_core::config::{register_scope_policy, clear_scope_policies};
///
/// clear_scope_policies();
/// register_scope_policy("POST|/api/transfer|", &["amount", "recipient"]);
/// register_scope_policy("PUT|/api/users/<id>|", &["role", "permissions"]);
/// ```
pub fn register_scope_policy(binding: &str, fields: &[&str]) {
    let mut policies = POLICIES.write().unwrap();
    policies.insert(
        binding.to_string(),
        fields.iter().map(|s| s.to_string()).collect(),
    );
}

/// Register multiple scope policies at once.
///
/// # Arguments
///
/// * `policies` - Map of binding => fields
///
/// # Example
///
/// ```rust
/// use std::collections::HashMap;
/// use ash_core::config::{register_scope_policies, clear_scope_policies};
///
/// clear_scope_policies();
/// let mut policies = HashMap::new();
/// policies.insert("POST|/api/transfer|", vec!["amount", "recipient"]);
/// policies.insert("POST|/api/payment|", vec!["amount", "card_last4"]);
/// register_scope_policies(&policies);
/// ```
pub fn register_scope_policies(policies_map: &HashMap<&str, Vec<&str>>) {
    let mut policies = POLICIES.write().unwrap();
    for (binding, fields) in policies_map {
        policies.insert(
            binding.to_string(),
            fields.iter().map(|s| s.to_string()).collect(),
        );
    }
}

/// Get the scope policy for a binding.
///
/// Returns empty vector if no policy is defined (full payload protection).
///
/// # Arguments
///
/// * `binding` - The normalized binding string
///
/// # Returns
///
/// The fields that must be protected
///
/// # Example
///
/// ```rust
/// use ash_core::config::{register_scope_policy, get_scope_policy, clear_scope_policies};
///
/// clear_scope_policies();
/// register_scope_policy("POST|/api/transfer|", &["amount", "recipient"]);
///
/// let scope = get_scope_policy("POST|/api/transfer|");
/// assert_eq!(scope, vec!["amount", "recipient"]);
///
/// let no_scope = get_scope_policy("GET|/api/users|");
/// assert!(no_scope.is_empty());
/// ```
pub fn get_scope_policy(binding: &str) -> Vec<String> {
    let policies = POLICIES.read().unwrap();

    // Exact match first
    if let Some(fields) = policies.get(binding) {
        return fields.clone();
    }

    // Pattern match
    for (pattern, fields) in policies.iter() {
        if matches_pattern(binding, pattern) {
            return fields.clone();
        }
    }

    // Default: no scoping (full payload protection)
    Vec::new()
}

/// Check if a binding has a scope policy defined.
///
/// # Arguments
///
/// * `binding` - The normalized binding string
///
/// # Returns
///
/// True if a policy exists
pub fn has_scope_policy(binding: &str) -> bool {
    let policies = POLICIES.read().unwrap();

    if policies.contains_key(binding) {
        return true;
    }

    for pattern in policies.keys() {
        if matches_pattern(binding, pattern) {
            return true;
        }
    }

    false
}

/// Get all registered policies.
///
/// # Returns
///
/// All registered scope policies
pub fn get_all_scope_policies() -> HashMap<String, Vec<String>> {
    let policies = POLICIES.read().unwrap();
    policies.clone()
}

/// Clear all registered policies.
///
/// Useful for testing.
pub fn clear_scope_policies() {
    let mut policies = POLICIES.write().unwrap();
    policies.clear();
}

/// Check if a binding matches a pattern with wildcards.
///
/// Supports:
/// - `<param>` for Flask-style route parameters
/// - `:param` for Express-style route parameters
/// - `{param}` for Laravel/OpenAPI-style route parameters
/// - `*` for single path segment wildcard
/// - `**` for multi-segment wildcard
fn matches_pattern(binding: &str, pattern: &str) -> bool {
    // If no wildcards or params, must be exact match
    if !pattern.contains('*')
        && !pattern.contains('<')
        && !pattern.contains(':')
        && !pattern.contains('{')
    {
        return binding == pattern;
    }

    // Convert pattern to regex
    let mut regex_str = regex::escape(pattern);

    // Replace ** first (multi-segment)
    regex_str = regex_str.replace(r"\*\*", ".*");

    // Replace * (single segment - not containing | or /)
    regex_str = regex_str.replace(r"\*", "[^|/]*");

    // Replace <param> (Flask-style route params)
    // Note: regex::escape does NOT escape < and >, so we match them directly
    let flask_re = Regex::new(r"<[a-zA-Z_][a-zA-Z0-9_]*>").unwrap();
    regex_str = flask_re.replace_all(&regex_str, "[^|/]+").to_string();

    // Replace :param (Express-style route params)
    let express_re = Regex::new(r":[a-zA-Z_][a-zA-Z0-9_]*").unwrap();
    regex_str = express_re.replace_all(&regex_str, "[^|/]+").to_string();

    // Replace {param} (Laravel/OpenAPI-style route params)
    // Note: { and } are escaped by regex::escape to \{ and \}, so we match \\{ and \\}
    // Using character class [{}] to avoid regex quantifier interpretation
    let laravel_re = Regex::new(r"\\[{][a-zA-Z_][a-zA-Z0-9_]*\\[}]").unwrap();
    regex_str = laravel_re.replace_all(&regex_str, "[^|/]+").to_string();

    // Match against the binding
    if let Ok(re) = Regex::new(&format!("^{}$", regex_str)) {
        re.is_match(binding)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_get_scope_policy() {
        clear_scope_policies();
        register_scope_policy("POST|/api/transfer|", &["amount", "recipient"]);

        let scope = get_scope_policy("POST|/api/transfer|");
        assert_eq!(scope, vec!["amount", "recipient"]);
    }

    #[test]
    fn test_get_scope_policy_no_match() {
        clear_scope_policies();

        let scope = get_scope_policy("GET|/api/users|");
        assert!(scope.is_empty());
    }

    #[test]
    fn test_has_scope_policy() {
        clear_scope_policies();
        register_scope_policy("POST|/api/transfer|", &["amount"]);

        assert!(has_scope_policy("POST|/api/transfer|"));
        assert!(!has_scope_policy("GET|/api/users|"));
    }

    #[test]
    fn test_pattern_matching_flask_style() {
        clear_scope_policies();
        register_scope_policy("PUT|/api/users/<id>|", &["role", "permissions"]);

        let scope = get_scope_policy("PUT|/api/users/123|");
        assert_eq!(scope, vec!["role", "permissions"]);
    }

    #[test]
    fn test_pattern_matching_express_style() {
        clear_scope_policies();
        register_scope_policy("PUT|/api/users/:id|", &["role"]);

        let scope = get_scope_policy("PUT|/api/users/456|");
        assert_eq!(scope, vec!["role"]);
    }

    #[test]
    fn test_pattern_matching_laravel_style() {
        clear_scope_policies();
        register_scope_policy("PUT|/api/users/{id}|", &["email"]);

        let scope = get_scope_policy("PUT|/api/users/789|");
        assert_eq!(scope, vec!["email"]);
    }

    #[test]
    fn test_pattern_matching_wildcard() {
        clear_scope_policies();
        register_scope_policy("POST|/api/*/transfer|", &["amount"]);

        let scope = get_scope_policy("POST|/api/v1/transfer|");
        assert_eq!(scope, vec!["amount"]);
    }

    #[test]
    fn test_pattern_matching_double_wildcard() {
        clear_scope_policies();
        register_scope_policy("POST|/api/**/transfer|", &["amount"]);

        let scope = get_scope_policy("POST|/api/v1/users/transfer|");
        assert_eq!(scope, vec!["amount"]);
    }

    #[test]
    fn test_clear_policies() {
        clear_scope_policies();
        register_scope_policy("POST|/api/transfer|", &["amount"]);

        assert!(has_scope_policy("POST|/api/transfer|"));

        clear_scope_policies();

        assert!(!has_scope_policy("POST|/api/transfer|"));
    }
}
