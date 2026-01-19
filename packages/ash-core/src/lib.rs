//! # ASH Core
//!
//! ASH (Anti-tamper Security Hash) is a request integrity and anti-replay protection library.
//!
//! This crate provides the core functionality for:
//! - Deterministic JSON and URL-encoded payload canonicalization
//! - Cryptographic proof generation and verification
//! - Constant-time comparison for timing-attack resistance
//! - Binding normalization for endpoint protection
//!
//! ## Features
//!
//! - **Tamper Detection**: Cryptographic proof ensures payload integrity
//! - **Replay Prevention**: One-time contexts prevent request replay
//! - **Deterministic**: Byte-identical output across all platforms
//! - **WASM Compatible**: Works in browsers and server environments
//!
//! ## Example
//!
//! ```rust
//! use ash_core::{canonicalize_json, build_proof, AshMode};
//!
//! // Canonicalize a JSON payload
//! let canonical = canonicalize_json(r#"{"z":1,"a":2}"#).unwrap();
//! assert_eq!(canonical, r#"{"a":2,"z":1}"#);
//!
//! // Build a proof
//! let proof = build_proof(
//!     AshMode::Balanced,
//!     "POST /api/update",
//!     "context-id-123",
//!     None,
//!     &canonical,
//! ).unwrap();
//! ```
//!
//! ## Security Notes
//!
//! ASH verifies **what** is being submitted, not **who** is submitting it.
//! It should be used alongside authentication systems (JWT, OAuth, etc.).

mod canonicalize;
mod compare;
mod errors;
mod proof;
mod types;

pub use canonicalize::{canonicalize_json, canonicalize_urlencoded, canonicalize_query};
pub use compare::timing_safe_equal;
pub use errors::{AshError, AshErrorCode};
pub use proof::{
    build_proof, verify_proof,
    // v2.1 functions
    generate_nonce, generate_context_id,
    derive_client_secret, build_proof_v21,
    verify_proof_v21, hash_body,
    // v2.2 scoping functions
    extract_scoped_fields, build_proof_v21_scoped,
    verify_proof_v21_scoped, hash_scoped_body,
    // v2.3 unified functions (scoping + chaining)
    UnifiedProofResult, hash_proof,
    build_proof_v21_unified, verify_proof_v21_unified,
};
pub use types::{AshMode, BuildProofInput, VerifyInput};

/// Normalize a binding string to canonical form (v2.3.2+ format).
///
/// Bindings are in the format: `METHOD|PATH|CANONICAL_QUERY`
///
/// # Normalization Rules
/// - Method is uppercased
/// - Path must start with `/`
/// - Path has duplicate slashes collapsed
/// - Trailing slash is removed (except for root `/`)
/// - Query string is canonicalized (sorted, normalized)
/// - Parts are joined with `|` (pipe) separator
///
/// # Example
///
/// ```rust
/// use ash_core::normalize_binding;
///
/// let binding = normalize_binding("post", "/api//users/", "").unwrap();
/// assert_eq!(binding, "POST|/api/users|");
///
/// let binding_with_query = normalize_binding("GET", "/api/users", "page=1&sort=name").unwrap();
/// assert_eq!(binding_with_query, "GET|/api/users|page=1&sort=name");
/// ```
pub fn normalize_binding(method: &str, path: &str, query: &str) -> Result<String, AshError> {
    // Validate method
    let method = method.trim().to_uppercase();
    if method.is_empty() {
        return Err(AshError::new(
            AshErrorCode::MalformedRequest,
            "Method cannot be empty",
        ));
    }

    // Validate path starts with /
    let path = path.trim();
    if !path.starts_with('/') {
        return Err(AshError::new(
            AshErrorCode::MalformedRequest,
            "Path must start with /",
        ));
    }

    // Extract path without query string (in case path contains ?)
    let path_only = path.split('?').next().unwrap_or(path);

    // Collapse duplicate slashes and normalize
    let mut normalized_path = String::with_capacity(path_only.len());
    let mut prev_slash = false;

    for ch in path_only.chars() {
        if ch == '/' {
            if !prev_slash {
                normalized_path.push(ch);
            }
            prev_slash = true;
        } else {
            normalized_path.push(ch);
            prev_slash = false;
        }
    }

    // Remove trailing slash (except for root)
    if normalized_path.len() > 1 && normalized_path.ends_with('/') {
        normalized_path.pop();
    }

    // Canonicalize query string
    let canonical_query = if query.is_empty() {
        String::new()
    } else {
        canonicalize::canonicalize_query(query)?
    };

    // v2.3.2 format: METHOD|PATH|CANONICAL_QUERY
    Ok(format!("{}|{}|{}", method, normalized_path, canonical_query))
}

/// Normalize a binding from a full URL path (including query string).
///
/// This is a convenience function that extracts the query string from the path.
///
/// # Example
///
/// ```rust
/// use ash_core::normalize_binding_from_url;
///
/// let binding = normalize_binding_from_url("GET", "/api/users?page=1&sort=name").unwrap();
/// assert_eq!(binding, "GET|/api/users|page=1&sort=name");
/// ```
pub fn normalize_binding_from_url(method: &str, full_path: &str) -> Result<String, AshError> {
    let (path, query) = match full_path.find('?') {
        Some(pos) => (&full_path[..pos], &full_path[pos + 1..]),
        None => (full_path, ""),
    };
    normalize_binding(method, path, query)
}

#[cfg(test)]
mod tests {
    use super::*;

    // v2.3.2 Binding Format Tests (METHOD|PATH|CANONICAL_QUERY)

    #[test]
    fn test_normalize_binding_basic() {
        assert_eq!(
            normalize_binding("POST", "/api/users", "").unwrap(),
            "POST|/api/users|"
        );
    }

    #[test]
    fn test_normalize_binding_lowercase_method() {
        assert_eq!(
            normalize_binding("post", "/api/users", "").unwrap(),
            "POST|/api/users|"
        );
    }

    #[test]
    fn test_normalize_binding_duplicate_slashes() {
        assert_eq!(
            normalize_binding("GET", "/api//users///profile", "").unwrap(),
            "GET|/api/users/profile|"
        );
    }

    #[test]
    fn test_normalize_binding_trailing_slash() {
        assert_eq!(
            normalize_binding("PUT", "/api/users/", "").unwrap(),
            "PUT|/api/users|"
        );
    }

    #[test]
    fn test_normalize_binding_root() {
        assert_eq!(normalize_binding("GET", "/", "").unwrap(), "GET|/|");
    }

    #[test]
    fn test_normalize_binding_with_query() {
        assert_eq!(
            normalize_binding("GET", "/api/users", "page=1&sort=name").unwrap(),
            "GET|/api/users|page=1&sort=name"
        );
    }

    #[test]
    fn test_normalize_binding_query_sorted() {
        assert_eq!(
            normalize_binding("GET", "/api/users", "z=3&a=1&b=2").unwrap(),
            "GET|/api/users|a=1&b=2&z=3"
        );
    }

    #[test]
    fn test_normalize_binding_from_url_basic() {
        assert_eq!(
            normalize_binding_from_url("GET", "/api/users?page=1&sort=name").unwrap(),
            "GET|/api/users|page=1&sort=name"
        );
    }

    #[test]
    fn test_normalize_binding_from_url_no_query() {
        assert_eq!(
            normalize_binding_from_url("POST", "/api/users").unwrap(),
            "POST|/api/users|"
        );
    }

    #[test]
    fn test_normalize_binding_from_url_query_sorted() {
        assert_eq!(
            normalize_binding_from_url("GET", "/api/search?z=last&a=first").unwrap(),
            "GET|/api/search|a=first&z=last"
        );
    }

    #[test]
    fn test_normalize_binding_empty_method() {
        assert!(normalize_binding("", "/api", "").is_err());
    }

    #[test]
    fn test_normalize_binding_no_leading_slash() {
        assert!(normalize_binding("GET", "api/users", "").is_err());
    }
}
