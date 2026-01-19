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

pub use canonicalize::{canonicalize_json, canonicalize_urlencoded};
pub use compare::timing_safe_equal;
pub use errors::{AshError, AshErrorCode};
pub use proof::{
    build_proof, verify_proof,
    // v2.1 functions
    generate_nonce, generate_context_id,
    derive_client_secret, build_proof_v21,
    verify_proof_v21, hash_body,
};
pub use types::{AshMode, BuildProofInput, VerifyInput};

/// Normalize a binding string to canonical form.
///
/// Bindings are in the format: `METHOD /path`
///
/// # Normalization Rules
/// - Method is uppercased
/// - Path must start with `/`
/// - Query string is excluded
/// - Duplicate slashes are collapsed
/// - Trailing slash is removed (except for root `/`)
///
/// # Example
///
/// ```rust
/// use ash_core::normalize_binding;
///
/// let binding = normalize_binding("post", "/api//users/").unwrap();
/// assert_eq!(binding, "POST /api/users");
/// ```
pub fn normalize_binding(method: &str, path: &str) -> Result<String, AshError> {
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

    // Remove query string
    let path = path.split('?').next().unwrap_or(path);

    // Collapse duplicate slashes and normalize
    let mut normalized = String::with_capacity(path.len());
    let mut prev_slash = false;

    for ch in path.chars() {
        if ch == '/' {
            if !prev_slash {
                normalized.push(ch);
            }
            prev_slash = true;
        } else {
            normalized.push(ch);
            prev_slash = false;
        }
    }

    // Remove trailing slash (except for root)
    if normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }

    Ok(format!("{} {}", method, normalized))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_binding_basic() {
        assert_eq!(
            normalize_binding("POST", "/api/users").unwrap(),
            "POST /api/users"
        );
    }

    #[test]
    fn test_normalize_binding_lowercase_method() {
        assert_eq!(
            normalize_binding("post", "/api/users").unwrap(),
            "POST /api/users"
        );
    }

    #[test]
    fn test_normalize_binding_duplicate_slashes() {
        assert_eq!(
            normalize_binding("GET", "/api//users///profile").unwrap(),
            "GET /api/users/profile"
        );
    }

    #[test]
    fn test_normalize_binding_trailing_slash() {
        assert_eq!(
            normalize_binding("PUT", "/api/users/").unwrap(),
            "PUT /api/users"
        );
    }

    #[test]
    fn test_normalize_binding_root() {
        assert_eq!(normalize_binding("GET", "/").unwrap(), "GET /");
    }

    #[test]
    fn test_normalize_binding_query_string() {
        assert_eq!(
            normalize_binding("GET", "/api/users?page=1").unwrap(),
            "GET /api/users"
        );
    }

    #[test]
    fn test_normalize_binding_empty_method() {
        assert!(normalize_binding("", "/api").is_err());
    }

    #[test]
    fn test_normalize_binding_no_leading_slash() {
        assert!(normalize_binding("GET", "api/users").is_err());
    }
}
