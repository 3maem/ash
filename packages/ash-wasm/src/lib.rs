//! # ASH WASM
//!
//! WebAssembly bindings for ASH (Anti-tamper Security Hash).
//!
//! This module provides universal access to ASH functionality from any
//! WASM-compatible environment: browsers, Node.js, Deno, Python, Go, .NET, PHP.
//!
//! ## Usage (JavaScript/TypeScript)
//!
//! ```javascript
//! import * as ash from '@3meam/ash';
//!
//! // Canonicalize JSON
//! const canonical = ash.canonicalizeJson('{"z":1,"a":2}');
//! // => '{"a":2,"z":1}'
//!
//! // Build proof
//! const proof = ash.buildProof('balanced', 'POST /api/update', 'ctx123', null, canonical);
//!
//! // Verify proof
//! const isValid = ash.verifyProof(expectedProof, actualProof);
//! ```

use wasm_bindgen::prelude::*;

// Initialize panic hook for better error messages in development
#[cfg(feature = "console_error_panic_hook")]
pub fn set_panic_hook() {
    console_error_panic_hook::set_once();
}

/// Initialize the ASH WASM module.
///
/// Call this once before using other functions.
/// Sets up panic hooks for better error messages.
#[wasm_bindgen(js_name = "ashInit")]
pub fn ash_init() {
    #[cfg(feature = "console_error_panic_hook")]
    set_panic_hook();
}

/// Canonicalize a JSON string to deterministic form.
///
/// # Canonicalization Rules
/// - Object keys sorted lexicographically
/// - No whitespace
/// - Unicode NFC normalized
/// - Numbers normalized (no -0, no trailing zeros)
///
/// @param input - JSON string to canonicalize
/// @returns Canonical JSON string
/// @throws Error if input is not valid JSON
#[wasm_bindgen(js_name = "ashCanonicalizeJson")]
pub fn ash_canonicalize_json(input: &str) -> Result<String, JsValue> {
    ash_core::canonicalize_json(input).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Canonicalize URL-encoded form data to deterministic form.
///
/// # Canonicalization Rules
/// - Key-value pairs sorted by key
/// - Percent-decoded and re-encoded consistently
/// - Unicode NFC normalized
///
/// @param input - URL-encoded string to canonicalize
/// @returns Canonical URL-encoded string
/// @throws Error if input cannot be canonicalized
#[wasm_bindgen(js_name = "ashCanonicalizeUrlencoded")]
pub fn ash_canonicalize_urlencoded(input: &str) -> Result<String, JsValue> {
    ash_core::canonicalize_urlencoded(input).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Build a cryptographic proof for request integrity.
///
/// The proof binds the payload to a specific context and endpoint,
/// preventing tampering and replay attacks.
///
/// @param mode - Security mode: "minimal", "balanced", or "strict"
/// @param binding - Endpoint binding: "METHOD /path"
/// @param contextId - Context ID from server
/// @param nonce - Optional nonce for server-assisted mode (null if not used)
/// @param canonicalPayload - Canonicalized payload string
/// @returns Base64URL-encoded proof string
/// @throws Error if mode is invalid
#[wasm_bindgen(js_name = "ashBuildProof")]
pub fn ash_build_proof(
    mode: &str,
    binding: &str,
    context_id: &str,
    nonce: Option<String>,
    canonical_payload: &str,
) -> Result<String, JsValue> {
    let ash_mode: ash_core::AshMode = mode
        .parse()
        .map_err(|e: ash_core::AshError| JsValue::from_str(&e.to_string()))?;

    ash_core::build_proof(
        ash_mode,
        binding,
        context_id,
        nonce.as_deref(),
        canonical_payload,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Verify that two proofs match using constant-time comparison.
///
/// This function is safe against timing attacks - the comparison
/// takes the same amount of time regardless of where differences occur.
///
/// @param expected - Expected proof (computed by server)
/// @param actual - Actual proof (received from client)
/// @returns true if proofs match, false otherwise
#[wasm_bindgen(js_name = "ashVerifyProof")]
pub fn ash_verify_proof(expected: &str, actual: &str) -> bool {
    ash_core::timing_safe_equal(expected.as_bytes(), actual.as_bytes())
}

/// Normalize a binding string to canonical form.
///
/// Bindings are in the format: "METHOD /path"
///
/// # Normalization Rules
/// - Method uppercased
/// - Path starts with /
/// - Query string excluded
/// - Duplicate slashes collapsed
/// - Trailing slash removed
///
/// @param method - HTTP method (GET, POST, etc.)
/// @param path - URL path
/// @returns Canonical binding string
/// @throws Error if method is empty or path doesn't start with /
#[wasm_bindgen(js_name = "ashNormalizeBinding")]
pub fn ash_normalize_binding(method: &str, path: &str) -> Result<String, JsValue> {
    ash_core::normalize_binding(method, path).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Constant-time comparison of two strings.
///
/// Use this for comparing any security-sensitive values.
///
/// @param a - First string
/// @param b - Second string
/// @returns true if strings are equal, false otherwise
#[wasm_bindgen(js_name = "ashTimingSafeEqual")]
pub fn ash_timing_safe_equal(a: &str, b: &str) -> bool {
    ash_core::timing_safe_equal(a.as_bytes(), b.as_bytes())
}

/// Get the ASH protocol version.
///
/// @returns Version string (e.g., "ASHv1")
#[wasm_bindgen(js_name = "ashVersion")]
pub fn ash_version() -> String {
    "ASHv1".to_string()
}

/// Get the library version.
///
/// @returns Semantic version string
#[wasm_bindgen(js_name = "ashLibraryVersion")]
pub fn ash_library_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// Re-export for convenience without prefix (backwards compatibility)
// These will be deprecated in future versions

#[wasm_bindgen(js_name = "canonicalizeJson")]
pub fn canonicalize_json(input: &str) -> Result<String, JsValue> {
    ash_canonicalize_json(input)
}

#[wasm_bindgen(js_name = "canonicalizeUrlencoded")]
pub fn canonicalize_urlencoded(input: &str) -> Result<String, JsValue> {
    ash_canonicalize_urlencoded(input)
}

#[wasm_bindgen(js_name = "buildProof")]
pub fn build_proof(
    mode: &str,
    binding: &str,
    context_id: &str,
    nonce: Option<String>,
    canonical_payload: &str,
) -> Result<String, JsValue> {
    ash_build_proof(mode, binding, context_id, nonce, canonical_payload)
}

#[wasm_bindgen(js_name = "verifyProof")]
pub fn verify_proof(expected: &str, actual: &str) -> bool {
    ash_verify_proof(expected, actual)
}

#[wasm_bindgen(js_name = "normalizeBinding")]
pub fn normalize_binding(method: &str, path: &str) -> Result<String, JsValue> {
    ash_normalize_binding(method, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_json() {
        let result = ash_canonicalize_json(r#"{"z":1,"a":2}"#).unwrap();
        assert_eq!(result, r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn test_canonicalize_urlencoded() {
        let result = ash_canonicalize_urlencoded("z=1&a=2").unwrap();
        assert_eq!(result, "a=2&z=1");
    }

    #[test]
    fn test_build_and_verify_proof() {
        let proof1 =
            ash_build_proof("balanced", "POST /api/test", "ctx123", None, r#"{"a":1}"#).unwrap();

        let proof2 =
            ash_build_proof("balanced", "POST /api/test", "ctx123", None, r#"{"a":1}"#).unwrap();

        assert!(ash_verify_proof(&proof1, &proof2));
    }

    #[test]
    fn test_normalize_binding() {
        let result = ash_normalize_binding("post", "/api//test/").unwrap();
        assert_eq!(result, "POST /api/test");
    }

    #[test]
    fn test_version() {
        assert_eq!(ash_version(), "ASHv1");
    }
}
