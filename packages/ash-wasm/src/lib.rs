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
    "ASHv2.1".to_string()
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
        assert_eq!(ash_version(), "ASHv2.1");
    }
}

// =========================================================================
// ASH v2.1 - Derived Client Secret & Cryptographic Proof (WASM Bindings)
// =========================================================================

/// Generate a cryptographically secure random nonce.
/// @param bytes - Number of bytes (default 32)
/// @returns Hex-encoded nonce
#[wasm_bindgen(js_name = "ashGenerateNonce")]
pub fn ash_generate_nonce(bytes: Option<usize>) -> String {
    ash_core::generate_nonce(bytes.unwrap_or(32))
}

/// Generate a unique context ID with "ash_" prefix.
#[wasm_bindgen(js_name = "ashGenerateContextId")]
pub fn ash_generate_context_id() -> String {
    ash_core::generate_context_id()
}

/// Derive client secret from server nonce (v2.1).
/// @param nonce - Server-side secret nonce
/// @param contextId - Context identifier  
/// @param binding - Request binding (e.g., "POST /login")
/// @returns Derived client secret (64 hex chars)
#[wasm_bindgen(js_name = "ashDeriveClientSecret")]
pub fn ash_derive_client_secret(nonce: &str, context_id: &str, binding: &str) -> String {
    ash_core::derive_client_secret(nonce, context_id, binding)
}

/// Build v2.1 cryptographic proof.
/// @param clientSecret - Derived client secret
/// @param timestamp - Request timestamp (milliseconds as string)
/// @param binding - Request binding
/// @param bodyHash - SHA-256 hash of canonical body
/// @returns Proof (64 hex chars)
#[wasm_bindgen(js_name = "ashBuildProofV21")]
pub fn ash_build_proof_v21(
    client_secret: &str,
    timestamp: &str,
    binding: &str,
    body_hash: &str,
) -> String {
    ash_core::build_proof_v21(client_secret, timestamp, binding, body_hash)
}

/// Verify v2.1 proof.
/// @param nonce - Server-side secret nonce
/// @param contextId - Context identifier
/// @param binding - Request binding
/// @param timestamp - Request timestamp
/// @param bodyHash - SHA-256 hash of canonical body
/// @param clientProof - Proof received from client
/// @returns true if proof is valid
#[wasm_bindgen(js_name = "ashVerifyProofV21")]
pub fn ash_verify_proof_v21(
    nonce: &str,
    context_id: &str,
    binding: &str,
    timestamp: &str,
    body_hash: &str,
    client_proof: &str,
) -> bool {
    ash_core::verify_proof_v21(nonce, context_id, binding, timestamp, body_hash, client_proof)
}

/// Compute SHA-256 hash of canonical body.
/// @param canonicalBody - Canonicalized request body
/// @returns SHA-256 hash (64 hex chars)
#[wasm_bindgen(js_name = "ashHashBody")]
pub fn ash_hash_body(canonical_body: &str) -> String {
    ash_core::hash_body(canonical_body)
}

// =========================================================================
// ASH v2.2 - Context Scoping WASM Bindings
// =========================================================================

/// Build v2.2 cryptographic proof with scoped fields.
/// @param clientSecret - Derived client secret
/// @param timestamp - Request timestamp (milliseconds as string)
/// @param binding - Request binding
/// @param payload - Full JSON payload
/// @param scope - Comma-separated list of fields to protect (e.g., "amount,recipient")
/// @returns Object with { proof, scopeHash }
#[wasm_bindgen(js_name = "ashBuildProofScoped")]
pub fn ash_build_proof_scoped(
    client_secret: &str,
    timestamp: &str,
    binding: &str,
    payload: &str,
    scope: &str,
) -> Result<JsValue, JsValue> {
    let scope_vec: Vec<&str> = if scope.is_empty() {
        vec![]
    } else {
        scope.split(',').collect()
    };

    let (proof, scope_hash) = ash_core::build_proof_v21_scoped(
        client_secret,
        timestamp,
        binding,
        payload,
        &scope_vec,
    ).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = serde_json::json!({
        "proof": proof,
        "scopeHash": scope_hash
    });

    Ok(JsValue::from_str(&result.to_string()))
}

/// Verify v2.2 proof with scoped fields.
/// @param nonce - Server-side secret nonce
/// @param contextId - Context identifier
/// @param binding - Request binding
/// @param timestamp - Request timestamp
/// @param payload - Full JSON payload
/// @param scope - Comma-separated list of protected fields
/// @param scopeHash - Scope hash from client
/// @param clientProof - Proof received from client
/// @returns true if proof is valid
#[wasm_bindgen(js_name = "ashVerifyProofScoped")]
pub fn ash_verify_proof_scoped(
    nonce: &str,
    context_id: &str,
    binding: &str,
    timestamp: &str,
    payload: &str,
    scope: &str,
    scope_hash: &str,
    client_proof: &str,
) -> Result<bool, JsValue> {
    let scope_vec: Vec<&str> = if scope.is_empty() {
        vec![]
    } else {
        scope.split(',').collect()
    };

    ash_core::verify_proof_v21_scoped(
        nonce,
        context_id,
        binding,
        timestamp,
        payload,
        &scope_vec,
        scope_hash,
        client_proof,
    ).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Hash scoped payload fields.
/// @param payload - Full JSON payload
/// @param scope - Comma-separated list of fields to hash
/// @returns SHA-256 hash of scoped fields
#[wasm_bindgen(js_name = "ashHashScopedBody")]
pub fn ash_hash_scoped_body(payload: &str, scope: &str) -> Result<String, JsValue> {
    let scope_vec: Vec<&str> = if scope.is_empty() {
        vec![]
    } else {
        scope.split(',').collect()
    };

    ash_core::hash_scoped_body(payload, &scope_vec)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

// =========================================================================
// ASH v2.3 - Unified Proof Functions (Scoping + Chaining) WASM Bindings
// =========================================================================

/// Hash a proof for chaining purposes.
/// @param proof - Proof to hash
/// @returns SHA-256 hash of the proof (64 hex chars)
#[wasm_bindgen(js_name = "ashHashProof")]
pub fn ash_hash_proof(proof: &str) -> String {
    ash_core::hash_proof(proof)
}

/// Build unified v2.3 cryptographic proof with optional scoping and chaining.
/// @param clientSecret - Derived client secret
/// @param timestamp - Request timestamp (milliseconds as string)
/// @param binding - Request binding
/// @param payload - Full JSON payload
/// @param scope - Comma-separated list of fields to protect (empty for full payload)
/// @param previousProof - Previous proof in chain (empty or null for no chaining)
/// @returns Object with { proof, scopeHash, chainHash }
#[wasm_bindgen(js_name = "ashBuildProofUnified")]
pub fn ash_build_proof_unified(
    client_secret: &str,
    timestamp: &str,
    binding: &str,
    payload: &str,
    scope: &str,
    previous_proof: Option<String>,
) -> Result<JsValue, JsValue> {
    let scope_vec: Vec<&str> = if scope.is_empty() {
        vec![]
    } else {
        scope.split(',').collect()
    };

    let prev_proof = previous_proof.as_deref().filter(|s| !s.is_empty());

    let result = ash_core::build_proof_v21_unified(
        client_secret,
        timestamp,
        binding,
        payload,
        &scope_vec,
        prev_proof,
    ).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let json_result = serde_json::json!({
        "proof": result.proof,
        "scopeHash": result.scope_hash,
        "chainHash": result.chain_hash
    });

    Ok(JsValue::from_str(&json_result.to_string()))
}

/// Verify unified v2.3 proof with optional scoping and chaining.
/// @param nonce - Server-side secret nonce
/// @param contextId - Context identifier
/// @param binding - Request binding
/// @param timestamp - Request timestamp
/// @param payload - Full JSON payload
/// @param clientProof - Proof received from client
/// @param scope - Comma-separated list of protected fields (empty for full payload)
/// @param scopeHash - Scope hash from client (empty if no scoping)
/// @param previousProof - Previous proof in chain (empty or null if no chaining)
/// @param chainHash - Chain hash from client (empty if no chaining)
/// @returns true if proof is valid
#[wasm_bindgen(js_name = "ashVerifyProofUnified")]
pub fn ash_verify_proof_unified(
    nonce: &str,
    context_id: &str,
    binding: &str,
    timestamp: &str,
    payload: &str,
    client_proof: &str,
    scope: &str,
    scope_hash: &str,
    previous_proof: Option<String>,
    chain_hash: &str,
) -> Result<bool, JsValue> {
    let scope_vec: Vec<&str> = if scope.is_empty() {
        vec![]
    } else {
        scope.split(',').collect()
    };

    let prev_proof = previous_proof.as_deref().filter(|s| !s.is_empty());

    ash_core::verify_proof_v21_unified(
        nonce,
        context_id,
        binding,
        timestamp,
        payload,
        client_proof,
        &scope_vec,
        scope_hash,
        prev_proof,
        chain_hash,
    ).map_err(|e| JsValue::from_str(&e.to_string()))
}
