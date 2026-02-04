//! API Surface Tests for ASH WASM bindings.
//! These tests verify that all exported functions work correctly and have expected signatures.

use ash_core;

// ============================================================================
// CANONICALIZATION API TESTS
// ============================================================================

#[test]
fn api_canonicalize_json_basic() {
    let result = ash_core::ash_canonicalize_json(r#"{"b":2,"a":1}"#);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), r#"{"a":1,"b":2}"#);
}

#[test]
fn api_canonicalize_json_error() {
    let result = ash_core::ash_canonicalize_json("{invalid}");
    assert!(result.is_err());
}

#[test]
fn api_canonicalize_urlencoded_basic() {
    let result = ash_core::ash_canonicalize_urlencoded("b=2&a=1");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "a=1&b=2");
}

#[test]
fn api_canonicalize_urlencoded_empty() {
    let result = ash_core::ash_canonicalize_urlencoded("");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "");
}

#[test]
fn api_canonicalize_query_basic() {
    let result = ash_core::ash_canonicalize_query("z=3&a=1");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "a=1&z=3");
}

#[test]
fn api_canonicalize_query_with_question_mark() {
    let result = ash_core::ash_canonicalize_query("?b=2&a=1");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "a=1&b=2");
}

// ============================================================================
// BINDING NORMALIZATION API TESTS
// ============================================================================

#[test]
fn api_normalize_binding_basic() {
    let result = ash_core::ash_normalize_binding("GET", "/api", "");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "GET|/api|");
}

#[test]
fn api_normalize_binding_with_query() {
    let result = ash_core::ash_normalize_binding("POST", "/api", "a=1");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "POST|/api|a=1");
}

#[test]
fn api_normalize_binding_method_case() {
    let result = ash_core::ash_normalize_binding("post", "/api", "");
    assert!(result.is_ok());
    assert!(result.unwrap().starts_with("POST"));
}

#[test]
fn api_normalize_binding_from_url_basic() {
    let result = ash_core::ash_normalize_binding_from_url("GET", "/api?a=1");
    assert!(result.is_ok());
    assert!(result.unwrap().contains("a=1"));
}

#[test]
fn api_normalize_binding_from_url_no_query() {
    let result = ash_core::ash_normalize_binding_from_url("GET", "/api");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "GET|/api|");
}

// ============================================================================
// HASH API TESTS
// ============================================================================

#[test]
fn api_hash_body_basic() {
    let result = ash_core::ash_hash_body("test");
    assert_eq!(result.len(), 64);
    assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn api_hash_body_empty() {
    let result = ash_core::ash_hash_body("");
    assert_eq!(result.len(), 64);
    assert_eq!(result, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

#[test]
fn api_hash_body_deterministic() {
    let hash1 = ash_core::ash_hash_body("test");
    let hash2 = ash_core::ash_hash_body("test");
    assert_eq!(hash1, hash2);
}

#[test]
fn api_hash_proof_basic() {
    let proof = "a".repeat(64);
    let result = ash_core::ash_hash_proof(&proof);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 64);
}

#[test]
fn api_hash_proof_empty_error() {
    let result = ash_core::ash_hash_proof("");
    assert!(result.is_err());
}

#[test]
fn api_hash_scoped_body_basic() {
    let result = ash_core::ash_hash_scoped_body(r#"{"a":1,"b":2}"#, &["a"]);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 64);
}

#[test]
fn api_hash_scope_basic() {
    let result = ash_core::ash_hash_scope(&["field1", "field2"]);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 64);
}

// ============================================================================
// GENERATION API TESTS
// ============================================================================

#[test]
fn api_generate_nonce_default() {
    let result = ash_core::ash_generate_nonce(32);
    assert!(result.is_ok());
    let nonce = result.unwrap();
    assert_eq!(nonce.len(), 64);
    assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn api_generate_nonce_custom_size() {
    let result = ash_core::ash_generate_nonce(16);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 32);
}

#[test]
fn api_generate_context_id_format() {
    let result = ash_core::ash_generate_context_id();
    assert!(result.is_ok());
    let ctx = result.unwrap();
    assert!(ctx.starts_with("ash_"));
}

#[test]
fn api_generate_context_id_unique() {
    let ctx1 = ash_core::ash_generate_context_id().unwrap();
    let ctx2 = ash_core::ash_generate_context_id().unwrap();
    assert_ne!(ctx1, ctx2);
}

// ============================================================================
// CLIENT SECRET DERIVATION API TESTS
// ============================================================================

#[test]
fn api_derive_client_secret_basic() {
    let nonce = "a".repeat(64);
    let result = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/api|");
    assert!(result.is_ok());
    let secret = result.unwrap();
    assert_eq!(secret.len(), 64);
    assert!(secret.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn api_derive_client_secret_deterministic() {
    let nonce = "a".repeat(64);
    let secret1 = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/api|").unwrap();
    let secret2 = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/api|").unwrap();
    assert_eq!(secret1, secret2);
}

#[test]
fn api_derive_client_secret_error_empty_nonce() {
    let result = ash_core::ash_derive_client_secret("", "ctx", "POST|/api|");
    assert!(result.is_err());
}

#[test]
fn api_derive_client_secret_error_short_nonce() {
    let result = ash_core::ash_derive_client_secret("abc", "ctx", "POST|/api|");
    assert!(result.is_err());
}

// ============================================================================
// BUILD PROOF API TESTS
// ============================================================================

#[test]
fn api_build_proof_basic() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/api|").unwrap();
    let body_hash = ash_core::ash_hash_body("{}");

    let result = ash_core::ash_build_proof(&secret, "12345", "POST|/api|", &body_hash);
    assert!(result.is_ok());
    let proof = result.unwrap();
    assert_eq!(proof.len(), 64);
}

#[test]
fn api_build_proof_deterministic() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/api|").unwrap();
    let body_hash = ash_core::ash_hash_body("{}");

    let proof1 = ash_core::ash_build_proof(&secret, "12345", "POST|/api|", &body_hash).unwrap();
    let proof2 = ash_core::ash_build_proof(&secret, "12345", "POST|/api|", &body_hash).unwrap();
    assert_eq!(proof1, proof2);
}

#[test]
fn api_build_proof_scoped_basic() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/api|").unwrap();

    let result = ash_core::ash_build_proof_scoped(&secret, "12345", "POST|/api|", r#"{"a":1,"b":2}"#, &["a"]);
    assert!(result.is_ok());
    let (proof, scope_hash) = result.unwrap();
    assert_eq!(proof.len(), 64);
    assert_eq!(scope_hash.len(), 64);
}

#[test]
fn api_build_proof_unified_basic() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/api|").unwrap();

    let result = ash_core::ash_build_proof_unified(&secret, "12345", "POST|/api|", r#"{"a":1}"#, &[], None);
    assert!(result.is_ok());
    let unified = result.unwrap();
    assert_eq!(unified.proof.len(), 64);
}

#[test]
fn api_build_proof_unified_with_scope() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/api|").unwrap();

    let result = ash_core::ash_build_proof_unified(&secret, "12345", "POST|/api|", r#"{"a":1,"b":2}"#, &["a"], None);
    assert!(result.is_ok());
    let unified = result.unwrap();
    assert!(!unified.scope_hash.is_empty());
}

#[test]
fn api_build_proof_unified_with_chain() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/api|").unwrap();
    let prev_proof = "b".repeat(64);

    let result = ash_core::ash_build_proof_unified(&secret, "12345", "POST|/api|", r#"{"a":1}"#, &[], Some(&prev_proof));
    assert!(result.is_ok());
    let unified = result.unwrap();
    assert!(!unified.chain_hash.is_empty());
}

// ============================================================================
// VERIFY PROOF API TESTS
// ============================================================================

#[test]
fn api_verify_proof_valid() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let timestamp = "12345";
    let body_hash = ash_core::ash_hash_body("{}");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    let result = ash_core::ash_verify_proof(&nonce, ctx, binding, timestamp, &body_hash, &proof);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn api_verify_proof_invalid() {
    let nonce = "a".repeat(64);
    let body_hash = ash_core::ash_hash_body("{}");
    let wrong_proof = "0".repeat(64);

    let result = ash_core::ash_verify_proof(&nonce, "ctx", "POST|/api|", "12345", &body_hash, &wrong_proof);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn api_verify_proof_scoped_valid() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let timestamp = "12345";
    let payload = r#"{"a":1,"b":2}"#;
    let scope = &["a"];

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, payload, scope).unwrap();

    let result = ash_core::ash_verify_proof_scoped(&nonce, ctx, binding, timestamp, payload, scope, &scope_hash, &proof);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn api_verify_proof_unified_valid() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let timestamp = "12345";
    let payload = r#"{"a":1}"#;

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let unified = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], None).unwrap();

    let result = ash_core::ash_verify_proof_unified(
        &nonce, ctx, binding, timestamp, payload, &unified.proof,
        &[], "", None, ""
    );
    assert!(result.is_ok());
    assert!(result.unwrap());
}

// ============================================================================
// TIMING SAFE COMPARISON API TESTS
// ============================================================================

#[test]
fn api_timing_safe_equal_same() {
    assert!(ash_core::ash_timing_safe_equal(b"test", b"test"));
}

#[test]
fn api_timing_safe_equal_different() {
    assert!(!ash_core::ash_timing_safe_equal(b"test", b"other"));
}

#[test]
fn api_timing_safe_equal_different_lengths() {
    assert!(!ash_core::ash_timing_safe_equal(b"short", b"longer"));
}

#[test]
fn api_timing_safe_equal_empty() {
    assert!(ash_core::ash_timing_safe_equal(b"", b""));
}

// ============================================================================
// EXTRACT SCOPED FIELDS API TESTS
// ============================================================================

#[test]
fn api_extract_scoped_fields_basic() {
    let payload: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":2,"c":3}"#).unwrap();
    let result = ash_core::ash_extract_scoped_fields(&payload, &["a", "b"]);
    assert!(result.is_ok());
    let extracted = result.unwrap();
    assert!(extracted.get("a").is_some());
    assert!(extracted.get("b").is_some());
    assert!(extracted.get("c").is_none());
}

#[test]
fn api_extract_scoped_fields_nested() {
    let payload: serde_json::Value = serde_json::from_str(r#"{"user":{"name":"test","age":30}}"#).unwrap();
    let result = ash_core::ash_extract_scoped_fields(&payload, &["user.name"]);
    assert!(result.is_ok());
}

#[test]
fn api_extract_scoped_fields_empty_scope() {
    let payload: serde_json::Value = serde_json::from_str(r#"{"a":1}"#).unwrap();
    let result = ash_core::ash_extract_scoped_fields(&payload, &[]);
    assert!(result.is_ok());
    // Empty scope returns full payload
    let extracted = result.unwrap();
    assert!(extracted.get("a").is_some());
}

// ============================================================================
// TIMESTAMP VALIDATION API TESTS
// ============================================================================

#[test]
fn api_validate_timestamp_current() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let result = ash_core::ash_validate_timestamp(&now.to_string(), 300, 60);
    assert!(result.is_ok());
}

#[test]
fn api_validate_timestamp_expired() {
    // Timestamp from 2001 - definitely expired
    let result = ash_core::ash_validate_timestamp("1000000000", 300, 60);
    assert!(result.is_err());
}

#[test]
fn api_validate_timestamp_invalid() {
    let result = ash_core::ash_validate_timestamp("not_a_number", 300, 60);
    assert!(result.is_err());
}

// ============================================================================
// COMPREHENSIVE API WORKFLOW TEST
// ============================================================================

#[test]
fn api_complete_workflow() {
    // 1. Generate nonce and context ID
    let nonce = ash_core::ash_generate_nonce(32).unwrap();
    let ctx = ash_core::ash_generate_context_id().unwrap();

    // 2. Prepare request data
    let method = "POST";
    let path = "/api/transfer";
    let query = "confirm=true";
    let payload = r#"{"amount":100,"recipient":"user123"}"#;
    let timestamp = "1700000000"; // Unix timestamp in seconds

    // 3. Normalize binding
    let binding = ash_core::ash_normalize_binding(method, path, query).unwrap();

    // 4. Canonicalize and hash body
    let canonical = ash_core::ash_canonicalize_json(payload).unwrap();
    let body_hash = ash_core::ash_hash_body(&canonical);

    // 5. Derive client secret
    let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, &binding).unwrap();

    // 6. Build proof
    let proof = ash_core::ash_build_proof(&secret, timestamp, &binding, &body_hash).unwrap();

    // 7. Verify proof
    let valid = ash_core::ash_verify_proof(&nonce, &ctx, &binding, timestamp, &body_hash, &proof).unwrap();
    assert!(valid);

    // 8. Verify with timing-safe comparison
    let proof_clone = proof.clone();
    assert!(ash_core::ash_timing_safe_equal(proof.as_bytes(), proof_clone.as_bytes()));
}

#[test]
fn api_complete_scoped_workflow() {
    let nonce = ash_core::ash_generate_nonce(32).unwrap();
    let ctx = ash_core::ash_generate_context_id().unwrap();
    let binding = "POST|/api/payment|";
    let timestamp = "1700000000"; // Unix timestamp in seconds
    let payload = r#"{"amount":100,"currency":"USD","note":"optional"}"#;
    let scope = &["amount", "currency"];

    let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, binding).unwrap();
    let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, payload, scope).unwrap();

    let valid = ash_core::ash_verify_proof_scoped(&nonce, &ctx, binding, timestamp, payload, scope, &scope_hash, &proof).unwrap();
    assert!(valid);
}

#[test]
fn api_complete_unified_workflow() {
    let nonce = ash_core::ash_generate_nonce(32).unwrap();
    let ctx = ash_core::ash_generate_context_id().unwrap();

    // Step 1
    let binding1 = "POST|/api/init|";
    let payload1 = r#"{"action":"start"}"#;
    let timestamp1 = "1700000000"; // Unix timestamp in seconds

    let secret1 = ash_core::ash_derive_client_secret(&nonce, &ctx, binding1).unwrap();
    let result1 = ash_core::ash_build_proof_unified(&secret1, timestamp1, binding1, payload1, &[], None).unwrap();

    let valid1 = ash_core::ash_verify_proof_unified(&nonce, &ctx, binding1, timestamp1, payload1, &result1.proof, &[], "", None, "").unwrap();
    assert!(valid1);

    // Step 2 with chain
    let binding2 = "POST|/api/confirm|";
    let payload2 = r#"{"amount":100,"confirmed":true}"#;
    let timestamp2 = "1700000001"; // 1 second later
    let scope2 = &["amount", "confirmed"];

    let secret2 = ash_core::ash_derive_client_secret(&nonce, &ctx, binding2).unwrap();
    let result2 = ash_core::ash_build_proof_unified(&secret2, timestamp2, binding2, payload2, scope2, Some(&result1.proof)).unwrap();

    let valid2 = ash_core::ash_verify_proof_unified(
        &nonce, &ctx, binding2, timestamp2, payload2, &result2.proof,
        scope2, &result2.scope_hash, Some(&result1.proof), &result2.chain_hash
    ).unwrap();
    assert!(valid2);
}
