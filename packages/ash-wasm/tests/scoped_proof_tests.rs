//! Comprehensive scoped proof tests for ASH WASM bindings.
//! These tests use ash_core directly since wasm_bindgen functions can't run on native targets.

use ash_core;

// ============================================================================
// HASH SCOPED BODY TESTS
// ============================================================================

#[test]
fn hash_scoped_body_single_field() {
    let payload = r#"{"amount":100,"recipient":"alice","memo":"test"}"#;
    let hash = ash_core::ash_hash_scoped_body(payload, &["amount"]).unwrap();
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn hash_scoped_body_multiple_fields() {
    let payload = r#"{"amount":100,"recipient":"alice","memo":"test"}"#;
    let hash = ash_core::ash_hash_scoped_body(payload, &["amount", "recipient"]).unwrap();
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_scoped_body_all_fields() {
    let payload = r#"{"amount":100,"recipient":"alice","memo":"test"}"#;
    let hash = ash_core::ash_hash_scoped_body(payload, &["amount", "recipient", "memo"]).unwrap();
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_scoped_body_is_deterministic() {
    let payload = r#"{"amount":100,"recipient":"alice"}"#;
    let hash1 = ash_core::ash_hash_scoped_body(payload, &["amount"]).unwrap();
    let hash2 = ash_core::ash_hash_scoped_body(payload, &["amount"]).unwrap();
    assert_eq!(hash1, hash2);
}

#[test]
fn hash_scoped_body_different_fields_different_hashes() {
    let payload = r#"{"amount":100,"recipient":"alice"}"#;
    let hash1 = ash_core::ash_hash_scoped_body(payload, &["amount"]).unwrap();
    let hash2 = ash_core::ash_hash_scoped_body(payload, &["recipient"]).unwrap();
    assert_ne!(hash1, hash2);
}

#[test]
fn hash_scoped_body_order_independent() {
    let payload = r#"{"amount":100,"recipient":"alice"}"#;
    let hash1 = ash_core::ash_hash_scoped_body(payload, &["amount", "recipient"]).unwrap();
    let hash2 = ash_core::ash_hash_scoped_body(payload, &["recipient", "amount"]).unwrap();
    assert_eq!(hash1, hash2);
}

#[test]
fn hash_scoped_body_nested_field() {
    let payload = r#"{"user":{"name":"alice","age":30},"action":"login"}"#;
    let hash = ash_core::ash_hash_scoped_body(payload, &["user.name"]).unwrap();
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_scoped_body_deeply_nested() {
    let payload = r#"{"a":{"b":{"c":{"d":"value"}}}}"#;
    let hash = ash_core::ash_hash_scoped_body(payload, &["a.b.c.d"]).unwrap();
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_scoped_body_handles_unicode() {
    let payload = r#"{"name":"日本語","emoji":"🎉"}"#;
    let hash = ash_core::ash_hash_scoped_body(payload, &["name"]).unwrap();
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_scoped_body_handles_numbers() {
    let payload = r#"{"int":42,"float":3.14,"negative":-100}"#;
    let hash = ash_core::ash_hash_scoped_body(payload, &["int", "float"]).unwrap();
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_scoped_body_handles_boolean() {
    let payload = r#"{"active":true,"deleted":false}"#;
    let hash = ash_core::ash_hash_scoped_body(payload, &["active"]).unwrap();
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_scoped_body_handles_null() {
    let payload = r#"{"value":null,"other":"test"}"#;
    let hash = ash_core::ash_hash_scoped_body(payload, &["value"]).unwrap();
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_scoped_body_handles_array_field() {
    let payload = r#"{"items":[1,2,3],"count":3}"#;
    let hash = ash_core::ash_hash_scoped_body(payload, &["items"]).unwrap();
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_scoped_body_handles_object_field() {
    let payload = r#"{"config":{"timeout":30,"retries":3}}"#;
    let hash = ash_core::ash_hash_scoped_body(payload, &["config"]).unwrap();
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_scoped_body_empty_scope_returns_full_hash() {
    let payload = r#"{"a":1,"b":2}"#;
    let scoped_hash = ash_core::ash_hash_scoped_body(payload, &[]).unwrap();
    let full_hash = ash_core::ash_hash_body(&ash_core::ash_canonicalize_json(payload).unwrap());
    assert_eq!(scoped_hash, full_hash);
}

// ============================================================================
// EXTRACT SCOPED FIELDS TESTS
// ============================================================================

#[test]
fn extract_scoped_fields_single_field() {
    let payload: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":2,"c":3}"#).unwrap();
    let result = ash_core::ash_extract_scoped_fields(&payload, &["a"]).unwrap();
    assert_eq!(result.get("a").unwrap(), 1);
    assert!(result.get("b").is_none());
}

#[test]
fn extract_scoped_fields_multiple_fields() {
    let payload: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":2,"c":3}"#).unwrap();
    let result = ash_core::ash_extract_scoped_fields(&payload, &["a", "b"]).unwrap();
    assert_eq!(result.get("a").unwrap(), 1);
    assert_eq!(result.get("b").unwrap(), 2);
    assert!(result.get("c").is_none());
}

#[test]
fn extract_scoped_fields_nested_field() {
    let payload: serde_json::Value = serde_json::from_str(r#"{"user":{"name":"alice","age":30}}"#).unwrap();
    let result = ash_core::ash_extract_scoped_fields(&payload, &["user.name"]).unwrap();
    let user = result.get("user").unwrap().as_object().unwrap();
    assert_eq!(user.get("name").unwrap(), "alice");
    assert!(user.get("age").is_none());
}

#[test]
fn extract_scoped_fields_deeply_nested() {
    let payload: serde_json::Value = serde_json::from_str(r#"{"a":{"b":{"c":{"d":"value","e":"other"}}}}"#).unwrap();
    let result = ash_core::ash_extract_scoped_fields(&payload, &["a.b.c.d"]).unwrap();
    let a = result.get("a").unwrap().as_object().unwrap();
    let b = a.get("b").unwrap().as_object().unwrap();
    let c = b.get("c").unwrap().as_object().unwrap();
    assert_eq!(c.get("d").unwrap(), "value");
    assert!(c.get("e").is_none());
}

#[test]
fn extract_scoped_fields_preserves_types() {
    let payload: serde_json::Value = serde_json::from_str(r#"{"num":42,"str":"hello","bool":true,"null":null}"#).unwrap();
    let result = ash_core::ash_extract_scoped_fields(&payload, &["num", "str", "bool", "null"]).unwrap();
    assert!(result.get("num").unwrap().is_i64());
    assert!(result.get("str").unwrap().is_string());
    assert!(result.get("bool").unwrap().is_boolean());
    assert!(result.get("null").unwrap().is_null());
}

#[test]
fn extract_scoped_fields_array_field() {
    let payload: serde_json::Value = serde_json::from_str(r#"{"items":[1,2,3],"other":"data"}"#).unwrap();
    let result = ash_core::ash_extract_scoped_fields(&payload, &["items"]).unwrap();
    assert!(result.get("items").unwrap().is_array());
    assert!(result.get("other").is_none());
}

#[test]
fn extract_scoped_fields_object_field() {
    let payload: serde_json::Value = serde_json::from_str(r#"{"config":{"a":1,"b":2},"status":"ok"}"#).unwrap();
    let result = ash_core::ash_extract_scoped_fields(&payload, &["config"]).unwrap();
    assert!(result.get("config").unwrap().is_object());
    assert!(result.get("status").is_none());
}

// ============================================================================
// BUILD PROOF SCOPED TESTS
// ============================================================================

#[test]
fn build_proof_scoped_returns_proof_and_scope_hash() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100,"recipient":"alice"}"#;

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, payload, &["amount"]).unwrap();

    assert_eq!(proof.len(), 64);
    assert_eq!(scope_hash.len(), 64);
    assert!(proof.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(scope_hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn build_proof_scoped_is_deterministic() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100,"recipient":"alice"}"#;

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let (proof1, hash1) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, payload, &["amount"]).unwrap();
    let (proof2, hash2) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, payload, &["amount"]).unwrap();

    assert_eq!(proof1, proof2);
    assert_eq!(hash1, hash2);
}

#[test]
fn build_proof_scoped_different_scopes_different_proofs() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100,"recipient":"alice"}"#;

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let (proof1, hash1) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, payload, &["amount"]).unwrap();
    let (proof2, hash2) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, payload, &["recipient"]).unwrap();

    assert_ne!(proof1, proof2);
    assert_ne!(hash1, hash2);
}

#[test]
fn build_proof_scoped_handles_empty_scope() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100}"#;

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, payload, &[]).unwrap();

    assert_eq!(proof.len(), 64);
    // When scope is empty, scope_hash is empty (no fields to hash)
    assert!(scope_hash.is_empty());
}

#[test]
fn build_proof_scoped_handles_nested_fields() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"user":{"name":"alice","age":30},"action":"update"}"#;

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, payload, &["user.name"]).unwrap();

    assert_eq!(proof.len(), 64);
    assert_eq!(scope_hash.len(), 64);
}

#[test]
fn build_proof_scoped_stress_50() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_stress";

    for i in 0..50 {
        let binding = format!("POST|/api/resource/{}|", i);
        let timestamp = format!("{}", 1000000000 + i);
        let payload = format!(r#"{{"amount":{},"recipient":"user_{}"}}"#, i * 100, i);

        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, &binding).unwrap();
        let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, &timestamp, &binding, &payload, &["amount"]).unwrap();

        assert_eq!(proof.len(), 64);
        assert_eq!(scope_hash.len(), 64);
    }
}

// ============================================================================
// VERIFY PROOF SCOPED TESTS
// ============================================================================

#[test]
fn verify_proof_scoped_valid_proof() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100,"recipient":"alice"}"#;
    let scope = &["amount"];

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, payload, scope).unwrap();

    let result = ash_core::ash_verify_proof_scoped(&nonce, ctx, binding, timestamp, payload, scope, &scope_hash, &proof).unwrap();
    assert!(result);
}

#[test]
fn verify_proof_scoped_wrong_nonce() {
    let nonce = "a".repeat(64);
    let wrong_nonce = "b".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100,"recipient":"alice"}"#;
    let scope = &["amount"];

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, payload, scope).unwrap();

    let result = ash_core::ash_verify_proof_scoped(&wrong_nonce, ctx, binding, timestamp, payload, scope, &scope_hash, &proof).unwrap();
    assert!(!result);
}

#[test]
fn verify_proof_scoped_wrong_context() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let wrong_ctx = "ctx_wrong";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100,"recipient":"alice"}"#;
    let scope = &["amount"];

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, payload, scope).unwrap();

    let result = ash_core::ash_verify_proof_scoped(&nonce, wrong_ctx, binding, timestamp, payload, scope, &scope_hash, &proof).unwrap();
    assert!(!result);
}

#[test]
fn verify_proof_scoped_wrong_binding() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let wrong_binding = "GET|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100,"recipient":"alice"}"#;
    let scope = &["amount"];

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, payload, scope).unwrap();

    let result = ash_core::ash_verify_proof_scoped(&nonce, ctx, wrong_binding, timestamp, payload, scope, &scope_hash, &proof).unwrap();
    assert!(!result);
}

#[test]
fn verify_proof_scoped_wrong_timestamp() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let wrong_timestamp = "1234567891";
    let payload = r#"{"amount":100,"recipient":"alice"}"#;
    let scope = &["amount"];

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, payload, scope).unwrap();

    let result = ash_core::ash_verify_proof_scoped(&nonce, ctx, binding, wrong_timestamp, payload, scope, &scope_hash, &proof).unwrap();
    assert!(!result);
}

#[test]
fn verify_proof_scoped_modified_non_scoped_field() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100,"recipient":"alice"}"#;
    let modified_payload = r#"{"amount":100,"recipient":"bob"}"#;  // recipient changed
    let scope = &["amount"];  // only amount is scoped

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, payload, scope).unwrap();

    // Verification should still pass because only 'amount' is protected
    let result = ash_core::ash_verify_proof_scoped(&nonce, ctx, binding, timestamp, modified_payload, scope, &scope_hash, &proof).unwrap();
    assert!(result);
}

#[test]
fn verify_proof_scoped_modified_scoped_field() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100,"recipient":"alice"}"#;
    let modified_payload = r#"{"amount":200,"recipient":"alice"}"#;  // amount changed
    let scope = &["amount"];

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, payload, scope).unwrap();

    // Verification should fail because 'amount' was modified
    let result = ash_core::ash_verify_proof_scoped(&nonce, ctx, binding, timestamp, modified_payload, scope, &scope_hash, &proof).unwrap();
    assert!(!result);
}

#[test]
fn verify_proof_scoped_wrong_scope_hash() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100,"recipient":"alice"}"#;
    let scope = &["amount"];

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let (proof, _) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, payload, scope).unwrap();
    let wrong_scope_hash = "0".repeat(64);

    let result = ash_core::ash_verify_proof_scoped(&nonce, ctx, binding, timestamp, payload, scope, &wrong_scope_hash, &proof).unwrap();
    assert!(!result);
}

#[test]
fn verify_proof_scoped_stress_50() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_stress";

    for i in 0..50 {
        let binding = format!("POST|/api/resource/{}|", i);
        let timestamp = format!("{}", 1000000000 + i);
        let payload = format!(r#"{{"amount":{},"recipient":"user_{}"}}"#, i * 100, i);
        let scope = &["amount"];

        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, &binding).unwrap();
        let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, &timestamp, &binding, &payload, scope).unwrap();

        let result = ash_core::ash_verify_proof_scoped(&nonce, ctx, &binding, &timestamp, &payload, scope, &scope_hash, &proof).unwrap();
        assert!(result);
    }
}

// ============================================================================
// HASH SCOPE TESTS
// ============================================================================

#[test]
fn hash_scope_single_field() {
    let hash = ash_core::ash_hash_scope(&["amount"]).unwrap();
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn hash_scope_multiple_fields() {
    let hash = ash_core::ash_hash_scope(&["amount", "recipient"]).unwrap();
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_scope_is_deterministic() {
    let hash1 = ash_core::ash_hash_scope(&["a", "b"]).unwrap();
    let hash2 = ash_core::ash_hash_scope(&["a", "b"]).unwrap();
    assert_eq!(hash1, hash2);
}

#[test]
fn hash_scope_order_matters() {
    let hash1 = ash_core::ash_hash_scope(&["a", "b"]).unwrap();
    let hash2 = ash_core::ash_hash_scope(&["b", "a"]).unwrap();
    // Order should be normalized, so they should be equal
    assert_eq!(hash1, hash2);
}

#[test]
fn hash_scope_different_fields_different_hashes() {
    let hash1 = ash_core::ash_hash_scope(&["amount"]).unwrap();
    let hash2 = ash_core::ash_hash_scope(&["recipient"]).unwrap();
    assert_ne!(hash1, hash2);
}

#[test]
fn hash_scope_nested_fields() {
    let hash = ash_core::ash_hash_scope(&["user.name", "user.email"]).unwrap();
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_scope_stress_100() {
    for i in 0..100 {
        let fields: Vec<String> = (0..=i % 10).map(|j| format!("field_{}", j)).collect();
        let fields_refs: Vec<&str> = fields.iter().map(|s| s.as_str()).collect();
        let hash = ash_core::ash_hash_scope(&fields_refs).unwrap();
        assert_eq!(hash.len(), 64);
    }
}
