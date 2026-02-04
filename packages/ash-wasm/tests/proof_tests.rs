//! Comprehensive proof generation and verification tests for ASH WASM bindings.
//! These tests use ash_core directly since wasm_bindgen functions can't run on native targets.

use ash_core;

// ============================================================================
// HASH BODY TESTS
// ============================================================================

#[test]
fn hash_body_returns_64_char_hex() {
    let hash = ash_core::ash_hash_body("test");
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn hash_body_is_deterministic() {
    let hash1 = ash_core::ash_hash_body("test");
    let hash2 = ash_core::ash_hash_body("test");
    assert_eq!(hash1, hash2);
}

#[test]
fn hash_body_different_inputs_different_hashes() {
    let hash1 = ash_core::ash_hash_body("test1");
    let hash2 = ash_core::ash_hash_body("test2");
    assert_ne!(hash1, hash2);
}

#[test]
fn hash_body_handles_empty_string() {
    let hash = ash_core::ash_hash_body("");
    assert_eq!(hash.len(), 64);
    assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

#[test]
fn hash_body_handles_unicode() {
    let hash = ash_core::ash_hash_body("你好世界");
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_body_handles_emoji() {
    let hash = ash_core::ash_hash_body("🎉🚀");
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_body_handles_long_string() {
    let long_string = "a".repeat(10000);
    let hash = ash_core::ash_hash_body(&long_string);
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_body_handles_json() {
    let hash = ash_core::ash_hash_body(r#"{"a":1,"b":2}"#);
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_body_stress_100() {
    for i in 0..100 {
        let input = format!("test_input_{}", i);
        let hash = ash_core::ash_hash_body(&input);
        assert_eq!(hash.len(), 64);
    }
}

// ============================================================================
// DERIVE CLIENT SECRET TESTS
// ============================================================================

#[test]
fn derive_client_secret_returns_64_char_hex() {
    let nonce = "a".repeat(64);  // 64 hex chars = 32 bytes
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx456", "POST|/api|").unwrap();
    assert_eq!(secret.len(), 64);
    assert!(secret.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn derive_client_secret_is_deterministic() {
    let nonce = "a".repeat(64);
    let secret1 = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/api|").unwrap();
    let secret2 = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/api|").unwrap();
    assert_eq!(secret1, secret2);
}

#[test]
fn derive_client_secret_different_nonces_different_secrets() {
    let nonce1 = "a".repeat(64);
    let nonce2 = "b".repeat(64);
    let secret1 = ash_core::ash_derive_client_secret(&nonce1, "ctx", "POST|/api|").unwrap();
    let secret2 = ash_core::ash_derive_client_secret(&nonce2, "ctx", "POST|/api|").unwrap();
    assert_ne!(secret1, secret2);
}

#[test]
fn derive_client_secret_different_contexts_different_secrets() {
    let nonce = "a".repeat(64);
    let secret1 = ash_core::ash_derive_client_secret(&nonce, "ctx1", "POST|/api|").unwrap();
    let secret2 = ash_core::ash_derive_client_secret(&nonce, "ctx2", "POST|/api|").unwrap();
    assert_ne!(secret1, secret2);
}

#[test]
fn derive_client_secret_different_bindings_different_secrets() {
    let nonce = "a".repeat(64);
    let secret1 = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/api|").unwrap();
    let secret2 = ash_core::ash_derive_client_secret(&nonce, "ctx", "GET|/api|").unwrap();
    assert_ne!(secret1, secret2);
}

#[test]
fn derive_client_secret_handles_long_nonce() {
    let long_nonce = "a".repeat(128);
    let secret = ash_core::ash_derive_client_secret(&long_nonce, "ctx", "POST|/api|").unwrap();
    assert_eq!(secret.len(), 64);
}

#[test]
fn derive_client_secret_stress_100() {
    for i in 0..100 {
        let nonce = format!("{:064x}", i);  // 64-char hex nonce
        let ctx = format!("ctx_{}", i);
        let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, "POST|/api|").unwrap();
        assert_eq!(secret.len(), 64);
    }
}

// ============================================================================
// BUILD PROOF TESTS
// ============================================================================

#[test]
fn build_proof_returns_64_char_hex() {
    let body_hash = ash_core::ash_hash_body("test");  // Proper 64-char SHA-256 hash
    let secret = "a".repeat(64);
    let proof = ash_core::ash_build_proof(&secret, "1234567890", "POST|/api|", &body_hash).unwrap();
    assert_eq!(proof.len(), 64);
    assert!(proof.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn build_proof_is_deterministic() {
    let body_hash = ash_core::ash_hash_body("test");
    let secret = "a".repeat(64);
    let proof1 = ash_core::ash_build_proof(&secret, "123", "POST|/api|", &body_hash).unwrap();
    let proof2 = ash_core::ash_build_proof(&secret, "123", "POST|/api|", &body_hash).unwrap();
    assert_eq!(proof1, proof2);
}

#[test]
fn build_proof_different_secrets_different_proofs() {
    let body_hash = ash_core::ash_hash_body("test");
    let secret1 = "a".repeat(64);
    let secret2 = "b".repeat(64);
    let proof1 = ash_core::ash_build_proof(&secret1, "123", "POST|/api|", &body_hash).unwrap();
    let proof2 = ash_core::ash_build_proof(&secret2, "123", "POST|/api|", &body_hash).unwrap();
    assert_ne!(proof1, proof2);
}

#[test]
fn build_proof_different_timestamps_different_proofs() {
    let body_hash = ash_core::ash_hash_body("test");
    let secret = "a".repeat(64);
    let proof1 = ash_core::ash_build_proof(&secret, "123", "POST|/api|", &body_hash).unwrap();
    let proof2 = ash_core::ash_build_proof(&secret, "456", "POST|/api|", &body_hash).unwrap();
    assert_ne!(proof1, proof2);
}

#[test]
fn build_proof_different_bindings_different_proofs() {
    let body_hash = ash_core::ash_hash_body("test");
    let secret = "a".repeat(64);
    let proof1 = ash_core::ash_build_proof(&secret, "123", "POST|/api|", &body_hash).unwrap();
    let proof2 = ash_core::ash_build_proof(&secret, "123", "GET|/api|", &body_hash).unwrap();
    assert_ne!(proof1, proof2);
}

#[test]
fn build_proof_different_hashes_different_proofs() {
    let body_hash1 = ash_core::ash_hash_body("test1");
    let body_hash2 = ash_core::ash_hash_body("test2");
    let secret = "a".repeat(64);
    let proof1 = ash_core::ash_build_proof(&secret, "123", "POST|/api|", &body_hash1).unwrap();
    let proof2 = ash_core::ash_build_proof(&secret, "123", "POST|/api|", &body_hash2).unwrap();
    assert_ne!(proof1, proof2);
}

#[test]
fn build_proof_stress_100() {
    for i in 0..100 {
        let secret = format!("{:064x}", i);  // 64-char hex secret
        let timestamp = format!("{}", 1000000000 + i);
        let body_hash = ash_core::ash_hash_body(&format!("content_{}", i));
        let proof = ash_core::ash_build_proof(&secret, &timestamp, "POST|/api|", &body_hash).unwrap();
        assert_eq!(proof.len(), 64);
    }
}

// ============================================================================
// VERIFY PROOF TESTS
// ============================================================================

#[test]
fn verify_proof_returns_true_for_valid_proof() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    let result = ash_core::ash_verify_proof(&nonce, ctx, binding, timestamp, &body_hash, &proof).unwrap();
    assert!(result);
}

#[test]
fn verify_proof_returns_false_for_wrong_nonce() {
    let nonce = "a".repeat(64);
    let wrong_nonce = "b".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    let result = ash_core::ash_verify_proof(&wrong_nonce, ctx, binding, timestamp, &body_hash, &proof).unwrap();
    assert!(!result);
}

#[test]
fn verify_proof_returns_false_for_wrong_context() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let wrong_ctx = "ctx_wrong";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    let result = ash_core::ash_verify_proof(&nonce, wrong_ctx, binding, timestamp, &body_hash, &proof).unwrap();
    assert!(!result);
}

#[test]
fn verify_proof_returns_false_for_wrong_binding() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let wrong_binding = "GET|/api|";
    let timestamp = "1234567890";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    let result = ash_core::ash_verify_proof(&nonce, ctx, wrong_binding, timestamp, &body_hash, &proof).unwrap();
    assert!(!result);
}

#[test]
fn verify_proof_returns_false_for_wrong_timestamp() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let wrong_timestamp = "1234567891";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    let result = ash_core::ash_verify_proof(&nonce, ctx, binding, wrong_timestamp, &body_hash, &proof).unwrap();
    assert!(!result);
}

#[test]
fn verify_proof_returns_false_for_wrong_body_hash() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let body_hash = ash_core::ash_hash_body("test");
    let wrong_body_hash = ash_core::ash_hash_body("wrong");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    let result = ash_core::ash_verify_proof(&nonce, ctx, binding, timestamp, &wrong_body_hash, &proof).unwrap();
    assert!(!result);
}

#[test]
fn verify_proof_stress_50() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_stress";

    for i in 0..50 {
        let binding = format!("POST|/api/resource/{}|", i);
        let timestamp = format!("{}", 1000000000 + i);
        let body_hash = ash_core::ash_hash_body(&format!("content_{}", i));

        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, &binding).unwrap();
        let proof = ash_core::ash_build_proof(&secret, &timestamp, &binding, &body_hash).unwrap();

        let result = ash_core::ash_verify_proof(&nonce, ctx, &binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(result);
    }
}

// ============================================================================
// GENERATE NONCE TESTS
// ============================================================================

#[test]
fn generate_nonce_returns_hex_string() {
    let nonce = ash_core::ash_generate_nonce(32).unwrap();
    assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn generate_nonce_default_length_64_chars() {
    let nonce = ash_core::ash_generate_nonce(32).unwrap();
    assert_eq!(nonce.len(), 64);
}

#[test]
fn generate_nonce_custom_length() {
    let nonce = ash_core::ash_generate_nonce(16).unwrap();
    assert_eq!(nonce.len(), 32);
}

#[test]
fn generate_nonce_is_unique() {
    let nonce1 = ash_core::ash_generate_nonce(32).unwrap();
    let nonce2 = ash_core::ash_generate_nonce(32).unwrap();
    assert_ne!(nonce1, nonce2);
}

#[test]
fn generate_nonce_stress_100() {
    let mut nonces = std::collections::HashSet::new();
    for _ in 0..100 {
        let nonce = ash_core::ash_generate_nonce(32).unwrap();
        nonces.insert(nonce);
    }
    assert_eq!(nonces.len(), 100);
}

// ============================================================================
// GENERATE CONTEXT ID TESTS
// ============================================================================

#[test]
fn generate_context_id_has_ash_prefix() {
    let ctx = ash_core::ash_generate_context_id().unwrap();
    assert!(ctx.starts_with("ash_"));
}

#[test]
fn generate_context_id_is_unique() {
    let ctx1 = ash_core::ash_generate_context_id().unwrap();
    let ctx2 = ash_core::ash_generate_context_id().unwrap();
    assert_ne!(ctx1, ctx2);
}

#[test]
fn generate_context_id_stress_100() {
    let mut contexts = std::collections::HashSet::new();
    for _ in 0..100 {
        let ctx = ash_core::ash_generate_context_id().unwrap();
        contexts.insert(ctx);
    }
    assert_eq!(contexts.len(), 100);
}

// ============================================================================
// TIMING SAFE EQUAL TESTS
// ============================================================================

#[test]
fn timing_safe_equal_returns_true_for_equal() {
    assert!(ash_core::ash_timing_safe_equal(b"test", b"test"));
}

#[test]
fn timing_safe_equal_returns_false_for_unequal() {
    assert!(!ash_core::ash_timing_safe_equal(b"test", b"other"));
}

#[test]
fn timing_safe_equal_returns_false_for_different_lengths() {
    assert!(!ash_core::ash_timing_safe_equal(b"test", b"testing"));
}

#[test]
fn timing_safe_equal_handles_empty() {
    assert!(ash_core::ash_timing_safe_equal(b"", b""));
}

#[test]
fn timing_safe_equal_stress_100() {
    for i in 0..100 {
        let s = format!("test_{}", i);
        assert!(ash_core::ash_timing_safe_equal(s.as_bytes(), s.as_bytes()));
    }
}
