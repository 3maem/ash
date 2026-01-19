//! Integration tests for ASH v2.3 Unified Proof Functions
//!
//! These tests verify cross-SDK compatibility by using fixed test vectors.

use ash_core::{
    build_proof_v21_unified, derive_client_secret, hash_proof, verify_proof_v21_unified,
};

/// Test basic proof without scoping or chaining
#[test]
fn test_unified_basic() {
    let nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let context_id = "ash_test_context_001";
    let binding = "POST|/api/transfer|";
    let timestamp = "1704067200000";
    let payload = r#"{"amount":100,"note":"test","recipient":"user123"}"#;

    let client_secret = derive_client_secret(nonce, context_id, binding);

    let result = build_proof_v21_unified(&client_secret, timestamp, binding, payload, &[], None)
        .expect("build should succeed");

    assert!(result.scope_hash.is_empty(), "scope_hash should be empty");
    assert!(result.chain_hash.is_empty(), "chain_hash should be empty");
    assert_eq!(result.proof.len(), 64, "proof should be 64 hex chars");

    // Verify the proof
    let valid = verify_proof_v21_unified(
        nonce,
        context_id,
        binding,
        timestamp,
        payload,
        &result.proof,
        &[],
        "",
        None,
        "",
    )
    .expect("verify should succeed");

    assert!(valid, "proof should verify");
}

/// Test scoped proof with single field
#[test]
fn test_unified_scoped_single() {
    let nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let context_id = "ash_test_context_002";
    let binding = "POST|/api/transfer|";
    let timestamp = "1704067200000";
    let payload = r#"{"amount":100,"note":"test","recipient":"user123"}"#;

    let client_secret = derive_client_secret(nonce, context_id, binding);
    let scope = ["amount"];

    let result = build_proof_v21_unified(&client_secret, timestamp, binding, payload, &scope, None)
        .expect("build should succeed");

    assert!(
        !result.scope_hash.is_empty(),
        "scope_hash should not be empty"
    );
    assert!(result.chain_hash.is_empty(), "chain_hash should be empty");

    // Verify the proof
    let valid = verify_proof_v21_unified(
        nonce,
        context_id,
        binding,
        timestamp,
        payload,
        &result.proof,
        &scope,
        &result.scope_hash,
        None,
        "",
    )
    .expect("verify should succeed");

    assert!(valid, "scoped proof should verify");
}

/// Test scoped proof with multiple fields
#[test]
fn test_unified_scoped_multiple() {
    let nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let context_id = "ash_test_context_003";
    let binding = "POST|/api/transfer|";
    let timestamp = "1704067200000";
    let payload = r#"{"amount":100,"note":"test","recipient":"user123"}"#;

    let client_secret = derive_client_secret(nonce, context_id, binding);
    let scope = ["amount", "recipient"];

    let result = build_proof_v21_unified(&client_secret, timestamp, binding, payload, &scope, None)
        .expect("build should succeed");

    assert!(!result.scope_hash.is_empty());

    let valid = verify_proof_v21_unified(
        nonce,
        context_id,
        binding,
        timestamp,
        payload,
        &result.proof,
        &scope,
        &result.scope_hash,
        None,
        "",
    )
    .expect("verify should succeed");

    assert!(valid);
}

/// Test chained proof
#[test]
fn test_unified_chained() {
    let nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let context_id = "ash_test_context_004";
    let binding = "POST|/api/confirm|";
    let timestamp = "1704067260000";
    let payload = r#"{"confirmed":true}"#;
    let previous_proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

    let client_secret = derive_client_secret(nonce, context_id, binding);

    let result = build_proof_v21_unified(
        &client_secret,
        timestamp,
        binding,
        payload,
        &[],
        Some(previous_proof),
    )
    .expect("build should succeed");

    assert!(result.scope_hash.is_empty());
    assert!(
        !result.chain_hash.is_empty(),
        "chain_hash should not be empty"
    );

    // Verify chain hash is SHA256 of previous proof
    let expected_chain_hash = hash_proof(previous_proof);
    assert_eq!(result.chain_hash, expected_chain_hash);

    let valid = verify_proof_v21_unified(
        nonce,
        context_id,
        binding,
        timestamp,
        payload,
        &result.proof,
        &[],
        "",
        Some(previous_proof),
        &result.chain_hash,
    )
    .expect("verify should succeed");

    assert!(valid);
}

/// Test full proof with scoping AND chaining
#[test]
fn test_unified_full() {
    let nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let context_id = "ash_test_context_005";
    let binding = "POST|/api/finalize|";
    let timestamp = "1704067320000";
    let payload = r#"{"amount":500,"approved":true,"recipient":"user456"}"#;
    let previous_proof = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let scope = ["amount", "approved"];

    let client_secret = derive_client_secret(nonce, context_id, binding);

    let result = build_proof_v21_unified(
        &client_secret,
        timestamp,
        binding,
        payload,
        &scope,
        Some(previous_proof),
    )
    .expect("build should succeed");

    assert!(!result.scope_hash.is_empty());
    assert!(!result.chain_hash.is_empty());

    let valid = verify_proof_v21_unified(
        nonce,
        context_id,
        binding,
        timestamp,
        payload,
        &result.proof,
        &scope,
        &result.scope_hash,
        Some(previous_proof),
        &result.chain_hash,
    )
    .expect("verify should succeed");

    assert!(valid);
}

/// Test that wrong scope hash fails verification
#[test]
fn test_unified_wrong_scope_hash_fails() {
    let nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let context_id = "ash_test_context_010";
    let binding = "POST|/api/test|";
    let timestamp = "1704067200000";
    let payload = r#"{"amount":100}"#;
    let scope = ["amount"];

    let client_secret = derive_client_secret(nonce, context_id, binding);

    let result = build_proof_v21_unified(&client_secret, timestamp, binding, payload, &scope, None)
        .expect("build should succeed");

    // Use wrong scope hash
    let valid = verify_proof_v21_unified(
        nonce,
        context_id,
        binding,
        timestamp,
        payload,
        &result.proof,
        &scope,
        "wrongscopehash1234567890abcdef1234567890abcdef1234567890abcdef12",
        None,
        "",
    )
    .expect("verify should return result");

    assert!(!valid, "wrong scope hash should fail");
}

/// Test that wrong chain hash fails verification
#[test]
fn test_unified_wrong_chain_hash_fails() {
    let nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let context_id = "ash_test_context_011";
    let binding = "POST|/api/test|";
    let timestamp = "1704067200000";
    let payload = r#"{"confirmed":true}"#;
    let previous_proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

    let client_secret = derive_client_secret(nonce, context_id, binding);

    let result = build_proof_v21_unified(
        &client_secret,
        timestamp,
        binding,
        payload,
        &[],
        Some(previous_proof),
    )
    .expect("build should succeed");

    // Use wrong chain hash
    let valid = verify_proof_v21_unified(
        nonce,
        context_id,
        binding,
        timestamp,
        payload,
        &result.proof,
        &[],
        "",
        Some(previous_proof),
        "wrongchainhash1234567890abcdef1234567890abcdef1234567890abcdef12",
    )
    .expect("verify should return result");

    assert!(!valid, "wrong chain hash should fail");
}

/// Test hash_proof function
#[test]
fn test_hash_proof() {
    let proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let hash = hash_proof(proof);

    assert_eq!(hash.len(), 64, "hash should be 64 hex chars");

    // Hash should be deterministic
    let hash2 = hash_proof(proof);
    assert_eq!(hash, hash2);
}
