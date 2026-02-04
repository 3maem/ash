//! Comprehensive unified proof tests for ASH WASM bindings.
//! These tests use ash_core directly since wasm_bindgen functions can't run on native targets.

use ash_core;

// ============================================================================
// HASH PROOF TESTS
// ============================================================================

#[test]
fn hash_proof_returns_64_char_hex() {
    let hash = ash_core::ash_hash_proof("a".repeat(64).as_str()).unwrap();
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn hash_proof_is_deterministic() {
    let proof = "a".repeat(64);
    let hash1 = ash_core::ash_hash_proof(&proof).unwrap();
    let hash2 = ash_core::ash_hash_proof(&proof).unwrap();
    assert_eq!(hash1, hash2);
}

#[test]
fn hash_proof_different_proofs_different_hashes() {
    let proof1 = "a".repeat(64);
    let proof2 = "b".repeat(64);
    let hash1 = ash_core::ash_hash_proof(&proof1).unwrap();
    let hash2 = ash_core::ash_hash_proof(&proof2).unwrap();
    assert_ne!(hash1, hash2);
}

#[test]
fn hash_proof_rejects_empty() {
    let result = ash_core::ash_hash_proof("");
    assert!(result.is_err());
}

#[test]
fn hash_proof_stress_100() {
    for i in 0..100 {
        let proof = format!("{:064x}", i);
        let hash = ash_core::ash_hash_proof(&proof).unwrap();
        assert_eq!(hash.len(), 64);
    }
}

// ============================================================================
// BUILD PROOF UNIFIED TESTS - NO CHAINING
// ============================================================================

#[test]
fn build_unified_basic() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100}"#;

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], None).unwrap();

    assert_eq!(result.proof.len(), 64);
    // scope_hash is empty when no scope fields are provided
    assert!(result.scope_hash.is_empty());
    assert!(result.chain_hash.is_empty());  // Empty when no chaining
}

#[test]
fn build_unified_with_scope() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100,"recipient":"alice"}"#;

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &["amount"], None).unwrap();

    assert_eq!(result.proof.len(), 64);
    assert_eq!(result.scope_hash.len(), 64);
    assert!(result.chain_hash.is_empty());
}

#[test]
fn build_unified_is_deterministic() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100}"#;

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result1 = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], None).unwrap();
    let result2 = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], None).unwrap();

    assert_eq!(result1.proof, result2.proof);
    assert_eq!(result1.scope_hash, result2.scope_hash);
}

#[test]
fn build_unified_different_payloads_different_proofs() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result1 = ash_core::ash_build_proof_unified(&secret, timestamp, binding, r#"{"a":1}"#, &[], None).unwrap();
    let result2 = ash_core::ash_build_proof_unified(&secret, timestamp, binding, r#"{"a":2}"#, &[], None).unwrap();

    assert_ne!(result1.proof, result2.proof);
}

#[test]
fn build_unified_different_scopes_different_proofs() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"a":1,"b":2}"#;

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result1 = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &["a"], None).unwrap();
    let result2 = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &["b"], None).unwrap();

    assert_ne!(result1.proof, result2.proof);
    assert_ne!(result1.scope_hash, result2.scope_hash);
}

// ============================================================================
// BUILD PROOF UNIFIED TESTS - WITH CHAINING
// ============================================================================

#[test]
fn build_unified_with_chain() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100}"#;
    let previous_proof = "b".repeat(64);

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], Some(&previous_proof)).unwrap();

    assert_eq!(result.proof.len(), 64);
    // scope_hash is empty when no scope fields are provided
    assert!(result.scope_hash.is_empty());
    assert!(!result.chain_hash.is_empty());  // Non-empty when chaining
    assert_eq!(result.chain_hash.len(), 64);
}

#[test]
fn build_unified_chain_is_deterministic() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100}"#;
    let previous_proof = "b".repeat(64);

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result1 = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], Some(&previous_proof)).unwrap();
    let result2 = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], Some(&previous_proof)).unwrap();

    assert_eq!(result1.proof, result2.proof);
    assert_eq!(result1.chain_hash, result2.chain_hash);
}

#[test]
fn build_unified_different_previous_proofs_different_results() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100}"#;

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result1 = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], Some(&"a".repeat(64))).unwrap();
    let result2 = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], Some(&"b".repeat(64))).unwrap();

    assert_ne!(result1.proof, result2.proof);
    assert_ne!(result1.chain_hash, result2.chain_hash);
}

#[test]
fn build_unified_chain_vs_no_chain_different() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100}"#;
    let previous_proof = "b".repeat(64);

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result_no_chain = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], None).unwrap();
    let result_with_chain = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], Some(&previous_proof)).unwrap();

    assert_ne!(result_no_chain.proof, result_with_chain.proof);
    assert!(result_no_chain.chain_hash.is_empty());
    assert!(!result_with_chain.chain_hash.is_empty());
}

#[test]
fn build_unified_scope_and_chain() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100,"recipient":"alice"}"#;
    let previous_proof = "b".repeat(64);

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &["amount"], Some(&previous_proof)).unwrap();

    assert_eq!(result.proof.len(), 64);
    assert_eq!(result.scope_hash.len(), 64);
    assert!(!result.chain_hash.is_empty());
}

#[test]
fn build_unified_stress_50() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_stress";

    for i in 0..50 {
        let binding = format!("POST|/api/resource/{}|", i);
        let timestamp = format!("{}", 1000000000 + i);
        let payload = format!(r#"{{"amount":{},"recipient":"user_{}"}}"#, i * 100, i);
        let previous = if i > 0 { Some(format!("{:064x}", i - 1)) } else { None };

        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, &binding).unwrap();
        let result = ash_core::ash_build_proof_unified(
            &secret,
            &timestamp,
            &binding,
            &payload,
            &["amount"],
            previous.as_deref(),
        ).unwrap();

        assert_eq!(result.proof.len(), 64);
        assert_eq!(result.scope_hash.len(), 64);
        if i > 0 {
            assert!(!result.chain_hash.is_empty());
        }
    }
}

// ============================================================================
// VERIFY PROOF UNIFIED TESTS - NO CHAINING
// ============================================================================

#[test]
fn verify_unified_basic() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100}"#;

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], None).unwrap();

    let verified = ash_core::ash_verify_proof_unified(
        &nonce,
        ctx,
        binding,
        timestamp,
        payload,
        &result.proof,
        &[],
        &result.scope_hash,
        None,
        &result.chain_hash,
    ).unwrap();
    assert!(verified);
}

#[test]
fn verify_unified_with_scope() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100,"recipient":"alice"}"#;
    let scope = &["amount"];

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, scope, None).unwrap();

    let verified = ash_core::ash_verify_proof_unified(
        &nonce,
        ctx,
        binding,
        timestamp,
        payload,
        &result.proof,
        scope,
        &result.scope_hash,
        None,
        &result.chain_hash,
    ).unwrap();
    assert!(verified);
}

#[test]
fn verify_unified_wrong_nonce() {
    let nonce = "a".repeat(64);
    let wrong_nonce = "b".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100}"#;

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], None).unwrap();

    let verified = ash_core::ash_verify_proof_unified(
        &wrong_nonce,
        ctx,
        binding,
        timestamp,
        payload,
        &result.proof,
        &[],
        &result.scope_hash,
        None,
        &result.chain_hash,
    ).unwrap();
    assert!(!verified);
}

#[test]
fn verify_unified_wrong_context() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let wrong_ctx = "ctx_wrong";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100}"#;

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], None).unwrap();

    let verified = ash_core::ash_verify_proof_unified(
        &nonce,
        wrong_ctx,
        binding,
        timestamp,
        payload,
        &result.proof,
        &[],
        &result.scope_hash,
        None,
        &result.chain_hash,
    ).unwrap();
    assert!(!verified);
}

#[test]
fn verify_unified_wrong_binding() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let wrong_binding = "GET|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100}"#;

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], None).unwrap();

    let verified = ash_core::ash_verify_proof_unified(
        &nonce,
        ctx,
        wrong_binding,
        timestamp,
        payload,
        &result.proof,
        &[],
        &result.scope_hash,
        None,
        &result.chain_hash,
    ).unwrap();
    assert!(!verified);
}

#[test]
fn verify_unified_wrong_timestamp() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let wrong_timestamp = "1234567891";
    let payload = r#"{"amount":100}"#;

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], None).unwrap();

    let verified = ash_core::ash_verify_proof_unified(
        &nonce,
        ctx,
        binding,
        wrong_timestamp,
        payload,
        &result.proof,
        &[],
        &result.scope_hash,
        None,
        &result.chain_hash,
    ).unwrap();
    assert!(!verified);
}

#[test]
fn verify_unified_modified_payload() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100}"#;
    let modified_payload = r#"{"amount":200}"#;

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], None).unwrap();

    let verified = ash_core::ash_verify_proof_unified(
        &nonce,
        ctx,
        binding,
        timestamp,
        modified_payload,
        &result.proof,
        &[],
        &result.scope_hash,
        None,
        &result.chain_hash,
    ).unwrap();
    assert!(!verified);
}

// ============================================================================
// VERIFY PROOF UNIFIED TESTS - WITH CHAINING
// ============================================================================

#[test]
fn verify_unified_with_chain() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100}"#;
    let previous_proof = "b".repeat(64);

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], Some(&previous_proof)).unwrap();

    let verified = ash_core::ash_verify_proof_unified(
        &nonce,
        ctx,
        binding,
        timestamp,
        payload,
        &result.proof,
        &[],
        &result.scope_hash,
        Some(&previous_proof),
        &result.chain_hash,
    ).unwrap();
    assert!(verified);
}

#[test]
fn verify_unified_wrong_previous_proof() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100}"#;
    let previous_proof = "b".repeat(64);
    let wrong_previous = "c".repeat(64);

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], Some(&previous_proof)).unwrap();

    let verified = ash_core::ash_verify_proof_unified(
        &nonce,
        ctx,
        binding,
        timestamp,
        payload,
        &result.proof,
        &[],
        &result.scope_hash,
        Some(&wrong_previous),
        &result.chain_hash,
    ).unwrap();
    assert!(!verified);
}

#[test]
fn verify_unified_wrong_chain_hash() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100}"#;
    let previous_proof = "b".repeat(64);

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], Some(&previous_proof)).unwrap();
    let wrong_chain_hash = "0".repeat(64);

    let verified = ash_core::ash_verify_proof_unified(
        &nonce,
        ctx,
        binding,
        timestamp,
        payload,
        &result.proof,
        &[],
        &result.scope_hash,
        Some(&previous_proof),
        &wrong_chain_hash,
    ).unwrap();
    assert!(!verified);
}

#[test]
fn verify_unified_scope_and_chain() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100,"recipient":"alice"}"#;
    let scope = &["amount"];
    let previous_proof = "b".repeat(64);

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, scope, Some(&previous_proof)).unwrap();

    let verified = ash_core::ash_verify_proof_unified(
        &nonce,
        ctx,
        binding,
        timestamp,
        payload,
        &result.proof,
        scope,
        &result.scope_hash,
        Some(&previous_proof),
        &result.chain_hash,
    ).unwrap();
    assert!(verified);
}

#[test]
fn verify_unified_stress_50() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_stress";

    for i in 0..50 {
        let binding = format!("POST|/api/resource/{}|", i);
        let timestamp = format!("{}", 1000000000 + i);
        let payload = format!(r#"{{"amount":{},"recipient":"user_{}"}}"#, i * 100, i);
        let previous = if i > 0 { Some(format!("{:064x}", i - 1)) } else { None };
        let scope = &["amount"];

        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, &binding).unwrap();
        let result = ash_core::ash_build_proof_unified(
            &secret,
            &timestamp,
            &binding,
            &payload,
            scope,
            previous.as_deref(),
        ).unwrap();

        let verified = ash_core::ash_verify_proof_unified(
            &nonce,
            ctx,
            &binding,
            &timestamp,
            &payload,
            &result.proof,
            scope,
            &result.scope_hash,
            previous.as_deref(),
            &result.chain_hash,
        ).unwrap();
        assert!(verified);
    }
}

// ============================================================================
// CHAIN CONTINUITY TESTS
// ============================================================================

#[test]
fn chain_three_proofs() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_chain";
    let binding = "POST|/api|";
    let payload = r#"{"action":"step"}"#;

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    // Step 1: Initial proof
    let result1 = ash_core::ash_build_proof_unified(&secret, "1000000001", binding, payload, &[], None).unwrap();
    assert!(result1.chain_hash.is_empty());

    // Step 2: Chain from proof 1
    let result2 = ash_core::ash_build_proof_unified(&secret, "1000000002", binding, payload, &[], Some(&result1.proof)).unwrap();
    assert!(!result2.chain_hash.is_empty());

    // Step 3: Chain from proof 2
    let result3 = ash_core::ash_build_proof_unified(&secret, "1000000003", binding, payload, &[], Some(&result2.proof)).unwrap();
    assert!(!result3.chain_hash.is_empty());

    // Verify all three
    let v1 = ash_core::ash_verify_proof_unified(&nonce, ctx, binding, "1000000001", payload, &result1.proof, &[], &result1.scope_hash, None, &result1.chain_hash).unwrap();
    let v2 = ash_core::ash_verify_proof_unified(&nonce, ctx, binding, "1000000002", payload, &result2.proof, &[], &result2.scope_hash, Some(&result1.proof), &result2.chain_hash).unwrap();
    let v3 = ash_core::ash_verify_proof_unified(&nonce, ctx, binding, "1000000003", payload, &result3.proof, &[], &result3.scope_hash, Some(&result2.proof), &result3.chain_hash).unwrap();

    assert!(v1);
    assert!(v2);
    assert!(v3);
}

#[test]
fn chain_broken_in_middle() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_chain";
    let binding = "POST|/api|";
    let payload = r#"{"action":"step"}"#;

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    // Build chain of 3
    let result1 = ash_core::ash_build_proof_unified(&secret, "1000000001", binding, payload, &[], None).unwrap();
    let result2 = ash_core::ash_build_proof_unified(&secret, "1000000002", binding, payload, &[], Some(&result1.proof)).unwrap();
    let result3 = ash_core::ash_build_proof_unified(&secret, "1000000003", binding, payload, &[], Some(&result2.proof)).unwrap();

    // Try to verify result3 with wrong previous proof (result1 instead of result2)
    let verified = ash_core::ash_verify_proof_unified(
        &nonce,
        ctx,
        binding,
        "1000000003",
        payload,
        &result3.proof,
        &[],
        &result3.scope_hash,
        Some(&result1.proof),  // Wrong! Should be result2.proof
        &result3.chain_hash,
    ).unwrap();
    assert!(!verified);
}

#[test]
fn chain_stress_10() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_chain_stress";
    let binding = "POST|/api|";

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    let mut previous_proof: Option<String> = None;
    let mut proofs = Vec::new();

    // Build chain of 10
    for i in 0..10 {
        let timestamp = format!("{}", 1000000000 + i);
        let payload = format!(r#"{{"step":{}}}"#, i);

        let result = ash_core::ash_build_proof_unified(
            &secret,
            &timestamp,
            binding,
            &payload,
            &[],
            previous_proof.as_deref(),
        ).unwrap();

        proofs.push((timestamp, payload, result.proof.clone(), result.scope_hash.clone(), result.chain_hash.clone()));
        previous_proof = Some(result.proof);
    }

    // Verify entire chain
    for i in 0..10 {
        let (timestamp, payload, proof, scope_hash, chain_hash) = &proofs[i];
        let prev = if i > 0 { Some(proofs[i - 1].2.as_str()) } else { None };

        let verified = ash_core::ash_verify_proof_unified(
            &nonce,
            ctx,
            binding,
            timestamp,
            payload,
            proof,
            &[],
            scope_hash,
            prev,
            chain_hash,
        ).unwrap();
        assert!(verified, "Failed at step {}", i);
    }
}
