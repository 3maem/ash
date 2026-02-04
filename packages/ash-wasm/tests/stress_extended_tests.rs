//! Extended stress tests for ASH WASM bindings.
//! These tests use higher iteration counts (500-1000) to verify stability and performance.

use ash_core;
use std::collections::HashSet;

// ============================================================================
// HASH BODY STRESS TESTS
// ============================================================================

#[test]
fn stress_hash_body_500() {
    for i in 0..500 {
        let input = format!("test_input_{}", i);
        let hash = ash_core::ash_hash_body(&input);
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

#[test]
fn stress_hash_body_1000() {
    for i in 0..1000 {
        let input = format!("stress_test_body_content_{}_with_more_data", i);
        let hash = ash_core::ash_hash_body(&input);
        assert_eq!(hash.len(), 64);
    }
}

#[test]
fn stress_hash_body_uniqueness_1000() {
    let mut hashes = HashSet::new();
    for i in 0..1000 {
        let input = format!("unique_input_{}", i);
        let hash = ash_core::ash_hash_body(&input);
        hashes.insert(hash);
    }
    assert_eq!(hashes.len(), 1000, "All hashes should be unique");
}

#[test]
fn stress_hash_body_determinism_500() {
    for i in 0..500 {
        let input = format!("deterministic_test_{}", i);
        let hash1 = ash_core::ash_hash_body(&input);
        let hash2 = ash_core::ash_hash_body(&input);
        assert_eq!(hash1, hash2);
    }
}

// ============================================================================
// JSON CANONICALIZATION STRESS TESTS
// ============================================================================

#[test]
fn stress_json_canonicalize_500() {
    for i in 0..500 {
        let json = format!(r#"{{"index":{},"name":"item_{}","value":{}}}"#, i, i, i * 10);
        let result = ash_core::ash_canonicalize_json(&json).unwrap();
        assert!(result.contains("index"));
        assert!(result.contains("name"));
        assert!(result.contains("value"));
    }
}

#[test]
fn stress_json_canonicalize_1000() {
    for i in 0..1000 {
        let json = format!(r#"{{"a":{},"b":"{}","c":{}}}"#, i, i, i % 100);
        let result = ash_core::ash_canonicalize_json(&json).unwrap();
        // Keys should be sorted
        let a_pos = result.find("\"a\"").unwrap();
        let b_pos = result.find("\"b\"").unwrap();
        let c_pos = result.find("\"c\"").unwrap();
        assert!(a_pos < b_pos && b_pos < c_pos);
    }
}

#[test]
fn stress_json_nested_500() {
    for i in 0..500 {
        let json = format!(
            r#"{{"outer":{{"z":{},"a":{}}},"inner":{{"b":{},"a":{}}}}}"#,
            i, i + 1, i + 2, i + 3
        );
        let result = ash_core::ash_canonicalize_json(&json).unwrap();
        assert!(result.contains("inner"));
        assert!(result.contains("outer"));
    }
}

#[test]
fn stress_json_array_500() {
    for i in 0..500 {
        let json = format!(r#"{{"arr":[{},{},{}]}}"#, i, i + 1, i + 2);
        let result = ash_core::ash_canonicalize_json(&json).unwrap();
        // Array order should be preserved
        let expected = format!(r#"{{"arr":[{},{},{}]}}"#, i, i + 1, i + 2);
        assert_eq!(result, expected);
    }
}

// ============================================================================
// QUERY CANONICALIZATION STRESS TESTS
// ============================================================================

#[test]
fn stress_query_canonicalize_500() {
    for i in 0..500 {
        let query = format!("z={}&a={}&m={}", i, i + 1, i + 2);
        let result = ash_core::ash_canonicalize_query(&query).unwrap();
        // Should be sorted by key
        let a_pos = result.find("a=").unwrap();
        let m_pos = result.find("m=").unwrap();
        let z_pos = result.find("z=").unwrap();
        assert!(a_pos < m_pos && m_pos < z_pos);
    }
}

#[test]
fn stress_query_many_params_500() {
    for i in 0..500 {
        let query = format!(
            "p1={}&p2={}&p3={}&p4={}&p5={}",
            i, i + 1, i + 2, i + 3, i + 4
        );
        let result = ash_core::ash_canonicalize_query(&query).unwrap();
        assert!(result.contains("p1="));
        assert!(result.contains("p5="));
    }
}

// ============================================================================
// URLENCODED CANONICALIZATION STRESS TESTS
// ============================================================================

#[test]
fn stress_urlencoded_500() {
    for i in 0..500 {
        let input = format!("b={}&a={}", i, i + 1);
        let result = ash_core::ash_canonicalize_urlencoded(&input).unwrap();
        // Should be sorted
        assert!(result.starts_with("a="));
    }
}

// ============================================================================
// BINDING NORMALIZATION STRESS TESTS
// ============================================================================

#[test]
fn stress_binding_500() {
    let methods = ["GET", "POST", "PUT", "DELETE", "PATCH"];
    for i in 0..500 {
        let method = methods[i % methods.len()];
        let path = format!("/api/resource/{}", i);
        let result = ash_core::ash_normalize_binding(method, &path, "").unwrap();
        assert!(result.starts_with(method.to_uppercase().as_str()));
        assert!(result.contains(&path));
    }
}

#[test]
fn stress_binding_with_query_500() {
    for i in 0..500 {
        let path = format!("/api/items/{}", i);
        let query = format!("page={}&limit={}", i % 100, 10);
        let result = ash_core::ash_normalize_binding("GET", &path, &query).unwrap();
        assert!(result.contains("limit="));
        assert!(result.contains("page="));
    }
}

// ============================================================================
// NONCE GENERATION STRESS TESTS
// ============================================================================

#[test]
fn stress_nonce_generation_500() {
    let mut nonces = HashSet::new();
    for _ in 0..500 {
        let nonce = ash_core::ash_generate_nonce(32).unwrap();
        assert_eq!(nonce.len(), 64);
        nonces.insert(nonce);
    }
    assert_eq!(nonces.len(), 500, "All nonces should be unique");
}

#[test]
fn stress_nonce_generation_1000() {
    let mut nonces = HashSet::new();
    for _ in 0..1000 {
        let nonce = ash_core::ash_generate_nonce(32).unwrap();
        nonces.insert(nonce);
    }
    assert_eq!(nonces.len(), 1000);
}

// ============================================================================
// CONTEXT ID GENERATION STRESS TESTS
// ============================================================================

#[test]
fn stress_context_id_500() {
    let mut contexts = HashSet::new();
    for _ in 0..500 {
        let ctx = ash_core::ash_generate_context_id().unwrap();
        assert!(ctx.starts_with("ash_"));
        contexts.insert(ctx);
    }
    assert_eq!(contexts.len(), 500);
}

#[test]
fn stress_context_id_1000() {
    let mut contexts = HashSet::new();
    for _ in 0..1000 {
        let ctx = ash_core::ash_generate_context_id().unwrap();
        contexts.insert(ctx);
    }
    assert_eq!(contexts.len(), 1000);
}

// ============================================================================
// CLIENT SECRET DERIVATION STRESS TESTS
// ============================================================================

#[test]
fn stress_derive_secret_500() {
    let nonce = "a".repeat(64);
    for i in 0..500 {
        let ctx = format!("ctx_{}", i);
        let binding = format!("POST|/api/resource/{}|", i);
        let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, &binding).unwrap();
        assert_eq!(secret.len(), 64);
    }
}

#[test]
fn stress_derive_secret_determinism_500() {
    let nonce = "a".repeat(64);
    for i in 0..500 {
        let ctx = format!("ctx_{}", i);
        let binding = "POST|/api|";
        let secret1 = ash_core::ash_derive_client_secret(&nonce, &ctx, binding).unwrap();
        let secret2 = ash_core::ash_derive_client_secret(&nonce, &ctx, binding).unwrap();
        assert_eq!(secret1, secret2);
    }
}

// ============================================================================
// PROOF BUILDING STRESS TESTS
// ============================================================================

#[test]
fn stress_build_proof_500() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_stress";
    let binding = "POST|/api|";
    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    for i in 0..500 {
        let timestamp = format!("{}", 1000000000 + i);
        let body_hash = ash_core::ash_hash_body(&format!("content_{}", i));
        let proof = ash_core::ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();
        assert_eq!(proof.len(), 64);
    }
}

#[test]
fn stress_build_proof_1000() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_stress_1000";
    let binding = "POST|/api/stress|";
    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    for i in 0..1000 {
        let timestamp = format!("{}", 1700000000 + i);
        let body_hash = ash_core::ash_hash_body(&format!(r#"{{"id":{}}}"#, i));
        let proof = ash_core::ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();
        assert_eq!(proof.len(), 64);
    }
}

// ============================================================================
// PROOF VERIFICATION STRESS TESTS
// ============================================================================

#[test]
fn stress_verify_proof_500() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_verify";
    let binding = "POST|/api|";

    for i in 0..500 {
        let timestamp = format!("{}", 1000000000 + i);
        let body_hash = ash_core::ash_hash_body(&format!("verify_content_{}", i));

        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
        let proof = ash_core::ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

        let valid = ash_core::ash_verify_proof(&nonce, ctx, binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(valid);
    }
}

// ============================================================================
// SCOPED PROOF STRESS TESTS
// ============================================================================

#[test]
fn stress_scoped_proof_500() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_scoped_stress";

    for i in 0..500 {
        let binding = format!("POST|/api/item/{}|", i);
        let timestamp = format!("{}", 1000000000 + i);
        let payload = format!(r#"{{"amount":{},"recipient":"user_{}","note":"test"}}"#, i * 100, i);
        let scope = &["amount", "recipient"];

        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, &binding).unwrap();
        let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, &timestamp, &binding, &payload, scope).unwrap();

        assert_eq!(proof.len(), 64);
        assert_eq!(scope_hash.len(), 64);

        let valid = ash_core::ash_verify_proof_scoped(&nonce, ctx, &binding, &timestamp, &payload, scope, &scope_hash, &proof).unwrap();
        assert!(valid);
    }
}

// ============================================================================
// UNIFIED PROOF STRESS TESTS
// ============================================================================

#[test]
fn stress_unified_proof_500() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_unified_stress";

    for i in 0..500 {
        let binding = format!("POST|/api/unified/{}|", i);
        let timestamp = format!("{}", 1000000000 + i);
        let payload = format!(r#"{{"data":{},"type":"test"}}"#, i);

        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, &binding).unwrap();
        let result = ash_core::ash_build_proof_unified(&secret, &timestamp, &binding, &payload, &[], None).unwrap();

        assert_eq!(result.proof.len(), 64);

        let valid = ash_core::ash_verify_proof_unified(
            &nonce, ctx, &binding, &timestamp, &payload, &result.proof,
            &[], "", None, ""
        ).unwrap();
        assert!(valid);
    }
}

#[test]
fn stress_unified_with_scope_500() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_unified_scope";

    for i in 0..500 {
        let binding = format!("POST|/api/scoped/{}|", i);
        let timestamp = format!("{}", 1000000000 + i);
        let payload = format!(r#"{{"amount":{},"note":"optional","id":{}}}"#, i * 10, i);
        let scope = &["amount", "id"];

        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, &binding).unwrap();
        let result = ash_core::ash_build_proof_unified(&secret, &timestamp, &binding, &payload, scope, None).unwrap();

        assert_eq!(result.proof.len(), 64);
        assert!(!result.scope_hash.is_empty());

        let valid = ash_core::ash_verify_proof_unified(
            &nonce, ctx, &binding, &timestamp, &payload, &result.proof,
            scope, &result.scope_hash, None, ""
        ).unwrap();
        assert!(valid);
    }
}

// ============================================================================
// PROOF CHAIN STRESS TESTS
// ============================================================================

#[test]
fn stress_proof_chain_100() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_chain_stress";
    let mut previous_proof: Option<String> = None;

    for i in 0..100 {
        let binding = format!("POST|/api/step/{}|", i);
        let timestamp = format!("{}", 1000000000 + i);
        let payload = format!(r#"{{"step":{}}}"#, i);

        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, &binding).unwrap();
        let result = ash_core::ash_build_proof_unified(
            &secret, &timestamp, &binding, &payload, &[],
            previous_proof.as_deref()
        ).unwrap();

        assert_eq!(result.proof.len(), 64);

        if previous_proof.is_some() {
            assert!(!result.chain_hash.is_empty());
        }

        previous_proof = Some(result.proof);
    }
}

// ============================================================================
// TIMING SAFE COMPARISON STRESS TESTS
// ============================================================================

#[test]
fn stress_timing_safe_equal_500() {
    for i in 0..500 {
        let s = format!("comparison_test_{:06}", i);
        assert!(ash_core::ash_timing_safe_equal(s.as_bytes(), s.as_bytes()));
    }
}

#[test]
fn stress_timing_safe_unequal_500() {
    for i in 0..500 {
        let a = format!("string_a_{:06}", i);
        let b = format!("string_b_{:06}", i);
        assert!(!ash_core::ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
    }
}

// ============================================================================
// FULL WORKFLOW STRESS TESTS
// ============================================================================

#[test]
fn stress_full_workflow_500() {
    for i in 0..500 {
        let nonce = ash_core::ash_generate_nonce(32).unwrap();
        let ctx = format!("ctx_workflow_{}", i);
        let binding = format!("POST|/api/workflow/{}|", i);
        let timestamp = format!("{}", 1700000000 + i);
        let payload = format!(r#"{{"id":{},"action":"test","value":{}}}"#, i, i * 10);

        // 1. Canonicalize
        let canonical = ash_core::ash_canonicalize_json(&payload).unwrap();

        // 2. Hash body
        let body_hash = ash_core::ash_hash_body(&canonical);

        // 3. Derive secret
        let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, &binding).unwrap();

        // 4. Build proof
        let proof = ash_core::ash_build_proof(&secret, &timestamp, &binding, &body_hash).unwrap();

        // 5. Verify proof
        let valid = ash_core::ash_verify_proof(&nonce, &ctx, &binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(valid, "Workflow {} failed", i);
    }
}

#[test]
fn stress_full_workflow_different_contexts_1000() {
    let nonce = "a".repeat(64);

    for i in 0..1000 {
        let ctx = format!("ctx_{}", i);
        let binding = "POST|/api|";
        let timestamp = format!("{}", 1000000000 + i);
        let body_hash = ash_core::ash_hash_body("{}");

        let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, binding).unwrap();
        let proof = ash_core::ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

        let valid = ash_core::ash_verify_proof(&nonce, &ctx, binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(valid);
    }
}
