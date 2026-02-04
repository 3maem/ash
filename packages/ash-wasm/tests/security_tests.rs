//! Security-focused tests for ASH WASM bindings.
//! These tests use ash_core directly since wasm_bindgen functions can't run on native targets.

use ash_core;
use std::collections::HashSet;

// ============================================================================
// CRYPTOGRAPHIC RANDOMNESS TESTS
// ============================================================================

#[test]
fn nonce_entropy_check() {
    // Generate 1000 nonces and ensure they're all unique
    let mut nonces = HashSet::new();
    for _ in 0..1000 {
        let nonce = ash_core::ash_generate_nonce(32).unwrap();
        assert!(nonces.insert(nonce), "Duplicate nonce generated");
    }
    assert_eq!(nonces.len(), 1000);
}

#[test]
fn nonce_distribution_check() {
    // Generate many nonces and check that all hex digits appear
    let mut digit_counts = [0u32; 16];

    for _ in 0..100 {
        let nonce = ash_core::ash_generate_nonce(32).unwrap();
        for c in nonce.chars() {
            let idx = c.to_digit(16).unwrap() as usize;
            digit_counts[idx] += 1;
        }
    }

    // Each digit should appear at least once (statistically almost certain with 6400 chars)
    for (i, count) in digit_counts.iter().enumerate() {
        assert!(*count > 0, "Hex digit {:x} never appeared", i);
    }
}

#[test]
fn context_id_entropy_check() {
    let mut contexts = HashSet::new();
    for _ in 0..1000 {
        let ctx = ash_core::ash_generate_context_id().unwrap();
        assert!(contexts.insert(ctx), "Duplicate context ID generated");
    }
    assert_eq!(contexts.len(), 1000);
}

// ============================================================================
// PROOF SECURITY TESTS
// ============================================================================

#[test]
fn proof_changes_with_any_input_change() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let base_proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    // Change each component and verify proof changes
    let proofs = vec![
        // Different secret
        {
            let diff_secret = ash_core::ash_derive_client_secret(&"b".repeat(64), ctx, binding).unwrap();
            ash_core::ash_build_proof(&diff_secret, timestamp, binding, &body_hash).unwrap()
        },
        // Different timestamp
        ash_core::ash_build_proof(&secret, "1234567891", binding, &body_hash).unwrap(),
        // Different binding
        ash_core::ash_build_proof(&secret, timestamp, "GET|/api|", &body_hash).unwrap(),
        // Different body hash
        ash_core::ash_build_proof(&secret, timestamp, binding, &ash_core::ash_hash_body("other")).unwrap(),
    ];

    for (i, proof) in proofs.iter().enumerate() {
        assert_ne!(*proof, base_proof, "Proof unchanged for variation {}", i);
    }
}

#[test]
fn proof_verification_fails_on_any_tamper() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    // Verify original works
    assert!(ash_core::ash_verify_proof(&nonce, ctx, binding, timestamp, &body_hash, &proof).unwrap());

    // Test all tampering scenarios
    let tamperings = vec![
        ("nonce", ash_core::ash_verify_proof(&"b".repeat(64), ctx, binding, timestamp, &body_hash, &proof).unwrap()),
        ("context", ash_core::ash_verify_proof(&nonce, "wrong_ctx", binding, timestamp, &body_hash, &proof).unwrap()),
        ("binding", ash_core::ash_verify_proof(&nonce, ctx, "GET|/api|", timestamp, &body_hash, &proof).unwrap()),
        ("timestamp", ash_core::ash_verify_proof(&nonce, ctx, binding, "9999999999", &body_hash, &proof).unwrap()),
        ("body_hash", ash_core::ash_verify_proof(&nonce, ctx, binding, timestamp, &ash_core::ash_hash_body("tampered"), &proof).unwrap()),
        ("proof", ash_core::ash_verify_proof(&nonce, ctx, binding, timestamp, &body_hash, &"0".repeat(64)).unwrap()),
    ];

    for (name, result) in tamperings {
        assert!(!result, "Verification should fail for tampered {}", name);
    }
}

#[test]
fn proof_bit_flip_detection() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    // Flip each character in the proof and verify it fails
    for i in 0..proof.len() {
        let mut tampered: Vec<char> = proof.chars().collect();
        let original = tampered[i];
        tampered[i] = if original == '0' { '1' } else { '0' };
        let tampered_proof: String = tampered.into_iter().collect();

        let result = ash_core::ash_verify_proof(&nonce, ctx, binding, timestamp, &body_hash, &tampered_proof).unwrap();
        assert!(!result, "Bit flip at position {} should be detected", i);
    }
}

#[test]
fn secret_derivation_is_one_way() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    // Secret should be different from all inputs
    assert_ne!(secret, nonce);
    assert_ne!(secret, ctx);
    assert_ne!(secret, binding);

    // Secret should look random (all hex digits)
    assert!(secret.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn hash_collision_resistance() {
    // Generate hashes for many different inputs and check uniqueness
    let mut hashes = HashSet::new();

    for i in 0..1000 {
        let input = format!("test_input_{}", i);
        let hash = ash_core::ash_hash_body(&input);
        assert!(hashes.insert(hash), "Hash collision detected for input {}", i);
    }

    assert_eq!(hashes.len(), 1000);
}

#[test]
fn hash_avalanche_effect() {
    // Small change in input should cause large change in hash
    let hash1 = ash_core::ash_hash_body("test");
    let hash2 = ash_core::ash_hash_body("Test");  // Just capitalization change

    // Count different characters
    let diff_count: usize = hash1.chars().zip(hash2.chars())
        .filter(|(a, b)| a != b)
        .count();

    // With avalanche effect, roughly half the characters should differ
    assert!(diff_count > 20, "Avalanche effect weak: only {} chars differ", diff_count);
}

// ============================================================================
// TIMING ATTACK RESISTANCE TESTS
// ============================================================================

#[test]
fn timing_safe_equal_same_strings() {
    let a = "a".repeat(64);
    let b = "a".repeat(64);
    assert!(ash_core::ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
}

#[test]
fn timing_safe_equal_different_first_char() {
    let a = "a".repeat(64);
    let b = format!("b{}", "a".repeat(63));
    assert!(!ash_core::ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
}

#[test]
fn timing_safe_equal_different_last_char() {
    let a = "a".repeat(64);
    let b = format!("{}b", "a".repeat(63));
    assert!(!ash_core::ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
}

#[test]
fn timing_safe_equal_different_middle() {
    let a = "a".repeat(64);
    let b = format!("{}b{}", "a".repeat(32), "a".repeat(31));
    assert!(!ash_core::ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
}

#[test]
fn timing_safe_equal_different_lengths() {
    let a = "a".repeat(64);
    let b = "a".repeat(63);
    assert!(!ash_core::ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
}

// ============================================================================
// SCOPED PROOF SECURITY TESTS
// ============================================================================

#[test]
fn scoped_proof_protects_scoped_fields() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"amount":100,"recipient":"alice","memo":"test"}"#;
    let scope = &["amount", "recipient"];

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, payload, scope).unwrap();

    // Original should verify
    assert!(ash_core::ash_verify_proof_scoped(&nonce, ctx, binding, timestamp, payload, scope, &scope_hash, &proof).unwrap());

    // Modified scoped field should fail
    let modified_amount = r#"{"amount":200,"recipient":"alice","memo":"test"}"#;
    assert!(!ash_core::ash_verify_proof_scoped(&nonce, ctx, binding, timestamp, modified_amount, scope, &scope_hash, &proof).unwrap());

    // Modified non-scoped field should pass
    let modified_memo = r#"{"amount":100,"recipient":"alice","memo":"changed"}"#;
    assert!(ash_core::ash_verify_proof_scoped(&nonce, ctx, binding, timestamp, modified_memo, scope, &scope_hash, &proof).unwrap());
}

#[test]
fn scoped_proof_nested_field_protection() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let payload = r#"{"user":{"name":"alice","age":30},"action":"update"}"#;
    let scope = &["user.name"];

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, payload, scope).unwrap();

    // Modified protected nested field should fail
    let modified_name = r#"{"user":{"name":"bob","age":30},"action":"update"}"#;
    assert!(!ash_core::ash_verify_proof_scoped(&nonce, ctx, binding, timestamp, modified_name, scope, &scope_hash, &proof).unwrap());

    // Modified non-protected nested field should pass
    let modified_age = r#"{"user":{"name":"alice","age":31},"action":"update"}"#;
    assert!(ash_core::ash_verify_proof_scoped(&nonce, ctx, binding, timestamp, modified_age, scope, &scope_hash, &proof).unwrap());
}

// ============================================================================
// UNIFIED PROOF SECURITY TESTS
// ============================================================================

#[test]
fn unified_proof_chain_integrity() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let payload = r#"{"action":"step"}"#;

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    // Build chain
    let result1 = ash_core::ash_build_proof_unified(&secret, "1000000001", binding, payload, &[], None).unwrap();
    let result2 = ash_core::ash_build_proof_unified(&secret, "1000000002", binding, payload, &[], Some(&result1.proof)).unwrap();
    let result3 = ash_core::ash_build_proof_unified(&secret, "1000000003", binding, payload, &[], Some(&result2.proof)).unwrap();

    // Verify chain works correctly
    assert!(ash_core::ash_verify_proof_unified(&nonce, ctx, binding, "1000000003", payload, &result3.proof, &[], &result3.scope_hash, Some(&result2.proof), &result3.chain_hash).unwrap());

    // Verify wrong chain link fails
    assert!(!ash_core::ash_verify_proof_unified(&nonce, ctx, binding, "1000000003", payload, &result3.proof, &[], &result3.scope_hash, Some(&result1.proof), &result3.chain_hash).unwrap());
}

#[test]
fn unified_proof_scope_and_chain_security() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let payload = r#"{"amount":100,"memo":"test"}"#;
    let scope = &["amount"];
    let previous_proof = "b".repeat(64);

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result = ash_core::ash_build_proof_unified(&secret, "1234567890", binding, payload, scope, Some(&previous_proof)).unwrap();

    // Original should verify
    assert!(ash_core::ash_verify_proof_unified(&nonce, ctx, binding, "1234567890", payload, &result.proof, scope, &result.scope_hash, Some(&previous_proof), &result.chain_hash).unwrap());

    // Modified scoped field should fail
    let modified = r#"{"amount":200,"memo":"test"}"#;
    assert!(!ash_core::ash_verify_proof_unified(&nonce, ctx, binding, "1234567890", modified, &result.proof, scope, &result.scope_hash, Some(&previous_proof), &result.chain_hash).unwrap());

    // Wrong chain should fail
    let wrong_previous = "c".repeat(64);
    assert!(!ash_core::ash_verify_proof_unified(&nonce, ctx, binding, "1234567890", payload, &result.proof, scope, &result.scope_hash, Some(&wrong_previous), &result.chain_hash).unwrap());
}

// ============================================================================
// INPUT VALIDATION SECURITY TESTS
// ============================================================================

#[test]
fn json_rejects_malformed() {
    let malformed_inputs = vec![
        "{",
        "}",
        "{\"a\":",
        "{\"a\":}",
        "{\"a\":1,}",
        "[",
        "]",
        "[1,]",
        "{'a':1}",  // Single quotes
        "{a:1}",    // Unquoted key
        "",
    ];

    for input in malformed_inputs {
        assert!(ash_core::ash_canonicalize_json(input).is_err(), "Should reject: {}", input);
    }
}

#[test]
fn proof_handles_special_chars_safely() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";  // Valid context_id (only alphanumeric, underscore, hyphen, dot allowed)
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    // XSS attempt in body - should be safely hashed
    let body_hash = ash_core::ash_hash_body("<script>alert(1)</script>");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    // Should work without executing any scripts - body is safely hashed
    assert_eq!(proof.len(), 64);
    assert!(proof.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn context_id_rejects_special_chars() {
    let nonce = "a".repeat(64);
    let ctx = "ctx<script>alert(1)</script>";  // Invalid - contains special chars
    let binding = "POST|/api|";

    // Should be rejected due to invalid context_id
    let result = ash_core::ash_derive_client_secret(&nonce, ctx, binding);
    assert!(result.is_err());
}

#[test]
fn proof_handles_null_bytes_safely() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";  // Valid context_id
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    // Null bytes in body - should be safely hashed
    let body_hash = ash_core::ash_hash_body("test\x00data");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    // Body with null bytes should be safely hashed
    assert_eq!(proof.len(), 64);
}

#[test]
fn context_id_rejects_null_bytes() {
    let nonce = "a".repeat(64);
    let ctx = "ctx\x00test";  // Invalid - contains null byte
    let binding = "POST|/api|";

    // Should be rejected due to invalid context_id
    let result = ash_core::ash_derive_client_secret(&nonce, ctx, binding);
    assert!(result.is_err());
}

// ============================================================================
// STRESS TESTS
// ============================================================================

#[test]
fn stress_concurrent_proofs_100() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_stress";

    for i in 0..100 {
        let binding = format!("POST|/api/resource/{}|", i);
        let timestamp = format!("{}", 1000000000 + i);
        let body = format!(r#"{{"data":{}}}"#, i);
        let body_hash = ash_core::ash_hash_body(&body);

        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, &binding).unwrap();
        let proof = ash_core::ash_build_proof(&secret, &timestamp, &binding, &body_hash).unwrap();

        assert!(ash_core::ash_verify_proof(&nonce, ctx, &binding, &timestamp, &body_hash, &proof).unwrap());
    }
}

#[test]
fn stress_rapid_nonce_generation_1000() {
    let mut nonces = HashSet::new();
    for _ in 0..1000 {
        let nonce = ash_core::ash_generate_nonce(32).unwrap();
        nonces.insert(nonce);
    }
    assert_eq!(nonces.len(), 1000);
}

#[test]
fn stress_hash_computation_1000() {
    for i in 0..1000 {
        let input = format!("stress_test_input_{}_with_some_extra_content", i);
        let hash = ash_core::ash_hash_body(&input);
        assert_eq!(hash.len(), 64);
    }
}

#[test]
fn stress_json_canonicalization_500() {
    for i in 0..500 {
        let input = format!(r#"{{"z":{},"y":{},"x":{},"w":{},"v":{}}}"#, i, i+1, i+2, i+3, i+4);
        let result = ash_core::ash_canonicalize_json(&input).unwrap();
        assert!(result.starts_with("{\"v\":"));
    }
}

#[test]
fn stress_scoped_proof_100() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_scoped_stress";

    for i in 0..100 {
        let binding = format!("POST|/api/{}|", i);
        let timestamp = format!("{}", 1000000000 + i);
        let payload = format!(r#"{{"amount":{},"recipient":"user_{}","memo":"test_{}"}}"#, i * 100, i, i);
        let scope = &["amount", "recipient"];

        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, &binding).unwrap();
        let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, &timestamp, &binding, &payload, scope).unwrap();

        assert!(ash_core::ash_verify_proof_scoped(&nonce, ctx, &binding, &timestamp, &payload, scope, &scope_hash, &proof).unwrap());
    }
}

#[test]
fn stress_unified_proof_chain_20() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_chain_stress";
    let binding = "POST|/api|";

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    let mut previous_proof: Option<String> = None;

    for i in 0..20 {
        let timestamp = format!("{}", 1000000000 + i);
        let payload = format!(r#"{{"step":{}}}"#, i);

        let result = ash_core::ash_build_proof_unified(&secret, &timestamp, binding, &payload, &[], previous_proof.as_deref()).unwrap();

        let verified = ash_core::ash_verify_proof_unified(
            &nonce,
            ctx,
            binding,
            &timestamp,
            &payload,
            &result.proof,
            &[],
            &result.scope_hash,
            previous_proof.as_deref(),
            &result.chain_hash,
        ).unwrap();

        assert!(verified, "Failed at chain step {}", i);
        previous_proof = Some(result.proof);
    }
}
