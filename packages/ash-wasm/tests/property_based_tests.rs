//! Property-based tests for ASH WASM bindings.
//! Tests that verify invariants and properties that should always hold.

use ash_core;
use std::collections::HashSet;

// ============================================================================
// HASH PROPERTIES
// ============================================================================

#[test]
fn property_hash_deterministic_100() {
    for i in 0..100 {
        let input = format!("test_input_{}", i);
        let hash1 = ash_core::ash_hash_body(&input);
        let hash2 = ash_core::ash_hash_body(&input);
        assert_eq!(hash1, hash2, "Hash must be deterministic");
    }
}

#[test]
fn property_hash_length_always_64() {
    let long_x = "x".repeat(1000);
    let long_y = "y".repeat(10000);
    let inputs: Vec<&str> = vec![
        "",
        "a",
        "test",
        &long_x,
        &long_y,
        "unicode: 你好世界 🎉",
        "\n\t\r",
        "null\x00byte",
    ];

    for input in inputs {
        let hash = ash_core::ash_hash_body(input);
        assert_eq!(hash.len(), 64, "Hash length must always be 64");
    }
}

#[test]
fn property_hash_always_hex() {
    for i in 0..100 {
        let input = format!("random_input_for_hex_test_{}", i);
        let hash = ash_core::ash_hash_body(&input);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()),
            "Hash must contain only hex characters");
    }
}

#[test]
fn property_hash_different_inputs_different_outputs() {
    let mut hashes = HashSet::new();
    for i in 0..1000 {
        let input = format!("unique_input_{}", i);
        let hash = ash_core::ash_hash_body(&input);
        assert!(hashes.insert(hash), "Each input should produce unique hash");
    }
}

#[test]
fn property_hash_lowercase() {
    for i in 0..100 {
        let input = format!("lowercase_test_{}", i);
        let hash = ash_core::ash_hash_body(&input);
        assert_eq!(hash, hash.to_lowercase(), "Hash must be lowercase");
    }
}

// ============================================================================
// JSON CANONICALIZATION PROPERTIES
// ============================================================================

#[test]
fn property_json_idempotent_100() {
    for i in 0..100 {
        let json = format!(r#"{{"z":{},"a":{},"m":{}}}"#, i, i + 1, i + 2);
        let once = ash_core::ash_canonicalize_json(&json).unwrap();
        let twice = ash_core::ash_canonicalize_json(&once).unwrap();
        assert_eq!(once, twice, "Canonicalization must be idempotent");
    }
}

#[test]
fn property_json_no_whitespace() {
    let jsons = vec![
        r#"{ "a" : 1 }"#,
        "{\n\"a\":\n1\n}",
        "{\t\"a\":\t1\t}",
        "{  \"a\":  1  }",
    ];

    for json in jsons {
        let result = ash_core::ash_canonicalize_json(json).unwrap();
        assert!(!result.contains(' '), "Canonical JSON should have no spaces");
        assert!(!result.contains('\n'), "Canonical JSON should have no newlines");
        assert!(!result.contains('\t'), "Canonical JSON should have no tabs");
    }
}

#[test]
fn property_json_keys_sorted_100() {
    for i in 0..100 {
        let json = format!(r#"{{"z":{},"a":{},"m":{},"b":{},"y":{}}}"#, i, i+1, i+2, i+3, i+4);
        let result = ash_core::ash_canonicalize_json(&json).unwrap();

        // Check key order
        let a_pos = result.find("\"a\"").unwrap();
        let b_pos = result.find("\"b\"").unwrap();
        let m_pos = result.find("\"m\"").unwrap();
        let y_pos = result.find("\"y\"").unwrap();
        let z_pos = result.find("\"z\"").unwrap();

        assert!(a_pos < b_pos && b_pos < m_pos && m_pos < y_pos && y_pos < z_pos,
            "Keys must be sorted");
    }
}

#[test]
fn property_json_array_order_preserved_100() {
    for i in 0..100 {
        let json = format!(r#"{{"arr":[{},{},{}]}}"#, i+2, i, i+1);
        let result = ash_core::ash_canonicalize_json(&json).unwrap();
        let expected = format!(r#"{{"arr":[{},{},{}]}}"#, i+2, i, i+1);
        assert_eq!(result, expected, "Array order must be preserved");
    }
}

// ============================================================================
// QUERY STRING PROPERTIES
// ============================================================================

#[test]
fn property_query_idempotent_100() {
    for i in 0..100 {
        let query = format!("z={}&a={}&m={}", i, i+1, i+2);
        let once = ash_core::ash_canonicalize_query(&query).unwrap();
        let twice = ash_core::ash_canonicalize_query(&once).unwrap();
        assert_eq!(once, twice, "Query canonicalization must be idempotent");
    }
}

#[test]
fn property_query_keys_sorted_100() {
    for i in 0..100 {
        let query = format!("z={}&a={}&m={}", i, i+1, i+2);
        let result = ash_core::ash_canonicalize_query(&query).unwrap();

        let a_pos = result.find("a=").unwrap();
        let m_pos = result.find("m=").unwrap();
        let z_pos = result.find("z=").unwrap();

        assert!(a_pos < m_pos && m_pos < z_pos, "Keys must be sorted");
    }
}

#[test]
fn property_query_no_leading_question_mark() {
    let queries = vec!["?a=1", "?a=1&b=2", "?"];
    for query in queries {
        let result = ash_core::ash_canonicalize_query(query).unwrap();
        assert!(!result.starts_with('?'), "Result should not start with ?");
    }
}

// ============================================================================
// BINDING PROPERTIES
// ============================================================================

#[test]
fn property_binding_uppercase_method_100() {
    let methods = ["get", "post", "put", "delete", "patch"];
    for i in 0..100 {
        let method = methods[i % methods.len()];
        let result = ash_core::ash_normalize_binding(method, "/api", "").unwrap();
        assert!(result.starts_with(&method.to_uppercase()),
            "Method must be uppercased");
    }
}

#[test]
fn property_binding_has_pipe_separators() {
    for i in 0..100 {
        let path = format!("/api/{}", i);
        let result = ash_core::ash_normalize_binding("GET", &path, "").unwrap();
        assert_eq!(result.matches('|').count(), 2, "Binding must have exactly 2 pipes");
    }
}

#[test]
fn property_binding_idempotent() {
    // Once normalized, normalizing again should give same result
    for i in 0..50 {
        let path = format!("/api//test/{}/", i);
        let first = ash_core::ash_normalize_binding("get", &path, "z=1&a=2").unwrap();

        // Extract parts from first result
        let parts: Vec<&str> = first.split('|').collect();
        let method = parts[0];
        let norm_path = format!("/{}", parts[1].trim_start_matches('/'));
        let query = parts[2];

        let second = ash_core::ash_normalize_binding(method, &norm_path, query).unwrap();
        assert_eq!(first, second, "Binding normalization must be idempotent");
    }
}

// ============================================================================
// NONCE PROPERTIES
// ============================================================================

#[test]
fn property_nonce_always_hex() {
    for _ in 0..100 {
        let nonce = ash_core::ash_generate_nonce(32).unwrap();
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()),
            "Nonce must be hex");
    }
}

#[test]
fn property_nonce_correct_length() {
    // Minimum is 16 bytes for adequate entropy
    let sizes = [16, 32, 64, 128];
    for size in sizes {
        for _ in 0..25 {
            let nonce = ash_core::ash_generate_nonce(size).unwrap();
            assert_eq!(nonce.len(), size * 2, "Nonce length must be 2x byte size");
        }
    }
}

#[test]
fn property_nonce_always_unique() {
    let mut seen = HashSet::new();
    for _ in 0..1000 {
        let nonce = ash_core::ash_generate_nonce(32).unwrap();
        assert!(seen.insert(nonce), "Nonces must be unique");
    }
}

// ============================================================================
// CONTEXT ID PROPERTIES
// ============================================================================

#[test]
fn property_context_id_has_prefix() {
    for _ in 0..100 {
        let ctx = ash_core::ash_generate_context_id().unwrap();
        assert!(ctx.starts_with("ash_"), "Context ID must start with ash_");
    }
}

#[test]
fn property_context_id_valid_chars() {
    for _ in 0..100 {
        let ctx = ash_core::ash_generate_context_id().unwrap();
        assert!(ctx.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "Context ID must contain only alphanumeric and underscore");
    }
}

#[test]
fn property_context_id_always_unique() {
    let mut seen = HashSet::new();
    for _ in 0..1000 {
        let ctx = ash_core::ash_generate_context_id().unwrap();
        assert!(seen.insert(ctx), "Context IDs must be unique");
    }
}

// ============================================================================
// SECRET DERIVATION PROPERTIES
// ============================================================================

#[test]
fn property_secret_deterministic_100() {
    let nonce = "a".repeat(64);
    for i in 0..100 {
        let ctx = format!("ctx_{}", i);
        let binding = "POST|/api|";

        let s1 = ash_core::ash_derive_client_secret(&nonce, &ctx, binding).unwrap();
        let s2 = ash_core::ash_derive_client_secret(&nonce, &ctx, binding).unwrap();
        assert_eq!(s1, s2, "Secret derivation must be deterministic");
    }
}

#[test]
fn property_secret_length_always_64() {
    let nonce = "a".repeat(64);
    for i in 0..100 {
        let ctx = format!("ctx_{}", i);
        let binding = format!("POST|/api/{}|", i);

        let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, &binding).unwrap();
        assert_eq!(secret.len(), 64, "Secret must be 64 chars");
    }
}

#[test]
fn property_secret_different_inputs_different_outputs() {
    let nonce = "a".repeat(64);
    let mut secrets = HashSet::new();

    for i in 0..100 {
        let ctx = format!("ctx_{}", i);
        let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, "POST|/api|").unwrap();
        assert!(secrets.insert(secret), "Different inputs should give different secrets");
    }
}

// ============================================================================
// PROOF PROPERTIES
// ============================================================================

#[test]
fn property_proof_deterministic_100() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    for i in 0..100 {
        let timestamp = format!("{}", 1000000000 + i);
        let body_hash = ash_core::ash_hash_body("{}");

        let p1 = ash_core::ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();
        let p2 = ash_core::ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();
        assert_eq!(p1, p2, "Proof must be deterministic");
    }
}

#[test]
fn property_proof_length_always_64() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    for i in 0..100 {
        let timestamp = format!("{}", 1000000000 + i);
        let body_hash = ash_core::ash_hash_body(&format!("body_{}", i));

        let proof = ash_core::ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();
        assert_eq!(proof.len(), 64, "Proof must be 64 chars");
    }
}

#[test]
fn property_proof_verifies_correctly_100() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";

    for i in 0..100 {
        let timestamp = format!("{}", 1000000000 + i);
        let body_hash = ash_core::ash_hash_body(&format!("body_{}", i));

        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
        let proof = ash_core::ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

        let valid = ash_core::ash_verify_proof(&nonce, ctx, binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(valid, "Valid proof must verify");
    }
}

#[test]
fn property_proof_rejects_tampered_100() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let body_hash = ash_core::ash_hash_body("{}");
    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    for i in 0..100 {
        let timestamp = format!("{}", 1000000000 + i);
        let proof = ash_core::ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

        // Tamper with proof
        let mut chars: Vec<char> = proof.chars().collect();
        let pos = i % 64;
        chars[pos] = if chars[pos] == 'a' { 'b' } else { 'a' };
        let tampered: String = chars.into_iter().collect();

        let valid = ash_core::ash_verify_proof(&nonce, ctx, binding, &timestamp, &body_hash, &tampered).unwrap();
        assert!(!valid, "Tampered proof must not verify");
    }
}

// ============================================================================
// TIMING SAFE COMPARISON PROPERTIES
// ============================================================================

#[test]
fn property_timing_safe_reflexive() {
    for i in 0..100 {
        let s = format!("test_string_{}", i);
        assert!(ash_core::ash_timing_safe_equal(s.as_bytes(), s.as_bytes()),
            "String must equal itself");
    }
}

#[test]
fn property_timing_safe_symmetric() {
    for i in 0..100 {
        let a = format!("string_a_{}", i);
        let b = format!("string_b_{}", i);

        let ab = ash_core::ash_timing_safe_equal(a.as_bytes(), b.as_bytes());
        let ba = ash_core::ash_timing_safe_equal(b.as_bytes(), a.as_bytes());
        assert_eq!(ab, ba, "Comparison must be symmetric");
    }
}

// ============================================================================
// SCOPED PROOF PROPERTIES
// ============================================================================

#[test]
fn property_scoped_proof_verifies_100() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";

    for i in 0..100 {
        let timestamp = format!("{}", 1000000000 + i);
        let payload = format!(r#"{{"a":{},"b":{}}}"#, i, i+1);
        let scope = &["a"];

        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
        let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, &timestamp, binding, &payload, scope).unwrap();

        let valid = ash_core::ash_verify_proof_scoped(&nonce, ctx, binding, &timestamp, &payload, scope, &scope_hash, &proof).unwrap();
        assert!(valid, "Valid scoped proof must verify");
    }
}

#[test]
fn property_scoped_allows_non_scoped_changes() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let timestamp = "1000000000";
    let scope = &["amount"];

    for i in 0..50 {
        let original = format!(r#"{{"amount":100,"note":"note_{}"}}"#, i);
        let modified = format!(r#"{{"amount":100,"note":"modified_{}"}}"#, i);

        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
        let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, &original, scope).unwrap();

        // Verify with modified payload (non-scoped field changed)
        let valid = ash_core::ash_verify_proof_scoped(&nonce, ctx, binding, timestamp, &modified, scope, &scope_hash, &proof).unwrap();
        assert!(valid, "Non-scoped field changes should verify");
    }
}

#[test]
fn property_scoped_rejects_scoped_changes() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let timestamp = "1000000000";
    let scope = &["amount"];

    for i in 0..50 {
        let original = format!(r#"{{"amount":{},"note":"test"}}"#, i);
        let modified = format!(r#"{{"amount":{},"note":"test"}}"#, i + 1);

        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
        let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, &original, scope).unwrap();

        // Verify with modified payload (scoped field changed)
        let valid = ash_core::ash_verify_proof_scoped(&nonce, ctx, binding, timestamp, &modified, scope, &scope_hash, &proof).unwrap();
        assert!(!valid, "Scoped field changes should not verify");
    }
}

// ============================================================================
// UNIFIED PROOF PROPERTIES
// ============================================================================

#[test]
fn property_unified_basic_verifies_100() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";

    for i in 0..100 {
        let binding = format!("POST|/api/{}|", i);
        let timestamp = format!("{}", 1000000000 + i);
        let payload = format!(r#"{{"id":{}}}"#, i);

        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, &binding).unwrap();
        let result = ash_core::ash_build_proof_unified(&secret, &timestamp, &binding, &payload, &[], None).unwrap();

        let valid = ash_core::ash_verify_proof_unified(
            &nonce, ctx, &binding, &timestamp, &payload, &result.proof,
            &[], "", None, ""
        ).unwrap();
        assert!(valid, "Valid unified proof must verify");
    }
}

#[test]
fn property_unified_chain_hash_deterministic() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let timestamp = "1000000000";
    let payload = "{}";
    let prev_proof = "b".repeat(64);

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    let r1 = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], Some(&prev_proof)).unwrap();
    let r2 = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], Some(&prev_proof)).unwrap();

    assert_eq!(r1.chain_hash, r2.chain_hash, "Chain hash must be deterministic");
}
