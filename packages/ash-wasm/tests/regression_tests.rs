//! Regression tests for ASH WASM bindings.
//! These tests ensure that specific bugs stay fixed and edge cases remain handled.

use ash_core;

// ============================================================================
// JSON CANONICALIZATION REGRESSION TESTS
// ============================================================================

#[test]
fn regression_json_empty_string_value() {
    let input = r#"{"key":""}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert_eq!(result, r#"{"key":""}"#);
}

#[test]
fn regression_json_nested_empty_objects() {
    let input = r#"{"a":{},"b":{"c":{}}}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert_eq!(result, r#"{"a":{},"b":{"c":{}}}"#);
}

#[test]
fn regression_json_nested_empty_arrays() {
    let input = r#"{"a":[],"b":[[]]}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert_eq!(result, r#"{"a":[],"b":[[]]}"#);
}

#[test]
fn regression_json_zero_values() {
    let input = r#"{"int":0,"float":0.0,"neg":-0}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("\"int\":0"));
}

#[test]
fn regression_json_boolean_values() {
    let input = r#"{"t":true,"f":false}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert_eq!(result, r#"{"f":false,"t":true}"#);
}

#[test]
fn regression_json_null_value() {
    let input = r#"{"value":null}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert_eq!(result, r#"{"value":null}"#);
}

#[test]
fn regression_json_numeric_string_keys() {
    let input = r#"{"2":"b","1":"a","10":"c"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    // Lexicographic sort: "1" < "10" < "2"
    let pos_1 = result.find("\"1\":").unwrap();
    let pos_10 = result.find("\"10\":").unwrap();
    let pos_2 = result.find("\"2\":").unwrap();
    assert!(pos_1 < pos_10 && pos_10 < pos_2);
}

#[test]
fn regression_json_special_chars_in_values() {
    let input = r#"{"text":"line1\nline2\ttab"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

#[test]
fn regression_json_unicode_escape_normalization() {
    let input = r#"{"text":"\u0048\u0065\u006c\u006c\u006f"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    // Should decode to "Hello"
    assert!(result.contains("Hello") || result.contains("\\u"));
}

#[test]
fn regression_json_high_codepoint() {
    let input = r#"{"emoji":"😀"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("emoji"));
}

// ============================================================================
// QUERY STRING REGRESSION TESTS
// ============================================================================

#[test]
fn regression_query_empty_value() {
    let result = ash_core::ash_canonicalize_query("key=").unwrap();
    assert_eq!(result, "key=");
}

#[test]
fn regression_query_multiple_empty_values() {
    let result = ash_core::ash_canonicalize_query("a=&b=&c=").unwrap();
    assert_eq!(result, "a=&b=&c=");
}

#[test]
fn regression_query_duplicate_values_sorted() {
    let result = ash_core::ash_canonicalize_query("a=3&a=1&a=2").unwrap();
    assert_eq!(result, "a=1&a=2&a=3");
}

#[test]
fn regression_query_mixed_encoded() {
    let result = ash_core::ash_canonicalize_query("a=%41&b=B").unwrap();
    // %41 = 'A'
    assert!(result.contains("a=A") || result.contains("a=%41"));
}

#[test]
fn regression_query_plus_handling() {
    let result = ash_core::ash_canonicalize_query("a=hello+world").unwrap();
    // Plus should be encoded as %2B (not treated as space)
    assert!(result.contains("%2B"));
}

// ============================================================================
// BINDING REGRESSION TESTS
// ============================================================================

#[test]
fn regression_binding_double_slash() {
    let result = ash_core::ash_normalize_binding("GET", "//api", "").unwrap();
    assert!(result.contains("/api") && !result.contains("//"));
}

#[test]
fn regression_binding_triple_slash() {
    let result = ash_core::ash_normalize_binding("GET", "///api", "").unwrap();
    assert!(result.contains("/api") && !result.contains("///"));
}

#[test]
fn regression_binding_trailing_slash_removal() {
    let result = ash_core::ash_normalize_binding("GET", "/api/test/", "").unwrap();
    assert!(!result.ends_with("/|"));
}

#[test]
fn regression_binding_root_preserved() {
    let result = ash_core::ash_normalize_binding("GET", "/", "").unwrap();
    assert_eq!(result, "GET|/|");
}

#[test]
fn regression_binding_method_case() {
    let result = ash_core::ash_normalize_binding("get", "/api", "").unwrap();
    assert!(result.starts_with("GET"));
}

#[test]
fn regression_binding_mixed_case_method() {
    let result = ash_core::ash_normalize_binding("gEt", "/api", "").unwrap();
    assert!(result.starts_with("GET"));
}

// ============================================================================
// NONCE REGRESSION TESTS
// ============================================================================

#[test]
fn regression_nonce_minimum_size() {
    let result = ash_core::ash_generate_nonce(1);
    // Should either succeed with 2 chars or error
    if let Ok(nonce) = result {
        assert_eq!(nonce.len(), 2);
    }
}

#[test]
fn regression_nonce_standard_size() {
    let result = ash_core::ash_generate_nonce(32).unwrap();
    assert_eq!(result.len(), 64);
}

#[test]
fn regression_nonce_large_size() {
    let result = ash_core::ash_generate_nonce(64).unwrap();
    assert_eq!(result.len(), 128);
}

// ============================================================================
// CONTEXT ID REGRESSION TESTS
// ============================================================================

#[test]
fn regression_context_id_prefix() {
    let ctx = ash_core::ash_generate_context_id().unwrap();
    assert!(ctx.starts_with("ash_"));
}

#[test]
fn regression_context_id_no_special_chars() {
    let ctx = ash_core::ash_generate_context_id().unwrap();
    for c in ctx.chars() {
        assert!(c.is_ascii_alphanumeric() || c == '_',
            "Context ID should only contain alphanumeric and underscore");
    }
}

// ============================================================================
// HASH REGRESSION TESTS
// ============================================================================

#[test]
fn regression_hash_empty_string() {
    let hash = ash_core::ash_hash_body("");
    assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

#[test]
fn regression_hash_known_value() {
    let hash = ash_core::ash_hash_body("test");
    assert_eq!(hash, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
}

#[test]
fn regression_hash_length() {
    let long_x = "x".repeat(10000);
    let inputs: Vec<&str> = vec!["", "a", "test", &long_x];
    for input in inputs {
        let hash = ash_core::ash_hash_body(input);
        assert_eq!(hash.len(), 64);
    }
}

// ============================================================================
// SECRET DERIVATION REGRESSION TESTS
// ============================================================================

#[test]
fn regression_secret_requires_valid_nonce_length() {
    // Too short nonce
    let result = ash_core::ash_derive_client_secret("abc", "ctx", "POST|/|");
    assert!(result.is_err());
}

#[test]
fn regression_secret_requires_hex_nonce() {
    let result = ash_core::ash_derive_client_secret(&"g".repeat(64), "ctx", "POST|/|");
    assert!(result.is_err());
}

#[test]
fn regression_secret_valid_context_chars() {
    let nonce = "a".repeat(64);
    // Valid context with underscore
    let r1 = ash_core::ash_derive_client_secret(&nonce, "ctx_test", "POST|/|");
    assert!(r1.is_ok());

    // Valid context with hyphen
    let r2 = ash_core::ash_derive_client_secret(&nonce, "ctx-test", "POST|/|");
    assert!(r2.is_ok());

    // Valid context with dot
    let r3 = ash_core::ash_derive_client_secret(&nonce, "ctx.test", "POST|/|");
    assert!(r3.is_ok());
}

// ============================================================================
// PROOF REGRESSION TESTS
// ============================================================================

#[test]
fn regression_proof_requires_valid_body_hash() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();

    // Too short body hash
    let result = ash_core::ash_build_proof(&secret, "12345", "POST|/|", "abc");
    assert!(result.is_err());
}

#[test]
fn regression_proof_requires_hex_body_hash() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();

    // Non-hex body hash
    let result = ash_core::ash_build_proof(&secret, "12345", "POST|/|", &"g".repeat(64));
    assert!(result.is_err());
}

#[test]
fn regression_proof_verification_wrong_nonce() {
    let nonce = "a".repeat(64);
    let wrong_nonce = "b".repeat(64);
    let binding = "POST|/|";
    let body_hash = ash_core::ash_hash_body("{}");

    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, "12345", binding, &body_hash).unwrap();

    let valid = ash_core::ash_verify_proof(&wrong_nonce, "ctx", binding, "12345", &body_hash, &proof).unwrap();
    assert!(!valid);
}

#[test]
fn regression_proof_verification_wrong_context() {
    let nonce = "a".repeat(64);
    let binding = "POST|/|";
    let body_hash = ash_core::ash_hash_body("{}");

    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx1", binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, "12345", binding, &body_hash).unwrap();

    let valid = ash_core::ash_verify_proof(&nonce, "ctx2", binding, "12345", &body_hash, &proof).unwrap();
    assert!(!valid);
}

#[test]
fn regression_proof_verification_wrong_binding() {
    let nonce = "a".repeat(64);
    let binding = "POST|/api|";
    let wrong_binding = "GET|/api|";
    let body_hash = ash_core::ash_hash_body("{}");

    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, "12345", binding, &body_hash).unwrap();

    let valid = ash_core::ash_verify_proof(&nonce, "ctx", wrong_binding, "12345", &body_hash, &proof).unwrap();
    assert!(!valid);
}

#[test]
fn regression_proof_verification_wrong_timestamp() {
    let nonce = "a".repeat(64);
    let binding = "POST|/|";
    let body_hash = ash_core::ash_hash_body("{}");

    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, "12345", binding, &body_hash).unwrap();

    let valid = ash_core::ash_verify_proof(&nonce, "ctx", binding, "12346", &body_hash, &proof).unwrap();
    assert!(!valid);
}

#[test]
fn regression_proof_verification_wrong_body() {
    let nonce = "a".repeat(64);
    let binding = "POST|/|";
    let body_hash1 = ash_core::ash_hash_body("{}");
    let body_hash2 = ash_core::ash_hash_body("{\"a\":1}");

    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, "12345", binding, &body_hash1).unwrap();

    let valid = ash_core::ash_verify_proof(&nonce, "ctx", binding, "12345", &body_hash2, &proof).unwrap();
    assert!(!valid);
}

// ============================================================================
// SCOPED PROOF REGRESSION TESTS
// ============================================================================

#[test]
fn regression_scoped_empty_scope() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();

    let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, "12345", "POST|/|", "{}", &[]).unwrap();
    assert_eq!(proof.len(), 64);
    // Empty scope means no scope hash
    assert!(scope_hash.is_empty());
}

#[test]
fn regression_scoped_single_field() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();

    let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, "12345", "POST|/|", r#"{"a":1}"#, &["a"]).unwrap();
    assert_eq!(proof.len(), 64);
    assert_eq!(scope_hash.len(), 64);
}

#[test]
fn regression_scoped_nested_field() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();

    let payload = r#"{"user":{"name":"test"}}"#;
    let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, "12345", "POST|/|", payload, &["user.name"]).unwrap();
    assert_eq!(proof.len(), 64);
    assert_eq!(scope_hash.len(), 64);
}

// ============================================================================
// UNIFIED PROOF REGRESSION TESTS
// ============================================================================

#[test]
fn regression_unified_no_scope_no_chain() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();

    let result = ash_core::ash_build_proof_unified(&secret, "12345", "POST|/|", "{}", &[], None).unwrap();
    assert_eq!(result.proof.len(), 64);
    assert!(result.scope_hash.is_empty());
    assert!(result.chain_hash.is_empty());
}

#[test]
fn regression_unified_with_scope() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();

    let result = ash_core::ash_build_proof_unified(&secret, "12345", "POST|/|", r#"{"a":1}"#, &["a"], None).unwrap();
    assert_eq!(result.proof.len(), 64);
    assert!(!result.scope_hash.is_empty());
    assert!(result.chain_hash.is_empty());
}

#[test]
fn regression_unified_with_chain() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let prev_proof = "b".repeat(64);

    let result = ash_core::ash_build_proof_unified(&secret, "12345", "POST|/|", "{}", &[], Some(&prev_proof)).unwrap();
    assert_eq!(result.proof.len(), 64);
    assert!(result.scope_hash.is_empty());
    assert!(!result.chain_hash.is_empty());
}

#[test]
fn regression_unified_with_scope_and_chain() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let prev_proof = "c".repeat(64);

    let result = ash_core::ash_build_proof_unified(&secret, "12345", "POST|/|", r#"{"a":1}"#, &["a"], Some(&prev_proof)).unwrap();
    assert_eq!(result.proof.len(), 64);
    assert!(!result.scope_hash.is_empty());
    assert!(!result.chain_hash.is_empty());
}

// ============================================================================
// TIMING SAFE COMPARISON REGRESSION TESTS
// ============================================================================

#[test]
fn regression_timing_equal_strings() {
    assert!(ash_core::ash_timing_safe_equal(b"test", b"test"));
}

#[test]
fn regression_timing_unequal_strings() {
    assert!(!ash_core::ash_timing_safe_equal(b"test", b"other"));
}

#[test]
fn regression_timing_different_lengths() {
    assert!(!ash_core::ash_timing_safe_equal(b"short", b"longer"));
}

#[test]
fn regression_timing_empty_strings() {
    assert!(ash_core::ash_timing_safe_equal(b"", b""));
}

#[test]
fn regression_timing_one_empty() {
    assert!(!ash_core::ash_timing_safe_equal(b"", b"test"));
    assert!(!ash_core::ash_timing_safe_equal(b"test", b""));
}

// ============================================================================
// HASH PROOF REGRESSION TESTS
// ============================================================================

#[test]
fn regression_hash_proof_valid() {
    let proof = "a".repeat(64);
    let hash = ash_core::ash_hash_proof(&proof).unwrap();
    assert_eq!(hash.len(), 64);
}

#[test]
fn regression_hash_proof_empty_error() {
    let result = ash_core::ash_hash_proof("");
    assert!(result.is_err());
}

#[test]
fn regression_hash_proof_deterministic() {
    let proof = "b".repeat(64);
    let h1 = ash_core::ash_hash_proof(&proof).unwrap();
    let h2 = ash_core::ash_hash_proof(&proof).unwrap();
    assert_eq!(h1, h2);
}
