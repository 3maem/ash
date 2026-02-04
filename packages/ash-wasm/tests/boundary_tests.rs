//! Boundary condition tests for ASH WASM bindings.
//! Tests edge cases at boundaries of valid input ranges.

use ash_core;

// ============================================================================
// NONCE BOUNDARY TESTS
// ============================================================================

#[test]
fn boundary_nonce_min_valid_16_bytes() {
    let result = ash_core::ash_generate_nonce(16);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 32);
}

#[test]
fn boundary_nonce_15_bytes_fails() {
    let result = ash_core::ash_generate_nonce(15);
    assert!(result.is_err());
}

#[test]
fn boundary_nonce_17_bytes_ok() {
    let result = ash_core::ash_generate_nonce(17);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 34);
}

#[test]
fn boundary_nonce_32_bytes() {
    let result = ash_core::ash_generate_nonce(32);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 64);
}

#[test]
fn boundary_nonce_64_bytes() {
    let result = ash_core::ash_generate_nonce(64);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 128);
}

#[test]
fn boundary_nonce_128_bytes() {
    let result = ash_core::ash_generate_nonce(128);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 256);
}

#[test]
fn boundary_nonce_256_bytes() {
    let result = ash_core::ash_generate_nonce(256);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 512);
}

// ============================================================================
// TIMESTAMP BOUNDARY TESTS
// ============================================================================

#[test]
fn boundary_timestamp_current_valid() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let result = ash_core::ash_validate_timestamp(&now.to_string(), 300, 60);
    assert!(result.is_ok());
}

#[test]
fn boundary_timestamp_zero_invalid() {
    let result = ash_core::ash_validate_timestamp("0", 300, 60);
    assert!(result.is_err());
}

#[test]
fn boundary_timestamp_negative_invalid() {
    let result = ash_core::ash_validate_timestamp("-1", 300, 60);
    assert!(result.is_err());
}

#[test]
fn boundary_timestamp_200_sec_past_valid() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let result = ash_core::ash_validate_timestamp(&(now - 200).to_string(), 300, 60);
    assert!(result.is_ok());
}

#[test]
fn boundary_timestamp_400_sec_past_invalid() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let result = ash_core::ash_validate_timestamp(&(now - 400).to_string(), 300, 60);
    assert!(result.is_err());
}

#[test]
fn boundary_timestamp_30_sec_future_valid() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let result = ash_core::ash_validate_timestamp(&(now + 30).to_string(), 300, 60);
    assert!(result.is_ok());
}

#[test]
fn boundary_timestamp_120_sec_future_invalid() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let result = ash_core::ash_validate_timestamp(&(now + 120).to_string(), 300, 60);
    assert!(result.is_err());
}

#[test]
fn boundary_timestamp_empty_invalid() {
    let result = ash_core::ash_validate_timestamp("", 300, 60);
    assert!(result.is_err());
}

#[test]
fn boundary_timestamp_non_numeric_invalid() {
    let result = ash_core::ash_validate_timestamp("abc", 300, 60);
    assert!(result.is_err());
}

#[test]
fn boundary_timestamp_float_invalid() {
    let result = ash_core::ash_validate_timestamp("1234567890.5", 300, 60);
    assert!(result.is_err());
}

// ============================================================================
// HASH BOUNDARY TESTS
// ============================================================================

#[test]
fn boundary_hash_empty() {
    let hash = ash_core::ash_hash_body("");
    assert_eq!(hash.len(), 64);
}

#[test]
fn boundary_hash_single_char() {
    let hash = ash_core::ash_hash_body("a");
    assert_eq!(hash.len(), 64);
}

#[test]
fn boundary_hash_null_byte() {
    let hash = ash_core::ash_hash_body("\x00");
    assert_eq!(hash.len(), 64);
}

#[test]
fn boundary_hash_1kb() {
    let input = "x".repeat(1024);
    let hash = ash_core::ash_hash_body(&input);
    assert_eq!(hash.len(), 64);
}

#[test]
fn boundary_hash_10kb() {
    let input = "x".repeat(10240);
    let hash = ash_core::ash_hash_body(&input);
    assert_eq!(hash.len(), 64);
}

#[test]
fn boundary_hash_100kb() {
    let input = "x".repeat(102400);
    let hash = ash_core::ash_hash_body(&input);
    assert_eq!(hash.len(), 64);
}

#[test]
fn boundary_hash_1mb() {
    let input = "x".repeat(1048576);
    let hash = ash_core::ash_hash_body(&input);
    assert_eq!(hash.len(), 64);
}

// ============================================================================
// JSON CANONICALIZATION BOUNDARY TESTS
// ============================================================================

#[test]
fn boundary_json_empty_object() {
    let result = ash_core::ash_canonicalize_json("{}");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "{}");
}

#[test]
fn boundary_json_empty_array() {
    let result = ash_core::ash_canonicalize_json("[]");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "[]");
}

#[test]
fn boundary_json_null() {
    let result = ash_core::ash_canonicalize_json("null");
    assert!(result.is_ok());
}

#[test]
fn boundary_json_true() {
    let result = ash_core::ash_canonicalize_json("true");
    assert!(result.is_ok());
}

#[test]
fn boundary_json_false() {
    let result = ash_core::ash_canonicalize_json("false");
    assert!(result.is_ok());
}

#[test]
fn boundary_json_zero() {
    let result = ash_core::ash_canonicalize_json("0");
    assert!(result.is_ok());
}

#[test]
fn boundary_json_empty_string() {
    let result = ash_core::ash_canonicalize_json("\"\"");
    assert!(result.is_ok());
}

#[test]
fn boundary_json_nested_10_levels() {
    let json = "{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":{\"g\":{\"h\":{\"i\":{\"j\":1}}}}}}}}}}";
    let result = ash_core::ash_canonicalize_json(json);
    assert!(result.is_ok());
}

#[test]
fn boundary_json_100_keys() {
    let pairs: Vec<String> = (0..100).map(|i| format!("\"k{}\":\"v{}\"", i, i)).collect();
    let json = format!("{{{}}}", pairs.join(","));
    let result = ash_core::ash_canonicalize_json(&json);
    assert!(result.is_ok());
}

#[test]
fn boundary_json_1000_element_array() {
    let elements: Vec<String> = (0..1000).map(|i| i.to_string()).collect();
    let json = format!("[{}]", elements.join(","));
    let result = ash_core::ash_canonicalize_json(&json);
    assert!(result.is_ok());
}

// ============================================================================
// QUERY STRING BOUNDARY TESTS
// ============================================================================

#[test]
fn boundary_query_empty() {
    let result = ash_core::ash_canonicalize_query("");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "");
}

#[test]
fn boundary_query_single_param() {
    let result = ash_core::ash_canonicalize_query("a=b");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "a=b");
}

#[test]
fn boundary_query_100_params() {
    let params: Vec<String> = (0..100).map(|i| format!("k{}=v{}", i, i)).collect();
    let query = params.join("&");
    let result = ash_core::ash_canonicalize_query(&query);
    assert!(result.is_ok());
}

#[test]
fn boundary_query_long_value() {
    let value = "x".repeat(1000);
    let query = format!("key={}", value);
    let result = ash_core::ash_canonicalize_query(&query);
    assert!(result.is_ok());
}

#[test]
fn boundary_query_with_leading_question_mark() {
    let result = ash_core::ash_canonicalize_query("?a=b");
    assert!(result.is_ok());
}

// ============================================================================
// BINDING BOUNDARY TESTS
// ============================================================================

#[test]
fn boundary_binding_minimal() {
    let result = ash_core::ash_normalize_binding("GET", "/", "");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "GET|/|");
}

#[test]
fn boundary_binding_long_path() {
    let path = "/".to_string() + &"x".repeat(1000);
    let result = ash_core::ash_normalize_binding("GET", &path, "");
    assert!(result.is_ok());
}

#[test]
fn boundary_binding_long_query() {
    let query = "a=".to_string() + &"x".repeat(1000);
    let result = ash_core::ash_normalize_binding("GET", "/test", &query);
    assert!(result.is_ok());
}

#[test]
fn boundary_binding_get_method() {
    let result = ash_core::ash_normalize_binding("GET", "/test", "");
    assert!(result.is_ok());
}

#[test]
fn boundary_binding_post_method() {
    let result = ash_core::ash_normalize_binding("POST", "/test", "");
    assert!(result.is_ok());
}

#[test]
fn boundary_binding_put_method() {
    let result = ash_core::ash_normalize_binding("PUT", "/test", "");
    assert!(result.is_ok());
}

#[test]
fn boundary_binding_delete_method() {
    let result = ash_core::ash_normalize_binding("DELETE", "/test", "");
    assert!(result.is_ok());
}

#[test]
fn boundary_binding_patch_method() {
    let result = ash_core::ash_normalize_binding("PATCH", "/test", "");
    assert!(result.is_ok());
}

#[test]
fn boundary_binding_options_method() {
    let result = ash_core::ash_normalize_binding("OPTIONS", "/test", "");
    assert!(result.is_ok());
}

#[test]
fn boundary_binding_head_method() {
    let result = ash_core::ash_normalize_binding("HEAD", "/test", "");
    assert!(result.is_ok());
}

// ============================================================================
// SECRET DERIVATION BOUNDARY TESTS
// ============================================================================

#[test]
fn boundary_secret_min_nonce_32_hex() {
    let nonce = "a".repeat(32);
    let result = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|");
    assert!(result.is_ok());
}

#[test]
fn boundary_secret_31_hex_fails() {
    let nonce = "a".repeat(31);
    let result = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|");
    assert!(result.is_err());
}

#[test]
fn boundary_secret_64_hex_ok() {
    let nonce = "a".repeat(64);
    let result = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|");
    assert!(result.is_ok());
}

#[test]
fn boundary_secret_256_hex_fails() {
    // Very long nonce exceeds allowed length
    let nonce = "a".repeat(256);
    let result = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|");
    assert!(result.is_err());
}

#[test]
fn boundary_secret_empty_context_fails() {
    // Empty context_id is not allowed
    let nonce = "a".repeat(64);
    let result = ash_core::ash_derive_client_secret(&nonce, "", "POST|/|");
    assert!(result.is_err());
}

#[test]
fn boundary_secret_long_context_fails() {
    // Very long context_id exceeds allowed length
    let nonce = "a".repeat(64);
    let ctx = "x".repeat(1000);
    let result = ash_core::ash_derive_client_secret(&nonce, &ctx, "POST|/|");
    assert!(result.is_err());
}

#[test]
fn boundary_secret_empty_binding_ok() {
    let nonce = "a".repeat(64);
    let result = ash_core::ash_derive_client_secret(&nonce, "ctx", "");
    assert!(result.is_ok());
}

// ============================================================================
// PROOF BOUNDARY TESTS
// ============================================================================

#[test]
fn boundary_proof_valid_inputs() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let hash = ash_core::ash_hash_body("test");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    let result = ash_core::ash_build_proof(&secret, &ts, "POST|/|", &hash);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 64);
}

#[test]
fn boundary_proof_empty_secret_fails() {
    let hash = ash_core::ash_hash_body("test");
    let result = ash_core::ash_build_proof("", "1234567890", "POST|/|", &hash);
    assert!(result.is_err());
}

#[test]
fn boundary_proof_empty_timestamp_fails() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let hash = ash_core::ash_hash_body("test");
    let result = ash_core::ash_build_proof(&secret, "", "POST|/|", &hash);
    assert!(result.is_err());
}

#[test]
fn boundary_proof_empty_binding_fails() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let hash = ash_core::ash_hash_body("test");
    let result = ash_core::ash_build_proof(&secret, "1234567890", "", &hash);
    assert!(result.is_err());
}

#[test]
fn boundary_proof_invalid_hash_length_fails() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let result = ash_core::ash_build_proof(&secret, "1234567890", "POST|/|", "abc");
    assert!(result.is_err());
}

#[test]
fn boundary_proof_invalid_hash_chars_fails() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let bad_hash = "g".repeat(64);
    let result = ash_core::ash_build_proof(&secret, "1234567890", "POST|/|", &bad_hash);
    assert!(result.is_err());
}

// ============================================================================
// SCOPED PROOF BOUNDARY TESTS
// ============================================================================

#[test]
fn boundary_scoped_empty_scope() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let ts = "1704067200";
    let scope: &[&str] = &[];
    let result = ash_core::ash_build_proof_scoped(&secret, ts, "POST|/|", "{}", scope);
    assert!(result.is_ok());
}

#[test]
fn boundary_scoped_single_field() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let ts = "1704067200";
    let result = ash_core::ash_build_proof_scoped(&secret, ts, "POST|/|", "{\"a\":1}", &["a"]);
    assert!(result.is_ok());
}

#[test]
fn boundary_scoped_50_fields() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let ts = "1704067200";
    let pairs: Vec<String> = (0..50).map(|i| format!("\"k{}\":{}", i, i)).collect();
    let json = format!("{{{}}}", pairs.join(","));
    let scope: Vec<String> = (0..50).map(|i| format!("k{}", i)).collect();
    let scope_refs: Vec<&str> = scope.iter().map(|s| s.as_str()).collect();
    let result = ash_core::ash_build_proof_scoped(&secret, ts, "POST|/|", &json, &scope_refs);
    assert!(result.is_ok());
}

#[test]
fn boundary_scoped_missing_field_ok() {
    // Missing scope field is allowed (produces empty scope hash for that field)
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let ts = "1704067200";
    let result = ash_core::ash_build_proof_scoped(&secret, ts, "POST|/|", "{\"a\":1}", &["b"]);
    assert!(result.is_ok());
}

// ============================================================================
// UNIFIED PROOF BOUNDARY TESTS
// ============================================================================

#[test]
fn boundary_unified_no_scope_no_chain() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let ts = "1704067200";
    let scope: &[&str] = &[];
    let result = ash_core::ash_build_proof_unified(&secret, ts, "POST|/|", "{}", scope, None);
    assert!(result.is_ok());
}

#[test]
fn boundary_unified_with_scope() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let ts = "1704067200";
    let result = ash_core::ash_build_proof_unified(&secret, ts, "POST|/|", "{\"a\":1}", &["a"], None);
    assert!(result.is_ok());
}

#[test]
fn boundary_unified_with_chain() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let ts = "1704067200";
    let scope: &[&str] = &[];
    let prev = "a".repeat(64);
    let result = ash_core::ash_build_proof_unified(&secret, ts, "POST|/|", "{}", scope, Some(&prev));
    assert!(result.is_ok());
}

#[test]
fn boundary_unified_with_both() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let ts = "1704067200";
    let prev = "a".repeat(64);
    let result = ash_core::ash_build_proof_unified(&secret, ts, "POST|/|", "{\"x\":1}", &["x"], Some(&prev));
    assert!(result.is_ok());
}

// ============================================================================
// CONTEXT ID BOUNDARY TESTS
// ============================================================================

#[test]
fn boundary_context_id_has_prefix() {
    let id = ash_core::ash_generate_context_id().unwrap();
    assert!(id.starts_with("ash_"));
}

#[test]
fn boundary_context_id_uniqueness() {
    let mut ids = std::collections::HashSet::new();
    for _ in 0..100 {
        let id = ash_core::ash_generate_context_id().unwrap();
        assert!(ids.insert(id));
    }
}

// ============================================================================
// TIMING SAFE COMPARISON BOUNDARY TESTS
// ============================================================================

#[test]
fn boundary_timing_empty_equal() {
    assert!(ash_core::ash_timing_safe_equal(b"", b""));
}

#[test]
fn boundary_timing_single_char_equal() {
    assert!(ash_core::ash_timing_safe_equal(b"a", b"a"));
}

#[test]
fn boundary_timing_single_char_unequal() {
    assert!(!ash_core::ash_timing_safe_equal(b"a", b"b"));
}

#[test]
fn boundary_timing_different_lengths() {
    assert!(!ash_core::ash_timing_safe_equal(b"a", b"aa"));
}

#[test]
fn boundary_timing_long_equal() {
    let s = "x".repeat(10000);
    assert!(ash_core::ash_timing_safe_equal(s.as_bytes(), s.as_bytes()));
}

#[test]
fn boundary_timing_long_unequal() {
    let s1 = "x".repeat(10000);
    let s2 = "y".repeat(10000);
    assert!(!ash_core::ash_timing_safe_equal(s1.as_bytes(), s2.as_bytes()));
}

// ============================================================================
// HASH PROOF BOUNDARY TESTS
// ============================================================================

#[test]
fn boundary_hash_proof_valid() {
    let proof = "a".repeat(64);
    let result = ash_core::ash_hash_proof(&proof);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 64);
}

#[test]
fn boundary_hash_proof_empty_fails() {
    let result = ash_core::ash_hash_proof("");
    assert!(result.is_err());
}

#[test]
fn boundary_hash_proof_short_ok() {
    // Short proof strings are still hashable
    let result = ash_core::ash_hash_proof("abc");
    assert!(result.is_ok());
}

// ============================================================================
// HASH SCOPE BOUNDARY TESTS
// ============================================================================

#[test]
fn boundary_hash_scope_empty() {
    let scope: &[&str] = &[];
    let result = ash_core::ash_hash_scope(scope);
    assert!(result.is_ok());
}

#[test]
fn boundary_hash_scope_single() {
    let result = ash_core::ash_hash_scope(&["field1"]);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 64);
}

#[test]
fn boundary_hash_scope_many() {
    let scope: Vec<String> = (0..100).map(|i| format!("field{}", i)).collect();
    let scope_refs: Vec<&str> = scope.iter().map(|s| s.as_str()).collect();
    let result = ash_core::ash_hash_scope(&scope_refs);
    assert!(result.is_ok());
}

// ============================================================================
// VERIFY PROOF BOUNDARY TESTS
// ============================================================================

#[test]
fn boundary_verify_valid_proof() {
    let nonce = "a".repeat(64);
    let ctx = "test_ctx";
    let binding = "POST|/api|";
    let ts = "1704067200";
    let body = "test";
    let body_hash = ash_core::ash_hash_body(body);
    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, ts, binding, &body_hash).unwrap();

    let result = ash_core::ash_verify_proof(&nonce, ctx, binding, ts, &body_hash, &proof);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn boundary_verify_wrong_nonce() {
    let nonce = "a".repeat(64);
    let wrong_nonce = "b".repeat(64);
    let ctx = "test_ctx";
    let binding = "POST|/api|";
    let ts = "1704067200";
    let body_hash = ash_core::ash_hash_body("test");
    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, ts, binding, &body_hash).unwrap();

    let result = ash_core::ash_verify_proof(&wrong_nonce, ctx, binding, ts, &body_hash, &proof);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn boundary_verify_wrong_context() {
    let nonce = "a".repeat(64);
    let ctx = "test_ctx";
    let binding = "POST|/api|";
    let ts = "1704067200";
    let body_hash = ash_core::ash_hash_body("test");
    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, ts, binding, &body_hash).unwrap();

    let result = ash_core::ash_verify_proof(&nonce, "wrong_ctx", binding, ts, &body_hash, &proof);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn boundary_verify_wrong_binding() {
    let nonce = "a".repeat(64);
    let ctx = "test_ctx";
    let binding = "POST|/api|";
    let ts = "1704067200";
    let body_hash = ash_core::ash_hash_body("test");
    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, ts, binding, &body_hash).unwrap();

    let result = ash_core::ash_verify_proof(&nonce, ctx, "GET|/api|", ts, &body_hash, &proof);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn boundary_verify_wrong_timestamp() {
    let nonce = "a".repeat(64);
    let ctx = "test_ctx";
    let binding = "POST|/api|";
    let ts = "1704067200";
    let body_hash = ash_core::ash_hash_body("test");
    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, ts, binding, &body_hash).unwrap();

    let result = ash_core::ash_verify_proof(&nonce, ctx, binding, "9999999999", &body_hash, &proof);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn boundary_verify_wrong_hash() {
    let nonce = "a".repeat(64);
    let ctx = "test_ctx";
    let binding = "POST|/api|";
    let ts = "1704067200";
    let body_hash = ash_core::ash_hash_body("test");
    let wrong_hash = ash_core::ash_hash_body("wrong");
    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, ts, binding, &body_hash).unwrap();

    let result = ash_core::ash_verify_proof(&nonce, ctx, binding, ts, &wrong_hash, &proof);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}
