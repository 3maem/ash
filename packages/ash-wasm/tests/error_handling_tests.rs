//! Comprehensive error handling tests for ASH WASM bindings.
//! These tests verify proper error handling for invalid inputs, malformed data, and boundary conditions.

use ash_core;

// ============================================================================
// JSON CANONICALIZATION ERROR TESTS
// ============================================================================

#[test]
fn err_invalid_json() {
    let result = ash_core::ash_canonicalize_json("{invalid}");
    assert!(result.is_err());
}

#[test]
fn err_malformed_json_unclosed_brace() {
    let result = ash_core::ash_canonicalize_json(r#"{"key":"#);
    assert!(result.is_err());
}

#[test]
fn err_unclosed_string() {
    let result = ash_core::ash_canonicalize_json(r#"{"key":"value}"#);
    assert!(result.is_err());
}

#[test]
fn err_unclosed_array() {
    let result = ash_core::ash_canonicalize_json(r#"{"arr":[1,2,3}"#);
    assert!(result.is_err());
}

#[test]
fn err_trailing_comma_object() {
    let result = ash_core::ash_canonicalize_json(r#"{"a":1,}"#);
    assert!(result.is_err());
}

#[test]
fn err_trailing_comma_array() {
    let result = ash_core::ash_canonicalize_json(r#"[1,2,3,]"#);
    assert!(result.is_err());
}

#[test]
fn err_missing_colon() {
    let result = ash_core::ash_canonicalize_json(r#"{"key" "value"}"#);
    assert!(result.is_err());
}

#[test]
fn err_double_colon() {
    let result = ash_core::ash_canonicalize_json(r#"{"key"::"value"}"#);
    assert!(result.is_err());
}

#[test]
fn err_missing_comma() {
    let result = ash_core::ash_canonicalize_json(r#"{"a":1 "b":2}"#);
    assert!(result.is_err());
}

#[test]
fn err_leading_comma() {
    let result = ash_core::ash_canonicalize_json(r#"{,"a":1}"#);
    assert!(result.is_err());
}

#[test]
fn err_only_comma() {
    let result = ash_core::ash_canonicalize_json(",");
    assert!(result.is_err());
}

#[test]
fn err_only_colon() {
    let result = ash_core::ash_canonicalize_json(":");
    assert!(result.is_err());
}

#[test]
fn err_random_text() {
    let result = ash_core::ash_canonicalize_json("hello world");
    assert!(result.is_err());
}

#[test]
fn err_unquoted_key() {
    let result = ash_core::ash_canonicalize_json("{key: \"value\"}");
    assert!(result.is_err());
}

#[test]
fn err_single_quoted_string() {
    let result = ash_core::ash_canonicalize_json("{'key': 'value'}");
    assert!(result.is_err());
}

#[test]
fn err_duplicate_keys_json() {
    // JSON with duplicate keys - behavior may vary
    let result = ash_core::ash_canonicalize_json(r#"{"a":1,"a":2}"#);
    // Should either error or use last value
    if let Ok(canonical) = result {
        assert!(canonical.contains("\"a\":"));
    }
}

#[test]
fn err_deeply_nested_100_levels() {
    let mut json = String::new();
    for _ in 0..100 {
        json.push_str(r#"{"nested":"#);
    }
    json.push_str("1");
    for _ in 0..100 {
        json.push('}');
    }
    // Should either handle or error gracefully
    let _ = ash_core::ash_canonicalize_json(&json);
}

// ============================================================================
// BINDING NORMALIZATION ERROR TESTS
// ============================================================================

#[test]
fn err_empty_method() {
    let result = ash_core::ash_normalize_binding("", "/api", "");
    // Should error on empty method
    assert!(result.is_err());
}

#[test]
fn err_whitespace_method() {
    let result = ash_core::ash_normalize_binding("   ", "/api", "");
    assert!(result.is_err());
}

#[test]
fn err_method_with_spaces() {
    let result = ash_core::ash_normalize_binding("POST GET", "/api", "");
    // Should either error or handle gracefully
    if let Ok(binding) = result {
        // Method should be uppercase
        assert!(binding.starts_with("POST") || binding.starts_with("POST GET"));
    }
}

#[test]
fn err_method_with_special_chars() {
    let result = ash_core::ash_normalize_binding("POST!", "/api", "");
    // Should handle or error
    if let Ok(binding) = result {
        assert!(binding.contains("|"));
    }
}

// ============================================================================
// QUERY CANONICALIZATION ERROR TESTS
// ============================================================================

#[test]
fn err_invalid_percent_encoding_incomplete() {
    // Invalid percent encoding - should handle gracefully
    let result = ash_core::ash_canonicalize_query("name=%");
    // Should either error or preserve
    if let Ok(canonical) = result {
        assert!(canonical.contains("name="));
    }
}

#[test]
fn err_invalid_percent_encoding_single_char() {
    let result = ash_core::ash_canonicalize_query("name=%2");
    // Should either error or preserve
    if let Ok(canonical) = result {
        assert!(canonical.contains("name="));
    }
}

#[test]
fn err_invalid_percent_encoding_non_hex() {
    let result = ash_core::ash_canonicalize_query("name=%ZZ");
    // Should either error or preserve
    if let Ok(canonical) = result {
        assert!(canonical.contains("name="));
    }
}

#[test]
fn err_double_ampersand() {
    let result = ash_core::ash_canonicalize_query("a=1&&b=2");
    // Should handle empty parts
    if let Ok(canonical) = result {
        assert!(canonical.contains("a=") && canonical.contains("b="));
    }
}

#[test]
fn err_leading_ampersand() {
    let result = ash_core::ash_canonicalize_query("&a=1&b=2");
    // Should handle leading ampersand
    if let Ok(canonical) = result {
        assert!(canonical.contains("a="));
    }
}

#[test]
fn err_trailing_ampersand() {
    let result = ash_core::ash_canonicalize_query("a=1&b=2&");
    // Should handle trailing ampersand
    if let Ok(canonical) = result {
        assert!(canonical.contains("a=") && canonical.contains("b="));
    }
}

#[test]
fn err_param_without_value() {
    let result = ash_core::ash_canonicalize_query("a&b=2");
    // Should handle param without equals
    if let Ok(canonical) = result {
        assert!(canonical.contains("b=2"));
    }
}

#[test]
fn err_only_equals() {
    let result = ash_core::ash_canonicalize_query("=");
    // Should handle gracefully
    let _ = result;
}

// ============================================================================
// PROOF INPUT VALIDATION ERROR TESTS
// ============================================================================

#[test]
fn err_empty_nonce() {
    let result = ash_core::ash_derive_client_secret("", "ctx", "POST|/api|");
    assert!(result.is_err());
}

#[test]
fn err_short_nonce() {
    let result = ash_core::ash_derive_client_secret("abc", "ctx", "POST|/api|");
    assert!(result.is_err());
}

#[test]
fn err_non_hex_nonce() {
    let result = ash_core::ash_derive_client_secret(&"g".repeat(64), "ctx", "POST|/api|");
    assert!(result.is_err());
}

#[test]
fn err_empty_context_id() {
    let nonce = "a".repeat(64);
    let result = ash_core::ash_derive_client_secret(&nonce, "", "POST|/api|");
    assert!(result.is_err());
}

#[test]
fn err_context_id_with_special_chars() {
    let nonce = "a".repeat(64);
    let result = ash_core::ash_derive_client_secret(&nonce, "ctx<script>", "POST|/api|");
    assert!(result.is_err());
}

#[test]
fn err_context_id_with_spaces() {
    let nonce = "a".repeat(64);
    let result = ash_core::ash_derive_client_secret(&nonce, "ctx with spaces", "POST|/api|");
    assert!(result.is_err());
}

#[test]
fn err_empty_binding() {
    let nonce = "a".repeat(64);
    let result = ash_core::ash_derive_client_secret(&nonce, "ctx", "");
    // Empty binding is accepted by derive_client_secret (binding is just part of HKDF info)
    // The validation happens at the API boundary, not in core crypto
    assert!(result.is_ok());
}

#[test]
fn err_invalid_body_hash_length() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/api|").unwrap();
    let result = ash_core::ash_build_proof(&secret, "12345", "POST|/api|", "abc");
    assert!(result.is_err());
}

#[test]
fn err_non_hex_body_hash() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/api|").unwrap();
    let result = ash_core::ash_build_proof(&secret, "12345", "POST|/api|", &"g".repeat(64));
    assert!(result.is_err());
}

// ============================================================================
// VERIFICATION ERROR TESTS
// ============================================================================

#[test]
fn err_wrong_nonce_verification() {
    let correct_nonce = "a".repeat(64);
    let wrong_nonce = "b".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let timestamp = "12345";
    let body_hash = ash_core::ash_hash_body("{}");

    let secret = ash_core::ash_derive_client_secret(&correct_nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    let valid = ash_core::ash_verify_proof(&wrong_nonce, ctx, binding, timestamp, &body_hash, &proof).unwrap();
    assert!(!valid);
}

#[test]
fn err_wrong_context_verification() {
    let nonce = "a".repeat(64);
    let correct_ctx = "ctx_correct";
    let wrong_ctx = "ctx_wrong";
    let binding = "POST|/api|";
    let timestamp = "12345";
    let body_hash = ash_core::ash_hash_body("{}");

    let secret = ash_core::ash_derive_client_secret(&nonce, correct_ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    let valid = ash_core::ash_verify_proof(&nonce, wrong_ctx, binding, timestamp, &body_hash, &proof).unwrap();
    assert!(!valid);
}

#[test]
fn err_wrong_binding_verification() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let correct_binding = "POST|/api/correct|";
    let wrong_binding = "POST|/api/wrong|";
    let timestamp = "12345";
    let body_hash = ash_core::ash_hash_body("{}");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, correct_binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, correct_binding, &body_hash).unwrap();

    let valid = ash_core::ash_verify_proof(&nonce, ctx, wrong_binding, timestamp, &body_hash, &proof).unwrap();
    assert!(!valid);
}

#[test]
fn err_wrong_timestamp_verification() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let correct_timestamp = "12345";
    let wrong_timestamp = "12346";
    let body_hash = ash_core::ash_hash_body("{}");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, correct_timestamp, binding, &body_hash).unwrap();

    let valid = ash_core::ash_verify_proof(&nonce, ctx, binding, wrong_timestamp, &body_hash, &proof).unwrap();
    assert!(!valid);
}

#[test]
fn err_wrong_body_hash_verification() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let timestamp = "12345";
    let correct_hash = ash_core::ash_hash_body(r#"{"a":1}"#);
    let wrong_hash = ash_core::ash_hash_body(r#"{"a":2}"#);

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &correct_hash).unwrap();

    let valid = ash_core::ash_verify_proof(&nonce, ctx, binding, timestamp, &wrong_hash, &proof).unwrap();
    assert!(!valid);
}

#[test]
fn err_tampered_proof() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let timestamp = "12345";
    let body_hash = ash_core::ash_hash_body("{}");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    // Tamper with proof
    let mut chars: Vec<char> = proof.chars().collect();
    chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
    let tampered_proof: String = chars.into_iter().collect();

    let valid = ash_core::ash_verify_proof(&nonce, ctx, binding, timestamp, &body_hash, &tampered_proof).unwrap();
    assert!(!valid);
}

#[test]
fn err_empty_proof_verification() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let timestamp = "12345";
    let body_hash = ash_core::ash_hash_body("{}");

    let valid = ash_core::ash_verify_proof(&nonce, ctx, binding, timestamp, &body_hash, "").unwrap();
    assert!(!valid);
}

#[test]
fn err_short_proof_verification() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let timestamp = "12345";
    let body_hash = ash_core::ash_hash_body("{}");

    let valid = ash_core::ash_verify_proof(&nonce, ctx, binding, timestamp, &body_hash, "abc123").unwrap();
    assert!(!valid);
}

#[test]
fn err_non_hex_proof_verification() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let timestamp = "12345";
    let body_hash = ash_core::ash_hash_body("{}");

    // 64 chars but not valid hex
    let non_hex_proof = "g".repeat(64);

    let valid = ash_core::ash_verify_proof(&nonce, ctx, binding, timestamp, &body_hash, &non_hex_proof).unwrap();
    assert!(!valid);
}

// ============================================================================
// HASH PROOF ERROR TESTS
// ============================================================================

#[test]
fn err_hash_proof_empty() {
    let result = ash_core::ash_hash_proof("");
    assert!(result.is_err());
}

// ============================================================================
// SCOPED PROOF ERROR TESTS
// ============================================================================

#[test]
fn err_scoped_invalid_json() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/api|").unwrap();
    let result = ash_core::ash_build_proof_scoped(&secret, "12345", "POST|/api|", "{invalid}", &["field"]);
    assert!(result.is_err());
}

#[test]
fn err_scoped_missing_field() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/api|").unwrap();
    // Trying to scope a field that doesn't exist should handle gracefully
    let result = ash_core::ash_build_proof_scoped(&secret, "12345", "POST|/api|", r#"{"a":1}"#, &["nonexistent"]);
    // Should either error or return empty scope
    let _ = result;
}

// ============================================================================
// UNIFIED PROOF ERROR TESTS
// ============================================================================

#[test]
fn err_unified_invalid_json() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/api|").unwrap();
    let result = ash_core::ash_build_proof_unified(&secret, "12345", "POST|/api|", "{invalid}", &[], None);
    assert!(result.is_err());
}

#[test]
fn err_unified_invalid_chain_hash() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let timestamp = "12345";
    let payload = "{}";

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result = ash_core::ash_build_proof_unified(&secret, timestamp, binding, payload, &[], None).unwrap();

    // Try to verify with wrong chain hash
    let valid = ash_core::ash_verify_proof_unified(
        &nonce, ctx, binding, timestamp, payload, &result.proof,
        &[], "", Some("fake_proof"), "wrong_chain_hash"
    ).unwrap();
    assert!(!valid);
}

// ============================================================================
// EDGE CASE ERROR TESTS
// ============================================================================

#[test]
fn err_very_long_input() {
    let long_string = "a".repeat(1_000_000); // 1MB
    let hash = ash_core::ash_hash_body(&long_string);
    assert_eq!(hash.len(), 64);
}

#[test]
fn err_very_long_json() {
    let long_value = "a".repeat(100_000);
    let json = format!(r#"{{"value":"{}"}}"#, long_value);
    let result = ash_core::ash_canonicalize_json(&json);
    // Should handle large JSON
    assert!(result.is_ok());
}

#[test]
fn err_binary_in_json_string() {
    // Binary characters in JSON string
    let json = r#"{"text":"test\u0000data"}"#;
    let result = ash_core::ash_canonicalize_json(json);
    // Should handle gracefully
    let _ = result;
}

#[test]
fn err_all_zeros_nonce() {
    let nonce = "0".repeat(64);
    let result = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/api|");
    // All zeros is valid hex
    assert!(result.is_ok());
}

#[test]
fn err_all_f_nonce() {
    let nonce = "f".repeat(64);
    let result = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/api|");
    // All f's is valid hex
    assert!(result.is_ok());
}

#[test]
fn err_mixed_case_nonce() {
    let nonce = "aAbBcCdDeEfF".repeat(5) + "aabb";
    let result = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/api|");
    // Mixed case should be valid
    assert!(result.is_ok());
}

// ============================================================================
// STRESS ERROR RECOVERY TESTS
// ============================================================================

#[test]
fn stress_err_invalid_json_100() {
    let invalid_jsons = vec![
        "{invalid}",
        "{\"key\":",
        "[1,2,",
        "{{}}",
        "[[]",
        "\"unclosed",
        "{\"a\":}",
        ",",
        ":",
        "}{",
    ];

    for _ in 0..10 {
        for json in &invalid_jsons {
            let result = ash_core::ash_canonicalize_json(json);
            assert!(result.is_err(), "Should reject: {}", json);
        }
    }
}

#[test]
fn stress_err_invalid_nonce_100() {
    for _ in 0..100 {
        // Too short
        let result = ash_core::ash_derive_client_secret("abc", "ctx", "POST|/api|");
        assert!(result.is_err());

        // Non-hex
        let result = ash_core::ash_derive_client_secret(&"g".repeat(64), "ctx", "POST|/api|");
        assert!(result.is_err());

        // Empty
        let result = ash_core::ash_derive_client_secret("", "ctx", "POST|/api|");
        assert!(result.is_err());
    }
}

#[test]
fn stress_err_tampered_proofs_100() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let body_hash = ash_core::ash_hash_body("{}");
    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    for i in 0..100 {
        let timestamp = format!("{}", 1000000000 + i);
        let proof = ash_core::ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

        // Tamper with different positions
        let pos = i % 64;
        let mut chars: Vec<char> = proof.chars().collect();
        chars[pos] = if chars[pos] == 'a' { 'b' } else { 'a' };
        let tampered: String = chars.into_iter().collect();

        let valid = ash_core::ash_verify_proof(&nonce, ctx, binding, &timestamp, &body_hash, &tampered).unwrap();
        assert!(!valid, "Tampered proof at position {} should fail", pos);
    }
}
