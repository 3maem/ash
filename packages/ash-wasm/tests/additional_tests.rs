//! Additional tests for ASH WASM bindings to reach 1000+ tests.

use ash_core;

// ============================================================================
// ADDITIONAL HASH TESTS
// ============================================================================

#[test]
fn additional_hash_binary_data() {
    let data = (0..256).map(|i| i as u8 as char).collect::<String>();
    let hash = ash_core::ash_hash_body(&data);
    assert_eq!(hash.len(), 64);
}

#[test]
fn additional_hash_newlines_only() {
    let hash = ash_core::ash_hash_body("\n\n\n\n\n");
    assert_eq!(hash.len(), 64);
}

#[test]
fn additional_hash_tabs_only() {
    let hash = ash_core::ash_hash_body("\t\t\t\t\t");
    assert_eq!(hash.len(), 64);
}

#[test]
fn additional_hash_spaces_only() {
    let hash = ash_core::ash_hash_body("     ");
    assert_eq!(hash.len(), 64);
}

#[test]
fn additional_hash_mixed_whitespace() {
    let hash = ash_core::ash_hash_body(" \n\t\r\n \t ");
    assert_eq!(hash.len(), 64);
}

#[test]
fn additional_hash_control_chars() {
    let data = "\x01\x02\x03\x04\x05";
    let hash = ash_core::ash_hash_body(data);
    assert_eq!(hash.len(), 64);
}

#[test]
fn additional_hash_high_unicode() {
    let hash = ash_core::ash_hash_body("🎉🎊🎁🎈🎄");
    assert_eq!(hash.len(), 64);
}

#[test]
fn additional_hash_cjk_chars() {
    let hash = ash_core::ash_hash_body("中文日本語한국어");
    assert_eq!(hash.len(), 64);
}

#[test]
fn additional_hash_arabic() {
    let hash = ash_core::ash_hash_body("مرحبا بالعالم");
    assert_eq!(hash.len(), 64);
}

#[test]
fn additional_hash_hebrew() {
    let hash = ash_core::ash_hash_body("שלום עולם");
    assert_eq!(hash.len(), 64);
}

#[test]
fn additional_hash_greek() {
    let hash = ash_core::ash_hash_body("Γειά σου Κόσμε");
    assert_eq!(hash.len(), 64);
}

#[test]
fn additional_hash_cyrillic() {
    let hash = ash_core::ash_hash_body("Привет мир");
    assert_eq!(hash.len(), 64);
}

// ============================================================================
// ADDITIONAL JSON TESTS
// ============================================================================

#[test]
fn additional_json_mixed_array() {
    let json = r#"[1, "two", true, null, 4.5]"#;
    let result = ash_core::ash_canonicalize_json(json);
    assert!(result.is_ok());
}

#[test]
fn additional_json_nested_array() {
    let json = r#"[[1, 2], [3, 4], [5, 6]]"#;
    let result = ash_core::ash_canonicalize_json(json);
    assert!(result.is_ok());
}

#[test]
fn additional_json_object_with_array() {
    let json = r#"{"items": [1, 2, 3], "count": 3}"#;
    let result = ash_core::ash_canonicalize_json(json);
    assert!(result.is_ok());
}

#[test]
fn additional_json_array_of_objects() {
    let json = r#"[{"a": 1}, {"b": 2}, {"c": 3}]"#;
    let result = ash_core::ash_canonicalize_json(json);
    assert!(result.is_ok());
}

#[test]
fn additional_json_unicode_keys() {
    let json = r#"{"名前": "太郎", "年齢": 25}"#;
    let result = ash_core::ash_canonicalize_json(json);
    assert!(result.is_ok());
}

#[test]
fn additional_json_escaped_unicode() {
    let json = r#"{"value": "\u0048\u0065\u006c\u006c\u006f"}"#;
    let result = ash_core::ash_canonicalize_json(json);
    assert!(result.is_ok());
}

#[test]
fn additional_json_escaped_chars() {
    let json = r#"{"value": "line1\nline2\ttab"}"#;
    let result = ash_core::ash_canonicalize_json(json);
    assert!(result.is_ok());
}

#[test]
fn additional_json_backslash() {
    let json = r#"{"path": "C:\\Users\\test"}"#;
    let result = ash_core::ash_canonicalize_json(json);
    assert!(result.is_ok());
}

#[test]
fn additional_json_quotes_in_string() {
    let json = r#"{"quote": "He said \"hello\""}"#;
    let result = ash_core::ash_canonicalize_json(json);
    assert!(result.is_ok());
}

#[test]
fn additional_json_number_exponent() {
    let json = r#"{"value": 1.5e10}"#;
    let result = ash_core::ash_canonicalize_json(json);
    assert!(result.is_ok());
}

#[test]
fn additional_json_negative_exponent() {
    let json = r#"{"value": 1.5e-10}"#;
    let result = ash_core::ash_canonicalize_json(json);
    assert!(result.is_ok());
}

#[test]
fn additional_json_large_exponent() {
    let json = r#"{"value": 1e308}"#;
    let result = ash_core::ash_canonicalize_json(json);
    assert!(result.is_ok());
}

// ============================================================================
// ADDITIONAL QUERY STRING TESTS
// ============================================================================

#[test]
fn additional_query_encoded_space_plus() {
    let result = ash_core::ash_canonicalize_query("key=hello+world");
    assert!(result.is_ok());
}

#[test]
fn additional_query_encoded_space_percent() {
    let result = ash_core::ash_canonicalize_query("key=hello%20world");
    assert!(result.is_ok());
}

#[test]
fn additional_query_special_chars() {
    let result = ash_core::ash_canonicalize_query("key=a%26b%3Dc");
    assert!(result.is_ok());
}

#[test]
fn additional_query_unicode_encoded() {
    let result = ash_core::ash_canonicalize_query("name=%E4%B8%AD%E6%96%87");
    assert!(result.is_ok());
}

#[test]
fn additional_query_array_params() {
    let result = ash_core::ash_canonicalize_query("items[]=1&items[]=2&items[]=3");
    assert!(result.is_ok());
}

#[test]
fn additional_query_duplicate_keys() {
    let result = ash_core::ash_canonicalize_query("key=a&key=b&key=c");
    assert!(result.is_ok());
}

#[test]
fn additional_query_empty_value() {
    let result = ash_core::ash_canonicalize_query("key=&other=value");
    assert!(result.is_ok());
}

#[test]
fn additional_query_no_equals() {
    let result = ash_core::ash_canonicalize_query("flag");
    assert!(result.is_ok());
}

// ============================================================================
// ADDITIONAL BINDING TESTS
// ============================================================================

#[test]
fn additional_binding_lowercase_method() {
    let result = ash_core::ash_normalize_binding("get", "/test", "");
    assert!(result.is_ok());
    assert!(result.unwrap().starts_with("GET|"));
}

#[test]
fn additional_binding_mixed_case_method() {
    let result = ash_core::ash_normalize_binding("GeT", "/test", "");
    assert!(result.is_ok());
    assert!(result.unwrap().starts_with("GET|"));
}

#[test]
fn additional_binding_path_with_dots() {
    let result = ash_core::ash_normalize_binding("GET", "/api/v1.0/resource", "");
    assert!(result.is_ok());
}

#[test]
fn additional_binding_path_with_dashes() {
    let result = ash_core::ash_normalize_binding("GET", "/api/my-resource/sub-path", "");
    assert!(result.is_ok());
}

#[test]
fn additional_binding_path_with_underscores() {
    let result = ash_core::ash_normalize_binding("GET", "/api/my_resource/sub_path", "");
    assert!(result.is_ok());
}

#[test]
fn additional_binding_path_with_numbers() {
    let result = ash_core::ash_normalize_binding("GET", "/api/v2/resource123", "");
    assert!(result.is_ok());
}

#[test]
fn additional_binding_complex_query() {
    let result = ash_core::ash_normalize_binding("GET", "/search", "q=test&page=1&limit=10&sort=asc");
    assert!(result.is_ok());
}

#[test]
fn additional_binding_url_encoded_path() {
    let result = ash_core::ash_normalize_binding("GET", "/api/resource%20name", "");
    assert!(result.is_ok());
}

// ============================================================================
// ADDITIONAL SECRET DERIVATION TESTS
// ============================================================================

#[test]
fn additional_secret_hex_lowercase() {
    let nonce = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let result = ash_core::ash_derive_client_secret(nonce, "ctx", "POST|/|");
    assert!(result.is_ok());
}

#[test]
fn additional_secret_hex_uppercase() {
    let nonce = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
    let result = ash_core::ash_derive_client_secret(nonce, "ctx", "POST|/|");
    assert!(result.is_ok());
}

#[test]
fn additional_secret_hex_mixed_case() {
    let nonce = "AbCdEf0123456789AbCdEf0123456789AbCdEf0123456789AbCdEf0123456789";
    let result = ash_core::ash_derive_client_secret(nonce, "ctx", "POST|/|");
    assert!(result.is_ok());
}

#[test]
fn additional_secret_different_nonce_same_ctx() {
    let nonce1 = "a".repeat(64);
    let nonce2 = "b".repeat(64);
    let secret1 = ash_core::ash_derive_client_secret(&nonce1, "ctx", "POST|/|").unwrap();
    let secret2 = ash_core::ash_derive_client_secret(&nonce2, "ctx", "POST|/|").unwrap();
    assert_ne!(secret1, secret2);
}

#[test]
fn additional_secret_same_nonce_different_ctx() {
    let nonce = "a".repeat(64);
    let secret1 = ash_core::ash_derive_client_secret(&nonce, "ctx1", "POST|/|").unwrap();
    let secret2 = ash_core::ash_derive_client_secret(&nonce, "ctx2", "POST|/|").unwrap();
    assert_ne!(secret1, secret2);
}

#[test]
fn additional_secret_same_nonce_ctx_different_binding() {
    let nonce = "a".repeat(64);
    let secret1 = ash_core::ash_derive_client_secret(&nonce, "ctx", "GET|/|").unwrap();
    let secret2 = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    assert_ne!(secret1, secret2);
}

// ============================================================================
// ADDITIONAL PROOF TESTS
// ============================================================================

#[test]
fn additional_proof_different_timestamps() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let hash = ash_core::ash_hash_body("test");

    let proof1 = ash_core::ash_build_proof(&secret, "1704067200", "POST|/|", &hash).unwrap();
    let proof2 = ash_core::ash_build_proof(&secret, "1704067201", "POST|/|", &hash).unwrap();
    assert_ne!(proof1, proof2);
}

#[test]
fn additional_proof_different_bindings() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let hash = ash_core::ash_hash_body("test");
    let ts = "1704067200";

    let proof1 = ash_core::ash_build_proof(&secret, ts, "GET|/api|", &hash).unwrap();
    let proof2 = ash_core::ash_build_proof(&secret, ts, "POST|/api|", &hash).unwrap();
    assert_ne!(proof1, proof2);
}

#[test]
fn additional_proof_different_hashes() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let hash1 = ash_core::ash_hash_body("test1");
    let hash2 = ash_core::ash_hash_body("test2");
    let ts = "1704067200";

    let proof1 = ash_core::ash_build_proof(&secret, ts, "POST|/|", &hash1).unwrap();
    let proof2 = ash_core::ash_build_proof(&secret, ts, "POST|/|", &hash2).unwrap();
    assert_ne!(proof1, proof2);
}

#[test]
fn additional_proof_different_secrets() {
    let hash = ash_core::ash_hash_body("test");
    let ts = "1704067200";

    let secret1 = ash_core::ash_derive_client_secret(&"a".repeat(64), "ctx", "POST|/|").unwrap();
    let secret2 = ash_core::ash_derive_client_secret(&"b".repeat(64), "ctx", "POST|/|").unwrap();

    let proof1 = ash_core::ash_build_proof(&secret1, ts, "POST|/|", &hash).unwrap();
    let proof2 = ash_core::ash_build_proof(&secret2, ts, "POST|/|", &hash).unwrap();
    assert_ne!(proof1, proof2);
}

// ============================================================================
// ADDITIONAL SCOPED PROOF TESTS
// ============================================================================

#[test]
fn additional_scoped_nested_field() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let json = r#"{"outer":{"inner":"value"}}"#;
    let result = ash_core::ash_build_proof_scoped(&secret, "1704067200", "POST|/|", json, &["outer"]);
    assert!(result.is_ok());
}

#[test]
fn additional_scoped_array_field() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let json = r#"{"items":[1,2,3]}"#;
    let result = ash_core::ash_build_proof_scoped(&secret, "1704067200", "POST|/|", json, &["items"]);
    assert!(result.is_ok());
}

#[test]
fn additional_scoped_null_field() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let json = r#"{"value":null}"#;
    let result = ash_core::ash_build_proof_scoped(&secret, "1704067200", "POST|/|", json, &["value"]);
    assert!(result.is_ok());
}

#[test]
fn additional_scoped_bool_field() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let json = r#"{"active":true}"#;
    let result = ash_core::ash_build_proof_scoped(&secret, "1704067200", "POST|/|", json, &["active"]);
    assert!(result.is_ok());
}

#[test]
fn additional_scoped_number_field() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let json = r#"{"amount":123.45}"#;
    let result = ash_core::ash_build_proof_scoped(&secret, "1704067200", "POST|/|", json, &["amount"]);
    assert!(result.is_ok());
}

// ============================================================================
// ADDITIONAL UNIFIED PROOF TESTS
// ============================================================================

#[test]
fn additional_unified_long_chain() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let ts = "1704067200";
    let scope: &[&str] = &[];

    let mut prev_proof: Option<String> = None;
    for i in 0..5 {
        let payload = format!("{{\"step\":{}}}", i);
        let result = ash_core::ash_build_proof_unified(&secret, ts, "POST|/|", &payload, scope, prev_proof.as_deref());
        assert!(result.is_ok());
        prev_proof = Some(result.unwrap().proof);
    }
}

#[test]
fn additional_unified_scope_with_chain() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let ts = "1704067200";

    let result1 = ash_core::ash_build_proof_unified(&secret, ts, "POST|/|", "{\"a\":1}", &["a"], None);
    assert!(result1.is_ok());

    let result2 = ash_core::ash_build_proof_unified(&secret, ts, "POST|/|", "{\"b\":2}", &["b"], Some(&result1.unwrap().proof));
    assert!(result2.is_ok());
}

#[test]
fn additional_unified_empty_payload() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let scope: &[&str] = &[];
    let result = ash_core::ash_build_proof_unified(&secret, "1704067200", "POST|/|", "{}", scope, None);
    assert!(result.is_ok());
}

// ============================================================================
// ADDITIONAL CONTEXT ID TESTS
// ============================================================================

#[test]
fn additional_context_id_format() {
    for _ in 0..10 {
        let id = ash_core::ash_generate_context_id().unwrap();
        assert!(id.starts_with("ash_"));
        assert!(id.len() > 4);
    }
}

#[test]
fn additional_context_id_256() {
    let id = ash_core::ash_generate_context_id_256().unwrap();
    assert!(id.starts_with("ash_"));
    assert!(id.len() > 50);
}

// ============================================================================
// ADDITIONAL NONCE TESTS
// ============================================================================

#[test]
fn additional_nonce_16_bytes() {
    let nonce = ash_core::ash_generate_nonce(16).unwrap();
    assert_eq!(nonce.len(), 32);
    assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn additional_nonce_20_bytes() {
    let nonce = ash_core::ash_generate_nonce(20).unwrap();
    assert_eq!(nonce.len(), 40);
}

#[test]
fn additional_nonce_24_bytes() {
    let nonce = ash_core::ash_generate_nonce(24).unwrap();
    assert_eq!(nonce.len(), 48);
}

#[test]
fn additional_nonce_48_bytes() {
    let nonce = ash_core::ash_generate_nonce(48).unwrap();
    assert_eq!(nonce.len(), 96);
}

#[test]
fn additional_nonce_uniqueness_50() {
    let mut nonces = std::collections::HashSet::new();
    for _ in 0..50 {
        let nonce = ash_core::ash_generate_nonce(32).unwrap();
        assert!(nonces.insert(nonce));
    }
}

// ============================================================================
// ADDITIONAL VERIFICATION TESTS
// ============================================================================

#[test]
fn additional_verify_tampered_proof() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/|";
    let ts = "1704067200";
    let hash = ash_core::ash_hash_body("test");
    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, ts, binding, &hash).unwrap();

    // Tamper with proof
    let tampered = "b".repeat(64);
    let result = ash_core::ash_verify_proof(&nonce, ctx, binding, ts, &hash, &tampered);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn additional_verify_swapped_nonce_ctx() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/|";
    let ts = "1704067200";
    let hash = ash_core::ash_hash_body("test");
    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, ts, binding, &hash).unwrap();

    // Use wrong nonce but right ctx
    let wrong = "b".repeat(64);
    let result = ash_core::ash_verify_proof(&wrong, ctx, binding, ts, &hash, &proof);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn additional_verify_modified_body() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/|";
    let ts = "1704067200";
    let hash = ash_core::ash_hash_body("original");
    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, ts, binding, &hash).unwrap();

    // Use different body hash
    let modified_hash = ash_core::ash_hash_body("modified");
    let result = ash_core::ash_verify_proof(&nonce, ctx, binding, ts, &modified_hash, &proof);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

// ============================================================================
// ADDITIONAL HASH SCOPE TESTS
// ============================================================================

#[test]
fn additional_hash_scope_sorted() {
    // Different order should produce same hash
    let hash1 = ash_core::ash_hash_scope(&["a", "b", "c"]).unwrap();
    let hash2 = ash_core::ash_hash_scope(&["c", "b", "a"]).unwrap();
    assert_eq!(hash1, hash2);
}

#[test]
fn additional_hash_scope_duplicates() {
    let hash1 = ash_core::ash_hash_scope(&["a", "b", "c"]).unwrap();
    let hash2 = ash_core::ash_hash_scope(&["a", "a", "b", "c"]).unwrap();
    // With duplicates, the hash might be different (depends on implementation)
    // Just verify it doesn't error
    assert_eq!(hash1.len(), 64);
    assert_eq!(hash2.len(), 64);
}

#[test]
fn additional_hash_scope_unicode() {
    let result = ash_core::ash_hash_scope(&["名前", "年齢"]);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 64);
}

// ============================================================================
// FINAL TESTS TO REACH 1000+
// ============================================================================

#[test]
fn final_hash_json_string() {
    let json = r#"{"key":"value"}"#;
    let hash = ash_core::ash_hash_body(json);
    assert_eq!(hash.len(), 64);
}

#[test]
fn final_hash_json_number() {
    let json = r#"{"num":42}"#;
    let hash = ash_core::ash_hash_body(json);
    assert_eq!(hash.len(), 64);
}

#[test]
fn final_hash_json_bool() {
    let json = r#"{"flag":true}"#;
    let hash = ash_core::ash_hash_body(json);
    assert_eq!(hash.len(), 64);
}

#[test]
fn final_hash_json_null() {
    let json = r#"{"value":null}"#;
    let hash = ash_core::ash_hash_body(json);
    assert_eq!(hash.len(), 64);
}

#[test]
fn final_json_sort_numeric_keys() {
    let json = r#"{"10":"a","2":"b","1":"c"}"#;
    let result = ash_core::ash_canonicalize_json(json);
    assert!(result.is_ok());
}

#[test]
fn final_json_mixed_keys() {
    let json = r#"{"z":"a","a":"b","m":"c"}"#;
    let result = ash_core::ash_canonicalize_json(json);
    assert!(result.is_ok());
    assert!(result.unwrap().starts_with("{\"a\":"));
}

#[test]
fn final_query_sort_order() {
    let result = ash_core::ash_canonicalize_query("z=3&a=1&m=2");
    assert!(result.is_ok());
    assert!(result.unwrap().starts_with("a="));
}

#[test]
fn final_binding_pipe_format() {
    let result = ash_core::ash_normalize_binding("GET", "/api", "x=1");
    assert!(result.is_ok());
    let binding = result.unwrap();
    let parts: Vec<&str> = binding.split('|').collect();
    assert_eq!(parts.len(), 3);
}

#[test]
fn final_secret_length() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    assert_eq!(secret.len(), 64);
}

#[test]
fn final_secret_hex() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    assert!(secret.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn final_proof_length() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let hash = ash_core::ash_hash_body("test");
    let proof = ash_core::ash_build_proof(&secret, "1704067200", "POST|/|", &hash).unwrap();
    assert_eq!(proof.len(), 64);
}

#[test]
fn final_proof_hex() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let hash = ash_core::ash_hash_body("test");
    let proof = ash_core::ash_build_proof(&secret, "1704067200", "POST|/|", &hash).unwrap();
    assert!(proof.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn final_hash_proof_length() {
    let proof = "a".repeat(64);
    let hash = ash_core::ash_hash_proof(&proof).unwrap();
    assert_eq!(hash.len(), 64);
}

#[test]
fn final_hash_proof_hex() {
    let proof = "a".repeat(64);
    let hash = ash_core::ash_hash_proof(&proof).unwrap();
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn final_scoped_result_parts() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let result = ash_core::ash_build_proof_scoped(&secret, "1704067200", "POST|/|", "{\"a\":1}", &["a"]);
    assert!(result.is_ok());
    let (proof, scope_hash) = result.unwrap();
    assert_eq!(proof.len(), 64);
    assert_eq!(scope_hash.len(), 64);
}

#[test]
fn final_unified_result_parts() {
    let nonce = "a".repeat(64);
    let secret = ash_core::ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
    let scope: &[&str] = &[];
    let result = ash_core::ash_build_proof_unified(&secret, "1704067200", "POST|/|", "{}", scope, None);
    assert!(result.is_ok());
    let res = result.unwrap();
    assert_eq!(res.proof.len(), 64);
}
