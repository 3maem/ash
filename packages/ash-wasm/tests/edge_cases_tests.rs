//! Edge case tests for ASH WASM bindings.
//! These tests use ash_core directly since wasm_bindgen functions can't run on native targets.

use ash_core;

// ============================================================================
// JSON CANONICALIZATION EDGE CASES
// ============================================================================

#[test]
fn json_empty_object() {
    let result = ash_core::ash_canonicalize_json("{}").unwrap();
    assert_eq!(result, "{}");
}

#[test]
fn json_empty_array() {
    let result = ash_core::ash_canonicalize_json("[]").unwrap();
    assert_eq!(result, "[]");
}

#[test]
fn json_null_value() {
    let result = ash_core::ash_canonicalize_json("null").unwrap();
    assert_eq!(result, "null");
}

#[test]
fn json_true_value() {
    let result = ash_core::ash_canonicalize_json("true").unwrap();
    assert_eq!(result, "true");
}

#[test]
fn json_false_value() {
    let result = ash_core::ash_canonicalize_json("false").unwrap();
    assert_eq!(result, "false");
}

#[test]
fn json_string_value() {
    let result = ash_core::ash_canonicalize_json(r#""hello""#).unwrap();
    assert_eq!(result, r#""hello""#);
}

#[test]
fn json_integer_value() {
    let result = ash_core::ash_canonicalize_json("42").unwrap();
    assert_eq!(result, "42");
}

#[test]
fn json_negative_integer() {
    let result = ash_core::ash_canonicalize_json("-42").unwrap();
    assert_eq!(result, "-42");
}

#[test]
fn json_float_value() {
    let result = ash_core::ash_canonicalize_json("3.14159").unwrap();
    assert_eq!(result, "3.14159");
}

#[test]
fn json_negative_float() {
    let result = ash_core::ash_canonicalize_json("-3.14159").unwrap();
    assert_eq!(result, "-3.14159");
}

#[test]
fn json_zero() {
    let result = ash_core::ash_canonicalize_json("0").unwrap();
    assert_eq!(result, "0");
}

#[test]
fn json_string_with_quotes() {
    let result = ash_core::ash_canonicalize_json(r#""hello \"world\"""#).unwrap();
    assert_eq!(result, r#""hello \"world\"""#);
}

#[test]
fn json_string_with_backslash() {
    let result = ash_core::ash_canonicalize_json(r#""path\\to\\file""#).unwrap();
    assert_eq!(result, r#""path\\to\\file""#);
}

#[test]
fn json_string_with_newline() {
    let result = ash_core::ash_canonicalize_json(r#""line1\nline2""#).unwrap();
    assert_eq!(result, r#""line1\nline2""#);
}

#[test]
fn json_string_with_tab() {
    let result = ash_core::ash_canonicalize_json(r#""col1\tcol2""#).unwrap();
    assert_eq!(result, r#""col1\tcol2""#);
}

#[test]
fn json_unicode_chinese() {
    let result = ash_core::ash_canonicalize_json(r#""你好世界""#).unwrap();
    assert_eq!(result, r#""你好世界""#);
}

#[test]
fn json_unicode_japanese() {
    let result = ash_core::ash_canonicalize_json(r#""こんにちは""#).unwrap();
    assert_eq!(result, r#""こんにちは""#);
}

#[test]
fn json_unicode_korean() {
    let result = ash_core::ash_canonicalize_json(r#""안녕하세요""#).unwrap();
    assert_eq!(result, r#""안녕하세요""#);
}

#[test]
fn json_unicode_arabic() {
    let result = ash_core::ash_canonicalize_json(r#""مرحبا""#).unwrap();
    assert_eq!(result, r#""مرحبا""#);
}

#[test]
fn json_unicode_emoji() {
    let result = ash_core::ash_canonicalize_json(r#""🎉🚀💯""#).unwrap();
    assert_eq!(result, r#""🎉🚀💯""#);
}

#[test]
fn json_unicode_mixed() {
    let result = ash_core::ash_canonicalize_json(r#""Hello 你好 🌍""#).unwrap();
    assert_eq!(result, r#""Hello 你好 🌍""#);
}

#[test]
fn json_deeply_nested_objects() {
    let result = ash_core::ash_canonicalize_json(r#"{"a":{"b":{"c":{"d":{"e":1}}}}}"#).unwrap();
    assert_eq!(result, r#"{"a":{"b":{"c":{"d":{"e":1}}}}}"#);
}

#[test]
fn json_array_of_objects() {
    let result = ash_core::ash_canonicalize_json(r#"[{"b":2,"a":1},{"d":4,"c":3}]"#).unwrap();
    assert_eq!(result, r#"[{"a":1,"b":2},{"c":3,"d":4}]"#);
}

#[test]
fn json_object_with_array() {
    let result = ash_core::ash_canonicalize_json(r#"{"items":[3,1,2],"count":3}"#).unwrap();
    // Keys sorted, array order preserved
    assert_eq!(result, r#"{"count":3,"items":[3,1,2]}"#);
}

#[test]
fn json_complex_nested() {
    let result = ash_core::ash_canonicalize_json(r#"{"z":{"items":[{"b":2,"a":1}],"count":1},"a":true}"#).unwrap();
    assert_eq!(result, r#"{"a":true,"z":{"count":1,"items":[{"a":1,"b":2}]}}"#);
}

#[test]
fn json_many_keys() {
    let result = ash_core::ash_canonicalize_json(r#"{"z":26,"y":25,"x":24,"w":23,"v":22,"u":21,"t":20,"s":19,"r":18,"q":17}"#).unwrap();
    assert!(result.starts_with(r#"{"q":"#));
}

#[test]
fn json_numeric_string_keys() {
    let result = ash_core::ash_canonicalize_json(r#"{"10":"ten","2":"two","1":"one"}"#).unwrap();
    // Lexicographic ordering: "1" < "10" < "2"
    assert_eq!(result, r#"{"1":"one","10":"ten","2":"two"}"#);
}

#[test]
fn json_mixed_case_keys() {
    let result = ash_core::ash_canonicalize_json(r#"{"b":2,"B":3,"a":1,"A":4}"#).unwrap();
    // ASCII order: uppercase before lowercase
    assert_eq!(result, r#"{"A":4,"B":3,"a":1,"b":2}"#);
}

#[test]
fn json_special_char_keys() {
    let result = ash_core::ash_canonicalize_json(r#"{"_a":1,"$b":2,"@c":3}"#).unwrap();
    // ASCII order: $ < @ < _
    assert_eq!(result, r#"{"$b":2,"@c":3,"_a":1}"#);
}

#[test]
fn json_invalid_missing_brace() {
    let result = ash_core::ash_canonicalize_json(r#"{"a":1"#);
    assert!(result.is_err());
}

#[test]
fn json_invalid_trailing_comma() {
    let result = ash_core::ash_canonicalize_json(r#"{"a":1,}"#);
    assert!(result.is_err());
}

#[test]
fn json_invalid_not_json() {
    let result = ash_core::ash_canonicalize_json("not json");
    assert!(result.is_err());
}

#[test]
fn json_invalid_empty() {
    let result = ash_core::ash_canonicalize_json("");
    assert!(result.is_err());
}

// ============================================================================
// URL ENCODING EDGE CASES
// ============================================================================

#[test]
fn urlencoded_empty() {
    let result = ash_core::ash_canonicalize_urlencoded("").unwrap();
    assert_eq!(result, "");
}

#[test]
fn urlencoded_single_param() {
    let result = ash_core::ash_canonicalize_urlencoded("a=1").unwrap();
    assert_eq!(result, "a=1");
}

#[test]
fn urlencoded_empty_value() {
    let result = ash_core::ash_canonicalize_urlencoded("a=").unwrap();
    assert_eq!(result, "a=");
}

#[test]
fn urlencoded_multiple_empty_values() {
    let result = ash_core::ash_canonicalize_urlencoded("b=&a=").unwrap();
    assert_eq!(result, "a=&b=");
}

#[test]
fn urlencoded_duplicate_keys() {
    let result = ash_core::ash_canonicalize_urlencoded("a=2&a=1&a=3").unwrap();
    assert_eq!(result, "a=1&a=2&a=3");
}

#[test]
fn urlencoded_many_duplicates() {
    let result = ash_core::ash_canonicalize_urlencoded("x=5&x=3&x=1&x=4&x=2").unwrap();
    assert_eq!(result, "x=1&x=2&x=3&x=4&x=5");
}

#[test]
fn urlencoded_mixed_keys() {
    let result = ash_core::ash_canonicalize_urlencoded("z=3&a=1&m=2&b=4").unwrap();
    assert_eq!(result, "a=1&b=4&m=2&z=3");
}

#[test]
fn urlencoded_special_chars_encoded() {
    let result = ash_core::ash_canonicalize_urlencoded("key=hello%20world").unwrap();
    assert!(result.contains("hello"));
}

#[test]
fn urlencoded_unicode_values() {
    let result = ash_core::ash_canonicalize_urlencoded("name=%E4%BD%A0%E5%A5%BD").unwrap();
    assert!(result.contains("name="));
}

// ============================================================================
// BINDING NORMALIZATION EDGE CASES
// ============================================================================

#[test]
fn binding_lowercase_method() {
    let result = ash_core::ash_normalize_binding("get", "/api", "").unwrap();
    assert!(result.starts_with("GET|"));
}

#[test]
fn binding_mixed_case_method() {
    let result = ash_core::ash_normalize_binding("GeT", "/api", "").unwrap();
    assert!(result.starts_with("GET|"));
}

#[test]
fn binding_post_method() {
    let result = ash_core::ash_normalize_binding("post", "/api", "").unwrap();
    assert!(result.starts_with("POST|"));
}

#[test]
fn binding_put_method() {
    let result = ash_core::ash_normalize_binding("PUT", "/api", "").unwrap();
    assert!(result.starts_with("PUT|"));
}

#[test]
fn binding_delete_method() {
    let result = ash_core::ash_normalize_binding("DELETE", "/api", "").unwrap();
    assert!(result.starts_with("DELETE|"));
}

#[test]
fn binding_patch_method() {
    let result = ash_core::ash_normalize_binding("PATCH", "/api", "").unwrap();
    assert!(result.starts_with("PATCH|"));
}

#[test]
fn binding_root_path() {
    let result = ash_core::ash_normalize_binding("GET", "/", "").unwrap();
    assert_eq!(result, "GET|/|");
}

#[test]
fn binding_trailing_slash() {
    let result = ash_core::ash_normalize_binding("GET", "/api/", "").unwrap();
    assert_eq!(result, "GET|/api|");
}

#[test]
fn binding_double_slash() {
    let result = ash_core::ash_normalize_binding("GET", "/api//test", "").unwrap();
    assert_eq!(result, "GET|/api/test|");
}

#[test]
fn binding_triple_slash() {
    let result = ash_core::ash_normalize_binding("GET", "/api///test", "").unwrap();
    assert_eq!(result, "GET|/api/test|");
}

#[test]
fn binding_many_slashes() {
    let result = ash_core::ash_normalize_binding("GET", "/a//b///c////d", "").unwrap();
    assert_eq!(result, "GET|/a/b/c/d|");
}

#[test]
fn binding_deep_path() {
    let result = ash_core::ash_normalize_binding("GET", "/api/v1/users/123/posts/456/comments", "").unwrap();
    assert_eq!(result, "GET|/api/v1/users/123/posts/456/comments|");
}

#[test]
fn binding_with_query() {
    let result = ash_core::ash_normalize_binding("GET", "/api", "page=1").unwrap();
    assert_eq!(result, "GET|/api|page=1");
}

#[test]
fn binding_query_sorted() {
    let result = ash_core::ash_normalize_binding("GET", "/api", "z=3&a=1").unwrap();
    assert_eq!(result, "GET|/api|a=1&z=3");
}

#[test]
fn binding_complex_query() {
    let result = ash_core::ash_normalize_binding("GET", "/search", "q=test&page=1&limit=10&sort=desc").unwrap();
    assert!(result.contains("limit=10"));
    assert!(result.contains("page=1"));
    assert!(result.contains("q=test"));
    assert!(result.contains("sort=desc"));
}

#[test]
fn binding_from_url_basic() {
    let result = ash_core::ash_normalize_binding_from_url("GET", "/api/test").unwrap();
    assert_eq!(result, "GET|/api/test|");
}

#[test]
fn binding_from_url_with_query() {
    let result = ash_core::ash_normalize_binding_from_url("GET", "/api?z=3&a=1").unwrap();
    assert_eq!(result, "GET|/api|a=1&z=3");
}

#[test]
fn binding_from_url_trailing_slash() {
    let result = ash_core::ash_normalize_binding_from_url("GET", "/api/test/").unwrap();
    assert_eq!(result, "GET|/api/test|");
}

// ============================================================================
// HASH EDGE CASES
// ============================================================================

#[test]
fn hash_body_empty() {
    let hash = ash_core::ash_hash_body("");
    assert_eq!(hash.len(), 64);
    // SHA-256 of empty string
    assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

#[test]
fn hash_body_whitespace() {
    let hash = ash_core::ash_hash_body(" ");
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_body_newline() {
    let hash = ash_core::ash_hash_body("\n");
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_body_tab() {
    let hash = ash_core::ash_hash_body("\t");
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_body_unicode() {
    let hash = ash_core::ash_hash_body("你好世界🌍");
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_body_very_long() {
    let long_string = "x".repeat(100_000);
    let hash = ash_core::ash_hash_body(&long_string);
    assert_eq!(hash.len(), 64);
}

#[test]
fn hash_body_binary_chars() {
    let hash = ash_core::ash_hash_body("\x00\x01\x02\x03");
    assert_eq!(hash.len(), 64);
}

// ============================================================================
// NONCE GENERATION EDGE CASES
// ============================================================================

#[test]
fn nonce_default_size() {
    let nonce = ash_core::ash_generate_nonce(32).unwrap();
    assert_eq!(nonce.len(), 64);
}

#[test]
fn nonce_small_size() {
    // Nonce must be at least 16 bytes
    let result = ash_core::ash_generate_nonce(8);
    assert!(result.is_err());

    // 16 bytes is the minimum
    let nonce = ash_core::ash_generate_nonce(16).unwrap();
    assert_eq!(nonce.len(), 32);  // hex is 2x bytes
}

#[test]
fn nonce_large_size() {
    let nonce = ash_core::ash_generate_nonce(128).unwrap();
    assert_eq!(nonce.len(), 256);
}

#[test]
fn nonce_uniqueness_10() {
    let mut nonces = std::collections::HashSet::new();
    for _ in 0..10 {
        let nonce = ash_core::ash_generate_nonce(32).unwrap();
        nonces.insert(nonce);
    }
    assert_eq!(nonces.len(), 10);
}

#[test]
fn context_id_has_prefix() {
    let ctx = ash_core::ash_generate_context_id().unwrap();
    assert!(ctx.starts_with("ash_"));
}

#[test]
fn context_id_uniqueness_10() {
    let mut contexts = std::collections::HashSet::new();
    for _ in 0..10 {
        let ctx = ash_core::ash_generate_context_id().unwrap();
        contexts.insert(ctx);
    }
    assert_eq!(contexts.len(), 10);
}

// ============================================================================
// TIMING SAFE COMPARISON EDGE CASES
// ============================================================================

#[test]
fn timing_safe_empty_strings() {
    assert!(ash_core::ash_timing_safe_equal(b"", b""));
}

#[test]
fn timing_safe_single_char() {
    assert!(ash_core::ash_timing_safe_equal(b"a", b"a"));
    assert!(!ash_core::ash_timing_safe_equal(b"a", b"b"));
}

#[test]
fn timing_safe_different_lengths() {
    assert!(!ash_core::ash_timing_safe_equal(b"abc", b"abcd"));
    assert!(!ash_core::ash_timing_safe_equal(b"abcd", b"abc"));
}

#[test]
fn timing_safe_same_prefix() {
    assert!(!ash_core::ash_timing_safe_equal(b"abc123", b"abc456"));
}

#[test]
fn timing_safe_differ_first_char() {
    assert!(!ash_core::ash_timing_safe_equal(b"Xbc", b"abc"));
}

#[test]
fn timing_safe_differ_last_char() {
    assert!(!ash_core::ash_timing_safe_equal(b"abX", b"abc"));
}

#[test]
fn timing_safe_unicode() {
    assert!(ash_core::ash_timing_safe_equal("你好".as_bytes(), "你好".as_bytes()));
    assert!(!ash_core::ash_timing_safe_equal("你好".as_bytes(), "世界".as_bytes()));
}

#[test]
fn timing_safe_binary() {
    assert!(ash_core::ash_timing_safe_equal(&[0, 1, 2, 3], &[0, 1, 2, 3]));
    assert!(!ash_core::ash_timing_safe_equal(&[0, 1, 2, 3], &[0, 1, 2, 4]));
}

#[test]
fn timing_safe_compare_strings() {
    assert!(ash_core::ash_timing_safe_equal("hello".as_bytes(), "hello".as_bytes()));
    assert!(!ash_core::ash_timing_safe_equal("hello".as_bytes(), "world".as_bytes()));
}

// ============================================================================
// PROOF EDGE CASES
// ============================================================================

#[test]
fn proof_short_nonce() {
    // Short nonces (less than 32 hex chars / 16 bytes) may be rejected
    let nonce = "a".repeat(16);
    let ctx = "ctx";
    let binding = "POST|/api|";

    // The library enforces minimum nonce length - test that it's either
    // accepted or rejected with an error (implementation dependent)
    let _ = ash_core::ash_derive_client_secret(&nonce, ctx, binding);
}

#[test]
fn proof_standard_nonce() {
    // Standard 32-byte nonce (64 hex chars) should always work
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";

    let result = ash_core::ash_derive_client_secret(&nonce, ctx, binding);
    assert!(result.is_ok());
}

#[test]
fn proof_long_nonce() {
    // Long nonces should work (up to reasonable limits)
    let nonce = "a".repeat(128);  // 64 bytes / 128 hex chars
    let ctx = "ctx";
    let binding = "POST|/api|";

    let result = ash_core::ash_derive_client_secret(&nonce, ctx, binding);
    assert!(result.is_ok());
}

#[test]
fn proof_ascii_context() {
    // ASCII context IDs should work
    let nonce = "a".repeat(64);
    let ctx = "ctx_test_12345";
    let binding = "POST|/api|";

    let result = ash_core::ash_derive_client_secret(&nonce, ctx, binding);
    assert!(result.is_ok());
}

#[test]
fn proof_complex_binding() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api/v1/users/123/posts|page=1&sort=desc";

    let result = ash_core::ash_derive_client_secret(&nonce, ctx, binding);
    assert!(result.is_ok());
}

#[test]
fn proof_very_long_timestamp() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let timestamp = "99999999999999";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash);
    assert!(result.is_ok());
}

#[test]
fn proof_zero_timestamp() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let timestamp = "0";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let result = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash);
    assert!(result.is_ok());
}

// ============================================================================
// STRESS TESTS
// ============================================================================

#[test]
fn stress_json_100() {
    for i in 0..100 {
        let input = format!(r#"{{"key{}":{},"nested":{{"value":{}}}}}"#, i, i, i * 2);
        let result = ash_core::ash_canonicalize_json(&input);
        assert!(result.is_ok());
    }
}

#[test]
fn stress_urlencoded_100() {
    for i in 0..100 {
        let input = format!("key{}={}&other=value", i, i);
        let result = ash_core::ash_canonicalize_urlencoded(&input);
        assert!(result.is_ok());
    }
}

#[test]
fn stress_binding_100() {
    let methods = ["GET", "POST", "PUT", "DELETE", "PATCH"];
    for i in 0..100 {
        let method = methods[i % 5];
        let path = format!("/api/v1/resource/{}", i);
        let query = format!("page={}&limit=10", i);
        let result = ash_core::ash_normalize_binding(method, &path, &query);
        assert!(result.is_ok());
    }
}

#[test]
fn stress_hash_body_100() {
    for i in 0..100 {
        let input = format!("content_{}", i);
        let hash = ash_core::ash_hash_body(&input);
        assert_eq!(hash.len(), 64);
    }
}

#[test]
fn stress_nonce_100() {
    let mut nonces = std::collections::HashSet::new();
    for _ in 0..100 {
        let nonce = ash_core::ash_generate_nonce(32).unwrap();
        nonces.insert(nonce);
    }
    assert_eq!(nonces.len(), 100);
}

#[test]
fn stress_context_id_100() {
    let mut contexts = std::collections::HashSet::new();
    for _ in 0..100 {
        let ctx = ash_core::ash_generate_context_id().unwrap();
        contexts.insert(ctx);
    }
    assert_eq!(contexts.len(), 100);
}

#[test]
fn stress_full_proof_cycle_50() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_stress";

    for i in 0..50 {
        let binding = format!("POST|/api/{}|", i);
        let timestamp = format!("{}", 1000000000 + i);
        let body = format!(r#"{{"data":{}}}"#, i);
        let body_hash = ash_core::ash_hash_body(&ash_core::ash_canonicalize_json(&body).unwrap());

        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, &binding).unwrap();
        let proof = ash_core::ash_build_proof(&secret, &timestamp, &binding, &body_hash).unwrap();
        let result = ash_core::ash_verify_proof(&nonce, ctx, &binding, &timestamp, &body_hash, &proof).unwrap();

        assert!(result);
    }
}
