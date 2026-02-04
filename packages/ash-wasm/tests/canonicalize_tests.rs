//! Comprehensive canonicalization tests for ASH WASM bindings.
//! These tests use ash_core directly since wasm_bindgen functions can't run on native targets.

use ash_core;

// ============================================================================
// JSON CANONICALIZATION TESTS
// ============================================================================

#[test]
fn json_sorts_two_keys() {
    let result = ash_core::ash_canonicalize_json(r#"{"b":2,"a":1}"#).unwrap();
    assert_eq!(result, r#"{"a":1,"b":2}"#);
}

#[test]
fn json_sorts_three_keys() {
    let result = ash_core::ash_canonicalize_json(r#"{"c":3,"a":1,"b":2}"#).unwrap();
    assert_eq!(result, r#"{"a":1,"b":2,"c":3}"#);
}

#[test]
fn json_sorts_five_keys() {
    let result = ash_core::ash_canonicalize_json(r#"{"e":5,"c":3,"a":1,"d":4,"b":2}"#).unwrap();
    assert_eq!(result, r#"{"a":1,"b":2,"c":3,"d":4,"e":5}"#);
}

#[test]
fn json_sorts_numeric_string_keys() {
    let result = ash_core::ash_canonicalize_json(r#"{"10":"ten","2":"two","1":"one"}"#).unwrap();
    assert_eq!(result, r#"{"1":"one","10":"ten","2":"two"}"#);
}

#[test]
fn json_sorts_mixed_case_keys() {
    let result = ash_core::ash_canonicalize_json(r#"{"B":2,"a":1,"A":3,"b":4}"#).unwrap();
    assert_eq!(result, r#"{"A":3,"B":2,"a":1,"b":4}"#);
}

#[test]
fn json_handles_empty_object() {
    let result = ash_core::ash_canonicalize_json(r#"{}"#).unwrap();
    assert_eq!(result, r#"{}"#);
}

#[test]
fn json_handles_single_key() {
    let result = ash_core::ash_canonicalize_json(r#"{"key":"value"}"#).unwrap();
    assert_eq!(result, r#"{"key":"value"}"#);
}

#[test]
fn json_handles_empty_array() {
    let result = ash_core::ash_canonicalize_json(r#"[]"#).unwrap();
    assert_eq!(result, r#"[]"#);
}

#[test]
fn json_preserves_array_order() {
    let result = ash_core::ash_canonicalize_json(r#"[3,1,2]"#).unwrap();
    assert_eq!(result, r#"[3,1,2]"#);
}

#[test]
fn json_handles_nested_objects() {
    let result = ash_core::ash_canonicalize_json(r#"{"z":{"b":2,"a":1},"a":1}"#).unwrap();
    assert_eq!(result, r#"{"a":1,"z":{"a":1,"b":2}}"#);
}

#[test]
fn json_handles_deeply_nested() {
    let result = ash_core::ash_canonicalize_json(r#"{"z":{"y":{"x":{"b":2,"a":1}}}}"#).unwrap();
    assert_eq!(result, r#"{"z":{"y":{"x":{"a":1,"b":2}}}}"#);
}

#[test]
fn json_handles_objects_in_arrays() {
    let result = ash_core::ash_canonicalize_json(r#"[{"b":2,"a":1},{"d":4,"c":3}]"#).unwrap();
    assert_eq!(result, r#"[{"a":1,"b":2},{"c":3,"d":4}]"#);
}

#[test]
fn json_handles_true() {
    let result = ash_core::ash_canonicalize_json(r#"true"#).unwrap();
    assert_eq!(result, r#"true"#);
}

#[test]
fn json_handles_false() {
    let result = ash_core::ash_canonicalize_json(r#"false"#).unwrap();
    assert_eq!(result, r#"false"#);
}

#[test]
fn json_handles_null() {
    let result = ash_core::ash_canonicalize_json(r#"null"#).unwrap();
    assert_eq!(result, r#"null"#);
}

#[test]
fn json_handles_positive_integer() {
    let result = ash_core::ash_canonicalize_json(r#"42"#).unwrap();
    assert_eq!(result, r#"42"#);
}

#[test]
fn json_handles_negative_integer() {
    let result = ash_core::ash_canonicalize_json(r#"-42"#).unwrap();
    assert_eq!(result, r#"-42"#);
}

#[test]
fn json_handles_zero() {
    let result = ash_core::ash_canonicalize_json(r#"0"#).unwrap();
    assert_eq!(result, r#"0"#);
}

#[test]
fn json_handles_positive_float() {
    let result = ash_core::ash_canonicalize_json(r#"3.14"#).unwrap();
    assert_eq!(result, r#"3.14"#);
}

#[test]
fn json_handles_negative_float() {
    let result = ash_core::ash_canonicalize_json(r#"-3.14"#).unwrap();
    assert_eq!(result, r#"-3.14"#);
}

#[test]
fn json_handles_string() {
    let result = ash_core::ash_canonicalize_json(r#""hello""#).unwrap();
    assert_eq!(result, r#""hello""#);
}

#[test]
fn json_handles_empty_string() {
    let result = ash_core::ash_canonicalize_json(r#""""#).unwrap();
    assert_eq!(result, r#""""#);
}

#[test]
fn json_escapes_double_quote() {
    let result = ash_core::ash_canonicalize_json(r#""hello\"world""#).unwrap();
    assert_eq!(result, r#""hello\"world""#);
}

#[test]
fn json_escapes_backslash() {
    let result = ash_core::ash_canonicalize_json(r#""hello\\world""#).unwrap();
    assert_eq!(result, r#""hello\\world""#);
}

#[test]
fn json_escapes_newline() {
    let result = ash_core::ash_canonicalize_json(r#""hello\nworld""#).unwrap();
    assert_eq!(result, r#""hello\nworld""#);
}

#[test]
fn json_escapes_tab() {
    let result = ash_core::ash_canonicalize_json(r#""hello\tworld""#).unwrap();
    assert_eq!(result, r#""hello\tworld""#);
}

#[test]
fn json_handles_unicode() {
    let result = ash_core::ash_canonicalize_json(r#""café""#).unwrap();
    assert_eq!(result, r#""café""#);
}

#[test]
fn json_handles_chinese() {
    let result = ash_core::ash_canonicalize_json(r#""你好""#).unwrap();
    assert_eq!(result, r#""你好""#);
}

#[test]
fn json_handles_emoji() {
    let result = ash_core::ash_canonicalize_json(r#""🎉🚀""#).unwrap();
    assert_eq!(result, r#""🎉🚀""#);
}

#[test]
fn json_is_deterministic() {
    let input = r#"{"z":26,"a":1,"m":13}"#;
    let result1 = ash_core::ash_canonicalize_json(input).unwrap();
    let result2 = ash_core::ash_canonicalize_json(input).unwrap();
    assert_eq!(result1, result2);
}

#[test]
fn json_produces_no_whitespace() {
    let result = ash_core::ash_canonicalize_json(r#"{"key":"value","nested":{"a":1}}"#).unwrap();
    assert!(!result.contains(' '));
    assert!(!result.contains('\n'));
    assert!(!result.contains('\t'));
}

#[test]
fn json_rejects_invalid_json() {
    let result = ash_core::ash_canonicalize_json(r#"{"invalid""#);
    assert!(result.is_err());
}

#[test]
fn json_handles_large_array() {
    let input = format!("[{}]", (0..100).map(|i| i.to_string()).collect::<Vec<_>>().join(","));
    let result = ash_core::ash_canonicalize_json(&input).unwrap();
    assert!(result.starts_with("[0,1,2,"));
    assert!(result.ends_with(",98,99]"));
}

// ============================================================================
// URL ENCODED CANONICALIZATION TESTS
// ============================================================================

#[test]
fn urlencoded_sorts_two_params() {
    let result = ash_core::ash_canonicalize_urlencoded("b=2&a=1").unwrap();
    assert_eq!(result, "a=1&b=2");
}

#[test]
fn urlencoded_sorts_three_params() {
    let result = ash_core::ash_canonicalize_urlencoded("c=3&a=1&b=2").unwrap();
    assert_eq!(result, "a=1&b=2&c=3");
}

#[test]
fn urlencoded_handles_empty_value() {
    let result = ash_core::ash_canonicalize_urlencoded("a=&b=2").unwrap();
    assert_eq!(result, "a=&b=2");
}

#[test]
fn urlencoded_handles_duplicate_keys() {
    let result = ash_core::ash_canonicalize_urlencoded("a=2&a=1").unwrap();
    assert_eq!(result, "a=1&a=2");
}

#[test]
fn urlencoded_handles_empty_input() {
    let result = ash_core::ash_canonicalize_urlencoded("").unwrap();
    assert_eq!(result, "");
}

#[test]
fn urlencoded_is_deterministic() {
    let input = "z=3&a=1&m=2";
    let result1 = ash_core::ash_canonicalize_urlencoded(input).unwrap();
    let result2 = ash_core::ash_canonicalize_urlencoded(input).unwrap();
    assert_eq!(result1, result2);
}

// ============================================================================
// QUERY STRING CANONICALIZATION TESTS
// ============================================================================

#[test]
fn query_sorts_params() {
    let result = ash_core::ash_canonicalize_query("z=3&a=1&b=2").unwrap();
    assert_eq!(result, "a=1&b=2&z=3");
}

#[test]
fn query_handles_leading_question_mark() {
    let result = ash_core::ash_canonicalize_query("?z=3&a=1").unwrap();
    assert_eq!(result, "a=1&z=3");
}

#[test]
fn query_handles_empty_string() {
    let result = ash_core::ash_canonicalize_query("").unwrap();
    assert_eq!(result, "");
}

#[test]
fn query_is_deterministic() {
    let input = "z=3&a=1";
    let result1 = ash_core::ash_canonicalize_query(input).unwrap();
    let result2 = ash_core::ash_canonicalize_query(input).unwrap();
    assert_eq!(result1, result2);
}

// ============================================================================
// BINDING NORMALIZATION TESTS
// ============================================================================

#[test]
fn binding_normalizes_method_to_uppercase() {
    let result = ash_core::ash_normalize_binding("post", "/api", "").unwrap();
    assert!(result.starts_with("POST|"));
}

#[test]
fn binding_handles_get_method() {
    let result = ash_core::ash_normalize_binding("GET", "/api", "").unwrap();
    assert!(result.starts_with("GET|"));
}

#[test]
fn binding_collapses_duplicate_slashes() {
    let result = ash_core::ash_normalize_binding("GET", "/api//test///path", "").unwrap();
    assert_eq!(result, "GET|/api/test/path|");
}

#[test]
fn binding_removes_trailing_slash() {
    let result = ash_core::ash_normalize_binding("GET", "/api/test/", "").unwrap();
    assert_eq!(result, "GET|/api/test|");
}

#[test]
fn binding_preserves_root_path() {
    let result = ash_core::ash_normalize_binding("GET", "/", "").unwrap();
    assert_eq!(result, "GET|/|");
}

#[test]
fn binding_includes_query_string() {
    let result = ash_core::ash_normalize_binding("GET", "/api", "page=1&limit=10").unwrap();
    assert!(result.contains("page=1"));
}

#[test]
fn binding_sorts_query_params() {
    let result = ash_core::ash_normalize_binding("GET", "/api", "z=3&a=1").unwrap();
    assert!(result.ends_with("|a=1&z=3"));
}

#[test]
fn binding_handles_empty_query() {
    let result = ash_core::ash_normalize_binding("GET", "/api", "").unwrap();
    assert_eq!(result, "GET|/api|");
}

#[test]
fn binding_is_deterministic() {
    let result1 = ash_core::ash_normalize_binding("POST", "/api/test", "b=2&a=1").unwrap();
    let result2 = ash_core::ash_normalize_binding("POST", "/api/test", "b=2&a=1").unwrap();
    assert_eq!(result1, result2);
}

#[test]
fn binding_from_url_extracts_query() {
    let result = ash_core::ash_normalize_binding_from_url("GET", "/api/search?z=3&a=1").unwrap();
    assert_eq!(result, "GET|/api/search|a=1&z=3");
}

#[test]
fn binding_from_url_handles_no_query() {
    let result = ash_core::ash_normalize_binding_from_url("GET", "/api/test").unwrap();
    assert_eq!(result, "GET|/api/test|");
}

// ============================================================================
// STRESS TESTS
// ============================================================================

#[test]
fn json_stress_100_iterations() {
    for i in 0..100 {
        let input = format!(r#"{{"key{}":{},"nested":{{"value":{}}}}}"#, i, i, i * 2);
        let result = ash_core::ash_canonicalize_json(&input);
        assert!(result.is_ok());
    }
}

#[test]
fn urlencoded_stress_100_iterations() {
    for i in 0..100 {
        let input = format!("key{}={}&other=test", i, i);
        let result = ash_core::ash_canonicalize_urlencoded(&input);
        assert!(result.is_ok());
    }
}

#[test]
fn binding_stress_100_iterations() {
    let methods = ["GET", "POST", "PUT", "DELETE", "PATCH"];
    for i in 0..100 {
        let method = methods[i % 5];
        let path = format!("/api/v1/resource/{}", i);
        let query = format!("page={}&limit=10", i);
        let result = ash_core::ash_normalize_binding(method, &path, &query);
        assert!(result.is_ok());
    }
}
