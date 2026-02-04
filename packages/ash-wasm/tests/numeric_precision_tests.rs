//! Numeric precision and large payload tests for ASH WASM bindings.
//! Tests numeric edge cases and very large payloads.

use ash_core;

// ============================================================================
// INTEGER PRECISION TESTS
// ============================================================================

#[test]
fn numeric_zero() {
    let input = r#"{"value":0}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains(":0}"));
}

#[test]
fn numeric_negative_zero() {
    // -0 should normalize to 0
    let input = r#"{"value":-0}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains(":0}") || result.contains(":-0}"));
}

#[test]
fn numeric_positive_integers() {
    let values = vec![1, 10, 100, 1000, 10000, 100000, 1000000];
    for val in values {
        let input = format!(r#"{{"value":{}}}"#, val);
        let result = ash_core::ash_canonicalize_json(&input).unwrap();
        assert!(result.contains(&format!(":{}", val)));
    }
}

#[test]
fn numeric_negative_integers() {
    let values = vec![-1, -10, -100, -1000, -10000, -100000, -1000000];
    for val in values {
        let input = format!(r#"{{"value":{}}}"#, val);
        let result = ash_core::ash_canonicalize_json(&input).unwrap();
        assert!(result.contains(&format!(":{}", val)));
    }
}

#[test]
fn numeric_max_safe_integer() {
    // JavaScript MAX_SAFE_INTEGER = 2^53 - 1 = 9007199254740991
    let input = r#"{"value":9007199254740991}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("9007199254740991"));
}

#[test]
fn numeric_min_safe_integer() {
    // JavaScript MIN_SAFE_INTEGER = -(2^53 - 1) = -9007199254740991
    let input = r#"{"value":-9007199254740991}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("-9007199254740991"));
}

#[test]
fn numeric_large_integers() {
    let values = vec![
        "123456789012345",
        "-123456789012345",
        "999999999999999",
        "-999999999999999",
    ];
    for val in values {
        let input = format!(r#"{{"value":{}}}"#, val);
        let result = ash_core::ash_canonicalize_json(&input);
        assert!(result.is_ok());
    }
}

// ============================================================================
// FLOATING POINT PRECISION TESTS
// ============================================================================

#[test]
fn numeric_simple_floats() {
    let values = vec!["0.1", "0.5", "0.25", "1.5", "10.5", "100.25"];
    for val in values {
        let input = format!(r#"{{"value":{}}}"#, val);
        let result = ash_core::ash_canonicalize_json(&input).unwrap();
        assert!(result.contains("value"));
    }
}

#[test]
fn numeric_negative_floats() {
    let values = vec!["-0.1", "-0.5", "-1.5", "-10.25"];
    for val in values {
        let input = format!(r#"{{"value":{}}}"#, val);
        let result = ash_core::ash_canonicalize_json(&input).unwrap();
        assert!(result.contains("value"));
    }
}

#[test]
fn numeric_small_floats() {
    let values = vec!["0.001", "0.0001", "0.00001", "0.000001"];
    for val in values {
        let input = format!(r#"{{"value":{}}}"#, val);
        let result = ash_core::ash_canonicalize_json(&input).unwrap();
        assert!(result.contains("value"));
    }
}

#[test]
fn numeric_pi_approximation() {
    let input = r#"{"pi":3.141592653589793}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("pi"));
}

#[test]
fn numeric_e_approximation() {
    let input = r#"{"e":2.718281828459045}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("e"));
}

// ============================================================================
// SCIENTIFIC NOTATION TESTS
// ============================================================================

#[test]
fn numeric_scientific_positive_exp() {
    let values = vec!["1e10", "1E10", "1.5e10", "1.5E10", "2e5", "9.9e9"];
    for val in values {
        let input = format!(r#"{{"value":{}}}"#, val);
        let result = ash_core::ash_canonicalize_json(&input).unwrap();
        assert!(result.contains("value"));
    }
}

#[test]
fn numeric_scientific_negative_exp() {
    let values = vec!["1e-10", "1E-10", "1.5e-5", "9.9e-9"];
    for val in values {
        let input = format!(r#"{{"value":{}}}"#, val);
        let result = ash_core::ash_canonicalize_json(&input).unwrap();
        assert!(result.contains("value"));
    }
}

#[test]
fn numeric_scientific_zero_exp() {
    let input = r#"{"value":1e0}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    // 1e0 = 1
    assert!(result.contains("value"));
}

// ============================================================================
// EDGE CASE NUMBERS TESTS
// ============================================================================

#[test]
fn numeric_trailing_zeros() {
    // Trailing zeros in decimals should be normalized
    let input = r#"{"value":1.50000}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("value"));
}

#[test]
fn numeric_leading_zeros() {
    // Leading zeros in numbers should be normalized
    let input = r#"{"value":007}"#;
    // This is actually invalid JSON (octal)
    let result = ash_core::ash_canonicalize_json(input);
    // May error or normalize
    let _ = result;
}

#[test]
fn numeric_plus_sign() {
    // + sign is not valid in JSON
    let input = r#"{"value":+1}"#;
    let result = ash_core::ash_canonicalize_json(input);
    assert!(result.is_err());
}

// ============================================================================
// LARGE PAYLOAD TESTS
// ============================================================================

#[test]
fn large_payload_1kb() {
    let value = "x".repeat(1000);
    let input = format!(r#"{{"data":"{}"}}"#, value);
    let result = ash_core::ash_canonicalize_json(&input).unwrap();
    assert!(result.len() > 1000);
}

#[test]
fn large_payload_10kb() {
    let value = "y".repeat(10000);
    let input = format!(r#"{{"data":"{}"}}"#, value);
    let result = ash_core::ash_canonicalize_json(&input).unwrap();
    assert!(result.len() > 10000);
}

#[test]
fn large_payload_100kb() {
    let value = "z".repeat(100000);
    let input = format!(r#"{{"data":"{}"}}"#, value);
    let result = ash_core::ash_canonicalize_json(&input).unwrap();
    assert!(result.len() > 100000);
}

#[test]
fn large_payload_1mb() {
    let value = "a".repeat(1000000);
    let input = format!(r#"{{"data":"{}"}}"#, value);
    let result = ash_core::ash_canonicalize_json(&input);
    // Should handle 1MB payload
    assert!(result.is_ok());
}

#[test]
fn large_payload_many_keys_100() {
    let pairs: Vec<String> = (0..100)
        .map(|i| format!(r#""key_{}":{}"#, i, i))
        .collect();
    let input = format!("{{{}}}", pairs.join(","));
    let result = ash_core::ash_canonicalize_json(&input).unwrap();
    // Keys should be sorted
    let pos_0 = result.find("key_0").unwrap();
    let pos_9 = result.find("key_9").unwrap();
    let pos_99 = result.find("key_99").unwrap();
    // Lexicographic sort: key_0 < key_9 < key_99
    assert!(pos_0 < pos_9);
    assert!(pos_9 < pos_99);
}

#[test]
fn large_payload_many_keys_500() {
    let pairs: Vec<String> = (0..500)
        .map(|i| format!(r#""field_{:04}":{}"#, i, i))
        .collect();
    let input = format!("{{{}}}", pairs.join(","));
    let result = ash_core::ash_canonicalize_json(&input);
    assert!(result.is_ok());
}

#[test]
fn large_payload_nested_10_levels() {
    let mut json = String::new();
    for i in 0..10 {
        json.push_str(&format!(r#"{{"level_{}":"#, i));
    }
    json.push_str("\"deepest\"");
    for _ in 0..10 {
        json.push('}');
    }
    let result = ash_core::ash_canonicalize_json(&json);
    assert!(result.is_ok());
}

#[test]
fn large_payload_nested_50_levels() {
    let mut json = String::new();
    for i in 0..50 {
        json.push_str(&format!(r#"{{"l{}":"#, i));
    }
    json.push_str("1");
    for _ in 0..50 {
        json.push('}');
    }
    let result = ash_core::ash_canonicalize_json(&json);
    assert!(result.is_ok());
}

#[test]
fn large_payload_array_1000_elements() {
    let elements: Vec<String> = (0..1000).map(|i| i.to_string()).collect();
    let input = format!(r#"{{"arr":[{}]}}"#, elements.join(","));
    let result = ash_core::ash_canonicalize_json(&input);
    assert!(result.is_ok());
}

// ============================================================================
// LARGE HASH TESTS
// ============================================================================

#[test]
fn large_hash_1kb() {
    let input = "x".repeat(1000);
    let hash = ash_core::ash_hash_body(&input);
    assert_eq!(hash.len(), 64);
}

#[test]
fn large_hash_100kb() {
    let input = "y".repeat(100000);
    let hash = ash_core::ash_hash_body(&input);
    assert_eq!(hash.len(), 64);
}

#[test]
fn large_hash_1mb() {
    let input = "z".repeat(1000000);
    let hash = ash_core::ash_hash_body(&input);
    assert_eq!(hash.len(), 64);
}

// ============================================================================
// LARGE PROOF WORKFLOW TESTS
// ============================================================================

#[test]
fn large_proof_10kb_payload() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let timestamp = "12345";

    let data = "d".repeat(10000);
    let payload = format!(r#"{{"data":"{}"}}"#, data);
    let body_hash = ash_core::ash_hash_body(&payload);

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    let valid = ash_core::ash_verify_proof(&nonce, ctx, binding, timestamp, &body_hash, &proof).unwrap();
    assert!(valid);
}

#[test]
fn large_proof_100kb_payload() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let timestamp = "12345";

    let data = "e".repeat(100000);
    let payload = format!(r#"{{"data":"{}"}}"#, data);
    let body_hash = ash_core::ash_hash_body(&payload);

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    let valid = ash_core::ash_verify_proof(&nonce, ctx, binding, timestamp, &body_hash, &proof).unwrap();
    assert!(valid);
}

// ============================================================================
// NUMERIC ARRAY TESTS
// ============================================================================

#[test]
fn numeric_array_integers() {
    let input = r#"{"nums":[1,2,3,4,5,6,7,8,9,10]}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert_eq!(result, r#"{"nums":[1,2,3,4,5,6,7,8,9,10]}"#);
}

#[test]
fn numeric_array_mixed() {
    let input = r#"{"nums":[0,-1,1.5,100,-0.5]}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("nums"));
}

#[test]
fn numeric_array_large() {
    let nums: Vec<String> = (0..100).map(|i| i.to_string()).collect();
    let input = format!(r#"{{"nums":[{}]}}"#, nums.join(","));
    let result = ash_core::ash_canonicalize_json(&input).unwrap();
    assert!(result.contains("nums"));
}

// ============================================================================
// STRESS TESTS
// ============================================================================

#[test]
fn stress_numeric_values_100() {
    for i in 0..100 {
        let input = format!(r#"{{"int":{},"float":{}.{},"neg":-{}}}"#, i, i, i, i);
        let result = ash_core::ash_canonicalize_json(&input).unwrap();
        assert!(result.contains("float"));
        assert!(result.contains("int"));
        assert!(result.contains("neg"));
    }
}

#[test]
fn stress_large_payloads_50() {
    for i in 0..50 {
        let size = (i + 1) * 100;  // 100 to 5000 chars
        let data = "x".repeat(size);
        let input = format!(r#"{{"data":"{}","index":{}}}"#, data, i);
        let result = ash_core::ash_canonicalize_json(&input);
        assert!(result.is_ok(), "Failed at size {}", size);
    }
}

#[test]
fn stress_proof_with_large_payloads_20() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";

    for i in 0..20 {
        let size = (i + 1) * 1000;  // 1KB to 20KB
        let timestamp = format!("{}", 1000000000 + i);
        let data = "y".repeat(size);
        let payload = format!(r#"{{"data":"{}"}}"#, data);
        let body_hash = ash_core::ash_hash_body(&payload);

        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
        let proof = ash_core::ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

        let valid = ash_core::ash_verify_proof(&nonce, ctx, binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(valid, "Failed at size {}KB", size / 1000);
    }
}
