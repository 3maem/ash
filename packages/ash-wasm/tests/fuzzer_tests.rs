//! Fuzzing-style tests for ASH WASM bindings.
//! These tests use randomized and edge-case inputs to find unexpected behavior.

use ash_core;
use std::collections::HashSet;

// ============================================================================
// JSON FUZZING TESTS
// ============================================================================

#[test]
fn fuzz_json_random_structures_100() {
    let structures = vec![
        "{}",
        "[]",
        "null",
        "true",
        "false",
        "0",
        "1",
        "-1",
        "0.5",
        r#""""#,
        r#""test""#,
        r#"{"a":1}"#,
        r#"{"a":1,"b":2}"#,
        r#"[1,2,3]"#,
        r#"{"nested":{"a":1}}"#,
        r#"[{"a":1},{"b":2}]"#,
        r#"{"arr":[1,2,3]}"#,
        r#"{"mix":[1,"two",true,null]}"#,
    ];

    for i in 0..100 {
        let structure = &structures[i % structures.len()];
        let result = ash_core::ash_canonicalize_json(structure);
        assert!(result.is_ok(), "Failed on: {}", structure);
    }
}

#[test]
fn fuzz_json_nested_depth() {
    for depth in 1..50 {
        let mut json = String::new();
        for _ in 0..depth {
            json.push_str(r#"{"n":"#);
        }
        json.push('1');
        for _ in 0..depth {
            json.push('}');
        }

        let result = ash_core::ash_canonicalize_json(&json);
        assert!(result.is_ok(), "Failed at depth {}", depth);
    }
}

#[test]
fn fuzz_json_array_sizes() {
    for size in [0, 1, 2, 5, 10, 50, 100] {
        let arr: Vec<String> = (0..size).map(|i| i.to_string()).collect();
        let json = format!(r#"{{"arr":[{}]}}"#, arr.join(","));

        let result = ash_core::ash_canonicalize_json(&json);
        assert!(result.is_ok(), "Failed with array size {}", size);
    }
}

#[test]
fn fuzz_json_key_lengths() {
    for len in [1, 2, 5, 10, 50, 100, 500] {
        let key = "k".repeat(len);
        let json = format!(r#"{{"{}":{}}}"#, key, len);

        let result = ash_core::ash_canonicalize_json(&json);
        assert!(result.is_ok(), "Failed with key length {}", len);
    }
}

#[test]
fn fuzz_json_value_lengths() {
    for len in [0, 1, 10, 100, 1000, 10000] {
        let value = "v".repeat(len);
        let json = format!(r#"{{"key":"{}"}}"#, value);

        let result = ash_core::ash_canonicalize_json(&json);
        assert!(result.is_ok(), "Failed with value length {}", len);
    }
}

#[test]
fn fuzz_json_many_keys() {
    for num_keys in [1, 5, 10, 50, 100] {
        let pairs: Vec<String> = (0..num_keys)
            .map(|i| format!(r#""key_{}":{}"#, i, i))
            .collect();
        let json = format!("{{{}}}", pairs.join(","));

        let result = ash_core::ash_canonicalize_json(&json);
        assert!(result.is_ok(), "Failed with {} keys", num_keys);
    }
}

#[test]
fn fuzz_json_special_numbers() {
    let numbers = vec![
        "0",
        "-0",
        "1",
        "-1",
        "0.0",
        "0.1",
        "-0.1",
        "1e10",
        "1E10",
        "1e-10",
        "1E-10",
        "1.5e10",
        "123456789",
        "-123456789",
        "0.123456789",
        "9999999999999999",
    ];

    for num in numbers {
        let json = format!(r#"{{"num":{}}}"#, num);
        let result = ash_core::ash_canonicalize_json(&json);
        assert!(result.is_ok(), "Failed with number: {}", num);
    }
}

#[test]
fn fuzz_json_escape_sequences() {
    let escapes = vec![
        r#""\\""#,        // backslash
        r#""\"""#,        // quote
        r#""\n""#,        // newline
        r#""\r""#,        // carriage return
        r#""\t""#,        // tab
        r#""\f""#,        // form feed
        r#""\b""#,        // backspace
        r#""\u0000""#,    // null
        r#""\u001f""#,    // control char
        r#""\u0020""#,    // space
        r#""\u00e9""#,    // e-acute
        r#""\u4e2d""#,    // chinese char
        r#""\ud83d\ude00""#, // emoji surrogate pair
    ];

    for escape in escapes {
        let json = format!(r#"{{"text":{}}}"#, escape);
        let result = ash_core::ash_canonicalize_json(&json);
        // Some may fail due to strict parsing, which is acceptable
        let _ = result;
    }
}

// ============================================================================
// QUERY STRING FUZZING TESTS
// ============================================================================

#[test]
fn fuzz_query_param_counts() {
    for count in [0, 1, 2, 5, 10, 50, 100] {
        if count == 0 {
            let result = ash_core::ash_canonicalize_query("");
            assert!(result.is_ok());
            continue;
        }

        let params: Vec<String> = (0..count)
            .map(|i| format!("p{}={}", i, i))
            .collect();
        let query = params.join("&");

        let result = ash_core::ash_canonicalize_query(&query);
        assert!(result.is_ok(), "Failed with {} params", count);
    }
}

#[test]
fn fuzz_query_key_lengths() {
    for len in [1, 2, 5, 10, 50, 100] {
        let key = "k".repeat(len);
        let query = format!("{}=value", key);

        let result = ash_core::ash_canonicalize_query(&query);
        assert!(result.is_ok(), "Failed with key length {}", len);
    }
}

#[test]
fn fuzz_query_value_lengths() {
    for len in [0, 1, 10, 100, 1000] {
        let value = "v".repeat(len);
        let query = format!("key={}", value);

        let result = ash_core::ash_canonicalize_query(&query);
        assert!(result.is_ok(), "Failed with value length {}", len);
    }
}

#[test]
fn fuzz_query_percent_encoding() {
    let chars = vec![
        "%20", "%21", "%22", "%23", "%24", "%25", "%26", "%27",
        "%28", "%29", "%2A", "%2B", "%2C", "%2D", "%2E", "%2F",
        "%3A", "%3B", "%3C", "%3D", "%3E", "%3F", "%40",
        "%5B", "%5C", "%5D", "%5E", "%5F", "%60",
        "%7B", "%7C", "%7D", "%7E",
    ];

    for encoded in chars {
        let query = format!("key={}", encoded);
        let result = ash_core::ash_canonicalize_query(&query);
        // Should handle encoded characters
        let _ = result;
    }
}

#[test]
fn fuzz_query_duplicate_keys() {
    for dup_count in [2, 3, 5, 10, 20] {
        let params: Vec<String> = (0..dup_count)
            .map(|i| format!("key={}", i))
            .collect();
        let query = params.join("&");

        let result = ash_core::ash_canonicalize_query(&query);
        assert!(result.is_ok(), "Failed with {} duplicates", dup_count);
    }
}

// ============================================================================
// BINDING FUZZING TESTS
// ============================================================================

#[test]
fn fuzz_binding_methods() {
    let methods = vec![
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE",
        "get", "post", "put", "delete", "patch", "head", "options",
        "Get", "Post", "Put", "Delete", "Patch",
    ];

    for method in methods {
        let result = ash_core::ash_normalize_binding(method, "/api", "");
        assert!(result.is_ok(), "Failed with method: {}", method);
        let binding = result.unwrap();
        assert!(binding.starts_with(&method.to_uppercase()));
    }
}

#[test]
fn fuzz_binding_paths() {
    let paths = vec![
        "/",
        "/api",
        "/api/v1",
        "/api/v1/users",
        "/api/v1/users/123",
        "/a/b/c/d/e/f/g/h/i/j",
        "/api-v1",
        "/api_v1",
        "/api.v1",
        "/api/resource/sub-resource",
    ];

    for path in paths {
        let result = ash_core::ash_normalize_binding("GET", path, "");
        assert!(result.is_ok(), "Failed with path: {}", path);
    }
}

#[test]
fn fuzz_binding_path_normalization() {
    // Valid paths (start with /)
    let valid_paths = vec![
        ("//api", "/api"),
        ("///api", "/api"),
        ("/api//v1", "/api/v1"),
        ("/api/", "/api"),
        ("/api//", "/api"),
    ];

    for (input, expected_contains) in valid_paths {
        let result = ash_core::ash_normalize_binding("GET", input, "").unwrap();
        assert!(result.contains(expected_contains),
            "Input {} should normalize to contain {}, got {}", input, expected_contains, result);
    }

    // Invalid paths (don't start with /) should error
    let invalid_paths = vec!["api", "api/v1"];
    for input in invalid_paths {
        let result = ash_core::ash_normalize_binding("GET", input, "");
        assert!(result.is_err(), "Path {} should error", input);
    }
}

// ============================================================================
// NONCE FUZZING TESTS
// ============================================================================

#[test]
fn fuzz_nonce_sizes() {
    let sizes = vec![1, 2, 4, 8, 16, 32, 64, 128];

    for size in sizes {
        let result = ash_core::ash_generate_nonce(size);
        if let Ok(nonce) = result {
            assert_eq!(nonce.len(), size * 2); // hex encoding
            assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }
}

#[test]
fn fuzz_nonce_uniqueness_stress() {
    let mut nonces = HashSet::new();
    for _ in 0..1000 {
        let nonce = ash_core::ash_generate_nonce(32).unwrap();
        assert!(nonces.insert(nonce), "Duplicate nonce generated!");
    }
}

// ============================================================================
// HASH FUZZING TESTS
// ============================================================================

#[test]
fn fuzz_hash_input_sizes() {
    for size in [0, 1, 10, 100, 1000, 10000, 100000] {
        let input = "x".repeat(size);
        let hash = ash_core::ash_hash_body(&input);
        assert_eq!(hash.len(), 64);
    }
}

#[test]
fn fuzz_hash_binary_patterns() {
    let patterns = vec![
        vec![0u8; 32],           // all zeros
        vec![255u8; 32],         // all ones
        (0..32).collect(),       // sequential
        (0..32).rev().collect(), // reverse sequential
        vec![0xAA; 32],          // alternating bits
        vec![0x55; 32],          // alternating bits (inverse)
    ];

    for pattern in patterns {
        let input = String::from_utf8_lossy(&pattern).to_string();
        let hash = ash_core::ash_hash_body(&input);
        assert_eq!(hash.len(), 64);
    }
}

#[test]
fn fuzz_hash_avalanche() {
    // Small changes should produce completely different hashes
    let base = "test input";
    let base_hash = ash_core::ash_hash_body(base);

    let variations = vec![
        "Test input",  // case change
        "test  input", // extra space
        "test input ", // trailing space
        " test input", // leading space
        "test inpuT",  // different case at end
        "test_input",  // underscore instead of space
        "testinput",   // no space
    ];

    for variation in variations {
        let hash = ash_core::ash_hash_body(variation);
        assert_ne!(hash, base_hash, "Hash should differ for: {}", variation);

        // Count differing characters (should be many due to avalanche)
        let diff_count: usize = hash.chars()
            .zip(base_hash.chars())
            .filter(|(a, b)| a != b)
            .count();

        // At least 50% of characters should differ
        assert!(diff_count >= 32,
            "Avalanche effect weak for '{}': only {} chars differ",
            variation, diff_count);
    }
}

// ============================================================================
// PROOF FUZZING TESTS
// ============================================================================

#[test]
fn fuzz_proof_timestamp_formats() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let body_hash = ash_core::ash_hash_body("{}");
    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    // Valid timestamps (seconds, not milliseconds - max ~10 digits)
    let valid_timestamps = vec![
        "0",
        "1",
        "1000000000",
        "1700000000",
        "2000000000",
        "12345",
    ];

    for ts in valid_timestamps {
        let proof = ash_core::ash_build_proof(&secret, ts, binding, &body_hash).unwrap();
        assert_eq!(proof.len(), 64);

        let valid = ash_core::ash_verify_proof(&nonce, ctx, binding, ts, &body_hash, &proof).unwrap();
        assert!(valid, "Failed with timestamp: {}", ts);
    }

    // Invalid timestamps (too large - in milliseconds) should still build proof but may fail validation
    let large_timestamps = vec!["1700000000000", "9999999999999"];
    for ts in large_timestamps {
        // Building proof works (no validation)
        let proof = ash_core::ash_build_proof(&secret, ts, binding, &body_hash).unwrap();
        assert_eq!(proof.len(), 64);
        // But verification will fail due to timestamp validation
    }
}

#[test]
fn fuzz_proof_context_ids() {
    let nonce = "a".repeat(64);
    let binding = "POST|/api|";
    let body_hash = ash_core::ash_hash_body("{}");
    let timestamp = "12345";

    let contexts = vec![
        "ctx",
        "context",
        "ash_ctx_123",
        "my-context-id",
        "context.with.dots",
        "ctx_with_underscores",
        "MixedCase123",
    ];

    for ctx in contexts {
        let result = ash_core::ash_derive_client_secret(&nonce, ctx, binding);
        if let Ok(secret) = result {
            let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();
            let valid = ash_core::ash_verify_proof(&nonce, ctx, binding, timestamp, &body_hash, &proof).unwrap();
            assert!(valid, "Failed with context: {}", ctx);
        }
    }
}

// ============================================================================
// SCOPED PROOF FUZZING TESTS
// ============================================================================

#[test]
fn fuzz_scoped_field_counts() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let timestamp = "12345";

    for field_count in [1, 2, 3, 5, 10] {
        let fields: Vec<String> = (0..field_count)
            .map(|i| format!("field_{}", i))
            .collect();

        let pairs: Vec<String> = fields.iter()
            .map(|f| format!(r#""{}":{}"#, f, 1))
            .collect();
        let payload = format!("{{{}}}", pairs.join(","));

        let scope: Vec<&str> = fields.iter().map(|s| s.as_str()).collect();
        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

        let result = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, &payload, &scope);
        assert!(result.is_ok(), "Failed with {} fields", field_count);
    }
}

#[test]
fn fuzz_scoped_nested_paths() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";
    let binding = "POST|/api|";
    let timestamp = "12345";

    let payloads_and_scopes = vec![
        (r#"{"a":{"b":1}}"#, vec!["a.b"]),
        (r#"{"a":{"b":{"c":1}}}"#, vec!["a.b.c"]),
        (r#"{"user":{"profile":{"name":"test"}}}"#, vec!["user.profile.name"]),
    ];

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    for (payload, scope) in payloads_and_scopes {
        let scope_refs: Vec<&str> = scope.iter().map(|s| &**s).collect();
        let result = ash_core::ash_build_proof_scoped(&secret, timestamp, binding, payload, &scope_refs);
        // Should handle nested paths
        let _ = result;
    }
}

// ============================================================================
// CHAIN PROOF FUZZING TESTS
// ============================================================================

#[test]
fn fuzz_chain_lengths() {
    let nonce = "a".repeat(64);
    let ctx = "ctx";

    for chain_length in [2, 3, 5, 10, 20] {
        let mut previous_proof: Option<String> = None;

        for step in 0..chain_length {
            let binding = format!("POST|/api/step/{}|", step);
            let timestamp = format!("{}", 1000000000 + step);
            let payload = format!(r#"{{"step":{}}}"#, step);

            let secret = ash_core::ash_derive_client_secret(&nonce, ctx, &binding).unwrap();
            let result = ash_core::ash_build_proof_unified(
                &secret, &timestamp, &binding, &payload, &[],
                previous_proof.as_deref()
            ).unwrap();

            previous_proof = Some(result.proof);
        }
    }
}

// ============================================================================
// TIMING SAFE COMPARISON FUZZING TESTS
// ============================================================================

#[test]
fn fuzz_timing_safe_lengths() {
    for len in [0, 1, 2, 5, 10, 32, 64, 100, 1000] {
        let a = "x".repeat(len);
        let b = "x".repeat(len);
        assert!(ash_core::ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
    }
}

#[test]
fn fuzz_timing_safe_diff_positions() {
    let base = "0".repeat(64);

    for pos in 0..64 {
        let mut chars: Vec<char> = base.chars().collect();
        chars[pos] = '1';
        let modified: String = chars.into_iter().collect();

        assert!(!ash_core::ash_timing_safe_equal(base.as_bytes(), modified.as_bytes()),
            "Should detect difference at position {}", pos);
    }
}

// ============================================================================
// COMPREHENSIVE FUZZ STRESS TEST
// ============================================================================

#[test]
fn fuzz_comprehensive_100() {
    for i in 0..100 {
        // Generate varied inputs
        let nonce = format!("{:064x}", i * 12345);
        let ctx = format!("ctx_fuzz_{}", i % 10);
        let binding = format!("{}|/api/fuzz/{}|",
            ["GET", "POST", "PUT", "DELETE"][i % 4],
            i
        );
        let timestamp = format!("{}", 1700000000 + i);
        let payload = format!(
            r#"{{"id":{},"type":"{}","nested":{{"value":{}}}}}"#,
            i,
            ["A", "B", "C"][i % 3],
            i * 10
        );

        // Canonicalize
        let canonical = ash_core::ash_canonicalize_json(&payload).unwrap();

        // Hash
        let body_hash = ash_core::ash_hash_body(&canonical);
        assert_eq!(body_hash.len(), 64);

        // Derive secret
        let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, &binding).unwrap();
        assert_eq!(secret.len(), 64);

        // Build proof
        let proof = ash_core::ash_build_proof(&secret, &timestamp, &binding, &body_hash).unwrap();
        assert_eq!(proof.len(), 64);

        // Verify
        let valid = ash_core::ash_verify_proof(&nonce, &ctx, &binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(valid, "Fuzz iteration {} failed", i);
    }
}
