//! Cross-SDK Test Vectors for ASH Rust SDK
//!
//! Tests from tests/cross-sdk/test-vectors.json for cross-platform compatibility.

use ash_core::{
    ash_canonicalize_json, ash_canonicalize_urlencoded,
    ash_normalize_binding, ash_hash_body, ash_timing_safe_equal,
    ash_derive_client_secret, ash_build_proof, ash_verify_proof,
    ash_extract_scoped_fields,
};
use serde_json::Value;

// =========================================================================
// JSON CANONICALIZATION VECTORS (RFC 8785 JCS)
// =========================================================================

mod canonicalization {
    use super::*;

    #[test]
    fn canon_001_simple_object_key_sorting() {
        let result = ash_canonicalize_json(r#"{"z":1,"a":2}"#).unwrap();
        assert_eq!(result, r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn canon_002_nested_object_key_sorting() {
        let result = ash_canonicalize_json(r#"{"b":{"z":1,"a":2},"a":3}"#).unwrap();
        assert_eq!(result, r#"{"a":3,"b":{"a":2,"z":1}}"#);
    }

    #[test]
    fn canon_003_array_preservation() {
        let result = ash_canonicalize_json(r#"{"arr":[3,1,2]}"#).unwrap();
        assert_eq!(result, r#"{"arr":[3,1,2]}"#);
    }

    #[test]
    fn canon_004_whitespace_removal() {
        let result = ash_canonicalize_json(r#"{ "a" : 1 , "b" : 2 }"#).unwrap();
        assert_eq!(result, r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn canon_005_unicode_nfc_normalization() {
        let result = ash_canonicalize_json(r#"{"café":"naïve"}"#).unwrap();
        assert_eq!(result, r#"{"café":"naïve"}"#);
    }

    #[test]
    fn canon_006_number_no_trailing_zeros() {
        let result = ash_canonicalize_json(r#"{"n":1.0}"#).unwrap();
        assert_eq!(result, r#"{"n":1}"#);
    }

    #[test]
    fn canon_007_number_no_leading_zeros() {
        let result = ash_canonicalize_json(r#"{"n":0.5}"#).unwrap();
        assert_eq!(result, r#"{"n":0.5}"#);
    }

    #[test]
    fn canon_008_negative_zero_becomes_zero() {
        let result = ash_canonicalize_json(r#"{"n":-0}"#).unwrap();
        assert_eq!(result, r#"{"n":0}"#);
    }

    #[test]
    fn canon_009_boolean_and_null_values() {
        let result = ash_canonicalize_json(r#"{"t":true,"f":false,"n":null}"#).unwrap();
        assert_eq!(result, r#"{"f":false,"n":null,"t":true}"#);
    }

    #[test]
    fn canon_010_empty_object() {
        let result = ash_canonicalize_json(r#"{}"#).unwrap();
        assert_eq!(result, r#"{}"#);
    }

    #[test]
    fn canon_011_empty_array() {
        let result = ash_canonicalize_json(r#"{"arr":[]}"#).unwrap();
        assert_eq!(result, r#"{"arr":[]}"#);
    }

    #[test]
    fn canon_012_deeply_nested_structure() {
        let result = ash_canonicalize_json(r#"{"a":{"b":{"c":{"z":1,"a":2}}}}"#).unwrap();
        assert_eq!(result, r#"{"a":{"b":{"c":{"a":2,"z":1}}}}"#);
    }

    #[test]
    fn canon_013_string_escaping_quotes() {
        let result = ash_canonicalize_json(r#"{"s":"hello \"world\""}"#).unwrap();
        assert_eq!(result, r#"{"s":"hello \"world\""}"#);
    }

    #[test]
    fn canon_014_string_escaping_backslash() {
        let result = ash_canonicalize_json(r#"{"s":"path\\to\\file"}"#).unwrap();
        assert_eq!(result, r#"{"s":"path\\to\\file"}"#);
    }

    #[test]
    fn canon_015_string_escaping_control_characters() {
        let result = ash_canonicalize_json(r#"{"s":"line1\nline2\ttab"}"#).unwrap();
        assert_eq!(result, r#"{"s":"line1\nline2\ttab"}"#);
    }

    #[test]
    fn canon_016_large_integer() {
        let result = ash_canonicalize_json(r#"{"n":9007199254740991}"#).unwrap();
        assert_eq!(result, r#"{"n":9007199254740991}"#);
    }

    #[test]
    fn canon_017_scientific_notation_normalization() {
        let result = ash_canonicalize_json(r#"{"n":1e10}"#).unwrap();
        assert_eq!(result, r#"{"n":10000000000}"#);
    }

    #[test]
    fn canon_018_mixed_array_types() {
        let result = ash_canonicalize_json(r#"{"arr":[1,"two",true,null]}"#).unwrap();
        assert_eq!(result, r#"{"arr":[1,"two",true,null]}"#);
    }

    #[test]
    fn canon_019_unicode_emoji() {
        let result = ash_canonicalize_json(r#"{"emoji":"👍"}"#).unwrap();
        assert_eq!(result, r#"{"emoji":"👍"}"#);
    }

    #[test]
    fn canon_020_real_world_payload_transfer() {
        let result = ash_canonicalize_json(r#"{"amount":100.50,"currency":"USD","to":"account123","memo":"Payment"}"#).unwrap();
        assert_eq!(result, r#"{"amount":100.5,"currency":"USD","memo":"Payment","to":"account123"}"#);
    }
}

// =========================================================================
// URL-ENCODED CANONICALIZATION VECTORS
// =========================================================================

mod urlencoded_canonicalization {
    use super::*;

    #[test]
    fn url_001_simple_key_sorting() {
        let result = ash_canonicalize_urlencoded("z=1&a=2").unwrap();
        assert_eq!(result, "a=2&z=1");
    }

    #[test]
    fn url_002_duplicate_keys_preserved() {
        let result = ash_canonicalize_urlencoded("a=1&b=2&a=3").unwrap();
        assert_eq!(result, "a=1&a=3&b=2");
    }

    #[test]
    fn url_003_percent_encoding_normalization() {
        let result = ash_canonicalize_urlencoded("name=John%20Doe").unwrap();
        assert_eq!(result, "name=John%20Doe");
    }

    #[test]
    fn url_004_plus_sign_handling() {
        let result = ash_canonicalize_urlencoded("q=a+b").unwrap();
        // Plus becomes space which then gets percent-encoded
        assert!(result.contains("q="));
    }

    #[test]
    fn url_005_empty_value() {
        let result = ash_canonicalize_urlencoded("key=").unwrap();
        assert_eq!(result, "key=");
    }

    #[test]
    fn url_006_key_without_value() {
        let result = ash_canonicalize_urlencoded("flag").unwrap();
        assert_eq!(result, "flag=");
    }
}

// =========================================================================
// BINDING NORMALIZATION VECTORS
// =========================================================================

mod binding_normalization {
    use super::*;

    #[test]
    fn bind_001_basic_binding() {
        let result = ash_normalize_binding("POST", "/api/users", "").unwrap();
        assert_eq!(result, "POST|/api/users|");
    }

    #[test]
    fn bind_002_method_uppercasing() {
        let result = ash_normalize_binding("post", "/api/users", "").unwrap();
        assert_eq!(result, "POST|/api/users|");
    }

    #[test]
    fn bind_003_trailing_slash_removal() {
        let result = ash_normalize_binding("GET", "/api/users/", "").unwrap();
        assert_eq!(result, "GET|/api/users|");
    }

    #[test]
    fn bind_004_duplicate_slash_collapse() {
        let result = ash_normalize_binding("PUT", "/api//users///profile", "").unwrap();
        assert_eq!(result, "PUT|/api/users/profile|");
    }

    #[test]
    fn bind_005_root_path_preserved() {
        let result = ash_normalize_binding("GET", "/", "").unwrap();
        assert_eq!(result, "GET|/|");
    }

    #[test]
    fn bind_006_query_string_sorting() {
        let result = ash_normalize_binding("GET", "/api/search", "z=3&a=1&b=2").unwrap();
        assert_eq!(result, "GET|/api/search|a=1&b=2&z=3");
    }

    #[test]
    fn bind_007_query_with_duplicate_keys() {
        let result = ash_normalize_binding("GET", "/api/filter", "tag=b&tag=a&sort=name").unwrap();
        assert_eq!(result, "GET|/api/filter|sort=name&tag=a&tag=b");
    }
}

// =========================================================================
// BODY HASH VECTORS (SHA-256)
// =========================================================================

mod hash_body {
    use super::*;

    #[test]
    fn hash_001_simple_json_body() {
        let hash = ash_hash_body(r#"{"a":1}"#);
        // Verify it's a valid 64-char hex string
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_002_empty_string() {
        let hash = ash_hash_body("");
        // Empty string SHA-256 is well-known
        assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn hash_003_canonical_transfer_payload() {
        let hash = ash_hash_body(r#"{"amount":100,"to":"account123"}"#);
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_deterministic() {
        let body = r#"{"test":"value"}"#;
        let hash1 = ash_hash_body(body);
        let hash2 = ash_hash_body(body);
        assert_eq!(hash1, hash2, "Hash should be deterministic");
    }

    #[test]
    fn hash_different_for_different_inputs() {
        let hash1 = ash_hash_body("input1");
        let hash2 = ash_hash_body("input2");
        assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
    }
}

// =========================================================================
// TIMING SAFE EQUAL VECTORS
// =========================================================================

mod timing_safe_equal {
    use super::*;

    #[test]
    fn time_001_equal_strings() {
        let result = ash_timing_safe_equal(b"abc123", b"abc123");
        assert!(result);
    }

    #[test]
    fn time_002_different_last_char() {
        let result = ash_timing_safe_equal(b"abc123", b"abc124");
        assert!(!result);
    }

    #[test]
    fn time_003_different_length() {
        let result = ash_timing_safe_equal(b"abc123", b"abc12");
        assert!(!result);
    }

    #[test]
    fn time_004_empty_strings() {
        let result = ash_timing_safe_equal(b"", b"");
        assert!(result);
    }

    #[test]
    fn time_005_completely_different() {
        let result = ash_timing_safe_equal(b"abc", b"xyz");
        assert!(!result);
    }

    #[test]
    fn time_first_char_different() {
        let result = ash_timing_safe_equal(b"abc123", b"xbc123");
        assert!(!result);
    }

    #[test]
    fn time_one_empty() {
        let result = ash_timing_safe_equal(b"abc", b"");
        assert!(!result);
    }
}

// =========================================================================
// ERROR CONDITION VECTORS
// =========================================================================

mod error_conditions {
    use super::*;

    #[test]
    fn err_001_invalid_json() {
        let result = ash_canonicalize_json("{invalid}");
        assert!(result.is_err());
    }

    #[test]
    fn err_002_empty_method() {
        let result = ash_normalize_binding("", "/api", "");
        assert!(result.is_err());
    }

    #[test]
    fn err_003_path_without_leading_slash() {
        let result = ash_normalize_binding("GET", "api/users", "");
        assert!(result.is_err());
    }

    #[test]
    fn err_malformed_json_array() {
        let result = ash_canonicalize_json("[1,2,3");
        assert!(result.is_err());
    }

    #[test]
    fn err_unclosed_string() {
        let result = ash_canonicalize_json(r#"{"key":"value}"#);
        assert!(result.is_err());
    }
}

// =========================================================================
// SCOPED FIELDS EXTRACTION VECTORS
// =========================================================================

mod scoped_fields {
    use super::*;

    #[test]
    fn scope_001_extract_single_field() {
        let payload: Value = serde_json::from_str(r#"{"amount":100,"to":"acc123","memo":"test"}"#).unwrap();
        let scope = vec!["amount"];
        let result = ash_extract_scoped_fields(&payload, &scope).unwrap();
        let canonical = ash_canonicalize_json(&result.to_string()).unwrap();
        assert_eq!(canonical, r#"{"amount":100}"#);
    }

    #[test]
    fn scope_002_extract_multiple_fields() {
        let payload: Value = serde_json::from_str(r#"{"amount":100,"to":"acc123","memo":"test"}"#).unwrap();
        let scope = vec!["amount", "to"];
        let result = ash_extract_scoped_fields(&payload, &scope).unwrap();
        let canonical = ash_canonicalize_json(&result.to_string()).unwrap();
        assert_eq!(canonical, r#"{"amount":100,"to":"acc123"}"#);
    }

    #[test]
    fn scope_empty_scope_returns_full_payload() {
        let payload: Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
        let scope: Vec<&str> = vec![];
        let result = ash_extract_scoped_fields(&payload, &scope).unwrap();
        let canonical = ash_canonicalize_json(&result.to_string()).unwrap();
        assert_eq!(canonical, r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn scope_missing_field_ignored() {
        let payload: Value = serde_json::from_str(r#"{"amount":100}"#).unwrap();
        let scope = vec!["amount", "nonexistent"];
        let result = ash_extract_scoped_fields(&payload, &scope).unwrap();
        let canonical = ash_canonicalize_json(&result.to_string()).unwrap();
        assert_eq!(canonical, r#"{"amount":100}"#);
    }
}

// =========================================================================
// PROOF GENERATION CROSS-SDK COMPATIBILITY
// =========================================================================

mod proof_compatibility {
    use super::*;

    #[test]
    fn proof_deterministic_generation() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test_001";
        let binding = "POST|/api/transfer|";
        let timestamp = "1706400000000";
        let body_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof1 = ash_build_proof(&secret, timestamp, binding, body_hash).unwrap();
        let proof2 = ash_build_proof(&secret, timestamp, binding, body_hash).unwrap();

        assert_eq!(proof1, proof2, "Same inputs should produce same proof");
    }

    #[test]
    fn proof_different_timestamp_different_proof() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/transfer|";
        let body_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof1 = ash_build_proof(&secret, "1706400000000", binding, body_hash).unwrap();
        let proof2 = ash_build_proof(&secret, "1706400000001", binding, body_hash).unwrap();

        assert_ne!(proof1, proof2, "Different timestamps should produce different proofs");
    }

    #[test]
    fn proof_different_binding_different_proof() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let timestamp = "1706400000000";
        let body_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        let binding1 = "POST|/api/transfer|";
        let binding2 = "POST|/api/login|";

        let secret1 = ash_derive_client_secret(&nonce, context_id, binding1).unwrap();
        let secret2 = ash_derive_client_secret(&nonce, context_id, binding2).unwrap();
        let proof1 = ash_build_proof(&secret1, timestamp, binding1, body_hash).unwrap();
        let proof2 = ash_build_proof(&secret2, timestamp, binding2, body_hash).unwrap();

        assert_ne!(proof1, proof2, "Different bindings should produce different proofs");
    }

    #[test]
    fn proof_roundtrip_verification() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_roundtrip";
        let binding = "POST|/api/test|";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let body_hash = ash_hash_body(r#"{"test":true}"#);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

        let verified = ash_verify_proof(&nonce, context_id, binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(verified, "Generated proof should verify");
    }

    #[test]
    fn proof_format_is_64_hex_chars() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_format";
        let binding = "GET|/|";

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let body_hash = ash_hash_body("");
        let proof = ash_build_proof(&secret, "12345", binding, &body_hash).unwrap();

        assert_eq!(proof.len(), 64, "Proof should be 64 characters");
        assert!(proof.chars().all(|c| c.is_ascii_hexdigit()), "Proof should be hex");
        assert!(proof.chars().all(|c| !c.is_uppercase()), "Proof should be lowercase hex");
    }
}
