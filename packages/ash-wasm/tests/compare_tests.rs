//! Comparison function tests for ASH WASM bindings.
//! These tests use ash_core directly since wasm_bindgen functions can't run on native targets.

use ash_core;

// ============================================================================
// TIMING SAFE EQUAL BASIC TESTS
// ============================================================================

#[test]
fn timing_safe_equal_identical_empty() {
    assert!(ash_core::ash_timing_safe_equal(b"", b""));
}

#[test]
fn timing_safe_equal_identical_single_char() {
    assert!(ash_core::ash_timing_safe_equal(b"a", b"a"));
}

#[test]
fn timing_safe_equal_identical_short() {
    assert!(ash_core::ash_timing_safe_equal(b"hello", b"hello"));
}

#[test]
fn timing_safe_equal_identical_medium() {
    let s = "a".repeat(64);
    assert!(ash_core::ash_timing_safe_equal(s.as_bytes(), s.as_bytes()));
}

#[test]
fn timing_safe_equal_identical_long() {
    let s = "x".repeat(1000);
    assert!(ash_core::ash_timing_safe_equal(s.as_bytes(), s.as_bytes()));
}

#[test]
fn timing_safe_equal_different_empty_vs_char() {
    assert!(!ash_core::ash_timing_safe_equal(b"", b"a"));
}

#[test]
fn timing_safe_equal_different_char_vs_empty() {
    assert!(!ash_core::ash_timing_safe_equal(b"a", b""));
}

#[test]
fn timing_safe_equal_different_single_chars() {
    assert!(!ash_core::ash_timing_safe_equal(b"a", b"b"));
}

#[test]
fn timing_safe_equal_different_lengths_short() {
    assert!(!ash_core::ash_timing_safe_equal(b"ab", b"abc"));
}

#[test]
fn timing_safe_equal_different_lengths_long() {
    let a = "a".repeat(100);
    let b = "a".repeat(101);
    assert!(!ash_core::ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
}

#[test]
fn timing_safe_equal_differ_first_byte() {
    assert!(!ash_core::ash_timing_safe_equal(b"Xbcdef", b"abcdef"));
}

#[test]
fn timing_safe_equal_differ_middle_byte() {
    assert!(!ash_core::ash_timing_safe_equal(b"abcXef", b"abcdef"));
}

#[test]
fn timing_safe_equal_differ_last_byte() {
    assert!(!ash_core::ash_timing_safe_equal(b"abcdeX", b"abcdef"));
}

#[test]
fn timing_safe_equal_case_sensitive() {
    assert!(!ash_core::ash_timing_safe_equal(b"Hello", b"hello"));
}

#[test]
fn timing_safe_equal_whitespace_matters() {
    assert!(!ash_core::ash_timing_safe_equal(b"hello", b"hello "));
    assert!(!ash_core::ash_timing_safe_equal(b" hello", b"hello"));
}

// ============================================================================
// TIMING SAFE EQUAL BINARY TESTS
// ============================================================================

#[test]
fn timing_safe_equal_binary_zeros() {
    assert!(ash_core::ash_timing_safe_equal(&[0, 0, 0, 0], &[0, 0, 0, 0]));
}

#[test]
fn timing_safe_equal_binary_ones() {
    assert!(ash_core::ash_timing_safe_equal(&[255, 255, 255, 255], &[255, 255, 255, 255]));
}

#[test]
fn timing_safe_equal_binary_mixed() {
    assert!(ash_core::ash_timing_safe_equal(&[0, 127, 128, 255], &[0, 127, 128, 255]));
}

#[test]
fn timing_safe_equal_binary_differ() {
    assert!(!ash_core::ash_timing_safe_equal(&[0, 0, 0, 0], &[0, 0, 0, 1]));
}

#[test]
fn timing_safe_equal_binary_null_bytes() {
    assert!(ash_core::ash_timing_safe_equal(&[0, 1, 0, 2, 0], &[0, 1, 0, 2, 0]));
    assert!(!ash_core::ash_timing_safe_equal(&[0, 1, 0, 2, 0], &[0, 1, 0, 3, 0]));
}

// ============================================================================
// TIMING SAFE EQUAL UNICODE TESTS
// ============================================================================

#[test]
fn timing_safe_equal_unicode_identical() {
    assert!(ash_core::ash_timing_safe_equal("你好".as_bytes(), "你好".as_bytes()));
}

#[test]
fn timing_safe_equal_unicode_different() {
    assert!(!ash_core::ash_timing_safe_equal("你好".as_bytes(), "世界".as_bytes()));
}

#[test]
fn timing_safe_equal_emoji_identical() {
    assert!(ash_core::ash_timing_safe_equal("🎉🚀".as_bytes(), "🎉🚀".as_bytes()));
}

#[test]
fn timing_safe_equal_emoji_different() {
    assert!(!ash_core::ash_timing_safe_equal("🎉🚀".as_bytes(), "🎉💯".as_bytes()));
}

#[test]
fn timing_safe_equal_mixed_unicode() {
    assert!(ash_core::ash_timing_safe_equal("Hello 你好 🌍".as_bytes(), "Hello 你好 🌍".as_bytes()));
}

// ============================================================================
// ADDITIONAL TIMING SAFE EQUAL TESTS
// ============================================================================

#[test]
fn timing_safe_equal_64_chars() {
    let a = "a".repeat(64);
    let b = "a".repeat(64);
    assert!(ash_core::ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
}

#[test]
fn timing_safe_equal_64_chars_differ() {
    let a = "a".repeat(64);
    let b = format!("{}b", "a".repeat(63));
    assert!(!ash_core::ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
}

// ============================================================================
// STRING COMPARISON TESTS (using bytes)
// ============================================================================

#[test]
fn compare_str_identical() {
    assert!(ash_core::ash_timing_safe_equal("hello".as_bytes(), "hello".as_bytes()));
}

#[test]
fn compare_str_different() {
    assert!(!ash_core::ash_timing_safe_equal("hello".as_bytes(), "world".as_bytes()));
}

#[test]
fn compare_str_empty() {
    assert!(ash_core::ash_timing_safe_equal("".as_bytes(), "".as_bytes()));
}

#[test]
fn compare_str_empty_vs_non_empty() {
    assert!(!ash_core::ash_timing_safe_equal("".as_bytes(), "x".as_bytes()));
    assert!(!ash_core::ash_timing_safe_equal("x".as_bytes(), "".as_bytes()));
}

#[test]
fn compare_str_case_sensitive() {
    assert!(!ash_core::ash_timing_safe_equal("Hello".as_bytes(), "hello".as_bytes()));
}

#[test]
fn compare_str_unicode() {
    assert!(ash_core::ash_timing_safe_equal("你好世界".as_bytes(), "你好世界".as_bytes()));
    assert!(!ash_core::ash_timing_safe_equal("你好".as_bytes(), "世界".as_bytes()));
}

#[test]
fn compare_str_hex_strings() {
    let a = "a".repeat(64);
    let b = "a".repeat(64);
    assert!(ash_core::ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
}

#[test]
fn compare_str_hex_strings_differ() {
    let a = "a".repeat(64);
    let b = "b".repeat(64);
    assert!(!ash_core::ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
}

// ============================================================================
// PROOF COMPARISON TESTS
// ============================================================================

#[test]
fn compare_identical_proofs() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    assert!(ash_core::ash_timing_safe_equal(proof.as_bytes(), proof.as_bytes()));
}

#[test]
fn compare_different_proofs() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof1 = ash_core::ash_build_proof(&secret, "1234567890", binding, &body_hash).unwrap();
    let proof2 = ash_core::ash_build_proof(&secret, "1234567891", binding, &body_hash).unwrap();

    assert!(!ash_core::ash_timing_safe_equal(proof1.as_bytes(), proof2.as_bytes()));
}

#[test]
fn compare_proof_with_tampered() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();
    let tampered = "0".repeat(64);

    assert!(!ash_core::ash_timing_safe_equal(proof.as_bytes(), tampered.as_bytes()));
}

// ============================================================================
// HASH COMPARISON TESTS
// ============================================================================

#[test]
fn compare_identical_hashes() {
    let hash1 = ash_core::ash_hash_body("test");
    let hash2 = ash_core::ash_hash_body("test");
    assert!(ash_core::ash_timing_safe_equal(hash1.as_bytes(), hash2.as_bytes()));
}

#[test]
fn compare_different_hashes() {
    let hash1 = ash_core::ash_hash_body("test1");
    let hash2 = ash_core::ash_hash_body("test2");
    assert!(!ash_core::ash_timing_safe_equal(hash1.as_bytes(), hash2.as_bytes()));
}

// ============================================================================
// STRESS TESTS
// ============================================================================

#[test]
fn stress_timing_safe_equal_100() {
    for i in 0..100 {
        let s = format!("test_string_{:03}", i);
        assert!(ash_core::ash_timing_safe_equal(s.as_bytes(), s.as_bytes()));
    }
}

#[test]
fn stress_timing_safe_equal_different_100() {
    for i in 0..100 {
        let a = format!("string_a_{:03}", i);
        let b = format!("string_b_{:03}", i);
        assert!(!ash_core::ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
    }
}

#[test]
fn stress_str_comparison_100() {
    for i in 0..100 {
        let s = format!("comparison_test_{:03}", i);
        assert!(ash_core::ash_timing_safe_equal(s.as_bytes(), s.as_bytes()));
    }
}

#[test]
fn stress_proof_comparison_50() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_stress";
    let binding = "POST|/api|";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    for i in 0..50 {
        let timestamp = format!("{}", 1000000000 + i);
        let proof = ash_core::ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

        // Proof should equal itself
        assert!(ash_core::ash_timing_safe_equal(proof.as_bytes(), proof.as_bytes()));

        // Proof should not equal zeros
        assert!(!ash_core::ash_timing_safe_equal(proof.as_bytes(), "0".repeat(64).as_bytes()));
    }
}

#[test]
fn stress_hash_comparison_100() {
    for i in 0..100 {
        let input = format!("hash_test_input_{}", i);
        let hash = ash_core::ash_hash_body(&input);

        // Hash should equal itself
        assert!(ash_core::ash_timing_safe_equal(hash.as_bytes(), hash.as_bytes()));

        // Hash should not equal a different input's hash
        let other_hash = ash_core::ash_hash_body(&format!("different_{}", i));
        assert!(!ash_core::ash_timing_safe_equal(hash.as_bytes(), other_hash.as_bytes()));
    }
}

// ============================================================================
// EDGE CASES
// ============================================================================

#[test]
fn compare_near_matches() {
    // Strings that are very similar but differ by one char
    let base = "abcdefghijklmnopqrstuvwxyz";

    for i in 0..base.len() {
        let mut modified: Vec<char> = base.chars().collect();
        modified[i] = 'X';
        let modified_str: String = modified.into_iter().collect();

        assert!(!ash_core::ash_timing_safe_equal(base.as_bytes(), modified_str.as_bytes()));
    }
}

#[test]
fn compare_prefix_strings() {
    assert!(!ash_core::ash_timing_safe_equal("prefix".as_bytes(), "prefix_extended".as_bytes()));
    assert!(!ash_core::ash_timing_safe_equal("prefix_extended".as_bytes(), "prefix".as_bytes()));
}

#[test]
fn compare_suffix_strings() {
    assert!(!ash_core::ash_timing_safe_equal("suffix".as_bytes(), "a_suffix".as_bytes()));
    assert!(!ash_core::ash_timing_safe_equal("a_suffix".as_bytes(), "suffix".as_bytes()));
}

#[test]
fn compare_repeated_patterns() {
    assert!(ash_core::ash_timing_safe_equal("aaaa".as_bytes(), "aaaa".as_bytes()));
    assert!(!ash_core::ash_timing_safe_equal("aaaa".as_bytes(), "aaa".as_bytes()));
    assert!(!ash_core::ash_timing_safe_equal("aaaa".as_bytes(), "aaaaa".as_bytes()));
    assert!(!ash_core::ash_timing_safe_equal("aaaa".as_bytes(), "aaab".as_bytes()));
}

#[test]
fn compare_special_characters() {
    assert!(ash_core::ash_timing_safe_equal("!@#$%^&*()".as_bytes(), "!@#$%^&*()".as_bytes()));
    assert!(!ash_core::ash_timing_safe_equal("!@#$%^&*()".as_bytes(), "!@#$%^&*()_".as_bytes()));
}

#[test]
fn compare_newlines_and_tabs() {
    assert!(ash_core::ash_timing_safe_equal("line1\nline2".as_bytes(), "line1\nline2".as_bytes()));
    assert!(ash_core::ash_timing_safe_equal("col1\tcol2".as_bytes(), "col1\tcol2".as_bytes()));
    assert!(!ash_core::ash_timing_safe_equal("line1\nline2".as_bytes(), "line1\rline2".as_bytes()));
}

#[test]
fn compare_null_bytes() {
    assert!(ash_core::ash_timing_safe_equal(b"a\0b", b"a\0b"));
    assert!(!ash_core::ash_timing_safe_equal(b"a\0b", b"a\0c"));
}
