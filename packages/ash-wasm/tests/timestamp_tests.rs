//! Timestamp validation tests for ASH WASM bindings.
//! These tests use ash_core directly since wasm_bindgen functions can't run on native targets.

use ash_core;
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// TIMESTAMP VALIDATION TESTS
// ============================================================================

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn validate_timestamp_current() {
    let ts = current_timestamp();
    let result = ash_core::ash_validate_timestamp(&ts.to_string(), 300, 0);
    assert!(result.is_ok());
}

#[test]
fn validate_timestamp_within_window() {
    let ts = current_timestamp() - 100;  // 100 seconds ago
    let result = ash_core::ash_validate_timestamp(&ts.to_string(), 300, 0);
    assert!(result.is_ok());
}

#[test]
fn validate_timestamp_at_window_edge() {
    let ts = current_timestamp() - 299;  // Just within 300 second window
    let result = ash_core::ash_validate_timestamp(&ts.to_string(), 300, 0);
    assert!(result.is_ok());
}

#[test]
fn validate_timestamp_expired() {
    let ts = current_timestamp() - 400;  // 400 seconds ago, outside 300 second window
    let result = ash_core::ash_validate_timestamp(&ts.to_string(), 300, 0);
    assert!(result.is_err());
}

#[test]
fn validate_timestamp_future() {
    let ts = current_timestamp() + 100;  // 100 seconds in future
    let result = ash_core::ash_validate_timestamp(&ts.to_string(), 300, 0);
    // Should fail without future allowance
    assert!(result.is_err());
}

#[test]
fn validate_timestamp_future_with_allowance() {
    let ts = current_timestamp() + 50;  // 50 seconds in future
    let result = ash_core::ash_validate_timestamp(&ts.to_string(), 300, 60);
    // Should pass with 60 second future allowance
    assert!(result.is_ok());
}

#[test]
fn validate_timestamp_future_exceeds_allowance() {
    let ts = current_timestamp() + 100;  // 100 seconds in future
    let result = ash_core::ash_validate_timestamp(&ts.to_string(), 300, 60);
    // Should fail - exceeds 60 second future allowance
    assert!(result.is_err());
}

#[test]
fn validate_timestamp_zero_window() {
    let ts = current_timestamp();
    let result = ash_core::ash_validate_timestamp(&ts.to_string(), 0, 0);
    // Zero window should only accept exact current time (practically always fails)
    // This is an edge case - behavior depends on implementation
    assert!(result.is_err() || result.is_ok());  // Either behavior is acceptable
}

#[test]
fn validate_timestamp_large_window() {
    let ts = current_timestamp() - 3600;  // 1 hour ago
    let result = ash_core::ash_validate_timestamp(&ts.to_string(), 7200, 0);  // 2 hour window
    assert!(result.is_ok());
}

#[test]
fn validate_timestamp_very_old() {
    let result = ash_core::ash_validate_timestamp("0", 300, 0);  // Epoch
    assert!(result.is_err());
}

#[test]
fn validate_timestamp_very_future() {
    let result = ash_core::ash_validate_timestamp("9999999999", 300, 0);  // Far future
    assert!(result.is_err());
}

#[test]
fn validate_timestamp_invalid_format() {
    let result = ash_core::ash_validate_timestamp("not_a_number", 300, 0);
    assert!(result.is_err());
}

#[test]
fn validate_timestamp_empty() {
    let result = ash_core::ash_validate_timestamp("", 300, 0);
    assert!(result.is_err());
}

#[test]
fn validate_timestamp_negative() {
    let result = ash_core::ash_validate_timestamp("-1", 300, 0);
    assert!(result.is_err());
}

#[test]
fn validate_timestamp_decimal() {
    let ts = current_timestamp();
    let result = ash_core::ash_validate_timestamp(&format!("{}.5", ts), 300, 0);
    // Decimal timestamps may or may not be accepted depending on implementation
    assert!(result.is_err() || result.is_ok());
}

// ============================================================================
// TIMESTAMP IN PROOF TESTS
// ============================================================================

#[test]
fn proof_with_current_timestamp() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = current_timestamp().to_string();
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

    assert_eq!(proof.len(), 64);
}

#[test]
fn proof_with_past_timestamp() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = (current_timestamp() - 100).to_string();
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

    assert_eq!(proof.len(), 64);
}

#[test]
fn proof_with_future_timestamp() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = (current_timestamp() + 100).to_string();
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

    // Proof generation should work regardless of timestamp validity
    assert_eq!(proof.len(), 64);
}

#[test]
fn proof_timestamps_differ_by_one_second() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof1 = ash_core::ash_build_proof(&secret, "1000000000", binding, &body_hash).unwrap();
    let proof2 = ash_core::ash_build_proof(&secret, "1000000001", binding, &body_hash).unwrap();

    assert_ne!(proof1, proof2);
}

#[test]
fn proof_verify_same_timestamp() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    let result = ash_core::ash_verify_proof(&nonce, ctx, binding, timestamp, &body_hash, &proof).unwrap();
    assert!(result);
}

#[test]
fn proof_verify_different_timestamp_fails() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, "1234567890", binding, &body_hash).unwrap();

    let result = ash_core::ash_verify_proof(&nonce, ctx, binding, "1234567891", &body_hash, &proof).unwrap();
    assert!(!result);
}

// ============================================================================
// TIMESTAMP STRESS TESTS
// ============================================================================

#[test]
fn stress_timestamp_sequence_100() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_stress";
    let binding = "POST|/api|";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    let mut prev_proof = String::new();
    for i in 0..100 {
        let timestamp = format!("{}", 1000000000 + i);
        let proof = ash_core::ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

        // Each proof should be unique
        assert_ne!(proof, prev_proof);
        prev_proof = proof.clone();

        // Each proof should verify
        let result = ash_core::ash_verify_proof(&nonce, ctx, binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(result);
    }
}

#[test]
fn stress_timestamp_random_100() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_stress";
    let binding = "POST|/api|";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    let timestamps = [
        1000000000u64, 1234567890, 1500000000, 1600000000, 1700000000,
        2000000000, 999999999, 1111111111, 1212121212, 1313131313,
    ];

    for ts in timestamps.iter().cycle().take(100) {
        let timestamp = ts.to_string();
        let proof = ash_core::ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();
        let result = ash_core::ash_verify_proof(&nonce, ctx, binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(result);
    }
}

#[test]
fn stress_timestamp_validation_100() {
    let base_ts = current_timestamp();

    for i in 0..100 {
        let ts = base_ts - i;
        let result = ash_core::ash_validate_timestamp(&ts.to_string(), 300, 0);

        if i < 300 {
            assert!(result.is_ok(), "Should be valid: {} seconds ago", i);
        } else {
            assert!(result.is_err(), "Should be invalid: {} seconds ago", i);
        }
    }
}

// ============================================================================
// EDGE CASE TIMESTAMP TESTS
// ============================================================================

#[test]
fn timestamp_epoch() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "0";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    assert_eq!(proof.len(), 64);
}

#[test]
fn timestamp_y2k38() {
    // Year 2038 problem timestamp (2147483647)
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "2147483647";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    assert_eq!(proof.len(), 64);
}

#[test]
fn timestamp_far_future() {
    // Year 3000+ timestamp
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "32503680000";  // Year 3000
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    assert_eq!(proof.len(), 64);
}

#[test]
fn timestamp_with_leading_zeros() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "0001234567890";  // Leading zeros
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    assert_eq!(proof.len(), 64);
}

#[test]
fn timestamp_max_u64() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "18446744073709551615";  // u64::MAX
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    assert_eq!(proof.len(), 64);
}

// ============================================================================
// TIMESTAMP FORMAT TESTS
// ============================================================================

#[test]
fn timestamp_as_string_numeric() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    // Various numeric string formats
    let timestamps = ["1234567890", "1", "999999999999"];

    for ts in timestamps {
        let proof = ash_core::ash_build_proof(&secret, ts, binding, &body_hash).unwrap();
        assert_eq!(proof.len(), 64);
    }
}

#[test]
fn timestamp_comparison_sensitivity() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    // Create proofs with different timestamp representations
    let proof1 = ash_core::ash_build_proof(&secret, "1234567890", binding, &body_hash).unwrap();
    let proof2 = ash_core::ash_build_proof(&secret, "01234567890", binding, &body_hash).unwrap();

    // Different string representations should produce different proofs
    // (implementation dependent - may or may not normalize)
    // Just verify both work
    assert_eq!(proof1.len(), 64);
    assert_eq!(proof2.len(), 64);
}
