//! Proof generation and verification.
//!
//! Proofs are deterministic integrity tokens derived from:
//! - Context ID
//! - Binding (endpoint)
//! - Canonical payload
//! - Optional nonce (server-assisted mode)

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

use crate::compare::timing_safe_equal;
use crate::errors::AshError;
use crate::types::{AshMode, BuildProofInput, VerifyInput};

/// Protocol version identifier.
const ASH_VERSION: &str = "ASHv1";

/// Build a cryptographic proof for request integrity.
///
/// The proof is computed as:
/// ```text
/// proof = BASE64URL(SHA256(
///   "ASHv1\n" +
///   mode + "\n" +
///   binding + "\n" +
///   contextId + "\n" +
///   (nonce + "\n" if present) +
///   canonicalPayload
/// ))
/// ```
///
/// # Arguments
///
/// * `mode` - Security mode (minimal, balanced, strict)
/// * `binding` - Canonical binding (e.g., "POST /api/update")
/// * `context_id` - Context ID from server
/// * `nonce` - Optional nonce for server-assisted mode
/// * `canonical_payload` - Canonicalized payload string
///
/// # Example
///
/// ```rust
/// use ash_core::{build_proof, AshMode};
///
/// let proof = build_proof(
///     AshMode::Balanced,
///     "POST /api/profile",
///     "ctx_abc123",
///     None,
///     r#"{"name":"John"}"#,
/// ).unwrap();
///
/// println!("Proof: {}", proof);
/// ```
pub fn build_proof(
    mode: AshMode,
    binding: &str,
    context_id: &str,
    nonce: Option<&str>,
    canonical_payload: &str,
) -> Result<String, AshError> {
    // Build the proof input string
    let mut input = String::new();

    // Version
    input.push_str(ASH_VERSION);
    input.push('\n');

    // Mode
    input.push_str(&mode.to_string());
    input.push('\n');

    // Binding
    input.push_str(binding);
    input.push('\n');

    // Context ID
    input.push_str(context_id);
    input.push('\n');

    // Nonce (if present)
    if let Some(n) = nonce {
        input.push_str(n);
        input.push('\n');
    }

    // Canonical payload
    input.push_str(canonical_payload);

    // Compute SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash = hasher.finalize();

    // Encode as Base64URL without padding
    Ok(URL_SAFE_NO_PAD.encode(hash))
}

/// Build proof from a structured input.
///
/// Convenience wrapper around `build_proof` that accepts `BuildProofInput`.
#[allow(dead_code)]
pub fn ash_build_proof(input: &BuildProofInput) -> Result<String, AshError> {
    build_proof(
        input.mode,
        &input.binding,
        &input.context_id,
        input.nonce.as_deref(),
        &input.canonical_payload,
    )
}

/// Verify a proof using constant-time comparison.
///
/// # Security Note
///
/// This function uses constant-time comparison to prevent timing attacks.
/// The comparison time does not depend on where differences occur.
///
/// # Example
///
/// ```rust
/// use ash_core::{build_proof, verify_proof, AshMode, VerifyInput};
///
/// let expected = build_proof(
///     AshMode::Balanced,
///     "POST /api/profile",
///     "ctx_abc123",
///     None,
///     r#"{"name":"John"}"#,
/// ).unwrap();
///
/// let input = VerifyInput::new(&expected, &expected);
/// assert!(verify_proof(&input));
/// ```
pub fn verify_proof(input: &VerifyInput) -> bool {
    timing_safe_equal(
        input.expected_proof.as_bytes(),
        input.actual_proof.as_bytes(),
    )
}

/// Verify that two proofs match.
///
/// Convenience function for direct string comparison.
#[allow(dead_code)]
pub fn ash_verify_proof(expected: &str, actual: &str) -> bool {
    timing_safe_equal(expected.as_bytes(), actual.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_proof_deterministic() {
        let proof1 = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        let proof2 = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        assert_eq!(proof1, proof2);
    }

    #[test]
    fn test_build_proof_different_payload() {
        let proof1 = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        let proof2 = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":2}"#,
        )
        .unwrap();

        assert_ne!(proof1, proof2);
    }

    #[test]
    fn test_build_proof_different_context() {
        let proof1 = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        let proof2 = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx456",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        assert_ne!(proof1, proof2);
    }

    #[test]
    fn test_build_proof_different_binding() {
        let proof1 = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        let proof2 = build_proof(
            AshMode::Balanced,
            "PUT /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        assert_ne!(proof1, proof2);
    }

    #[test]
    fn test_build_proof_with_nonce() {
        let proof_without = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        let proof_with = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            Some("nonce456"),
            r#"{"a":1}"#,
        )
        .unwrap();

        assert_ne!(proof_without, proof_with);
    }

    #[test]
    fn test_build_proof_different_mode() {
        let proof1 = build_proof(
            AshMode::Minimal,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        let proof2 = build_proof(
            AshMode::Strict,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        assert_ne!(proof1, proof2);
    }

    #[test]
    fn test_verify_proof_match() {
        let proof = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        let input = VerifyInput::new(&proof, &proof);
        assert!(verify_proof(&input));
    }

    #[test]
    fn test_verify_proof_mismatch() {
        let proof1 = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        let proof2 = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":2}"#,
        )
        .unwrap();

        let input = VerifyInput::new(&proof1, &proof2);
        assert!(!verify_proof(&input));
    }

    #[test]
    fn test_proof_is_base64url() {
        let proof = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        // Base64URL should not contain + / =
        assert!(!proof.contains('+'));
        assert!(!proof.contains('/'));
        assert!(!proof.contains('='));

        // Should be 43 characters (256 bits / 6 bits per char, no padding)
        assert_eq!(proof.len(), 43);
    }
}
