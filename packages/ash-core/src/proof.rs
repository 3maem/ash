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

// =========================================================================
// ASH v2.1 - Derived Client Secret & Cryptographic Proof
// =========================================================================

use hmac::{Hmac, Mac};
use sha2::Sha256 as HmacSha256;

type HmacSha256Type = Hmac<HmacSha256>;

/// ASH v2.1 protocol version.
#[allow(dead_code)]
const ASH_VERSION_V21: &str = "ASHv2.1";

/// Generate a cryptographically secure random nonce.
///
/// # Arguments
/// * `bytes` - Number of bytes (default 32)
///
/// # Returns
/// Hex-encoded nonce (64 chars for 32 bytes)
pub fn generate_nonce(bytes: usize) -> String {
    use getrandom::getrandom;
    let mut buf = vec![0u8; bytes];
    getrandom(&mut buf).expect("Failed to generate random bytes");
    hex::encode(buf)
}

/// Generate a unique context ID with "ash_" prefix.
pub fn generate_context_id() -> String {
    format!("ash_{}", generate_nonce(16))
}

/// Derive client secret from server nonce (v2.1).
///
/// SECURITY PROPERTIES:
/// - One-way: Cannot derive nonce from clientSecret (HMAC is irreversible)
/// - Context-bound: Unique per contextId + binding combination
/// - Safe to expose: Client can use it but cannot forge other contexts
///
/// Formula: clientSecret = HMAC-SHA256(nonce, contextId + "|" + binding)
pub fn derive_client_secret(nonce: &str, context_id: &str, binding: &str) -> String {
    let mut mac = HmacSha256Type::new_from_slice(nonce.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(format!("{}|{}", context_id, binding).as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Build v2.1 cryptographic proof (client-side).
///
/// Formula: proof = HMAC-SHA256(clientSecret, timestamp + "|" + binding + "|" + bodyHash)
pub fn build_proof_v21(
    client_secret: &str,
    timestamp: &str,
    binding: &str,
    body_hash: &str,
) -> String {
    let message = format!("{}|{}|{}", timestamp, binding, body_hash);
    let mut mac = HmacSha256Type::new_from_slice(client_secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Verify v2.1 proof (server-side).
pub fn verify_proof_v21(
    nonce: &str,
    context_id: &str,
    binding: &str,
    timestamp: &str,
    body_hash: &str,
    client_proof: &str,
) -> bool {
    let client_secret = derive_client_secret(nonce, context_id, binding);
    let expected_proof = build_proof_v21(&client_secret, timestamp, binding, body_hash);
    timing_safe_equal(expected_proof.as_bytes(), client_proof.as_bytes())
}

/// Compute SHA-256 hash of canonical body.
pub fn hash_body(canonical_body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_body.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests_v21 {
    use super::*;

    #[test]
    fn test_derive_client_secret_deterministic() {
        let secret1 = derive_client_secret("nonce123", "ctx_abc", "POST /login");
        let secret2 = derive_client_secret("nonce123", "ctx_abc", "POST /login");
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_derive_client_secret_different_inputs() {
        let secret1 = derive_client_secret("nonce123", "ctx_abc", "POST /login");
        let secret2 = derive_client_secret("nonce456", "ctx_abc", "POST /login");
        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_build_proof_v21_deterministic() {
        let proof1 = build_proof_v21("secret", "1234567890", "POST /login", "bodyhash");
        let proof2 = build_proof_v21("secret", "1234567890", "POST /login", "bodyhash");
        assert_eq!(proof1, proof2);
    }

    #[test]
    fn test_verify_proof_v21() {
        let nonce = "nonce123";
        let context_id = "ctx_abc";
        let binding = "POST /login";
        let timestamp = "1234567890";
        let body_hash = "bodyhash123";

        let client_secret = derive_client_secret(nonce, context_id, binding);
        let proof = build_proof_v21(&client_secret, timestamp, binding, body_hash);

        assert!(verify_proof_v21(nonce, context_id, binding, timestamp, body_hash, &proof));
    }

    #[test]
    fn test_hash_body() {
        let hash = hash_body(r#"{"name":"John"}"#);
        assert_eq!(hash.len(), 64); // SHA-256 produces 32 bytes = 64 hex chars
    }
}
