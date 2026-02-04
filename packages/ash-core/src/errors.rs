//! Error types for ASH protocol.
//!
//! This module provides structured error types with:
//! - Stable error codes for programmatic handling
//! - HTTP status code mappings for API responses
//! - Human-readable error messages
//!
//! ## Error Codes (v2.3.4 - Unique HTTP Status Codes)
//!
//! ASH uses unique HTTP status codes in the 450-499 range for precise error identification.
//!
//! | Code | HTTP Status | Meaning |
//! |------|-------------|---------|
//! | `CTX_NOT_FOUND` | 450 | Context ID not found in store |
//! | `CTX_EXPIRED` | 451 | Context has expired |
//! | `CTX_ALREADY_USED` | 452 | Context was already consumed (replay) |
//! | `PROOF_INVALID` | 460 | Proof verification failed |
//! | `BINDING_MISMATCH` | 461 | Request endpoint doesn't match context |
//! | `SCOPE_MISMATCH` | 473 | Scope hash mismatch |
//! | `CHAIN_BROKEN` | 474 | Chain verification failed |
//! | `TIMESTAMP_INVALID` | 482 | Invalid timestamp format |
//! | `PROOF_MISSING` | 483 | Required X-ASH-Proof header missing |
//! | `CANONICALIZATION_ERROR` | 422 | Payload cannot be canonicalized |
//! | `MALFORMED_REQUEST` | 400 | Invalid request format |
//! | `UNSUPPORTED_CONTENT_TYPE` | 415 | Content type not supported |
//! | `INTERNAL_ERROR` | 500 | Internal server error |
//!
//! ## Example
//!
//! ```rust
//! use ash_core::{AshError, AshErrorCode};
//!
//! fn verify_request() -> Result<(), AshError> {
//!     // Return an error with code and message
//!     Err(AshError::new(
//!         AshErrorCode::ProofInvalid,
//!         "Proof does not match expected value"
//!     ))
//! }
//!
//! match verify_request() {
//!     Ok(_) => println!("Valid!"),
//!     Err(e) => {
//!         println!("Error: {} (HTTP {})", e.message(), e.code().http_status());
//!     }
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;

/// Error codes for ASH protocol.
///
/// These codes are stable and should not change between versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AshErrorCode {
    /// Context not found in store
    CtxNotFound,
    /// Context has expired
    CtxExpired,
    /// Context was already consumed (replay detected)
    CtxAlreadyUsed,
    /// Binding does not match expected endpoint
    BindingMismatch,
    /// Required proof not provided
    ProofMissing,
    /// Proof does not match expected value
    ProofInvalid,
    /// Payload cannot be canonicalized
    CanonicalizationError,
    /// Malformed request (invalid method, path, etc.)
    MalformedRequest,
    /// Mode requirements not met
    ModeViolation,
    /// Content type not supported
    UnsupportedContentType,
    /// Scope hash mismatch (v2.2+)
    ScopeMismatch,
    /// Chain verification failed (v2.3+)
    ChainBroken,
    /// Internal server error (RNG failure, etc.)
    InternalError,
    /// Timestamp validation failed (SEC-005)
    TimestampInvalid,
    /// Required scoped field missing (SEC-006)
    ScopedFieldMissing,
}

impl AshErrorCode {
    /// Get the recommended HTTP status code for this error.
    ///
    /// v2.3.4: Uses unique HTTP status codes in the 450-499 range for ASH-specific errors.
    /// This enables precise error identification, better monitoring, and targeted retry logic.
    pub fn http_status(&self) -> u16 {
        match self {
            // Context errors (450-459)
            AshErrorCode::CtxNotFound => 450,
            AshErrorCode::CtxExpired => 451,
            AshErrorCode::CtxAlreadyUsed => 452,
            // Seal/Proof errors (460-469)
            AshErrorCode::ProofInvalid => 460,
            // Verification errors (461, 473-479)
            AshErrorCode::BindingMismatch => 461,
            AshErrorCode::ScopeMismatch => 473,
            AshErrorCode::ChainBroken => 474,
            // Format/Protocol errors (480-489)
            AshErrorCode::TimestampInvalid => 482,
            AshErrorCode::ProofMissing => 483,
            // Standard HTTP codes (preserved for semantic clarity)
            AshErrorCode::CanonicalizationError => 422,
            AshErrorCode::MalformedRequest => 400,
            AshErrorCode::ModeViolation => 400,
            AshErrorCode::UnsupportedContentType => 415,
            AshErrorCode::ScopedFieldMissing => 422,
            AshErrorCode::InternalError => 500,
        }
    }

    /// Get the error code as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            AshErrorCode::CtxNotFound => "ASH_CTX_NOT_FOUND",
            AshErrorCode::CtxExpired => "ASH_CTX_EXPIRED",
            AshErrorCode::CtxAlreadyUsed => "ASH_CTX_ALREADY_USED",
            AshErrorCode::BindingMismatch => "ASH_BINDING_MISMATCH",
            AshErrorCode::ProofMissing => "ASH_PROOF_MISSING",
            AshErrorCode::ProofInvalid => "ASH_PROOF_INVALID",
            AshErrorCode::CanonicalizationError => "ASH_CANONICALIZATION_ERROR",
            AshErrorCode::MalformedRequest => "ASH_MALFORMED_REQUEST",
            AshErrorCode::ModeViolation => "ASH_MODE_VIOLATION",
            AshErrorCode::UnsupportedContentType => "ASH_UNSUPPORTED_CONTENT_TYPE",
            AshErrorCode::ScopeMismatch => "ASH_SCOPE_MISMATCH",
            AshErrorCode::ChainBroken => "ASH_CHAIN_BROKEN",
            AshErrorCode::InternalError => "ASH_INTERNAL_ERROR",
            AshErrorCode::TimestampInvalid => "ASH_TIMESTAMP_INVALID",
            AshErrorCode::ScopedFieldMissing => "ASH_SCOPED_FIELD_MISSING",
        }
    }
}

impl fmt::Display for AshErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Main error type for ASH operations.
///
/// Error messages are designed to be safe for logging and client responses.
/// They never contain sensitive data like payloads, proofs, or canonical strings.
#[derive(Debug, Clone)]
pub struct AshError {
    /// Error code
    code: AshErrorCode,
    /// Human-readable message (safe for logging)
    message: String,
}

impl AshError {
    /// Create a new AshError.
    pub fn new(code: AshErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Get the error code.
    pub fn code(&self) -> AshErrorCode {
        self.code
    }

    /// Get the error message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Get the recommended HTTP status code.
    pub fn http_status(&self) -> u16 {
        self.code.http_status()
    }
}

impl fmt::Display for AshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AshError {}

/// Convenience functions for creating common errors.
impl AshError {
    /// Context not found.
    pub fn ctx_not_found() -> Self {
        Self::new(AshErrorCode::CtxNotFound, "Context not found")
    }

    /// Context expired.
    pub fn ctx_expired() -> Self {
        Self::new(AshErrorCode::CtxExpired, "Context has expired")
    }

    /// Context already used (replay detected).
    pub fn ctx_already_used() -> Self {
        Self::new(AshErrorCode::CtxAlreadyUsed, "Context already consumed")
    }

    /// Binding mismatch.
    pub fn binding_mismatch() -> Self {
        Self::new(
            AshErrorCode::BindingMismatch,
            "Binding does not match endpoint",
        )
    }

    /// Proof missing.
    pub fn proof_missing() -> Self {
        Self::new(AshErrorCode::ProofMissing, "Required proof not provided")
    }

    /// Proof invalid.
    pub fn proof_invalid() -> Self {
        Self::new(AshErrorCode::ProofInvalid, "Proof verification failed")
    }

    /// Canonicalization error.
    pub fn canonicalization_error(reason: &str) -> Self {
        Self::new(
            AshErrorCode::CanonicalizationError,
            format!("Failed to canonicalize payload: {}", reason),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_http_status() {
        // Context errors (450-459)
        assert_eq!(AshErrorCode::CtxNotFound.http_status(), 450);
        assert_eq!(AshErrorCode::CtxExpired.http_status(), 451);
        assert_eq!(AshErrorCode::CtxAlreadyUsed.http_status(), 452);
        // Seal/Proof errors (460-469)
        assert_eq!(AshErrorCode::ProofInvalid.http_status(), 460);
        // Binding errors (461)
        assert_eq!(AshErrorCode::BindingMismatch.http_status(), 461);
        assert_eq!(AshErrorCode::ScopeMismatch.http_status(), 473);
        assert_eq!(AshErrorCode::ChainBroken.http_status(), 474);
        // Format errors (480-489)
        assert_eq!(AshErrorCode::TimestampInvalid.http_status(), 482);
        assert_eq!(AshErrorCode::ProofMissing.http_status(), 483);
        // Standard HTTP codes
        assert_eq!(AshErrorCode::CanonicalizationError.http_status(), 422);
    }

    #[test]
    fn test_error_code_as_str() {
        assert_eq!(AshErrorCode::CtxNotFound.as_str(), "ASH_CTX_NOT_FOUND");
        assert_eq!(AshErrorCode::CtxAlreadyUsed.as_str(), "ASH_CTX_ALREADY_USED");
    }

    #[test]
    fn test_error_display() {
        let err = AshError::ctx_not_found();
        assert_eq!(err.to_string(), "ASH_CTX_NOT_FOUND: Context not found");
    }

    #[test]
    fn test_error_convenience_functions() {
        assert_eq!(
            AshError::ctx_not_found().code(),
            AshErrorCode::CtxNotFound
        );
        assert_eq!(
            AshError::ctx_expired().code(),
            AshErrorCode::CtxExpired
        );
        assert_eq!(
            AshError::ctx_already_used().code(),
            AshErrorCode::CtxAlreadyUsed
        );
    }
}
