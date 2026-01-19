//! Error types for ASH protocol.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Error codes for ASH protocol.
///
/// These codes are stable and should not change between versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AshErrorCode {
    /// Context not found in store
    InvalidContext,
    /// Context has expired
    ContextExpired,
    /// Context was already consumed (replay detected)
    ReplayDetected,
    /// Proof does not match expected value
    IntegrityFailed,
    /// Binding does not match expected endpoint
    EndpointMismatch,
    /// Mode requirements not met
    ModeViolation,
    /// Content type not supported
    UnsupportedContentType,
    /// Request format is invalid
    MalformedRequest,
    /// Payload cannot be canonicalized
    CanonicalizationFailed,
}

impl AshErrorCode {
    /// Get the recommended HTTP status code for this error.
    pub fn http_status(&self) -> u16 {
        match self {
            AshErrorCode::InvalidContext => 400,
            AshErrorCode::ContextExpired => 410,
            AshErrorCode::ReplayDetected => 409,
            AshErrorCode::IntegrityFailed => 400,
            AshErrorCode::EndpointMismatch => 400,
            AshErrorCode::ModeViolation => 400,
            AshErrorCode::UnsupportedContentType => 400,
            AshErrorCode::MalformedRequest => 400,
            AshErrorCode::CanonicalizationFailed => 400,
        }
    }

    /// Get the error code as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            AshErrorCode::InvalidContext => "ASH_INVALID_CONTEXT",
            AshErrorCode::ContextExpired => "ASH_CONTEXT_EXPIRED",
            AshErrorCode::ReplayDetected => "ASH_REPLAY_DETECTED",
            AshErrorCode::IntegrityFailed => "ASH_INTEGRITY_FAILED",
            AshErrorCode::EndpointMismatch => "ASH_ENDPOINT_MISMATCH",
            AshErrorCode::ModeViolation => "ASH_MODE_VIOLATION",
            AshErrorCode::UnsupportedContentType => "ASH_UNSUPPORTED_CONTENT_TYPE",
            AshErrorCode::MalformedRequest => "ASH_MALFORMED_REQUEST",
            AshErrorCode::CanonicalizationFailed => "ASH_CANONICALIZATION_FAILED",
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
    pub fn invalid_context() -> Self {
        Self::new(AshErrorCode::InvalidContext, "Context not found")
    }

    /// Context expired.
    pub fn context_expired() -> Self {
        Self::new(AshErrorCode::ContextExpired, "Context has expired")
    }

    /// Replay detected.
    pub fn replay_detected() -> Self {
        Self::new(AshErrorCode::ReplayDetected, "Context already consumed")
    }

    /// Integrity check failed.
    pub fn integrity_failed() -> Self {
        Self::new(AshErrorCode::IntegrityFailed, "Proof verification failed")
    }

    /// Endpoint mismatch.
    pub fn endpoint_mismatch() -> Self {
        Self::new(
            AshErrorCode::EndpointMismatch,
            "Binding does not match endpoint",
        )
    }

    /// Canonicalization failed.
    pub fn canonicalization_failed(reason: &str) -> Self {
        Self::new(
            AshErrorCode::CanonicalizationFailed,
            format!("Failed to canonicalize payload: {}", reason),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_http_status() {
        assert_eq!(AshErrorCode::InvalidContext.http_status(), 400);
        assert_eq!(AshErrorCode::ContextExpired.http_status(), 410);
        assert_eq!(AshErrorCode::ReplayDetected.http_status(), 409);
    }

    #[test]
    fn test_error_code_as_str() {
        assert_eq!(AshErrorCode::InvalidContext.as_str(), "ASH_INVALID_CONTEXT");
        assert_eq!(AshErrorCode::ReplayDetected.as_str(), "ASH_REPLAY_DETECTED");
    }

    #[test]
    fn test_error_display() {
        let err = AshError::invalid_context();
        assert_eq!(err.to_string(), "ASH_INVALID_CONTEXT: Context not found");
    }

    #[test]
    fn test_error_convenience_functions() {
        assert_eq!(
            AshError::invalid_context().code(),
            AshErrorCode::InvalidContext
        );
        assert_eq!(
            AshError::context_expired().code(),
            AshErrorCode::ContextExpired
        );
        assert_eq!(
            AshError::replay_detected().code(),
            AshErrorCode::ReplayDetected
        );
    }
}
