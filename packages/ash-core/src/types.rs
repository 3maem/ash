//! Core types for ASH protocol.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::errors::{AshError, AshErrorCode};

/// Security mode for ASH verification.
///
/// Different modes provide different levels of security and overhead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AshMode {
    /// Lightweight integrity check.
    /// Lowest overhead, basic protection.
    Minimal,

    /// Default recommended mode.
    /// Good balance between security and performance.
    Balanced,

    /// Highest security level.
    /// Field-level integrity, strongest protection.
    Strict,
}

impl Default for AshMode {
    fn default() -> Self {
        AshMode::Balanced
    }
}

impl fmt::Display for AshMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AshMode::Minimal => write!(f, "minimal"),
            AshMode::Balanced => write!(f, "balanced"),
            AshMode::Strict => write!(f, "strict"),
        }
    }
}

impl FromStr for AshMode {
    type Err = AshError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "minimal" => Ok(AshMode::Minimal),
            "balanced" => Ok(AshMode::Balanced),
            "strict" => Ok(AshMode::Strict),
            _ => Err(AshError::new(
                AshErrorCode::ModeViolation,
                format!(
                    "Invalid mode: {}. Expected: minimal, balanced, or strict",
                    s
                ),
            )),
        }
    }
}

/// Input for building a proof.
#[derive(Debug, Clone)]
pub struct BuildProofInput {
    /// Security mode
    pub mode: AshMode,
    /// Canonical binding (e.g., "POST /api/update")
    pub binding: String,
    /// Context ID from server
    pub context_id: String,
    /// Optional nonce for server-assisted mode
    pub nonce: Option<String>,
    /// Canonicalized payload string
    pub canonical_payload: String,
}

impl BuildProofInput {
    /// Create a new BuildProofInput.
    pub fn new(
        mode: AshMode,
        binding: impl Into<String>,
        context_id: impl Into<String>,
        nonce: Option<String>,
        canonical_payload: impl Into<String>,
    ) -> Self {
        Self {
            mode,
            binding: binding.into(),
            context_id: context_id.into(),
            nonce,
            canonical_payload: canonical_payload.into(),
        }
    }
}

/// Input for verifying a proof.
#[derive(Debug, Clone)]
pub struct VerifyInput {
    /// Expected proof (computed by server)
    pub expected_proof: String,
    /// Actual proof (received from client)
    pub actual_proof: String,
}

impl VerifyInput {
    /// Create a new VerifyInput.
    pub fn new(expected_proof: impl Into<String>, actual_proof: impl Into<String>) -> Self {
        Self {
            expected_proof: expected_proof.into(),
            actual_proof: actual_proof.into(),
        }
    }
}

/// Context information returned to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextPublicInfo {
    /// Opaque context ID
    pub context_id: String,
    /// Expiration time (milliseconds since epoch)
    pub expires_at: u64,
    /// Security mode
    pub mode: AshMode,
    /// Optional nonce for server-assisted mode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// Stored context (server-side).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredContext {
    /// Opaque context ID
    pub context_id: String,
    /// Canonical binding
    pub binding: String,
    /// Security mode
    pub mode: AshMode,
    /// Issue time (milliseconds since epoch)
    pub issued_at: u64,
    /// Expiration time (milliseconds since epoch)
    pub expires_at: u64,
    /// Optional nonce
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Consumption time (null until consumed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<u64>,
}

impl StoredContext {
    /// Check if context has been consumed.
    pub fn is_consumed(&self) -> bool {
        self.consumed_at.is_some()
    }

    /// Check if context has expired.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ash_mode_default() {
        assert_eq!(AshMode::default(), AshMode::Balanced);
    }

    #[test]
    fn test_ash_mode_from_str() {
        assert_eq!("minimal".parse::<AshMode>().unwrap(), AshMode::Minimal);
        assert_eq!("balanced".parse::<AshMode>().unwrap(), AshMode::Balanced);
        assert_eq!("strict".parse::<AshMode>().unwrap(), AshMode::Strict);
        assert_eq!("BALANCED".parse::<AshMode>().unwrap(), AshMode::Balanced);
    }

    #[test]
    fn test_ash_mode_display() {
        assert_eq!(AshMode::Minimal.to_string(), "minimal");
        assert_eq!(AshMode::Balanced.to_string(), "balanced");
        assert_eq!(AshMode::Strict.to_string(), "strict");
    }

    #[test]
    fn test_stored_context_is_expired() {
        let ctx = StoredContext {
            context_id: "test".to_string(),
            binding: "POST /api".to_string(),
            mode: AshMode::Balanced,
            issued_at: 1000,
            expires_at: 2000,
            nonce: None,
            consumed_at: None,
        };

        assert!(!ctx.is_expired(1500));
        assert!(ctx.is_expired(2000));
        assert!(ctx.is_expired(3000));
    }

    #[test]
    fn test_stored_context_is_consumed() {
        let mut ctx = StoredContext {
            context_id: "test".to_string(),
            binding: "POST /api".to_string(),
            mode: AshMode::Balanced,
            issued_at: 1000,
            expires_at: 2000,
            nonce: None,
            consumed_at: None,
        };

        assert!(!ctx.is_consumed());
        ctx.consumed_at = Some(1500);
        assert!(ctx.is_consumed());
    }
}
