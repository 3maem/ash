//! Constant-time comparison for timing-attack resistance.
//!
//! All proof comparisons must use these functions to prevent
//! timing-based side-channel attacks.

use subtle::ConstantTimeEq;

/// Perform a constant-time comparison of two byte slices.
///
/// This function takes the same amount of time regardless of where
/// the first difference occurs, preventing timing attacks.
///
/// # Security Note
///
/// Always use this function when comparing proofs, tokens, or any
/// security-sensitive values. Regular `==` comparison can leak
/// information about where differences occur.
///
/// # Example
///
/// ```rust
/// use ash_core::timing_safe_equal;
///
/// let a = b"secret_proof_123";
/// let b = b"secret_proof_123";
/// let c = b"secret_proof_456";
///
/// assert!(timing_safe_equal(a, b));
/// assert!(!timing_safe_equal(a, c));
/// ```
pub fn timing_safe_equal(a: &[u8], b: &[u8]) -> bool {
    // Length check is not constant-time, but that's acceptable
    // since proof lengths are public knowledge
    if a.len() != b.len() {
        return false;
    }

    // Use subtle crate for constant-time comparison
    a.ct_eq(b).into()
}

/// Compare two strings in constant time.
///
/// Convenience wrapper around `timing_safe_equal` for string comparison.
///
/// # Example
///
/// ```rust
/// use ash_core::timing_safe_equal;
///
/// let proof1 = "abc123xyz";
/// let proof2 = "abc123xyz";
///
/// assert!(timing_safe_equal(proof1.as_bytes(), proof2.as_bytes()));
/// ```
#[allow(dead_code)]
pub fn ash_timing_safe_compare(a: &str, b: &str) -> bool {
    timing_safe_equal(a.as_bytes(), b.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timing_safe_equal_same() {
        let a = b"hello world";
        let b = b"hello world";
        assert!(timing_safe_equal(a, b));
    }

    #[test]
    fn test_timing_safe_equal_different() {
        let a = b"hello world";
        let b = b"hello worle";
        assert!(!timing_safe_equal(a, b));
    }

    #[test]
    fn test_timing_safe_equal_different_length() {
        let a = b"hello";
        let b = b"hello world";
        assert!(!timing_safe_equal(a, b));
    }

    #[test]
    fn test_timing_safe_equal_empty() {
        let a = b"";
        let b = b"";
        assert!(timing_safe_equal(a, b));
    }

    #[test]
    fn test_ash_timing_safe_compare() {
        assert!(ash_timing_safe_compare("test", "test"));
        assert!(!ash_timing_safe_compare("test", "Test"));
    }
}
