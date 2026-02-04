//! Deterministic canonicalization for JSON and URL-encoded payloads.
//!
//! Canonicalization transforms payloads into a **deterministic byte sequence** that is
//! identical across all platforms, languages, and implementations. This is essential
//! for cryptographic hashing - the same logical data must always produce the same hash.
//!
//! ## Why Canonicalization?
//!
//! JSON and URL-encoded data can be represented in multiple equivalent ways:
//!
//! ```text
//! // These are logically equivalent but have different bytes:
//! {"a":1,"b":2}
//! {"b":2,"a":1}
//! { "a" : 1 , "b" : 2 }
//! ```
//!
//! Canonicalization ensures all representations normalize to a single form.
//!
//! ## JSON Canonicalization (RFC 8785)
//!
//! | Rule | Example |
//! |------|---------|
//! | Keys sorted lexicographically | `{"z":1,"a":2}` → `{"a":2,"z":1}` |
//! | No whitespace | `{ "a" : 1 }` → `{"a":1}` |
//! | Unicode NFC normalization | Combining characters normalized |
//! | `-0` becomes `0` | `{"a":-0}` → `{"a":0}` |
//! | Whole floats become integers | `{"a":5.0}` → `{"a":5}` |
//! | Arrays preserve order | `[3,1,2]` → `[3,1,2]` |
//!
//! ## Query String Canonicalization
//!
//! | Rule | Example |
//! |------|---------|
//! | Parameters sorted by key | `z=3&a=1` → `a=1&z=3` |
//! | Duplicate keys sorted by value | `a=2&a=1` → `a=1&a=2` |
//! | `+` is literal plus, not space | `a+b` → `a%2Bb` |
//! | Fragment stripped | `a=1#section` → `a=1` |
//! | Uppercase percent encoding | `%2f` → `%2F` |
//!
//! ## Security Limits
//!
//! - **Max recursion depth**: 64 levels (prevents stack overflow)
//! - **Max payload size**: 10 MB (prevents memory exhaustion)
//!
//! ## Example
//!
//! ```rust
//! use ash_core::{ash_canonicalize_json, ash_canonicalize_query};
//!
//! // JSON canonicalization
//! let json = r#"{ "z": 1, "a": { "c": 3, "b": 2 } }"#;
//! let canonical = ash_canonicalize_json(json).unwrap();
//! assert_eq!(canonical, r#"{"a":{"b":2,"c":3},"z":1}"#);
//!
//! // Query string canonicalization
//! let query = "z=3&a=1&a=2#fragment";
//! let canonical = ash_canonicalize_query(query).unwrap();
//! assert_eq!(canonical, "a=1&a=2&z=3");
//! ```

use serde_json::Value;
use unicode_normalization::UnicodeNormalization;

use crate::errors::{AshError, AshErrorCode};

/// Maximum recursion depth for JSON canonicalization to prevent stack overflow.
/// VULN-001: Prevents DoS via deeply nested JSON.
const MAX_RECURSION_DEPTH: usize = 64;

/// Maximum payload size in bytes for canonicalization.
/// VULN-002: Prevents memory exhaustion from large payloads.
const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Canonicalize a JSON string to deterministic form.
///
/// # Canonicalization Rules
///
/// 1. **Minified**: No whitespace between elements
/// 2. **Key Ordering**: Object keys sorted lexicographically (ascending)
/// 3. **Array Order**: Preserved (arrays are ordered)
/// 4. **Unicode**: NFC normalization applied to all strings
/// 5. **Numbers**:
///    - No scientific notation
///    - No trailing zeros after decimal
///    - `-0` becomes `0`
/// 6. **Unsupported Values**: `NaN`, `Infinity` cause rejection
///
/// # Example
///
/// ```rust
/// use ash_core::ash_canonicalize_json;
///
/// let input = r#"{ "z": 1, "a": { "c": 3, "b": 2 } }"#;
/// let output = ash_canonicalize_json(input).unwrap();
/// assert_eq!(output, r#"{"a":{"b":2,"c":3},"z":1}"#);
/// ```
///
/// # Errors
///
/// Returns `AshError` with `CanonicalizationError` if:
/// - Input is not valid JSON
/// - JSON contains unsupported values (NaN, Infinity)
pub fn ash_canonicalize_json(input: &str) -> Result<String, AshError> {
    // VULN-002: Validate payload size to prevent memory exhaustion
    if input.len() > MAX_PAYLOAD_SIZE {
        return Err(AshError::new(
            AshErrorCode::CanonicalizationError,
            format!("Payload exceeds maximum size of {} bytes", MAX_PAYLOAD_SIZE),
        ));
    }

    // Parse JSON
    let value: Value = serde_json::from_str(input).map_err(|e| {
        AshError::new(
            AshErrorCode::CanonicalizationError,
            format!("Invalid JSON: {}", e),
        )
    })?;

    // Canonicalize recursively with depth tracking (VULN-001)
    let canonical = ash_canonicalize_value_with_depth(&value, 0)?;

    // Serialize to minified JSON
    serde_json::to_string(&canonical).map_err(|e| {
        AshError::new(
            AshErrorCode::CanonicalizationError,
            format!("Failed to serialize: {}", e),
        )
    })
}

/// Recursively canonicalize a JSON value with depth tracking.
/// VULN-001: Prevents stack overflow via deeply nested JSON.
fn ash_canonicalize_value_with_depth(value: &Value, depth: usize) -> Result<Value, AshError> {
    // Check recursion depth to prevent stack overflow
    if depth > MAX_RECURSION_DEPTH {
        return Err(AshError::new(
            AshErrorCode::CanonicalizationError,
            format!("JSON exceeds maximum nesting depth of {}", MAX_RECURSION_DEPTH),
        ));
    }

    match value {
        Value::Null => Ok(Value::Null),
        Value::Bool(b) => Ok(Value::Bool(*b)),
        Value::Number(n) => ash_canonicalize_number(n),
        Value::String(s) => Ok(Value::String(ash_canonicalize_string(s))),
        Value::Array(arr) => {
            let canonical: Result<Vec<Value>, AshError> =
                arr.iter().map(|v| ash_canonicalize_value_with_depth(v, depth + 1)).collect();
            Ok(Value::Array(canonical?))
        }
        Value::Object(obj) => {
            // Sort keys lexicographically
            let mut sorted: Vec<(&String, &Value)> = obj.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));

            let mut canonical = serde_json::Map::new();
            for (key, val) in sorted {
                let canonical_key = ash_canonicalize_string(key);
                let canonical_val = ash_canonicalize_value_with_depth(val, depth + 1)?;
                canonical.insert(canonical_key, canonical_val);
            }
            Ok(Value::Object(canonical))
        }
    }
}

/// Canonicalize a number value per RFC 8785 (JCS).
///
/// Rules:
/// - MUST reject NaN and Infinity
/// - MUST convert -0 to 0
/// - MUST convert whole floats to integers (e.g., 5.0 -> 5)
fn ash_canonicalize_number(n: &serde_json::Number) -> Result<Value, AshError> {
    // Check for special values that shouldn't exist in valid JSON
    // but handle edge cases

    if let Some(i) = n.as_i64() {
        // Handle -0 case (though rare in integers)
        if i == 0 {
            return Ok(Value::Number(serde_json::Number::from(0)));
        }
        return Ok(Value::Number(serde_json::Number::from(i)));
    }

    if let Some(u) = n.as_u64() {
        return Ok(Value::Number(serde_json::Number::from(u)));
    }

    if let Some(f) = n.as_f64() {
        // Check for NaN and Infinity (MUST reject per RFC 8785)
        if f.is_nan() {
            return Err(AshError::new(
                AshErrorCode::CanonicalizationError,
                "NaN is not supported in ASH canonicalization (RFC 8785)",
            ));
        }
        if f.is_infinite() {
            return Err(AshError::new(
                AshErrorCode::CanonicalizationError,
                "Infinity is not supported in ASH canonicalization (RFC 8785)",
            ));
        }

        // Handle -0 -> 0 (MUST per RFC 8785)
        let f = if f == 0.0 && f.is_sign_negative() {
            0.0
        } else {
            f
        };

        // RFC 8785: Whole floats MUST become integers (5.0 -> 5)
        // Check if the float is a whole number within safe integer range
        // Note: i64::MAX as f64 rounds up, so we use JavaScript's MAX_SAFE_INTEGER (2^53 - 1)
        // which is the largest integer that can be exactly represented in f64
        const MAX_SAFE_INT: f64 = 9007199254740991.0; // 2^53 - 1
        if f.fract() == 0.0 && (-MAX_SAFE_INT..=MAX_SAFE_INT).contains(&f) {
            let i = f as i64;
            return Ok(Value::Number(serde_json::Number::from(i)));
        }

        // Convert back to Number for non-whole floats
        serde_json::Number::from_f64(f)
            .map(Value::Number)
            .ok_or_else(|| {
                AshError::new(
                    AshErrorCode::CanonicalizationError,
                    "Failed to canonicalize number",
                )
            })
    } else {
        Err(AshError::new(
            AshErrorCode::CanonicalizationError,
            "Unsupported number format",
        ))
    }
}

/// Canonicalize a string with Unicode NFC normalization.
fn ash_canonicalize_string(s: &str) -> String {
    s.nfc().collect()
}

/// Canonicalize a JSON Value to a deterministic string.
///
/// This is useful when you already have a parsed Value and want to canonicalize it.
///
/// # Security Note
///
/// Unlike [`ash_canonicalize_json`], this function does NOT validate the size of the input
/// Value, since it's already parsed and in memory. The size limit (MAX_PAYLOAD_SIZE)
/// is enforced by `canonicalize_json` during the string parsing phase.
///
/// If you're accepting Values from untrusted sources, use [`ash_canonicalize_json_value_with_size_check`]
/// instead, or ensure the original JSON string was validated via `ash_canonicalize_json` first.
///
/// # Example
///
/// ```rust
/// use ash_core::ash_canonicalize_json_value;
/// use serde_json::json;
///
/// let value = json!({"z": 1, "a": 2});
/// let output = ash_canonicalize_json_value(&value).unwrap();
/// assert_eq!(output, r#"{"a":2,"z":1}"#);
/// ```
pub fn ash_canonicalize_json_value(value: &Value) -> Result<String, AshError> {
    // VULN-001: Use depth-tracked version to prevent stack overflow
    let canonical = ash_canonicalize_value_with_depth(value, 0)?;
    serde_json::to_string(&canonical).map_err(|e| {
        AshError::new(
            AshErrorCode::CanonicalizationError,
            format!("Failed to serialize: {}", e),
        )
    })
}

/// Canonicalize a JSON Value with size validation.
///
/// BUG-044: This is the size-safe version for Values from untrusted sources.
/// It serializes the Value first to check size, then canonicalizes.
///
/// # Security Note
///
/// Use this function when the Value was constructed programmatically from untrusted
/// input without going through `ash_canonicalize_json` first.
///
/// # Example
///
/// ```rust
/// use ash_core::ash_canonicalize_json_value_with_size_check;
/// use serde_json::json;
///
/// let value = json!({"z": 1, "a": 2});
/// let output = ash_canonicalize_json_value_with_size_check(&value).unwrap();
/// assert_eq!(output, r#"{"a":2,"z":1}"#);
/// ```
pub fn ash_canonicalize_json_value_with_size_check(value: &Value) -> Result<String, AshError> {
    // BUG-044: Estimate size by serializing first
    let serialized = serde_json::to_string(value).map_err(|e| {
        AshError::new(
            AshErrorCode::CanonicalizationError,
            format!("Failed to serialize: {}", e),
        )
    })?;

    if serialized.len() > MAX_PAYLOAD_SIZE {
        return Err(AshError::new(
            AshErrorCode::CanonicalizationError,
            format!("Payload exceeds maximum size of {} bytes", MAX_PAYLOAD_SIZE),
        ));
    }

    ash_canonicalize_json_value(value)
}

/// Canonicalize URL-encoded form data.
///
/// # Canonicalization Rules
///
/// 1. Parse key=value pairs (split on `&`, then on first `=`)
/// 2. Percent-decode all values
/// 3. Apply Unicode NFC normalization
/// 4. Sort pairs by key lexicographically (byte order)
/// 5. For duplicate keys, sort by value (byte order)
/// 6. Re-encode with percent encoding
///
/// # Example
///
/// ```rust
/// use ash_core::ash_canonicalize_urlencoded;
///
/// let input = "z=3&a=1&a=2&b=hello%20world";
/// let output = ash_canonicalize_urlencoded(input).unwrap();
/// assert_eq!(output, "a=1&a=2&b=hello%20world&z=3");
/// ```
pub fn ash_canonicalize_urlencoded(input: &str) -> Result<String, AshError> {
    // VULN-002: Validate payload size
    if input.len() > MAX_PAYLOAD_SIZE {
        return Err(AshError::new(
            AshErrorCode::CanonicalizationError,
            format!("Payload exceeds maximum size of {} bytes", MAX_PAYLOAD_SIZE),
        ));
    }

    if input.is_empty() {
        return Ok(String::new());
    }

    // Parse pairs
    let mut pairs: Vec<(String, String)> = Vec::new();

    for part in input.split('&') {
        if part.is_empty() {
            continue;
        }

        let (key, value) = match part.find('=') {
            Some(pos) => (&part[..pos], &part[pos + 1..]),
            None => (part, ""),
        };

        // Percent-decode (+ is literal plus, not space, per ASH protocol)
        let decoded_key = ash_percent_decode_query(key)?;
        let decoded_value = ash_percent_decode_query(value)?;

        // NFC normalize
        let normalized_key: String = decoded_key.nfc().collect();
        let normalized_value: String = decoded_value.nfc().collect();

        pairs.push((normalized_key, normalized_value));
    }

    // Sort by key first, then by value for duplicate keys (byte-wise)
    pairs.sort_by(|a, b| {
        match a.0.as_bytes().cmp(b.0.as_bytes()) {
            std::cmp::Ordering::Equal => a.1.as_bytes().cmp(b.1.as_bytes()),
            other => other,
        }
    });

    // Re-encode and join (uppercase hex per spec)
    let encoded: Vec<String> = pairs
        .into_iter()
        .map(|(k, v)| format!("{}={}", ash_percent_encode_uppercase(&k), ash_percent_encode_uppercase(&v)))
        .collect();

    Ok(encoded.join("&"))
}

/// Percent-decode a string for URL-encoded form data.
/// NOTE: This treats + as space per application/x-www-form-urlencoded.
#[allow(dead_code)]
fn ash_percent_decode(input: &str) -> Result<String, AshError> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            // Read two hex digits
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() != 2 {
                return Err(AshError::new(
                    AshErrorCode::CanonicalizationError,
                    "Invalid percent encoding",
                ));
            }
            let byte = u8::from_str_radix(&hex, 16).map_err(|_| {
                AshError::new(
                    AshErrorCode::CanonicalizationError,
                    "Invalid percent encoding hex",
                )
            })?;
            bytes.push(byte);
        } else if ch == '+' {
            // Plus is space in form data (application/x-www-form-urlencoded)
            bytes.push(b' ');
        } else {
            // Encode character directly to UTF-8 bytes without allocation
            let mut buf = [0u8; 4];
            let encoded = ch.encode_utf8(&mut buf);
            bytes.extend_from_slice(encoded.as_bytes());
        }
    }

    // Convert bytes to UTF-8 string
    String::from_utf8(bytes).map_err(|_| {
        AshError::new(
            AshErrorCode::CanonicalizationError,
            "Invalid UTF-8 in percent-decoded string",
        )
    })
}

/// Percent-decode a string for query strings (RFC 3986).
/// NOTE: + is treated as literal plus, NOT space. Space must be %20.
fn ash_percent_decode_query(input: &str) -> Result<String, AshError> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            // Read two hex digits
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() != 2 {
                return Err(AshError::new(
                    AshErrorCode::CanonicalizationError,
                    "Invalid percent encoding",
                ));
            }
            let byte = u8::from_str_radix(&hex, 16).map_err(|_| {
                AshError::new(
                    AshErrorCode::CanonicalizationError,
                    "Invalid percent encoding hex",
                )
            })?;
            bytes.push(byte);
        } else {
            // + is literal plus in query strings (not space)
            // Encode character directly to UTF-8 bytes without allocation
            let mut buf = [0u8; 4];
            let encoded = ch.encode_utf8(&mut buf);
            bytes.extend_from_slice(encoded.as_bytes());
        }
    }

    // Convert bytes to UTF-8 string
    String::from_utf8(bytes).map_err(|_| {
        AshError::new(
            AshErrorCode::CanonicalizationError,
            "Invalid UTF-8 in percent-decoded string",
        )
    })
}

/// Canonicalize a URL query string according to ASH v2.3.1 specification.
///
/// # Canonicalization Rules (10 MUST rules)
///
/// 1. MUST parse query string after `?` (or use full string if no `?`)
/// 2. MUST strip fragment (#) and everything after it
/// 3. MUST split on `&` to get key=value pairs
/// 4. MUST handle keys without values (treat as empty string)
/// 5. MUST percent-decode all keys and values (+ is literal plus, NOT space)
/// 6. MUST apply Unicode NFC normalization
/// 7. MUST sort pairs by key lexicographically (byte order, strcmp)
/// 8. MUST sort by value for duplicate keys (byte order, strcmp)
/// 9. MUST re-encode with uppercase hex (%XX)
/// 10. MUST join with `&` separator
///
/// # Example
///
/// ```rust
/// use ash_core::ash_canonicalize_query;
///
/// let input = "z=3&a=1&b=hello%20world";
/// let output = ash_canonicalize_query(input).unwrap();
/// assert_eq!(output, "a=1&b=hello%20world&z=3");
///
/// // With leading ?
/// let input2 = "?z=3&a=1";
/// let output2 = ash_canonicalize_query(input2).unwrap();
/// assert_eq!(output2, "a=1&z=3");
///
/// // Fragment is stripped
/// let input3 = "z=3&a=1#section";
/// let output3 = ash_canonicalize_query(input3).unwrap();
/// assert_eq!(output3, "a=1&z=3");
/// ```
pub fn ash_canonicalize_query(input: &str) -> Result<String, AshError> {
    // VULN-002: Validate payload size
    if input.len() > MAX_PAYLOAD_SIZE {
        return Err(AshError::new(
            AshErrorCode::CanonicalizationError,
            format!("Query string exceeds maximum size of {} bytes", MAX_PAYLOAD_SIZE),
        ));
    }

    // Rule 1: Remove leading ? if present
    let query = input.strip_prefix('?').unwrap_or(input);

    // Rule 2: Strip fragment (#) and everything after
    let query = query.split('#').next().unwrap_or(query);

    if query.is_empty() {
        return Ok(String::new());
    }

    // Rule 3 & 4: Parse pairs
    let mut pairs: Vec<(String, String)> = Vec::new();

    for part in query.split('&') {
        if part.is_empty() {
            continue;
        }

        let (key, value) = match part.find('=') {
            Some(pos) => (&part[..pos], &part[pos + 1..]),
            None => (part, ""), // Rule 4: keys without values
        };

        // Rule 5: Percent-decode (+ is literal plus in query strings, NOT space)
        let decoded_key = ash_percent_decode_query(key)?;
        let decoded_value = ash_percent_decode_query(value)?;

        // Rule 6: NFC normalize
        let normalized_key: String = decoded_key.nfc().collect();
        let normalized_value: String = decoded_value.nfc().collect();

        pairs.push((normalized_key, normalized_value));
    }

    // Rule 7 & 8: Sort by key, then by value (byte-wise strcmp order)
    pairs.sort_by(|a, b| {
        match a.0.as_bytes().cmp(b.0.as_bytes()) {
            std::cmp::Ordering::Equal => a.1.as_bytes().cmp(b.1.as_bytes()),
            other => other,
        }
    });

    // Rule 9 & 10: Re-encode with uppercase hex and join
    let encoded: Vec<String> = pairs
        .into_iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                ash_percent_encode_uppercase(&k),
                ash_percent_encode_uppercase(&v)
            )
        })
        .collect();

    Ok(encoded.join("&"))
}

/// Percent-encode a string with uppercase hex digits.
fn ash_percent_encode_uppercase(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 3);

    for ch in input.chars() {
        match ch {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(ch);
            }
            ' ' => {
                result.push_str("%20");
            }
            _ => {
                // Encode character directly to UTF-8 bytes without allocation
                let mut buf = [0u8; 4];
                let encoded = ch.encode_utf8(&mut buf);
                for byte in encoded.as_bytes() {
                    result.push('%');
                    // Use write! to avoid format! allocation
                    use std::fmt::Write;
                    write!(result, "{:02X}", byte).unwrap();
                }
            }
        }
    }

    result
}


#[cfg(test)]
mod tests {
    use super::*;

    // JSON Canonicalization Tests

    #[test]
    fn test_canonicalize_json_simple_object() {
        let input = r#"{"z":1,"a":2}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn test_canonicalize_json_nested_object() {
        let input = r#"{"b":{"d":4,"c":3},"a":1}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":1,"b":{"c":3,"d":4}}"#);
    }

    #[test]
    fn test_canonicalize_json_with_whitespace() {
        let input = r#"{ "z" : 1 , "a" : 2 }"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn test_canonicalize_json_array_preserved() {
        let input = r#"{"arr":[3,1,2]}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"arr":[3,1,2]}"#);
    }

    #[test]
    fn test_canonicalize_json_null() {
        let input = r#"{"a":null}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":null}"#);
    }

    #[test]
    fn test_canonicalize_json_boolean() {
        let input = r#"{"b":true,"a":false}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":false,"b":true}"#);
    }

    #[test]
    fn test_canonicalize_json_empty_object() {
        let input = r#"{}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{}"#);
    }

    #[test]
    fn test_canonicalize_json_empty_array() {
        let input = r#"[]"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"[]"#);
    }

    #[test]
    fn test_canonicalize_json_unicode() {
        // Test with Unicode characters
        let input = r#"{"name":"café"}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"name":"café"}"#);
    }

    #[test]
    fn test_canonicalize_json_invalid() {
        let input = r#"{"a":}"#;
        assert!(ash_canonicalize_json(input).is_err());
    }

    #[test]
    fn test_canonicalize_json_whole_float_becomes_integer() {
        // RFC 8785: Whole floats MUST become integers (5.0 -> 5)
        let input = r#"{"a":5.0}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":5}"#);
    }

    #[test]
    fn test_canonicalize_json_negative_zero_becomes_zero() {
        // RFC 8785: -0 MUST become 0
        // Note: serde_json may normalize -0.0 on parse, but we handle it anyway
        let input = r#"{"a":-0.0}"#;
        let output = ash_canonicalize_json(input).unwrap();
        // Should be 0, not -0
        assert_eq!(output, r#"{"a":0}"#);
    }

    #[test]
    fn test_canonicalize_json_preserves_fractional() {
        // Non-whole floats should preserve their fractional part
        let input = r#"{"a":5.5}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":5.5}"#);
    }

    #[test]
    fn test_canonicalize_json_large_whole_float() {
        // Large whole floats within i64 range should become integers
        let input = r#"{"a":1000000.0}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":1000000}"#);
    }

    // URL-Encoded Canonicalization Tests

    #[test]
    fn test_canonicalize_urlencoded_simple() {
        let input = "z=3&a=1&b=2";
        let output = ash_canonicalize_urlencoded(input).unwrap();
        assert_eq!(output, "a=1&b=2&z=3");
    }

    #[test]
    fn test_canonicalize_urlencoded_duplicate_keys() {
        let input = "a=2&a=1&b=3";
        let output = ash_canonicalize_urlencoded(input).unwrap();
        // Duplicate keys should be sorted by value (byte-wise) per ASH spec
        assert_eq!(output, "a=1&a=2&b=3");
    }

    #[test]
    fn test_canonicalize_urlencoded_encoded_space() {
        let input = "a=hello%20world";
        let output = ash_canonicalize_urlencoded(input).unwrap();
        assert_eq!(output, "a=hello%20world");
    }

    #[test]
    fn test_canonicalize_urlencoded_plus_as_literal() {
        // ASH protocol treats + as literal plus, not space
        let input = "a=hello+world";
        let output = ash_canonicalize_urlencoded(input).unwrap();
        assert_eq!(output, "a=hello%2Bworld");
    }

    #[test]
    fn test_canonicalize_urlencoded_empty() {
        let input = "";
        let output = ash_canonicalize_urlencoded(input).unwrap();
        assert_eq!(output, "");
    }

    #[test]
    fn test_canonicalize_urlencoded_no_value() {
        let input = "a&b=2";
        let output = ash_canonicalize_urlencoded(input).unwrap();
        assert_eq!(output, "a=&b=2");
    }

    // Query String Canonicalization Tests (v2.3.1 compliance)

    #[test]
    fn test_canonicalize_query_strips_fragment() {
        let input = "z=3&a=1#section";
        let output = ash_canonicalize_query(input).unwrap();
        assert_eq!(output, "a=1&z=3");
    }

    #[test]
    fn test_canonicalize_query_strips_fragment_with_question_mark() {
        let input = "?z=3&a=1#fragment";
        let output = ash_canonicalize_query(input).unwrap();
        assert_eq!(output, "a=1&z=3");
    }

    #[test]
    fn test_canonicalize_query_plus_is_literal() {
        // In query strings, + is literal plus, not space
        let input = "a=hello+world";
        let output = ash_canonicalize_query(input).unwrap();
        // + is preserved as %2B (encoded plus)
        assert_eq!(output, "a=hello%2Bworld");
    }

    #[test]
    fn test_canonicalize_query_space_is_percent20() {
        let input = "a=hello%20world";
        let output = ash_canonicalize_query(input).unwrap();
        assert_eq!(output, "a=hello%20world");
    }

    #[test]
    fn test_canonicalize_query_preserves_empty_value() {
        let input = "a=&b=2";
        let output = ash_canonicalize_query(input).unwrap();
        assert_eq!(output, "a=&b=2");
    }

    #[test]
    fn test_canonicalize_query_key_without_equals() {
        let input = "flag&b=2";
        let output = ash_canonicalize_query(input).unwrap();
        assert_eq!(output, "b=2&flag=");
    }

    #[test]
    fn test_canonicalize_query_sorts_by_key_then_value() {
        // When keys are equal, sort by value
        let input = "a=2&a=1&a=3";
        let output = ash_canonicalize_query(input).unwrap();
        assert_eq!(output, "a=1&a=2&a=3");
    }

    #[test]
    fn test_canonicalize_query_uppercase_hex() {
        let input = "a=hello%20world"; // lowercase input
        let output = ash_canonicalize_query(input).unwrap();
        // Should be uppercase hex in output
        assert!(output.contains("%20"));
        assert!(!output.contains("%2a")); // no lowercase hex
    }

    #[test]
    fn test_canonicalize_query_byte_order_sorting() {
        // Ensure byte-wise (strcmp) sorting, not locale-dependent
        // ASCII order: '0' (48) < 'A' (65) < 'Z' (90) < 'a' (97) < 'z' (122)
        let input = "z=1&A=2&a=3&0=4";
        let output = ash_canonicalize_query(input).unwrap();
        assert_eq!(output, "0=4&A=2&a=3&z=1");
    }

    #[test]
    fn test_canonicalize_query_only_fragment() {
        let input = "#onlyfragment";
        let output = ash_canonicalize_query(input).unwrap();
        assert_eq!(output, "");
    }

    #[test]
    fn test_canonicalize_query_empty_with_question_mark() {
        let input = "?";
        let output = ash_canonicalize_query(input).unwrap();
        assert_eq!(output, "");
    }

    // Security Tests (VULN-001, VULN-002)

    #[test]
    fn test_rejects_deeply_nested_json() {
        // VULN-001: Test that deeply nested JSON is rejected
        let mut input = String::from("{\"a\":");
        for _ in 0..100 {
            input.push_str("{\"a\":");
        }
        input.push('1');
        for _ in 0..101 {
            input.push('}');
        }

        let result = ash_canonicalize_json(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("nesting depth"));
    }

    #[test]
    fn test_accepts_moderately_nested_json() {
        // Should accept nesting up to MAX_RECURSION_DEPTH (64)
        let mut input = String::from("{\"a\":");
        for _ in 0..30 {
            input.push_str("{\"a\":");
        }
        input.push('1');
        for _ in 0..31 {
            input.push('}');
        }

        let result = ash_canonicalize_json(&input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rejects_oversized_json_payload() {
        // VULN-002: Test that oversized payloads are rejected
        let large_value = "x".repeat(11 * 1024 * 1024); // 11 MB
        let input = format!(r#"{{"data":"{}"}}"#, large_value);

        let result = ash_canonicalize_json(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("maximum size"));
    }

    #[test]
    fn test_rejects_oversized_query_string() {
        // VULN-002: Test that oversized query strings are rejected
        let large_value = "x".repeat(11 * 1024 * 1024); // 11 MB
        let input = format!("a={}", large_value);

        let result = ash_canonicalize_query(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("maximum size"));
    }
}
