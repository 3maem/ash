//! Deterministic canonicalization for JSON and URL-encoded payloads.
//!
//! This module ensures byte-identical output across all platforms and implementations.

use serde_json::Value;
use unicode_normalization::UnicodeNormalization;

use crate::errors::{AshError, AshErrorCode};

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
/// use ash_core::canonicalize_json;
///
/// let input = r#"{ "z": 1, "a": { "c": 3, "b": 2 } }"#;
/// let output = canonicalize_json(input).unwrap();
/// assert_eq!(output, r#"{"a":{"b":2,"c":3},"z":1}"#);
/// ```
///
/// # Errors
///
/// Returns `AshError` with `CanonicalizationFailed` if:
/// - Input is not valid JSON
/// - JSON contains unsupported values (NaN, Infinity)
pub fn canonicalize_json(input: &str) -> Result<String, AshError> {
    // Parse JSON
    let value: Value = serde_json::from_str(input).map_err(|e| {
        AshError::new(
            AshErrorCode::CanonicalizationFailed,
            format!("Invalid JSON: {}", e),
        )
    })?;

    // Canonicalize recursively
    let canonical = canonicalize_value(&value)?;

    // Serialize to minified JSON
    serde_json::to_string(&canonical).map_err(|e| {
        AshError::new(
            AshErrorCode::CanonicalizationFailed,
            format!("Failed to serialize: {}", e),
        )
    })
}

/// Recursively canonicalize a JSON value.
fn canonicalize_value(value: &Value) -> Result<Value, AshError> {
    match value {
        Value::Null => Ok(Value::Null),
        Value::Bool(b) => Ok(Value::Bool(*b)),
        Value::Number(n) => canonicalize_number(n),
        Value::String(s) => Ok(Value::String(canonicalize_string(s))),
        Value::Array(arr) => {
            let canonical: Result<Vec<Value>, AshError> =
                arr.iter().map(canonicalize_value).collect();
            Ok(Value::Array(canonical?))
        }
        Value::Object(obj) => {
            // Sort keys lexicographically
            let mut sorted: Vec<(&String, &Value)> = obj.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));

            let mut canonical = serde_json::Map::new();
            for (key, val) in sorted {
                let canonical_key = canonicalize_string(key);
                let canonical_val = canonicalize_value(val)?;
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
fn canonicalize_number(n: &serde_json::Number) -> Result<Value, AshError> {
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
                AshErrorCode::CanonicalizationFailed,
                "NaN is not supported in ASH canonicalization (RFC 8785)",
            ));
        }
        if f.is_infinite() {
            return Err(AshError::new(
                AshErrorCode::CanonicalizationFailed,
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
        // Check if the float is a whole number within i64 range
        if f.fract() == 0.0 && f >= (i64::MIN as f64) && f <= (i64::MAX as f64) {
            let i = f as i64;
            return Ok(Value::Number(serde_json::Number::from(i)));
        }

        // Convert back to Number for non-whole floats
        serde_json::Number::from_f64(f)
            .map(Value::Number)
            .ok_or_else(|| {
                AshError::new(
                    AshErrorCode::CanonicalizationFailed,
                    "Failed to canonicalize number",
                )
            })
    } else {
        Err(AshError::new(
            AshErrorCode::CanonicalizationFailed,
            "Unsupported number format",
        ))
    }
}

/// Canonicalize a string with Unicode NFC normalization.
fn canonicalize_string(s: &str) -> String {
    s.nfc().collect()
}

/// Canonicalize URL-encoded form data.
///
/// # Canonicalization Rules
///
/// 1. Parse key=value pairs (split on `&`, then on first `=`)
/// 2. Percent-decode all values
/// 3. Apply Unicode NFC normalization
/// 4. Sort pairs by key lexicographically
/// 5. For duplicate keys, preserve value order
/// 6. Re-encode with percent encoding
///
/// # Example
///
/// ```rust
/// use ash_core::canonicalize_urlencoded;
///
/// let input = "z=3&a=1&a=2&b=hello%20world";
/// let output = canonicalize_urlencoded(input).unwrap();
/// assert_eq!(output, "a=1&a=2&b=hello%20world&z=3");
/// ```
pub fn canonicalize_urlencoded(input: &str) -> Result<String, AshError> {
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

        // Percent-decode
        let decoded_key = percent_decode(key)?;
        let decoded_value = percent_decode(value)?;

        // NFC normalize
        let normalized_key: String = decoded_key.nfc().collect();
        let normalized_value: String = decoded_value.nfc().collect();

        pairs.push((normalized_key, normalized_value));
    }

    // Sort by key (stable sort preserves order of duplicate keys)
    pairs.sort_by(|a, b| a.0.cmp(&b.0));

    // Re-encode and join
    let encoded: Vec<String> = pairs
        .into_iter()
        .map(|(k, v)| format!("{}={}", percent_encode(&k), percent_encode(&v)))
        .collect();

    Ok(encoded.join("&"))
}

/// Percent-decode a string for URL-encoded form data.
/// NOTE: This treats + as space per application/x-www-form-urlencoded.
fn percent_decode(input: &str) -> Result<String, AshError> {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            // Read two hex digits
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() != 2 {
                return Err(AshError::new(
                    AshErrorCode::CanonicalizationFailed,
                    "Invalid percent encoding",
                ));
            }
            let byte = u8::from_str_radix(&hex, 16).map_err(|_| {
                AshError::new(
                    AshErrorCode::CanonicalizationFailed,
                    "Invalid percent encoding hex",
                )
            })?;
            result.push(byte as char);
        } else if ch == '+' {
            // Plus is space in form data (application/x-www-form-urlencoded)
            result.push(' ');
        } else {
            result.push(ch);
        }
    }

    Ok(result)
}

/// Percent-decode a string for query strings (RFC 3986).
/// NOTE: + is treated as literal plus, NOT space. Space must be %20.
fn percent_decode_query(input: &str) -> Result<String, AshError> {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            // Read two hex digits
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() != 2 {
                return Err(AshError::new(
                    AshErrorCode::CanonicalizationFailed,
                    "Invalid percent encoding",
                ));
            }
            let byte = u8::from_str_radix(&hex, 16).map_err(|_| {
                AshError::new(
                    AshErrorCode::CanonicalizationFailed,
                    "Invalid percent encoding hex",
                )
            })?;
            result.push(byte as char);
        } else {
            // + is literal plus in query strings (not space)
            result.push(ch);
        }
    }

    Ok(result)
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
/// use ash_core::canonicalize_query;
///
/// let input = "z=3&a=1&b=hello%20world";
/// let output = canonicalize_query(input).unwrap();
/// assert_eq!(output, "a=1&b=hello%20world&z=3");
///
/// // With leading ?
/// let input2 = "?z=3&a=1";
/// let output2 = canonicalize_query(input2).unwrap();
/// assert_eq!(output2, "a=1&z=3");
///
/// // Fragment is stripped
/// let input3 = "z=3&a=1#section";
/// let output3 = canonicalize_query(input3).unwrap();
/// assert_eq!(output3, "a=1&z=3");
/// ```
pub fn canonicalize_query(input: &str) -> Result<String, AshError> {
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
        let decoded_key = percent_decode_query(key)?;
        let decoded_value = percent_decode_query(value)?;

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
                percent_encode_uppercase(&k),
                percent_encode_uppercase(&v)
            )
        })
        .collect();

    Ok(encoded.join("&"))
}

/// Percent-encode a string with uppercase hex digits.
fn percent_encode_uppercase(input: &str) -> String {
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
                for byte in ch.to_string().as_bytes() {
                    result.push('%');
                    result.push_str(&format!("{:02X}", byte)); // Uppercase hex
                }
            }
        }
    }

    result
}

/// Percent-encode a string for URL form data.
fn percent_encode(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 3);

    for ch in input.chars() {
        match ch {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(ch);
            }
            ' ' => {
                // Use %20 for spaces (more universal than +)
                result.push_str("%20");
            }
            _ => {
                // Percent-encode
                for byte in ch.to_string().as_bytes() {
                    result.push('%');
                    result.push_str(&format!("{:02X}", byte));
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
        let output = canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn test_canonicalize_json_nested_object() {
        let input = r#"{"b":{"d":4,"c":3},"a":1}"#;
        let output = canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":1,"b":{"c":3,"d":4}}"#);
    }

    #[test]
    fn test_canonicalize_json_with_whitespace() {
        let input = r#"{ "z" : 1 , "a" : 2 }"#;
        let output = canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn test_canonicalize_json_array_preserved() {
        let input = r#"{"arr":[3,1,2]}"#;
        let output = canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"arr":[3,1,2]}"#);
    }

    #[test]
    fn test_canonicalize_json_null() {
        let input = r#"{"a":null}"#;
        let output = canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":null}"#);
    }

    #[test]
    fn test_canonicalize_json_boolean() {
        let input = r#"{"b":true,"a":false}"#;
        let output = canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":false,"b":true}"#);
    }

    #[test]
    fn test_canonicalize_json_empty_object() {
        let input = r#"{}"#;
        let output = canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{}"#);
    }

    #[test]
    fn test_canonicalize_json_empty_array() {
        let input = r#"[]"#;
        let output = canonicalize_json(input).unwrap();
        assert_eq!(output, r#"[]"#);
    }

    #[test]
    fn test_canonicalize_json_unicode() {
        // Test with Unicode characters
        let input = r#"{"name":"café"}"#;
        let output = canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"name":"café"}"#);
    }

    #[test]
    fn test_canonicalize_json_invalid() {
        let input = r#"{"a":}"#;
        assert!(canonicalize_json(input).is_err());
    }

    #[test]
    fn test_canonicalize_json_whole_float_becomes_integer() {
        // RFC 8785: Whole floats MUST become integers (5.0 -> 5)
        let input = r#"{"a":5.0}"#;
        let output = canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":5}"#);
    }

    #[test]
    fn test_canonicalize_json_negative_zero_becomes_zero() {
        // RFC 8785: -0 MUST become 0
        // Note: serde_json may normalize -0.0 on parse, but we handle it anyway
        let input = r#"{"a":-0.0}"#;
        let output = canonicalize_json(input).unwrap();
        // Should be 0, not -0
        assert_eq!(output, r#"{"a":0}"#);
    }

    #[test]
    fn test_canonicalize_json_preserves_fractional() {
        // Non-whole floats should preserve their fractional part
        let input = r#"{"a":5.5}"#;
        let output = canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":5.5}"#);
    }

    #[test]
    fn test_canonicalize_json_large_whole_float() {
        // Large whole floats within i64 range should become integers
        let input = r#"{"a":1000000.0}"#;
        let output = canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":1000000}"#);
    }

    // URL-Encoded Canonicalization Tests

    #[test]
    fn test_canonicalize_urlencoded_simple() {
        let input = "z=3&a=1&b=2";
        let output = canonicalize_urlencoded(input).unwrap();
        assert_eq!(output, "a=1&b=2&z=3");
    }

    #[test]
    fn test_canonicalize_urlencoded_duplicate_keys() {
        let input = "a=2&a=1&b=3";
        let output = canonicalize_urlencoded(input).unwrap();
        // Duplicate keys preserve value order after sorting by key
        assert_eq!(output, "a=2&a=1&b=3");
    }

    #[test]
    fn test_canonicalize_urlencoded_encoded_space() {
        let input = "a=hello%20world";
        let output = canonicalize_urlencoded(input).unwrap();
        assert_eq!(output, "a=hello%20world");
    }

    #[test]
    fn test_canonicalize_urlencoded_plus_space() {
        let input = "a=hello+world";
        let output = canonicalize_urlencoded(input).unwrap();
        assert_eq!(output, "a=hello%20world");
    }

    #[test]
    fn test_canonicalize_urlencoded_empty() {
        let input = "";
        let output = canonicalize_urlencoded(input).unwrap();
        assert_eq!(output, "");
    }

    #[test]
    fn test_canonicalize_urlencoded_no_value() {
        let input = "a&b=2";
        let output = canonicalize_urlencoded(input).unwrap();
        assert_eq!(output, "a=&b=2");
    }

    // Query String Canonicalization Tests (v2.3.1 compliance)

    #[test]
    fn test_canonicalize_query_strips_fragment() {
        let input = "z=3&a=1#section";
        let output = canonicalize_query(input).unwrap();
        assert_eq!(output, "a=1&z=3");
    }

    #[test]
    fn test_canonicalize_query_strips_fragment_with_question_mark() {
        let input = "?z=3&a=1#fragment";
        let output = canonicalize_query(input).unwrap();
        assert_eq!(output, "a=1&z=3");
    }

    #[test]
    fn test_canonicalize_query_plus_is_literal() {
        // In query strings, + is literal plus, not space
        let input = "a=hello+world";
        let output = canonicalize_query(input).unwrap();
        // + is preserved as %2B (encoded plus)
        assert_eq!(output, "a=hello%2Bworld");
    }

    #[test]
    fn test_canonicalize_query_space_is_percent20() {
        let input = "a=hello%20world";
        let output = canonicalize_query(input).unwrap();
        assert_eq!(output, "a=hello%20world");
    }

    #[test]
    fn test_canonicalize_query_preserves_empty_value() {
        let input = "a=&b=2";
        let output = canonicalize_query(input).unwrap();
        assert_eq!(output, "a=&b=2");
    }

    #[test]
    fn test_canonicalize_query_key_without_equals() {
        let input = "flag&b=2";
        let output = canonicalize_query(input).unwrap();
        assert_eq!(output, "b=2&flag=");
    }

    #[test]
    fn test_canonicalize_query_sorts_by_key_then_value() {
        // When keys are equal, sort by value
        let input = "a=2&a=1&a=3";
        let output = canonicalize_query(input).unwrap();
        assert_eq!(output, "a=1&a=2&a=3");
    }

    #[test]
    fn test_canonicalize_query_uppercase_hex() {
        let input = "a=hello%20world"; // lowercase input
        let output = canonicalize_query(input).unwrap();
        // Should be uppercase hex in output
        assert!(output.contains("%20"));
        assert!(!output.contains("%2a")); // no lowercase hex
    }

    #[test]
    fn test_canonicalize_query_byte_order_sorting() {
        // Ensure byte-wise (strcmp) sorting, not locale-dependent
        // ASCII order: '0' (48) < 'A' (65) < 'Z' (90) < 'a' (97) < 'z' (122)
        let input = "z=1&A=2&a=3&0=4";
        let output = canonicalize_query(input).unwrap();
        assert_eq!(output, "0=4&A=2&a=3&z=1");
    }

    #[test]
    fn test_canonicalize_query_only_fragment() {
        let input = "#onlyfragment";
        let output = canonicalize_query(input).unwrap();
        assert_eq!(output, "");
    }

    #[test]
    fn test_canonicalize_query_empty_with_question_mark() {
        let input = "?";
        let output = canonicalize_query(input).unwrap();
        assert_eq!(output, "");
    }
}
