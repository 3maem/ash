# ASH Core Bug Report

This document details all bugs identified and fixed in ASH Core v2.3.4.

## Bug Summary Table

| Bug ID | Severity | Category | Description | Status |
|--------|----------|----------|-------------|--------|
| BUG-035 | High | Path Normalization | `.` and `..` segments not normalized | Fixed |
| BUG-036 | High | Memory Safety | Large array allocation DoS | Fixed |
| BUG-037 | Medium | Security | Comparison truncation at 1024 bytes | Fixed |
| BUG-038 | Medium | Validation | Leading zeros in timestamps accepted | Fixed |
| BUG-039 | Medium | Validation | Empty scope field names allowed | Fixed |
| BUG-040 | Medium | Validation | Body hash format not validated | Fixed |
| BUG-041 | Medium | Validation | Empty context_id allowed | Fixed |
| BUG-042 | Low | Cross-Platform | Unicode method name uppercase | Fixed |
| BUG-043 | Low | Edge Case | Whitespace-only query string | Fixed |
| BUG-044 | Low | Security | Size bypass via Value construction | Fixed |
| BUG-045 | Low | Overflow | Timestamp future check overflow | Fixed |

---

## Detailed Bug Reports

### BUG-035: Path Normalization Missing `.` and `..` Handling

**Severity:** High
**Category:** Path Normalization
**File:** `src/lib.rs`
**Function:** `ash_normalize_binding`

#### Description

The path normalization function collapsed duplicate slashes and removed trailing slashes, but did NOT normalize `.` (current directory) or `..` (parent directory) segments.

#### Impact

Cross-implementation mismatch if one SDK normalizes dots and another doesn't. An attacker could craft paths that hash differently on client vs server:

```
/api/./users        → Should normalize to /api/users
/api/users/../admin → Should normalize to /api/admin
```

#### Fix

Added `ash_normalize_path_segments()` function that:
- Removes `.` segments
- Resolves `..` by removing preceding segment
- Prevents traversal above root
- Collapses duplicate slashes
- Removes trailing slashes (except root `/`)

#### Test Cases

```rust
// Single dot removed
ash_normalize_binding("GET", "/api/./users", "") → "GET|/api/users|"

// Double dot goes up one level
ash_normalize_binding("GET", "/api/v1/../users", "") → "GET|/api/users|"

// Multiple dots
ash_normalize_binding("GET", "/api/v1/./users/../admin", "") → "GET|/api/v1/admin|"

// Can't go above root
ash_normalize_binding("GET", "/../api", "") → "GET|/api|"
```

---

### BUG-036: Large Array Allocation Memory Exhaustion

**Severity:** High
**Category:** Memory Safety / DoS Prevention
**File:** `src/proof.rs`
**Function:** `ash_extract_scoped_fields_internal`

#### Description

While individual array indices were capped at `MAX_ARRAY_INDEX` (10,000), the code still allowed extending arrays up to that index. Multiple scope paths with large indices could exhaust memory:

```rust
// Each creates 10,000 element array
let scope = vec!["items[9999]", "other[9999]"];  // = 20,000 elements
```

#### Impact

Potential DoS via carefully crafted scope arrays. An attacker could send scopes with multiple large array indices to exhaust server memory.

#### Fix

Added `MAX_TOTAL_ARRAY_ALLOCATION` constant (10,000) and `ash_calculate_total_array_allocation()` function that:
- Calculates total elements needed across all scope paths
- Validates before any extraction begins
- Rejects requests exceeding the limit

#### Test Cases

```rust
// Rejected: Total allocation 20,000 exceeds 10,000 limit
let scope = vec!["items[9999]", "other[9999]"];
ash_extract_scoped_fields(&payload, &scope) → Err(...)

// Accepted: Total allocation 6 is within limit
let scope = vec!["items[0]", "items[1]", "items[2]"];
ash_extract_scoped_fields(&payload, &scope) → Ok(...)
```

---

### BUG-037: Comparison Truncation Security Issue

**Severity:** Medium (for general use) / Low (for ASH proofs)
**Category:** Security
**File:** `src/compare.rs`
**Constant:** `FIXED_ITERATIONS`

#### Description

The constant-time comparison only compared the first 1,024 bytes of inputs. For inputs larger than this, differences beyond 1,024 bytes would not be detected (when combined with length equality).

#### Impact

For ASH proofs (64-128 hex chars), this was never a problem. However, it could be a footgun for general cryptographic use or future extensions.

#### Fix

Extended `FIXED_ITERATIONS` from 4 to 8 (2,048 bytes total), providing a safety margin for longer cryptographic values or chain proofs.

#### Documentation Update

```rust
/// # Input Size Limit
///
/// Inputs larger than 2048 bytes will only have their first 2048 bytes compared.
/// BUG-037: Extended from 1024 to 2048 bytes for safety margin.
```

---

### BUG-038: Timestamps Accept Leading Zeros

**Severity:** Medium
**Category:** Validation / Cross-Implementation
**File:** `src/proof.rs`
**Function:** `ash_validate_timestamp_format`

#### Description

Timestamps with leading zeros like `"0123456789"` were accepted and parsed as `123456789`. This could cause cross-implementation mismatches if one SDK normalizes leading zeros and another doesn't.

#### Impact

Signature mismatches between client and server implementations that handle leading zeros differently.

#### Fix

Added validation to reject timestamps with leading zeros (except `"0"` itself):

```rust
// BUG-038: Reject leading zeros (except "0" itself)
if timestamp.len() > 1 && timestamp.starts_with('0') {
    return Err(AshError::new(
        AshErrorCode::TimestampInvalid,
        "Timestamp must not have leading zeros",
    ));
}
```

#### Test Cases

```rust
ash_validate_timestamp_format("0123456789") → Err(...)  // Rejected
ash_validate_timestamp_format("123456789")  → Ok(...)   // Accepted
ash_validate_timestamp_format("0")          → Ok(...)   // Accepted (zero is valid)
```

---

### BUG-039: Empty Scope Field Names Allowed

**Severity:** Medium
**Category:** Validation
**File:** `src/proof.rs`
**Function:** `ash_join_scope_fields`

#### Description

Empty strings in scope arrays were accepted, which could cause confusion:
- `["", "amount"]` after sorting/dedup behaves unexpectedly
- Empty field names have no semantic meaning
- Could potentially cause hash collisions

#### Impact

Confusing behavior and potential for subtle bugs in scope handling.

#### Fix

Added validation to reject empty field names:

```rust
// BUG-039: Reject empty field names
if field.is_empty() {
    return Err(AshError::new(
        AshErrorCode::MalformedRequest,
        "Scope field names cannot be empty",
    ));
}
```

#### Test Cases

```rust
ash_hash_scope(&["amount", ""])      → Err(...)  // Rejected
ash_hash_scope(&[""])                → Err(...)  // Rejected
ash_hash_scope(&["amount", "recipient"]) → Ok(...)   // Accepted
```

---

### BUG-040: Body Hash Format Not Validated

**Severity:** Medium
**Category:** Validation
**File:** `src/proof.rs`
**Function:** `ash_build_proof`

#### Description

The `body_hash` parameter was only checked for non-empty, but not validated for:
- Correct length (64 hex characters for SHA-256)
- Valid hexadecimal characters

#### Impact

Malformed body hashes could cause verification failures that are hard to debug. Error messages would not clearly indicate the problem.

#### Fix

Added comprehensive body hash validation:

```rust
// BUG-040: Validate body_hash format (must be valid SHA-256 hex)
if body_hash.len() != SHA256_HEX_LENGTH {
    return Err(AshError::new(
        AshErrorCode::MalformedRequest,
        format!(
            "body_hash must be {} hex characters (SHA-256), got {}",
            SHA256_HEX_LENGTH,
            body_hash.len()
        ),
    ));
}
if !body_hash.chars().all(|c| c.is_ascii_hexdigit()) {
    return Err(AshError::new(
        AshErrorCode::MalformedRequest,
        "body_hash must contain only hexadecimal characters (0-9, a-f, A-F)",
    ));
}
```

#### Test Cases

```rust
// Too short
ash_build_proof("secret", "123", "binding", "abc123") → Err(...)

// Non-hex characters
ash_build_proof("secret", "123", "binding", "g3b0...") → Err(...)

// Valid SHA-256 hash
ash_build_proof("secret", "123", "binding", "e3b0c44298fc...") → Ok(...)
```

---

### BUG-041: Empty Context ID Allowed

**Severity:** Medium
**Category:** Validation
**File:** `src/proof.rs`
**Function:** `ash_derive_client_secret`

#### Description

Empty `context_id` was accepted, which:
- Has no semantic meaning
- Could cause ambiguous contexts
- Might indicate a programming error

#### Impact

Silent acceptance of likely invalid input, making bugs harder to detect.

#### Fix

Added validation to require non-empty context_id:

```rust
// BUG-041: Validate context_id is not empty
if context_id.is_empty() {
    return Err(AshError::new(
        AshErrorCode::MalformedRequest,
        "context_id cannot be empty",
    ));
}
```

#### Test Cases

```rust
ash_derive_client_secret(nonce, "", "binding") → Err(...)  // Rejected
ash_derive_client_secret(nonce, "ctx_123", "binding") → Ok(...)  // Accepted
```

---

### BUG-042: Unicode Method Name Uppercase Inconsistency

**Severity:** Low
**Category:** Cross-Platform Consistency
**File:** `src/lib.rs`
**Function:** `ash_normalize_binding`

#### Description

`to_uppercase()` was used for method names, which applies Unicode case mapping. Unicode uppercase rules can vary across platforms and Rust versions, potentially causing cross-platform inconsistencies.

#### Impact

Rare, but could cause signature mismatches if non-ASCII method names were used.

#### Fix

Changed to use ASCII-only uppercase and reject non-ASCII method names:

```rust
// BUG-042: Use ASCII-only uppercase to ensure cross-platform consistency
if !method.is_ascii() {
    return Err(AshError::new(
        AshErrorCode::MalformedRequest,
        "Method must contain only ASCII characters",
    ));
}
let method = method.to_ascii_uppercase();
```

#### Test Cases

```rust
ash_normalize_binding("GËṪ", "/api", "") → Err(...)  // Rejected
ash_normalize_binding("get", "/api", "") → Ok("GET|/api|")  // Uppercased
```

---

### BUG-043: Whitespace-Only Query String Handling

**Severity:** Low
**Category:** Edge Case
**File:** `src/lib.rs`
**Function:** `ash_normalize_binding`

#### Description

A query string containing only whitespace (e.g., `"   "` or `"\t\n"`) was not explicitly handled and could produce unexpected results.

#### Impact

Minor - could cause confusing behavior in edge cases.

#### Fix

Trim query string before processing:

```rust
// BUG-043: Trim whitespace from query string before canonicalization
let query = query.trim();
let canonical_query = if query.is_empty() {
    String::new()
} else {
    canonicalize::ash_canonicalize_query(query)?
};
```

#### Test Cases

```rust
ash_normalize_binding("GET", "/api", "   ") → "GET|/api|"   // Treated as empty
ash_normalize_binding("GET", "/api", "\t\n") → "GET|/api|"  // Treated as empty
ash_normalize_binding("GET", "/api", "  a=1  ") → "GET|/api|a=1"  // Trimmed
```

---

### BUG-044: Size Bypass via Value Construction

**Severity:** Low (documented)
**Category:** Security
**File:** `src/canonicalize.rs`
**Function:** `ash_canonicalize_json_value`

#### Description

`ash_canonicalize_json_value()` did not validate size limits because the Value is already in memory. If a Value is constructed programmatically from untrusted input, it could bypass the 10MB limit.

#### Impact

Potential DoS if Values are constructed from untrusted sources without going through `ash_canonicalize_json()` first.

#### Fix

Added new function `ash_canonicalize_json_value_with_size_check()` that validates size before canonicalization:

```rust
/// BUG-044: This is the size-safe version for Values from untrusted sources.
pub fn ash_canonicalize_json_value_with_size_check(value: &Value) -> Result<String, AshError> {
    // Serialize first to check size
    let serialized = serde_json::to_string(value)?;
    if serialized.len() > MAX_PAYLOAD_SIZE {
        return Err(AshError::new(
            AshErrorCode::CanonicalizationError,
            format!("Payload exceeds maximum size of {} bytes", MAX_PAYLOAD_SIZE),
        ));
    }
    ash_canonicalize_json_value(value)
}
```

---

### BUG-045: Timestamp Future Check Integer Overflow

**Severity:** Low (theoretical)
**Category:** Integer Overflow
**File:** `src/proof.rs`
**Function:** `ash_validate_timestamp`

#### Description

The expression `now + clock_skew_seconds` could theoretically overflow if `now` is near `u64::MAX`. While extremely unlikely in practice (timestamps are validated against `MAX_TIMESTAMP` ~32 billion), it was not handled safely.

#### Impact

Theoretical - in practice, timestamps are validated before this check.

#### Fix

Use `saturating_add` to prevent overflow:

```rust
// BUG-045: Check for future timestamp with overflow protection
if ts > now.saturating_add(clock_skew_seconds) {
    return Err(AshError::new(
        AshErrorCode::TimestampInvalid,
        "Timestamp is in the future",
    ));
}
```

---

## Migration Notes

### Breaking Changes

1. **Timestamps with leading zeros are now rejected**
   - Ensure all timestamps are normalized without leading zeros
   - `"0123456789"` → Use `"123456789"` instead

2. **Empty context_id is now rejected**
   - Ensure all context_id values are non-empty strings

3. **Body hash must be valid SHA-256 hex**
   - Must be exactly 64 hexadecimal characters
   - Use `ash_hash_body()` to generate valid hashes

4. **Empty scope field names are now rejected**
   - Remove any empty strings from scope arrays

5. **Non-ASCII method names are now rejected**
   - Use standard HTTP methods (GET, POST, PUT, DELETE, etc.)

6. **Large array indices may be rejected**
   - Total array allocation across all scope fields is limited to 10,000 elements
   - Example: `["items[9999]", "other[9999]"]` exceeds the limit

### New Function

- `ash_canonicalize_json_value_with_size_check()` - Use for Values from untrusted sources

---

## Test Coverage

All bugs have corresponding test cases. Run tests with:

```bash
cargo test
```

Total tests: 240 (158 unit + 50 integration + 9 regression + 23 doc tests)
