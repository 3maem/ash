# ASH Node.js SDK Deep Bug-Finding Review

**Date:** January 31, 2026
**Reviewer:** Claude Opus 4.5
**Scope:** ash-node (TypeScript) - focused review
**Focus:** Logic bugs, edge cases, and potential issues
**Status:** ALL ISSUES FIXED

---

## Executive Summary

A deep bug-finding review was performed on the Node.js SDK focusing on logic bugs, edge cases, and consistency with the CHANGELOG bug patterns. **One bug was found and fixed, two documentation improvements were made.**

| Severity | Found | Fixed | Description |
|----------|-------|-------|-------------|
| **Medium** | 1 | ✅ | Inconsistent scope sorting in middleware |
| **Info** | 2 | ✅ | Documentation clarifications |

---

## Bug Found and Fixed

### BUG-051: Inconsistent Scope Sorting in Middleware (Medium)

**Location:**
- `src/middleware/express.ts` lines 268-271
- `src/middleware/fastify.ts` lines 196-199

**Problem:**
The Express and Fastify middleware used JavaScript's default `.sort()` for scope policy comparison:

```typescript
// BEFORE (buggy):
const sortedClientScope = [...clientScope].sort();  // UTF-16 code unit sort
const sortedPolicyScope = [...policyScope].sort();

if (sortedClientScope.join(',') !== sortedPolicyScope.join(',')) {
  // Scope policy violation error
}
```

However, `normalizeScopeFields()` (used in proof verification) performs byte-wise sorting using `Buffer.compare()`:

```typescript
// In normalizeScopeFields():
return [...new Set(scope)].sort((a, b) => {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  return bufA.compare(bufB);  // Byte-wise comparison
});
```

**Impact:**
- For ASCII-only scope field names: No issue (UTF-16 sort equals byte-wise sort for ASCII)
- For non-ASCII scope field names (e.g., `["montañaélevé", "山水"]`): Different sort orders could produce false "scope policy violation" errors

**Example of inconsistency:**
```typescript
// Two strings with different UTF-16 vs byte-wise sort order
const scope = ["é", "a"];

// JavaScript default sort (UTF-16): ["a", "é"] (0x0061, 0x00E9)
// Byte-wise sort (UTF-8): ["a", "é"] (0x61, 0xC3 0xA9)
// Actually same for these, but more complex cases differ

// More problematic: strings with supplementary characters
const scope2 = ["𝄞", "a"];  // Musical note (U+1D11E) vs 'a'
// UTF-16: 0xD834 0xDD1E vs 0x0061 - 'a' sorts after!
// UTF-8 bytes: 0xF0 0x9D 0x84 0x9E vs 0x61 - 'a' sorts before!
```

**Fix Applied:**
```typescript
// AFTER (fixed):
import { normalizeScopeFields, SCOPE_FIELD_DELIMITER } from '../index';

// Use same normalization as proof verification
const normalizedClientScope = normalizeScopeFields(clientScope);
const normalizedPolicyScope = normalizeScopeFields(policyScope);

// Compare using the same delimiter as proof verification
if (normalizedClientScope.join(SCOPE_FIELD_DELIMITER) !== normalizedPolicyScope.join(SCOPE_FIELD_DELIMITER)) {
  // Scope policy violation error
}
```

**Files Modified:**
- `src/middleware/express.ts` - Added imports, updated comparison logic
- `src/middleware/fastify.ts` - Added imports, updated comparison logic

---

## Documentation Improvements

### INFO-004: Numeric String Keys Limitation

**Location:** `src/index.ts` - `ashExtractScopedFields()` function

**Issue:**
Scope paths with all-digit segments (e.g., `"items.0"`) are treated as array indices. If the original payload has an object with numeric string keys like `{"items": {"0": "value"}}`, the extracted result will have array structure `{"items": ["value"]}` instead.

**Documentation Added:**
```typescript
/**
 * INFO-004 LIMITATION: Numeric string keys vs array indices
 * Scope paths with all-digit segments (e.g., "items.0") are treated as array indices.
 * If the original payload has an object with numeric string keys like {"items": {"0": "value"}},
 * the extracted result will have array structure {"items": ["value"]} instead.
 * This is consistent across SDKs - use non-numeric keys for object properties if structure
 * preservation is critical.
 */
```

---

### INFO-005: SecureString.length Returns Byte Length

**Location:** `src/utils/secureMemory.ts` - `SecureString.length` getter

**Issue:**
The `length` property returns UTF-8 byte count, not JavaScript character count. For multi-byte characters, these differ.

**Documentation Added:**
```typescript
/**
 * Get the byte length of the string (UTF-8 encoded).
 * INFO-005 NOTE: Returns byte count, not character count.
 * For multi-byte UTF-8 characters, this may differ from string.length.
 * Example: "café" has 4 characters but 5 bytes (é is 2 bytes in UTF-8).
 */
```

---

## Verification

### Build Status
```
✅ Build successful (tsup)
```

### Test Status
```
✅ 162/162 tests passing
```

### Files Modified
| File | Change Type |
|------|-------------|
| `src/middleware/express.ts` | Bug fix (BUG-051) |
| `src/middleware/fastify.ts` | Bug fix (BUG-051) |
| `src/index.ts` | Documentation (INFO-004) |
| `src/utils/secureMemory.ts` | Documentation (INFO-005) |
| `CHANGELOG.md` | Added BUG-051, INFO-004, INFO-005 |

---

## Code Quality Observations

### Well-Implemented Security Measures

The Node.js SDK demonstrates excellent security practices:

1. **Comprehensive Input Validation**
   - All security limits from spec implemented (MAX_NONCE_LENGTH, MAX_CONTEXT_ID_LENGTH, etc.)
   - Validation functions for nonce, contextId, binding, bodyHash, timestamp

2. **Constant-Time Operations**
   - All hash comparisons use `crypto.timingSafeEqual`
   - Proper Buffer conversion before comparison
   - Dummy hash used for invalid inputs to prevent timing leaks

3. **Prototype Pollution Prevention**
   - `DANGEROUS_KEYS` Set blocks `__proto__`, `constructor`, `prototype`
   - `Object.prototype.hasOwnProperty.call()` used instead of `in` operator

4. **DoS Prevention**
   - `MAX_ARRAY_INDEX` and `MAX_TOTAL_ARRAY_ALLOCATION` limits
   - `MAX_SCOPE_FIELDS` and `MAX_SCOPE_PATH_DEPTH` limits
   - `MAX_PAYLOAD_SIZE` and `MAX_RECURSION_DEPTH` for JSON

5. **Well-Documented Bug Fixes**
   - Every fix references its bug ID (BUG-XXX, SEC-XXX, VULN-XXX)
   - Comments explain the security rationale

### No Additional Issues Found

After thorough review of:
- `src/index.ts` (2304 lines)
- `src/middleware/express.ts`
- `src/middleware/fastify.ts`
- `src/stores/memory.ts`
- `src/stores/sql.ts`
- `src/config/scopePolicies.ts`
- `src/utils/secureMemory.ts`

Cross-referencing with CHANGELOG bug patterns (BUG-001 through BUG-050, SEC-001 through SEC-019), no additional bugs were found beyond the middleware sorting inconsistency.

---

## Recommendations for Future Development

1. **Test with Non-ASCII Scope Fields**
   - Add cross-SDK test vectors with Unicode scope field names
   - Verify byte-wise sorting consistency

2. **Consider Adding `charLength` to SecureString**
   - Separate property for character count vs byte length
   - More intuitive API for users

3. **Document Object vs Array Behavior**
   - Clear examples in API docs showing numeric key handling
   - Recommend avoiding numeric string keys in payload schemas

---

*Report generated during deep bug-finding review on January 31, 2026*
