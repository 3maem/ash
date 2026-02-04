# ASH SDK Function Renames

This document lists all function renames required to comply with the ASH naming convention.
All functions (public and private) must use the `ash_` prefix.

## Go SDK Function Renames

### Exported Functions (PascalCase with `Ash` prefix)

| Original Name | New Name | Status |
|---------------|----------|--------|
| `NormalizeScopeFields` | `AshNormalizeScopeFields` | ✅ DONE |
| `JoinScopeFields` | `AshJoinScopeFields` | ✅ DONE |
| `NewAshError` | `AshNewError` | ✅ DONE |
| `BuildProof` | `AshBuildProof` | ✅ DONE |
| `Base64URLEncode` | `AshBase64URLEncode` | ✅ DONE |
| `Base64URLDecode` | `AshBase64URLDecode` | ✅ DONE |
| `CanonicalizeJSON` | `AshCanonicalizeJSON` | ✅ DONE |
| `CanonicalizeURLEncoded` | `AshCanonicalizeURLEncoded` | ✅ DONE |
| `CanonicalizeURLEncodedFromMap` | `AshCanonicalizeURLEncodedFromMap` | ✅ DONE |
| `CanonicalizeQuery` | `AshCanonicalizeQuery` | ✅ DONE |
| `NormalizeBinding` | `AshNormalizeBinding` | ✅ DONE |
| `NormalizeBindingFromURL` | `AshNormalizeBindingFromURL` | ✅ DONE |
| `TimingSafeCompare` | `AshTimingSafeCompare` | ✅ DONE |
| `TimingSafeCompareBytes` | `AshTimingSafeCompareBytes` | ✅ DONE |
| `IsValidMode` | `AshIsValidMode` | ✅ DONE |
| `IsValidHTTPMethod` | `AshIsValidHTTPMethod` | ✅ DONE |
| `ParseJSON` | `AshParseJSON` | ✅ DONE |
| `ValidateProofInput` | `AshValidateProofInput` | ✅ DONE |
| `IsASCII` | `AshIsASCII` | ✅ DONE |
| `GenerateNonce` | `AshGenerateNonce` | ✅ DONE |
| `GenerateContextID` | `AshGenerateContextID` | ✅ DONE |
| `DeriveClientSecret` | `AshDeriveClientSecret` | ✅ DONE |
| `BuildProofV21` | `AshBuildProofHMAC` | ✅ DONE |
| `VerifyProofV21` | `AshVerifyProof` | ✅ DONE |
| `HashBody` | `AshHashBody` | ✅ DONE |
| `ExtractScopedFields` | `AshExtractScopedFields` | ✅ DONE |
| `BuildProofV21Scoped` | `AshBuildProofScoped` | ✅ DONE |
| `VerifyProofV21Scoped` | `AshVerifyProofScoped` | ✅ DONE |
| `HashScopedBody` | `AshHashScopedBody` | ✅ DONE |
| `HashProof` | `AshHashProof` | ✅ DONE |
| `BuildProofUnified` | `AshBuildProofUnified` | ✅ DONE |
| `VerifyProofUnified` | `AshVerifyProofUnified` | ✅ DONE |
| `GetVersion` | `AshGetVersion` | ✅ DONE |

### Unexported Functions (camelCase with `ash` prefix)

| Original Name | New Name | Status |
|---------------|----------|--------|
| `canonicalizeValue` | `ashCanonicalizeValue` | ✅ DONE |
| `canonicalizeNumber` | `ashCanonicalizeNumber` | ✅ DONE |
| `buildCanonicalJSON` | `ashBuildCanonicalJSON` | ✅ DONE |
| `escapeJSONStringRFC8785` | `ashEscapeJSONStringRFC8785` | ✅ DONE |
| `formatNumber` | `ashFormatNumber` | ✅ DONE |
| `parseURLEncoded` | `ashParseURLEncoded` | ✅ DONE |
| `percentEncodeUppercase` | `ashPercentEncodeUppercase` | ✅ DONE |
| `uppercasePercentEncoding` | `ashUppercasePercentEncoding` | ✅ DONE |
| `toUpperHex` | `ashToUpperHex` | ✅ DONE |
| `getNestedValue` | `ashGetNestedValue` | ✅ DONE |
| `setNestedValue` | `ashSetNestedValue` | ✅ DONE |

## Rust SDK Function Renames

### Public Functions (snake_case with `ash_` prefix)

Already compliant - all public functions use `ash_` prefix.

### Private Functions (snake_case with `ash_` prefix)

| Original Name | New Name | Status |
|---------------|----------|--------|
| (check source) | `ash_*` | CHECK |

## Node.js SDK Function Renames

### Exported Functions (camelCase with `ash` prefix)

| Original Name | New Name | Status |
|---------------|----------|--------|
| `hashBody` | `ashHashBody` | RENAME |
| `buildProof` | `ashBuildProof` | RENAME |
| `verifyProof` | `ashVerifyProof` | RENAME |
| `canonicalizeJson` | `ashCanonicalizeJson` | RENAME |
| `canonicalizeQuery` | `ashCanonicalizeQuery` | RENAME |
| `deriveClientSecret` | `ashDeriveClientSecret` | RENAME |
| `normalizeBinding` | `ashNormalizeBinding` | RENAME |
| `timingSafeEqual` | `ashTimingSafeEqual` | RENAME |
| `generateNonce` | `ashGenerateNonce` | RENAME |
| `generateContextId` | `ashGenerateContextId` | RENAME |
| (and others...) | `ash*` | RENAME |

### Internal Functions (camelCase with `ash` prefix)

| Original Name | New Name | Status |
|---------------|----------|--------|
| (check source) | `ash*` | CHECK |

## Backward Compatibility

For each renamed function, keep the old name as a deprecated alias:

```go
// Deprecated: Use AshHashBody instead
func HashBody(body string) string {
    return AshHashBody(body)
}
```

```javascript
// Deprecated: Use ashHashBody instead
export const hashBody = ashHashBody;
```

## Migration Guide

1. Update all function definitions to use new names
2. Create deprecated aliases for backward compatibility
3. Update all internal function calls
4. Update all test files
5. Update documentation
6. Announce deprecation timeline for old names
