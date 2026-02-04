# ASH SDK Naming Convention

This document defines the standard naming convention for all ASH SDK functions across all languages (Rust, Go, Node.js, Python, PHP, .NET) and middlewares.

## Important Notes

1. **NO VERSION NUMBERS IN FUNCTION NAMES** - Do not use V21, V22, V23 etc. in function names
2. **ALL functions MUST start with `ash_` prefix** (both public AND private/internal)
3. Function names should be descriptive and consistent across all SDKs

## Language-Specific Naming Rules

| Language | Public Functions | Private Functions | Example |
|----------|------------------|-------------------|---------|
| Rust | `snake_case` with `ash_` | `snake_case` with `ash_` | `ash_build_proof` |
| Go | `PascalCase` with `Ash` | `camelCase` with `ash` | `AshBuildProof` |
| Node.js | `camelCase` with `ash` | `camelCase` with `ash` | `ashBuildProof` |
| Python | `snake_case` with `ash_` | `snake_case` with `_ash_` | `ash_build_proof` |
| PHP | `camelCase` with `ash` | `camelCase` with `ash` | `ashBuildProof` |
| .NET | `PascalCase` with `Ash` | `camelCase` with `ash` | `AshBuildProof` |

## Complete Function Name Mappings

### Core Proof Functions

| Category | Rust | Go | Node.js | Python | PHP | .NET |
|----------|------|----|---------| -------|-----|------|
| Build Proof (legacy) | `ash_build_proof` | `AshBuildProof` | `ashBuildProof` | `ash_build_proof` | `ashBuildProof` | `AshBuildProof` |
| Build Proof HMAC | `ash_build_proof_hmac` | `AshBuildProofHMAC` | `ashBuildProofHmac` | `ash_build_proof_hmac` | `ashBuildProofHmac` | `AshBuildProofHmac` |
| Verify Proof | `ash_verify_proof` | `AshVerifyProof` | `ashVerifyProof` | `ash_verify_proof` | `ashVerifyProof` | `AshVerifyProof` |
| Derive Secret | `ash_derive_client_secret` | `AshDeriveClientSecret` | `ashDeriveClientSecret` | `ash_derive_client_secret` | `ashDeriveClientSecret` | `AshDeriveClientSecret` |
| Hash Body | `ash_hash_body` | `AshHashBody` | `ashHashBody` | `ash_hash_body` | `ashHashBody` | `AshHashBody` |
| Hash Proof | `ash_hash_proof` | `AshHashProof` | `ashHashProof` | `ash_hash_proof` | `ashHashProof` | `AshHashProof` |

### Scoped Proof Functions

| Category | Rust | Go | Node.js | Python |
|----------|------|----|---------|--------|
| Build Scoped | `ash_build_proof_scoped` | `AshBuildProofScoped` | `ashBuildProofScoped` | `ash_build_proof_scoped` |
| Verify Scoped | `ash_verify_proof_scoped` | `AshVerifyProofScoped` | `ashVerifyProofScoped` | `ash_verify_proof_scoped` |
| Extract Fields | `ash_extract_scoped_fields` | `AshExtractScopedFields` | `ashExtractScopedFields` | `ash_extract_scoped_fields` |
| Hash Scoped Body | `ash_hash_scoped_body` | `AshHashScopedBody` | `ashHashScopedBody` | `ash_hash_scoped_body` |

### Unified Proof Functions

| Category | Rust | Go | Node.js | Python |
|----------|------|----|---------|--------|
| Build Unified | `ash_build_proof_unified` | `AshBuildProofUnified` | `ashBuildProofUnified` | `ash_build_proof_unified` |
| Verify Unified | `ash_verify_proof_unified` | `AshVerifyProofUnified` | `ashVerifyProofUnified` | `ash_verify_proof_unified` |

### Canonicalization Functions

| Category | Rust | Go | Node.js | Python |
|----------|------|----|---------|--------|
| Canonicalize JSON | `ash_canonicalize_json` | `AshCanonicalizeJSON` | `ashCanonicalizeJson` | `ash_canonicalize_json` |
| Canonicalize Query | `ash_canonicalize_query` | `AshCanonicalizeQuery` | `ashCanonicalizeQuery` | `ash_canonicalize_query` |
| Canonicalize URL Encoded | `ash_canonicalize_urlencoded` | `AshCanonicalizeURLEncoded` | `ashCanonicalizeUrlEncoded` | `ash_canonicalize_urlencoded` |

### Binding Functions

| Category | Rust | Go | Node.js | Python |
|----------|------|----|---------|--------|
| Normalize Binding | `ash_normalize_binding` | `AshNormalizeBinding` | `ashNormalizeBinding` | `ash_normalize_binding` |
| Normalize From URL | `ash_normalize_binding_from_url` | `AshNormalizeBindingFromURL` | `ashNormalizeBindingFromUrl` | `ash_normalize_binding_from_url` |

### Utility Functions

| Category | Rust | Go | Node.js | Python |
|----------|------|----|---------|--------|
| Timing Safe Compare | `ash_timing_safe_compare` | `AshTimingSafeCompare` | `ashTimingSafeCompare` | `ash_timing_safe_compare` |
| Generate Nonce | `ash_generate_nonce` | `AshGenerateNonce` | `ashGenerateNonce` | `ash_generate_nonce` |
| Generate Context ID | `ash_generate_context_id` | `AshGenerateContextID` | `ashGenerateContextId` | `ash_generate_context_id` |

### Scope Functions

| Category | Rust | Go | Node.js | Python |
|----------|------|----|---------|--------|
| Normalize Scope | `ash_normalize_scope_fields` | `AshNormalizeScopeFields` | `ashNormalizeScopeFields` | `ash_normalize_scope_fields` |
| Join Scope | `ash_join_scope_fields` | `AshJoinScopeFields` | `ashJoinScopeFields` | `ash_join_scope_fields` |

### Base64 Functions

| Category | Rust | Go | Node.js | Python |
|----------|------|----|---------|--------|
| Base64URL Encode | `ash_base64url_encode` | `AshBase64URLEncode` | `ashBase64UrlEncode` | `ash_base64url_encode` |
| Base64URL Decode | `ash_base64url_decode` | `AshBase64URLDecode` | `ashBase64UrlDecode` | `ash_base64url_decode` |

### Validation Functions

| Category | Rust | Go | Node.js | Python |
|----------|------|----|---------|--------|
| Is Valid Mode | `ash_is_valid_mode` | `AshIsValidMode` | `ashIsValidMode` | `ash_is_valid_mode` |
| Is Valid HTTP Method | `ash_is_valid_http_method` | `AshIsValidHTTPMethod` | `ashIsValidHttpMethod` | `ash_is_valid_http_method` |
| Validate Proof Input | `ash_validate_proof_input` | `AshValidateProofInput` | `ashValidateProofInput` | `ash_validate_proof_input` |
| Is ASCII | `ash_is_ascii` | `AshIsASCII` | `ashIsAscii` | `ash_is_ascii` |

### Error Functions

| Category | Rust | Go | Node.js | Python |
|----------|------|----|---------|--------|
| New Error | `ash_new_error` | `AshNewError` | `ashNewError` | `ash_new_error` |
| Get Version | `ash_get_version` | `AshGetVersion` | `ashGetVersion` | `ash_get_version` |
| Parse JSON | `ash_parse_json` | `AshParseJSON` | `ashParseJson` | `ash_parse_json` |

## Internal/Private Functions

All internal functions must also use the `ash` prefix:

| Category | Rust | Go | Node.js | Python | PHP | .NET |
|----------|------|----|---------|--------|-----|------|
| Canonicalize Value | `ash_canonicalize_value` | `ashCanonicalizeValue` | `ashCanonicalizeValue` | `_ash_canonicalize_value` | `ashCanonicalizeValue` | `AshCanonicalizeValue` |
| Canonicalize Number | `ash_canonicalize_number` | `ashCanonicalizeNumber` | `ashCanonicalizeNumber` | `_ash_canonicalize_number` | `ashCanonicalizeNumber` | `AshCanonicalizeNumber` |
| Build Canonical JSON | `ash_build_canonical_json` | `ashBuildCanonicalJSON` | `ashBuildCanonicalJson` | `_ash_build_canonical_json` | `ashBuildCanonicalJson` | `AshBuildCanonicalJson` |
| Escape JSON String | `ash_escape_json_string` | `ashEscapeJSONString` | `ashEscapeJsonString` | `_ash_escape_json_string` | `ashEscapeJsonString` | `AshEscapeJsonString` |
| Format Number | `ash_format_number` | `ashFormatNumber` | `ashFormatNumber` | `_ash_format_number` | `ashFormatNumber` | `AshFormatNumber` |
| Parse URL Encoded | `ash_parse_urlencoded` | `ashParseURLEncoded` | `ashParseUrlEncoded` | `_ash_parse_urlencoded` | `ashParseUrlEncoded` | `AshParseUrlEncoded` |
| Percent Encode | `ash_percent_encode_uppercase` | `ashPercentEncodeUppercase` | `ashPercentEncodeUppercase` | `_ash_percent_encode_uppercase` | `ashPercentEncodeUppercase` | `AshPercentEncodeUppercase` |
| Uppercase Percent Encoding | `ash_uppercase_percent_encoding` | `ashUppercasePercentEncoding` | `ashUppercasePercentEncoding` | `_ash_uppercase_percent_encoding` | `ashUppercasePercentEncoding` | `AshUppercasePercentEncoding` |
| To Upper Hex | `ash_to_upper_hex` | `ashToUpperHex` | `ashToUpperHex` | `_ash_to_upper_hex` | `ashToUpperHex` | `AshToUpperHex` |
| Get Nested Value | `ash_get_nested_value` | `ashGetNestedValue` | `ashGetNestedValue` | `_ash_get_nested_value` | `ashGetNestedValue` | `AshGetNestedValue` |
| Set Nested Value | `ash_set_nested_value` | `ashSetNestedValue` | `ashSetNestedValue` | `_ash_set_nested_value` | `ashSetNestedValue` | `AshSetNestedValue` |

## Type Naming

| Category | All Languages |
|----------|---------------|
| Error Type | `AshError` |
| Error Code | `AshErrorCode` |
| Mode | `AshMode` |
| Build Input | `BuildProofInput` |
| Unified Result | `UnifiedProofResult` |
| Scoped Result | `ScopedProofResult` |

## Constants Naming

| Constant | Value |
|----------|-------|
| `ASH_SDK_VERSION` | Current version string |
| `ASH_VERSION_PREFIX` | `"ASHv1"` |
| `ModeStrict` | `"strict"` |
| `ModeBalanced` | `"balanced"` |
| `ModeMinimal` | `"minimal"` |
| `SCOPE_FIELD_DELIMITER` | `"\x1F"` (Unit separator) |

## Error Codes

All SDKs must use these error codes consistently:

| Code | Description |
|------|-------------|
| `ASH_CTX_NOT_FOUND` | Context not found |
| `ASH_CTX_EXPIRED` | Context expired |
| `ASH_CTX_ALREADY_USED` | Context already used (replay) |
| `ASH_BINDING_MISMATCH` | Endpoint binding mismatch |
| `ASH_PROOF_MISSING` | Proof not provided |
| `ASH_PROOF_INVALID` | Proof verification failed |
| `ASH_CANONICALIZATION_ERROR` | Canonicalization failed |
| `ASH_MODE_VIOLATION` | Mode violation |
| `ASH_UNSUPPORTED_CONTENT_TYPE` | Unsupported content type |
| `ASH_SCOPE_MISMATCH` | Scope hash mismatch |
| `ASH_CHAIN_BROKEN` | Chain verification failed |

## Deprecated Names (Backward Compatibility)

The following old function names are deprecated but kept for backward compatibility:

| Old Name | New Name | Status |
|----------|----------|--------|
| `BuildProofV21` | `AshBuildProofHMAC` | Deprecated |
| `VerifyProofV21` | `AshVerifyProof` | Deprecated |
| `BuildProofV21Scoped` | `AshBuildProofScoped` | Deprecated |
| `VerifyProofV21Scoped` | `AshVerifyProofScoped` | Deprecated |
| `hashBody` | `ashHashBody` | Deprecated |
| `buildProof` | `ashBuildProof` | Deprecated |
| `verifyProof` | `ashVerifyProof` | Deprecated |

