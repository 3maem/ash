# ASH SDK v2.3.3 Release Notes

**Release Date:** 2026-01-29
**Developed by 3maem Co. | شركة عمائم**

---

## Highlights

- **Unified Error Codes** - Consistent error handling across all 6 SDKs
- **Cross-SDK Test Vectors** - 38 comprehensive test vectors for interoperability
- **Security Fix** - SQL injection vulnerability patched in Node.js SQL store
- **Secure Memory Utilities** - Auto-clearing sensitive data in Python and Node.js

---

## Security

### SQL Injection Fix (Node.js)

Fixed a vulnerability in the SQL store's table name handling:
- Added `validateSqlIdentifier()` function
- Only allows alphanumeric characters and underscores
- Limits identifier length to 64 characters

**Affected:** `@3maem/ash-node` SQL store users
**Severity:** Medium
**Action:** Update to v2.3.3 immediately

---

## New Features

### Unified Error Codes

All SDKs now use consistent error codes with semantically appropriate HTTP status codes:

| Code | HTTP | Description |
|------|------|-------------|
| `ASH_CTX_NOT_FOUND` | 404 | Context not found |
| `ASH_CTX_EXPIRED` | 401 | Context expired |
| `ASH_CTX_ALREADY_USED` | 409 | Replay detected |
| `ASH_BINDING_MISMATCH` | 403 | Endpoint mismatch |
| `ASH_PROOF_MISSING` | 401 | Missing proof header |
| `ASH_PROOF_INVALID` | 401 | Proof verification failed |
| `ASH_CANONICALIZATION_ERROR` | 422 | Canonicalization failed |
| `ASH_MODE_VIOLATION` | 400 | Mode requirements not met |
| `ASH_UNSUPPORTED_CONTENT_TYPE` | 415 | Unsupported content type |
| `ASH_SCOPE_MISMATCH` | 403 | Scope hash mismatch |
| `ASH_CHAIN_BROKEN` | 403 | Chain verification failed |

See [Error Code Specification](docs/ERROR_CODE_SPECIFICATION.md) for implementation details.

### Cross-SDK Test Vectors

New test suite ensuring interoperability:
- 20 JSON canonicalization vectors
- 6 URL-encoded canonicalization vectors
- 7 binding normalization vectors
- 5 timing-safe comparison vectors

Test runners available for all 6 SDKs in `tests/cross-sdk/`.

### Secure Memory Utilities

**Python:**
```python
from ash.core import SecureString, secure_derive_client_secret

with secure_derive_client_secret(nonce, context_id, binding) as secret:
    proof = build_proof_v21(secret.get(), timestamp, binding, body_hash)
# Memory automatically zeroed
```

**Node.js:**
```typescript
import { withSecureString, secureDeriveClientSecret } from '@3maem/ash-node';

const proof = await withSecureString(clientSecret, (secret) => {
  return buildProofV21(secret, timestamp, binding, bodyHash);
});
// Memory automatically cleared
```

---

## Documentation

- **Troubleshooting Guide** - Common issues and debugging tips
- **API Documentation** - Complete references for Go, PHP, and .NET
- **Error Code Specification** - Unified error handling guide
- **Release Checklist** - Publishing procedures for all registries

---

## Installation

### Node.js
```bash
npm install @3maem/ash-node@2.3.3
```

### Python
```bash
pip install ash-sdk==2.3.3
```

### Go
```bash
go get github.com/3maem/ash-go/v2@v2.3.3
```

### PHP
```bash
composer require 3maem/ash-sdk-php:^2.3.3
```

### .NET
```bash
dotnet add package Ash.Core --version 2.3.3
```

### Rust
```bash
cargo add ash-core@2.3.3
```

---

## Breaking Changes

None. This release is fully backward compatible with v2.3.x.

---

## Upgrade Guide

1. Update your package to v2.3.3
2. Update error handling to use new unified codes (optional but recommended)
3. Run cross-SDK test vectors to verify compatibility

---

## Full Changelog

See [CHANGELOG.md](CHANGELOG.md) for complete details.

---

## Packages

| Registry | Package | Version |
|----------|---------|---------|
| npm | [@3maem/ash-node](https://www.npmjs.com/package/@3maem/ash-node) | 2.3.3 |
| PyPI | [ash-sdk](https://pypi.org/project/ash-sdk/) | 2.3.3 |
| crates.io | [ash-core](https://crates.io/crates/ash-core) | 2.3.3 |
| Packagist | [3maem/ash-sdk-php](https://packagist.org/packages/3maem/ash-sdk-php) | 2.3.3 |
| NuGet | [Ash.Core](https://www.nuget.org/packages/Ash.Core) | 2.3.3 |
| Go | [github.com/3maem/ash-go/v2](https://pkg.go.dev/github.com/3maem/ash-go/v2) | 2.3.3 |

---

## Links

- [Main Repository](https://github.com/3maem/ash)
- [Documentation](https://github.com/3maem/ash/tree/main/docs)
- [Security Policy](https://github.com/3maem/ash/blob/main/SECURITY.md)
- [Troubleshooting](https://github.com/3maem/ash/blob/main/TROUBLESHOOTING.md)

---

**ASH Source-Available License (ASAL-1.0)**

© 3maem Co. | شركة عمائم
