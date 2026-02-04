# ASH Library Publishing Preparation Guide

This guide summarizes the steps needed to prepare the ASH library for publishing based on the comprehensive review.

## Quick Status

| Item | Status | Priority |
|------|--------|----------|
| Security Audit | ✅ Pass | - |
| Code Quality | ✅ Excellent | - |
| Test Coverage | ✅ 1300+ tests | - |
| Documentation | ✅ Complete | - |
| Input Validation Alignment | ✅ Complete (2026-02-02) | - |
| Unique HTTP Status Codes | ✅ Complete (2026-02-02) | - |
| **Publishing Readiness** | **✅ Ready** | **-** |

## Critical Actions (Do Before Publishing)

### 1. ~~Fix Input Validation Inconsistencies~~ ✅ COMPLETED (2026-02-02)

**Status: All SDKs now have consistent input validation matching the Rust implementation.**

All SDKs (Go, Python, PHP, .NET) have been updated with comprehensive validation in `ash_derive_client_secret`:
- SEC-014: Nonce minimum length (32 hex chars)
- SEC-NONCE-001: Nonce maximum length (128 chars)
- BUG-004: Nonce hexadecimal validation
- BUG-041: Context ID non-empty validation
- SEC-CTX-001: Context ID max length (256 chars)
- SEC-CTX-001: Context ID charset validation
- SEC-AUDIT-004: Binding max length (8KB)

<details>
<summary>Original Implementation Instructions (Click to expand)</summary>

### 1. Fix Input Validation Inconsistencies (HIGH PRIORITY)

The Rust SDK has comprehensive input validation that other SDKs lack. You should align the following:

**Go SDK (`packages/ash-go/ash.go`):**
Add to `AshDeriveClientSecret`:
```go
// Add validation
if len(nonce) < 32 {
    return "", errors.New("nonce must be at least 32 hex characters")
}
if len(nonce) > 128 {
    return "", errors.New("nonce exceeds maximum length")
}
// Validate hex format
for _, c := range nonce {
    if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
        return "", errors.New("nonce must be hexadecimal")
    }
}
// Validate context_id
if contextId == "" {
    return "", errors.New("context_id cannot be empty")
}
if len(contextId) > 256 {
    return "", errors.New("context_id exceeds maximum length")
}
```

**Python SDK (`packages/ash-python/src/ash/core/proof.py`):**
Add to `ash_derive_client_secret`:
```python
import re

def ash_derive_client_secret(nonce: str, context_id: str, binding: str) -> str:
    # SEC-014: Validate nonce length
    if len(nonce) < 32:
        raise ValueError("Nonce must be at least 32 hex characters")
    if len(nonce) > 128:
        raise ValueError("Nonce exceeds maximum length of 128 characters")
    
    # BUG-004: Validate nonce is hexadecimal
    if not re.match(r'^[0-9a-fA-F]+$', nonce):
        raise ValueError("Nonce must contain only hexadecimal characters")
    
    # BUG-041: Validate context_id is not empty
    if not context_id:
        raise ValueError("context_id cannot be empty")
    
    # SEC-CTX-001: Validate context_id length and charset
    if len(context_id) > 256:
        raise ValueError("context_id exceeds maximum length of 256 characters")
    if not re.match(r'^[A-Za-z0-9_.-]+$', context_id):
        raise ValueError("context_id must contain only alphanumeric characters, underscore, hyphen, or dot")
    
    # Existing implementation...
```

**PHP SDK (`packages/ash-php/src/Core/Proof.php`):**
Add to `ashDeriveClientSecret`:
```php
public static function ashDeriveClientSecret(string $nonce, string $contextId, string $binding): string
{
    // SEC-014: Validate nonce length
    if (strlen($nonce) < 32) {
        throw new \InvalidArgumentException("Nonce must be at least 32 hex characters");
    }
    if (strlen($nonce) > 128) {
        throw new \InvalidArgumentException("Nonce exceeds maximum length of 128 characters");
    }
    
    // BUG-004: Validate nonce is hexadecimal
    if (!ctype_xdigit($nonce)) {
        throw new \InvalidArgumentException("Nonce must contain only hexadecimal characters");
    }
    
    // BUG-041: Validate context_id
    if (empty($contextId)) {
        throw new \InvalidArgumentException("context_id cannot be empty");
    }
    if (strlen($contextId) > 256) {
        throw new \InvalidArgumentException("context_id exceeds maximum length of 256 characters");
    }
    if (!preg_match('/^[A-Za-z0-9_.-]+$/', $contextId)) {
        throw new \InvalidArgumentException("context_id contains invalid characters");
    }
    
    // Existing implementation...
}
```

</details>

### 2. ~~Complete Unified Proof Support~~ ✅ VERIFIED (2026-02-02)

**Status: PHP and .NET SDKs already have complete unified proof implementation.**

Both `ashBuildProofUnified` and `ashVerifyProofUnified` are fully implemented in:
- PHP: `packages/ash-php/src/Core/Proof.php`
- .NET: `packages/ash-dotnet/src/Ash.Core/Proof.cs`

### 3. Run All Tests

```bash
# Navigate to project root
cd Desktop/ash

# Run Rust tests
cargo test --all

# Run Go tests
cd packages/ash-go
go test -v ./...
cd ../..

# Run Node.js tests
cd packages/ash-node
npm test
cd ../..

# Run Python tests
cd packages/ash-python
pytest tests/ -v
cd ../..

# Run PHP tests
cd packages/ash-php
composer test
cd ../..

# Run .NET tests
cd packages/ash-dotnet
dotnet test
cd ../..

# Run new comprehensive tests
pytest tests/comprehensive/ -v

# Run security tests
pytest tests/security/ -v
```

### 4. Version Bump Checklist

Before publishing, ensure:

- [ ] `Cargo.toml` - version = "2.3.3"
- [ ] `package.json` (ash-node) - "version": "2.3.3"
- [ ] `setup.py` (ash-python) - version="2.3.3"
- [ ] `composer.json` (ash-php) - "version": "2.3.3"
- [ ] `Ash.Core.csproj` (.NET) - `<Version>2.3.3</Version>`
- [ ] `ASH_SDK_VERSION` constant in all source files
- [ ] `CHANGELOG.md` updated with v2.3.3 changes
- [ ] Git tag created: `git tag -a v2.3.3 -m "ASH v2.3.3 Release"`

## Publishing Order

Publish in this order to maintain cross-SDK compatibility:

1. **Rust (ash-core)** - Foundation crate
   ```bash
   cd packages/ash-core
   cargo publish --dry-run  # Verify first
   cargo publish
   ```

2. **Rust WASM (ash-wasm)** - Browser support
   ```bash
   cd packages/ash-wasm
   wasm-pack publish --dry-run
   wasm-pack publish
   ```

3. **Node.js (@3maem/ash-node)** - Depends on ash-wasm
   ```bash
   cd packages/ash-node
   npm publish --dry-run
   npm publish
   ```

4. **Python (ash-sdk)** - Independent
   ```bash
   cd packages/ash-python
   python -m build
   twine upload --repository-url https://test.pypi.org/legacy/ dist/*  # Test first
   twine upload dist/*
   ```

5. **PHP (3maem/ash-sdk-php)** - Independent
   ```bash
   cd packages/ash-php
   # Tag and push to GitHub, Packagist will auto-update
   ```

6. **Go (github.com/3maem/ash-go)** - Independent
   ```bash
   cd packages/ash-go
   git tag v2.3.3
   git push origin v2.3.3
   ```

7. **.NET (Ash.Core)** - Independent
   ```bash
   cd packages/ash-dotnet
   dotnet pack
   dotnet nuget push bin/Release/Ash.Core.2.3.3.nupkg --api-key YOUR_API_KEY --source https://api.nuget.org/v3/index.json
   ```

## Post-Publishing Verification

After publishing, verify:

1. **Installation Test**
   ```bash
   # Test each package can be installed
   cargo add ash-core
   npm install @3maem/ash-node
   pip install ash-sdk
   composer require 3maem/ash-sdk-php
   go get github.com/3maem/ash-go
   dotnet add package Ash.Core
   ```

2. **Basic Functionality Test**
   - Run cross-SDK test vectors
   - Verify proof generation/verification works

3. **Documentation Verification**
   - Check all links in README files
   - Verify API documentation is accessible

## Known Limitations (Document These)

The following should be documented as known limitations:

1. **PHP/.NET SDK:** Unified proof (v2.3) features partially implemented
2. **Field Names:** Dots in field names not supported for scoping
3. **Payload Size:** Maximum 10MB payload for canonicalization
4. **Browser Support:** WASM build required for browser usage

## Security Disclosure

Before publishing, ensure:

- [ ] `SECURITY.md` has correct contact information
- [ ] Security policy is published on GitHub
- [ ] HackerOne/bug bounty program configured (if applicable)

## Marketing Checklist

- [ ] GitHub repository is public
- [ ] Repository has good README with badges
- [ ] Examples are working and documented
- [ ] Blog post/announcement prepared (optional)
- [ ] Social media announcements prepared (optional)

## Support

After publishing, monitor:

- GitHub Issues for bug reports
- Security advisories
- Stack Overflow for questions
- Package manager download statistics

---

**Last Updated:** 2026-02-02  
**Version:** 2.3.3  
**Status:** Ready for publishing with minor fixes
