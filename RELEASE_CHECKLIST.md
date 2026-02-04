# ASH SDK Release Checklist

This document outlines the steps required to publish a new version of the ASH SDK across all package registries.

## Pre-Release Checklist

### 1. Version Updates

- [ ] Update version in `packages/ash-core/Cargo.toml`
- [ ] Update version in `packages/ash-wasm/Cargo.toml`
- [ ] Update version in `packages/ash-node/package.json`
- [ ] Update version in `packages/ash-python/pyproject.toml`
- [ ] Update version in `packages/ash-go/version.go`
- [ ] Update version in `packages/ash-php/composer.json`
- [ ] Update version in `packages/ash-dotnet/Ash.csproj`
- [ ] Update version badge in main `README.md`
- [ ] Update version badges in all SDK READMEs

### 2. Documentation

- [ ] Update `CHANGELOG.md` with release notes
- [ ] Review and update API documentation if needed
- [ ] Verify all links in documentation are working

### 3. Testing

- [ ] Run all SDK tests locally: `test-all-sdks.yml`
- [ ] Run security assurance pack: `pytest tests/security_assurance/`
- [ ] Run cross-SDK test vectors
- [ ] Verify examples work with new version

### 4. Code Quality

- [ ] Run linters on all SDKs
- [ ] Run security audits (`cargo audit`, `npm audit`, `safety check`, `govulncheck`)
- [ ] Review any new dependencies

---

## Release Process

### Step 1: Create Git Tag

```bash
# Ensure you're on main branch with latest changes
git checkout main
git pull origin main

# Create annotated tag
git tag -a v2.3.3 -m "ASH SDK v2.3.3"

# Push tag to trigger release workflow
git push origin v2.3.3
```

### Step 2: Automated Publishing (via GitHub Actions)

The `release.yml` workflow automatically publishes to all registries when a tag is pushed:

| Registry | Package | Workflow Job |
|----------|---------|--------------|
| crates.io | `ash-core` | `publish-rust` |
| npm | `@3maem/ash-node` | `publish-npm` |
| PyPI | `ash-sdk` | `publish-pypi` |
| Packagist | `3maem/ash-sdk-php` | `publish-packagist` |
| NuGet | `Ash.Core` | `publish-nuget` |
| Go Modules | `github.com/3maem/ash-go/v2` | Automatic (via tag) |

### Step 3: Verify Publications

After the workflow completes, verify packages are available:

#### crates.io (Rust)
```bash
cargo search ash-core
# Verify: https://crates.io/crates/ash-core
```

#### npm (Node.js)
```bash
npm view @3maem/ash-node version
# Verify: https://www.npmjs.com/package/@3maem/ash-node
```

#### PyPI (Python)
```bash
pip index versions ash-sdk
# Verify: https://pypi.org/project/ash-sdk/
```

#### Packagist (PHP)
```bash
composer show 3maem/ash-sdk-php --available
# Verify: https://packagist.org/packages/3maem/ash-sdk-php
```

#### NuGet (.NET)
```bash
dotnet package search Ash.Core
# Verify: https://www.nuget.org/packages/Ash.Core
```

#### Go Modules
```bash
go list -m github.com/3maem/ash-go/v2@v2.3.3
# Verify: https://pkg.go.dev/github.com/3maem/ash-go/v2
```

---

## Manual Publishing (if needed)

### Rust (crates.io)

```bash
cd packages/ash-core
cargo publish --dry-run  # Verify first
cargo publish
```

**Required:** `CRATES_IO_TOKEN` secret or `~/.cargo/credentials.toml`

### Node.js (npm)

```bash
cd packages/ash-node
npm run build
npm publish --access public
```

**Required:** `npm login` or `NPM_TOKEN`

### Python (PyPI)

```bash
cd packages/ash-python
pip install build twine
python -m build
twine upload dist/*
```

**Required:** `~/.pypirc` with API token or `TWINE_USERNAME`/`TWINE_PASSWORD`

### PHP (Packagist)

Packagist auto-updates from GitHub. Manual trigger:

```bash
curl -X POST "https://packagist.org/api/update-package" \
  -d "username=YOUR_USERNAME" \
  -d "apiToken=YOUR_TOKEN" \
  -d "repository[url]=https://github.com/3maem/ash"
```

### .NET (NuGet)

```bash
cd packages/ash-dotnet
dotnet pack --configuration Release
dotnet nuget push ./bin/Release/*.nupkg \
  --api-key YOUR_API_KEY \
  --source https://api.nuget.org/v3/index.json
```

**Required:** NuGet API key

### Go Modules

Go modules are automatically available via GitHub tags. Just push the tag:

```bash
git tag -a v2.3.3 -m "v2.3.3"
git push origin v2.3.3
```

The Go proxy will index it automatically. Force refresh if needed:

```bash
GOPROXY=proxy.golang.org go list -m github.com/3maem/ash-go/v2@v2.3.3
```

---

## Required Secrets

The following secrets must be configured in GitHub repository settings:

| Secret | Registry | How to Obtain |
|--------|----------|---------------|
| `CRATES_IO_TOKEN` | crates.io | [crates.io/settings/tokens](https://crates.io/settings/tokens) |
| `NPM_TOKEN` | npm | [npmjs.com/settings/tokens](https://www.npmjs.com/settings/tokens) |
| `PYPI_TOKEN` | PyPI | [pypi.org/manage/account/token](https://pypi.org/manage/account/token/) |
| `PACKAGIST_USERNAME` | Packagist | Packagist account username |
| `PACKAGIST_TOKEN` | Packagist | [packagist.org/profile](https://packagist.org/profile/) |
| `NUGET_API_KEY` | NuGet | [nuget.org/account/apikeys](https://www.nuget.org/account/apikeys) |

---

## Post-Release Checklist

- [ ] Verify GitHub Release was created with correct notes
- [ ] Verify all packages are published and accessible
- [ ] Test installation from each registry
- [ ] Update any external documentation or announcements
- [ ] Close relevant GitHub issues/milestones
- [ ] Announce release (if applicable)

---

## Rollback Procedure

If a release has critical issues:

### npm
```bash
npm deprecate @3maem/ash-node@2.3.3 "Critical bug, use 2.3.4"
# Or unpublish within 72 hours:
npm unpublish @3maem/ash-node@2.3.3
```

### PyPI
```bash
# Cannot unpublish, but can yank:
# Go to PyPI project page and use "Delete" for the release
```

### crates.io
```bash
cargo yank --version 2.3.3 ash-core
```

### NuGet
```bash
dotnet nuget delete Ash.Core 2.3.3 --source https://api.nuget.org/v3/index.json
```

### Go Modules
Go modules cannot be unpublished. Release a new patch version with fixes.

---

## Version Numbering

ASH follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (X.0.0): Breaking API changes
- **MINOR** (0.X.0): New features, backward compatible
- **PATCH** (0.0.X): Bug fixes, backward compatible

Protocol versions (ASHv2.1, ASHv2.2, ASHv2.3) are independent of SDK versions.

---

## Contact

For release issues, contact the maintainers at:
- GitHub: [github.com/3maem/ash/issues](https://github.com/3maem/ash/issues)
- Email: security@3maem.com

---

**Developed by 3maem Co. | شركة عمائم**
