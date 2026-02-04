# ASH SDK Documentation

This directory contains documentation generation configuration for all ASH SDK implementations.

## Generated API Documentation

| SDK | Language | Tool | Output | Online |
|-----|----------|------|--------|--------|
| **ash-core** | Rust | rustdoc | `target/doc/` | [docs.rs/ash-core](https://docs.rs/ash-core) |
| **ash-wasm** | Rust/WASM | rustdoc | `target/doc/` | [docs.rs/ash-wasm](https://docs.rs/ash-wasm) |
| **ash-node** | Node.js | TypeDoc | `packages/ash-node/docs/` | npm |
| **ash-python** | Python | Sphinx | `packages/ash-python/docs/_build/` | PyPI |
| **ash-go** | Go | godoc | pkg.go.dev | [pkg.go.dev](https://pkg.go.dev/github.com/3maem/ash-go/v2) |
| **ash-php** | PHP | phpDocumentor | `packages/ash-php/docs/api/` | Packagist |
| **ash-dotnet** | .NET | DocFX | `packages/ash-dotnet/_site/` | NuGet |

## Generating Documentation

### Quick Start (All SDKs)

```bash
# Generate documentation for all SDKs
./scripts/generate-docs.sh
```

### Individual SDK Documentation

#### Rust (ash-core, ash-wasm)
```bash
cargo doc --no-deps --workspace
# Output: target/doc/ash_core/index.html
```

#### Node.js (@3maem/ash-node)
```bash
cd packages/ash-node
npm install --save-dev typedoc  # if not installed
npm run docs
# Output: packages/ash-node/docs/index.html
```

#### Python (ash-sdk)
```bash
cd packages/ash-python
pip install sphinx sphinx-rtd-theme  # if not installed
sphinx-build -b html docs/source docs/_build
# Output: packages/ash-python/docs/_build/index.html
```

#### Go (ash-go)
```bash
cd packages/ash-go

# View in terminal
go doc -all .

# Generate markdown (requires gomarkdoc)
go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@latest
gomarkdoc --output docs/api.md .

# View online
# https://pkg.go.dev/github.com/3maem/ash-go/v2
```

#### PHP (ash-sdk-php)
```bash
cd packages/ash-php
composer require --dev phpdocumentor/phpdocumentor  # if not installed
composer docs
# Output: packages/ash-php/docs/api/index.html
```

#### .NET (Ash.Core)
```bash
cd packages/ash-dotnet
dotnet tool install -g docfx  # if not installed
docfx docfx.json
# Output: packages/ash-dotnet/_site/index.html
```

## Prerequisites

### Required Tools

| SDK | Tool | Installation |
|-----|------|--------------|
| Rust | rustdoc | Included with Rust |
| Node.js | TypeDoc | `npm install --save-dev typedoc` |
| Python | Sphinx | `pip install sphinx sphinx-rtd-theme` |
| Go | gomarkdoc | `go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@latest` |
| PHP | phpDocumentor | `composer require --dev phpdocumentor/phpdocumentor` |
| .NET | DocFX | `dotnet tool install -g docfx` |

## Documentation Standards

### Code Examples

All public APIs should include:
- Brief description
- Parameter descriptions with types
- Return value description
- Usage example
- Error conditions

### Cross-References

Link to related functions and types where appropriate.

### Version Information

Document which ASH protocol version each function supports:
- v1 (legacy)
- v2.1 (HMAC-SHA256)
- v2.2 (scoping)
- v2.3 (chaining)

## Directory Structure

```
docs/
├── README.md              # This file
└── generated/             # Generated documentation output
    ├── rust/              # Rust API docs
    ├── node/              # Node.js API docs
    ├── python/            # Python API docs
    ├── go/                # Go API docs
    ├── php/               # PHP API docs
    └── dotnet/            # .NET API docs
```

## Configuration Files

| SDK | Config File | Location |
|-----|-------------|----------|
| Rust | Cargo.toml | `packages/ash-core/Cargo.toml` |
| Node.js | typedoc.json | `packages/ash-node/typedoc.json` |
| Python | conf.py | `packages/ash-python/docs/source/conf.py` |
| Go | doc.go | `packages/ash-go/doc.go` |
| PHP | phpdoc.dist.xml | `packages/ash-php/phpdoc.dist.xml` |
| .NET | docfx.json | `packages/ash-dotnet/docfx.json` |
