# ASH Development Setup

## Prerequisites

### 1. Install Rust

**Windows:**
```powershell
# Download and run rustup-init.exe from https://rustup.rs
# Or using winget:
winget install Rustlang.Rustup
```

**macOS/Linux:**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

After installation, restart your terminal and verify:
```bash
rustc --version
cargo --version
```

### 2. Install wasm-pack (for WASM builds)

```bash
cargo install wasm-pack
```

### 3. Install Node.js (v18+)

Download from https://nodejs.org or use nvm:
```bash
nvm install 20
nvm use 20
```

### 4. Install Python (3.10+)

Download from https://python.org or use pyenv.

### 5. Install Go (1.21+)

Download from https://go.dev/dl/

### 6. Install .NET SDK (6.0+)

Download from https://dotnet.microsoft.com/download

### 7. Install PHP (8.1+)

Download from https://php.net or use your package manager.

---

## Building & Testing

### Rust Core

```bash
cd packages/ash-core

# Build
cargo build --release

# Run tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Check formatting
cargo fmt --check

# Run linter
cargo clippy
```

### WASM

```bash
cd packages/ash-wasm

# Build for web
wasm-pack build --target web --release

# Build for Node.js
wasm-pack build --target nodejs --release

# Run tests
wasm-pack test --node
```

### Node.js SDK

```bash
cd packages/ash-node

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Run linter
npm run lint
```

### Python SDK

```bash
cd packages/ash-python

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest -v

# Run linter
ruff check src/

# Run type checker
mypy src/ash/
```

### PHP SDK

```bash
cd packages/ash-php

# Install dependencies
composer install

# Run tests
composer test

# Run PHPStan
composer phpstan

# Check code style
composer cs
```

### Go SDK

```bash
cd packages/ash-go

# Download dependencies
go mod download

# Run tests
go test -v ./...

# Run tests with coverage
go test -v -race -coverprofile=coverage.out ./...

# Run linter
go vet ./...
```

### .NET SDK

```bash
cd packages/ash-dotnet

# Restore dependencies
dotnet restore

# Build
dotnet build --configuration Release

# Run tests
dotnet test --configuration Release
```

---

## Running All Tests

From the repository root:

```bash
# Rust
cargo test

# Node.js (after WASM build)
npm test

# Python
cd packages/ash-python && pytest

# PHP
cd packages/ash-php && composer test

# Go
cd packages/ash-go && go test ./...

# .NET
cd packages/ash-dotnet && dotnet test
```

---

## Conformance Testing

All SDKs must produce identical output for the test vectors in `vectors/`:

- `json_canon_vectors.json` - JSON canonicalization
- `urlencoded_canon_vectors.json` - URL-encoded canonicalization
- `proof_vectors.json` - Proof generation

Run conformance tests:
```bash
npm run test:conformance  # Node.js
pytest tests/test_conformance.py  # Python
composer test:conformance  # PHP
go test -run TestConformance  # Go
dotnet test --filter Conformance  # .NET
```

---

## Troubleshooting

### Cargo not found
Make sure Rust is installed and `~/.cargo/bin` is in your PATH.

### wasm-pack build fails
Ensure the `wasm32-unknown-unknown` target is installed:
```bash
rustup target add wasm32-unknown-unknown
```

### Node.js WASM import fails
Build WASM for the correct target (`nodejs` for Node.js, `web` for browsers).

### PHP intl extension missing
Install the intl extension for Unicode normalization support.

---

## IDE Setup

### VS Code Extensions
- rust-analyzer (Rust)
- ESLint + Prettier (Node.js)
- Python + Pylance (Python)
- PHP Intelephense (PHP)
- Go (Go)
- C# Dev Kit (.NET)

### JetBrains IDEs
- RustRover or IntelliJ with Rust plugin
- WebStorm (Node.js)
- PyCharm (Python)
- PhpStorm (PHP)
- GoLand (Go)
- Rider (.NET)
