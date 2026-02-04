# ASH Test Documentation

This directory contains the authoritative test documentation for all ASH SDK implementations.

## Documents

| Document | Purpose |
|----------|---------|
| [ASH-PROTOCOL-TESTS.md](./ASH-PROTOCOL-TESTS.md) | **Universal tests** - Must pass in ALL SDKs |
| [SDK-SPECIFIC-TESTS.md](./SDK-SPECIFIC-TESTS.md) | **Language-specific tests** - Types, benchmarks, etc. |
| [MIDDLEWARE-TESTS.md](./MIDDLEWARE-TESTS.md) | **HTTP middleware tests** - Express, Fastify, etc. |

## SDK Test Locations

Each SDK has its own test files:

| SDK | Test Location | Test Command |
|-----|--------------|--------------|
| ash-core (Rust) | `packages/ash-core/tests/` | `cargo test` |
| ash-node (Node.js) | `packages/ash-node/src/*.test.ts` | `npm test` |
| ash-go (Go) | `packages/ash-go/*_test.go` | `go test` |
| ash-python (Python) | `packages/ash-python/tests/` | `pytest tests/` |
| ash-php (PHP) | `packages/ash-php/tests/` | `vendor/bin/phpunit tests/` |
| ash-dotnet (.NET) | `packages/ash-dotnet/tests/` | `dotnet test` |

## Test Priority

When implementing a new SDK, implement tests in this order:

1. **Cross-SDK Test Vectors** - Ensures compatibility with other SDKs
2. **Core SDK Tests** - Basic functionality
3. **RFC Compliance Tests** - Protocol correctness
4. **Security Audit Tests** - Vulnerability prevention
5. **Error Handling Tests** - Graceful failure
6. **Production Edge Cases** - Real-world scenarios
7. **SDK-Specific Tests** - Language-specific features
8. **Middleware Tests** - HTTP integration (if applicable)

## Running All Tests

```bash
# Run tests for all SDKs
./scripts/test-all.sh

# Or run individually:
cd packages/ash-core && cargo test
cd packages/ash-node && npm test
cd packages/ash-go && go test
cd packages/ash-python && pytest tests/
cd packages/ash-php && vendor/bin/phpunit tests/
cd packages/ash-dotnet && dotnet test
```

## Contributing

When adding new tests:

1. Add to appropriate documentation file first
2. Implement in reference SDK (Rust)
3. Port to other SDKs
4. Update coverage matrix in ASH-PROTOCOL-TESTS.md

---

*Last Updated: January 2026*
