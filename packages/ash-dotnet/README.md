# ASH SDK for .NET

[![NuGet](https://img.shields.io/nuget/v/Ash.Core.svg)](https://www.nuget.org/packages/Ash.Core)
[![.NET](https://img.shields.io/badge/.NET-6.0%20%7C%207.0%20%7C%208.0-brightgreen)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/badge/license-ASAL--1.0-blue)](../../LICENSE)
[![Version](https://img.shields.io/badge/version-2.3.4-blue)](../../CHANGELOG.md)

**Developed by 3maem Co. | شركة عمائم**

ASH (Application Security Hash) - RFC 8785 compliant request integrity verification with server-signed seals, anti-replay protection, and zero client secrets. This package provides JCS canonicalization, proof generation, and ASP.NET Core middleware for .NET applications.

## Installation

```bash
dotnet add package Ash.Core
```

**Requirements:** .NET 6.0, 7.0, or 8.0

## Quick Start

### Canonicalize JSON

```csharp
using Ash;

// Canonicalize JSON to deterministic form
var canonical = AshService.AshCanonicalizeJson(@"{""z"":1,""a"":2}");
Console.WriteLine(canonical); // {"a":2,"z":1}
```

### Build a Proof

```csharp
using Ash;

// Canonicalize payload
var payload = @"{""username"":""test"",""action"":""login""}";
var canonical = AshService.AshCanonicalizeJson(payload);

// Build proof
var proof = AshService.AshBuildProof(
    mode: AshMode.Balanced,
    binding: "POST /api/login",
    contextId: "ctx_abc123",
    nonce: null,  // Optional: for server-assisted mode
    canonicalPayload: canonical
);

Console.WriteLine($"Proof: {proof}");
```

### Verify a Proof

```csharp
using Ash;

var expectedProof = "abc123...";
var receivedProof = "abc123...";

// Use timing-safe comparison to prevent timing attacks
if (AshService.AshVerifyProof(expectedProof, receivedProof))
{
    Console.WriteLine("Proof verified successfully");
}
else
{
    Console.WriteLine("Proof verification failed");
}
```

## ASP.NET Core Integration

### Setup with Dependency Injection

```csharp
using Ash;
using Ash.Stores;
using Ash.Middleware;

var builder = WebApplication.CreateBuilder(args);

// Register ASH services
builder.Services.AddSingleton<IContextStore, MemoryStore>();
builder.Services.AddSingleton<AshService>(sp =>
    new AshService(sp.GetRequiredService<IContextStore>(), AshMode.Balanced));

var app = builder.Build();

// Add ASH middleware for protected paths
var ash = app.Services.GetRequiredService<AshService>();
app.UseAsh(ash, "/api/*");

app.MapPost("/api/update", (HttpContext ctx) =>
{
    // Request has been verified by ASH middleware
    var metadata = ctx.Items["AshMetadata"];
    return Results.Ok(new { status = "success" });
});

app.Run();
```

### Issue Context Endpoint

```csharp
app.MapPost("/ash/context", async (AshService ash, HttpContext ctx) =>
{
    var context = await ash.AshIssueContextAsync(
        binding: "POST /api/update",
        ttlMs: 30000,
        mode: AshMode.Balanced
    );

    return Results.Ok(new
    {
        contextId = context.Id,
        expiresAt = context.ExpiresAt,
        mode = context.Mode.ToModeString()
    });
});
```

### Using Redis Store (Production)

```csharp
using Ash.Stores;
using StackExchange.Redis;

var redis = ConnectionMultiplexer.Connect("localhost:6379");
var store = new RedisStore(redis.GetDatabase());
var ash = new AshService(store, AshMode.Balanced);
```

## API Reference

### AshService Class

The main service class for ASH operations.

#### Constructor

```csharp
public AshService(IContextStore store, AshMode defaultMode = AshMode.Balanced)
```

#### Methods

##### `AshIssueContextAsync`

Issues a new context for a request.

```csharp
public async Task<AshContext> AshIssueContextAsync(
    string binding,
    long ttlMs,
    AshMode? mode = null,
    Dictionary<string, object>? metadata = null)
```

##### `AshVerifyAsync`

Verifies a request against its context and proof.

```csharp
public async Task<AshVerifyResult> AshVerifyAsync(
    string contextId,
    string proof,
    string binding,
    string payload,
    string contentType)
```

##### `AshCanonicalize`

Canonicalizes a payload based on content type.

```csharp
public string AshCanonicalize(string payload, string contentType)
```

### Static Methods

#### `AshCanonicalizeJson`

Canonicalizes JSON to deterministic form per RFC 8785 (JCS).

```csharp
public static string AshCanonicalizeJson(string json)
```

**Rules (RFC 8785 JCS):**
- Object keys sorted lexicographically (UTF-16 code units)
- No whitespace
- Unicode NFC normalized
- Minimal JSON escaping (only \b, \t, \n, \f, \r, \", \\)
- Numbers normalized (no leading zeros, no trailing decimal zeros)

```csharp
var canonical = AshService.AshCanonicalizeJson(@"{""z"":1,""a"":2}");
// Result: {"a":2,"z":1}
```

#### `AshCanonicalizeUrlEncoded`

Canonicalizes URL-encoded data.

```csharp
public static string AshCanonicalizeUrlEncoded(string data)
```

```csharp
var canonical = AshService.AshCanonicalizeUrlEncoded("z=1&a=2");
// Result: a=2&z=1
```

#### `AshBuildProof`

Builds a cryptographic proof.

```csharp
public static string AshBuildProof(
    AshMode mode,
    string binding,
    string contextId,
    string? nonce,
    string canonicalPayload)
```

#### `AshVerifyProof`

Verifies two proofs using constant-time comparison.

```csharp
public static bool AshVerifyProof(string expected, string actual)
```

#### `AshNormalizeBinding`

Normalizes a binding string to canonical form.

```csharp
public static string AshNormalizeBinding(string method, string path)
```

```csharp
var binding = AshService.AshNormalizeBinding("post", "/api//test/");
// Result: "POST /api/test"
```

#### `AshTimingSafeEqual`

Constant-time string comparison to prevent timing attacks.

```csharp
public static bool AshTimingSafeEqual(string a, string b)
```

## Security Modes

```csharp
public enum AshMode
{
    Minimal,   // Basic integrity checking
    Balanced,  // Recommended for most applications
    Strict     // Maximum security with nonce requirement
}
```

| Mode | Description |
|------|-------------|
| `Minimal` | Basic integrity checking |
| `Balanced` | Recommended for most applications |
| `Strict` | Maximum security with server nonce |

## Input Validation (v2.3.4)

All SDKs now implement consistent input validation in `Proof.AshDeriveClientSecret()`. Invalid inputs throw `ValidationException`.

### Validation Rules

| Parameter | Rule | Code |
|-----------|------|------|
| `nonce` | Minimum 32 hex characters | SEC-014 |
| `nonce` | Maximum 128 characters | SEC-NONCE-001 |
| `nonce` | Hexadecimal only (0-9, a-f, A-F) | BUG-004 |
| `contextId` | Cannot be empty | BUG-041 |
| `contextId` | Maximum 256 characters | SEC-CTX-001 |
| `contextId` | Alphanumeric, underscore, hyphen, dot only | SEC-CTX-001 |
| `binding` | Maximum 8192 bytes | SEC-AUDIT-004 |

### Example

```csharp
using Ash.Core;
using Ash.Core.Exceptions;

try
{
    var secret = Proof.AshDeriveClientSecret(nonce, contextId, binding);
}
catch (ValidationException ex)
{
    Console.WriteLine($"Validation failed: {ex.Message}");
    Console.WriteLine($"Error code: {ex.Code}");  // ASH_VALIDATION_ERROR
}
```

### Validation Constants

```csharp
public const int MinNonceHexChars = 32;    // Minimum nonce length
public const int MaxNonceLength = 128;     // Maximum nonce length
public const int MaxContextIdLength = 256; // Maximum context ID length
public const int MaxBindingLength = 8192;  // Maximum binding length (8KB)
```

## Error Codes (v2.3.4 - Unique HTTP Status Codes)

ASH uses unique HTTP status codes in the 450-499 range for precise error identification.

```csharp
public static class AshErrorCode
{
    // Context errors (450-459)
    public const string CtxNotFound = "ASH_CTX_NOT_FOUND";       // HTTP 450
    public const string CtxExpired = "ASH_CTX_EXPIRED";          // HTTP 451
    public const string CtxAlreadyUsed = "ASH_CTX_ALREADY_USED"; // HTTP 452

    // Seal/Proof errors (460-469)
    public const string ProofInvalid = "ASH_PROOF_INVALID";      // HTTP 460

    // Binding errors (461)
    public const string BindingMismatch = "ASH_BINDING_MISMATCH"; // HTTP 461
    public const string ScopeMismatch = "ASH_SCOPE_MISMATCH";     // HTTP 473
    public const string ChainBroken = "ASH_CHAIN_BROKEN";         // HTTP 474

    // Format/Protocol errors (480-489)
    public const string TimestampInvalid = "ASH_TIMESTAMP_INVALID"; // HTTP 482
    public const string ProofMissing = "ASH_PROOF_MISSING";         // HTTP 483

    // Standard HTTP codes
    public const string CanonicalizationError = "ASH_CANONICALIZATION_ERROR"; // HTTP 422
    public const string ModeViolation = "ASH_MODE_VIOLATION";                 // HTTP 400
    public const string ValidationError = "ASH_VALIDATION_ERROR";             // HTTP 400
}
```

| Code | HTTP | Description |
|------|------|-------------|
| `CtxNotFound` | 450 | Context not found |
| `CtxExpired` | 451 | Context expired |
| `CtxAlreadyUsed` | 452 | Replay detected |
| `ProofInvalid` | 460 | Proof invalid |
| `BindingMismatch` | 461 | Binding mismatch |
| `ScopeMismatch` | 473 | Scope mismatch |
| `ChainBroken` | 474 | Chain broken |
| `TimestampInvalid` | 482 | Timestamp invalid |
| `ProofMissing` | 483 | Proof missing |

## Context Stores

### IContextStore Interface

```csharp
public interface IContextStore
{
    Task<AshContext> CreateAsync(
        string binding,
        long ttlMs,
        AshMode mode,
        Dictionary<string, object>? metadata);
    Task<AshContext?> GetAsync(string id);
    Task<bool> ConsumeAsync(string id);
    Task<int> CleanupAsync();
}
```

### MemoryStore

In-memory store for development and testing.

```csharp
var store = new MemoryStore();
```

### RedisStore

Production-ready store with atomic operations.

```csharp
var redis = ConnectionMultiplexer.Connect("localhost:6379");
var store = new RedisStore(redis.GetDatabase());
```

## Middleware

### AshMiddlewareOptions

```csharp
public class AshMiddlewareOptions
{
    // Paths to protect with ASH verification
    // Supports wildcards (e.g., "/api/*")
    public List<string> ProtectedPaths { get; set; }

    // Verify client IP matches context metadata (v2.3.4)
    public bool EnforceIp { get; set; }

    // Verify user ID matches context metadata (v2.3.4)
    public bool EnforceUser { get; set; }

    // Extract user ID from HttpContext (v2.3.4)
    public Func<HttpContext, string?>? UserIdExtractor { get; set; }
}
```

### Usage

```csharp
// Protect specific paths
app.UseAsh(ash, "/api/update", "/api/delete");

// Protect with wildcards
app.UseAsh(ash, "/api/*");

// With options
app.UseAsh(ash, new AshMiddlewareOptions
{
    ProtectedPaths = new List<string> { "/api/*", "/secure/*" }
});

// With IP and user binding enforcement (v2.3.4)
app.UseAsh(ash, new AshMiddlewareOptions
{
    ProtectedPaths = new List<string> { "/api/*" },
    EnforceIp = true,
    EnforceUser = true,
    UserIdExtractor = ctx => ctx.User.Identity?.Name
});
```

### IP and User Binding (v2.3.4)

Store client IP and user ID in context metadata, then enforce matching on verification:

```csharp
// Store client IP and user ID when creating context
app.MapPost("/ash/context", async (AshService ash, HttpContext ctx) =>
{
    var context = await ash.AshIssueContextAsync(
        binding: "POST /api/transfer",
        ttlMs: 30000,
        metadata: new Dictionary<string, object>
        {
            ["ip"] = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            ["user_id"] = ctx.User.Identity?.Name ?? "anonymous"
        }
    );

    return Results.Ok(new { contextId = context.Id });
});

// Verify binding in middleware
app.UseAsh(ash, new AshMiddlewareOptions
{
    ProtectedPaths = new List<string> { "/api/*" },
    EnforceIp = true,
    EnforceUser = true
});
```

If the IP or user doesn't match, the middleware returns HTTP 461 (`ASH_BINDING_MISMATCH`).

### Environment Configuration (v2.3.4)

The SDK supports environment-based configuration:

| Variable | Default | Description |
|----------|---------|-------------|
| `ASH_TRUST_PROXY` | `false` | Enable X-Forwarded-For handling |
| `ASH_TRUSTED_PROXIES` | (empty) | Comma-separated trusted proxy IPs |
| `ASH_RATE_LIMIT_WINDOW` | `60` | Rate limit window in seconds |
| `ASH_RATE_LIMIT_MAX` | `10` | Max contexts per window per IP |
| `ASH_TIMESTAMP_TOLERANCE` | `30` | Clock skew tolerance in seconds |

```csharp
// Load configuration from environment
var config = new AshConfig();

// Get client IP with proxy support
var clientIP = config.GetClientIP(
    Request.Headers["X-Forwarded-For"],
    Request.Headers["X-Real-IP"],
    Request.HttpContext.Connection.RemoteIpAddress?.ToString()
);
```

## Complete Example

```csharp
using Ash;
using Ash.Stores;
using Ash.Middleware;

var builder = WebApplication.CreateBuilder(args);

// Setup ASH
builder.Services.AddSingleton<IContextStore, MemoryStore>();
builder.Services.AddSingleton<AshService>(sp =>
    new AshService(sp.GetRequiredService<IContextStore>()));

var app = builder.Build();

var ash = app.Services.GetRequiredService<AshService>();

// Context issuance endpoint
app.MapPost("/ash/context", async (AshService ash) =>
{
    var ctx = await ash.AshIssueContextAsync(
        binding: "POST /api/update",
        ttlMs: 30000
    );

    return Results.Ok(new
    {
        contextId = ctx.Id,
        expiresAt = ctx.ExpiresAt,
        mode = ctx.Mode.ToModeString()
    });
});

// Protected endpoint with middleware
app.UseAsh(ash, "/api/*");

app.MapPost("/api/update", (HttpContext ctx) =>
{
    // Request verified - safe to process
    return Results.Ok(new { status = "updated" });
});

app.Run();
```

## Client Usage

For .NET clients making requests to ASH-protected endpoints:

```csharp
using System.Net.Http;
using Ash;

var client = new HttpClient();

// 1. Get context from server
var contextResponse = await client.PostAsync("https://api.example.com/ash/context", null);
var context = await contextResponse.Content.ReadFromJsonAsync<ContextResponse>();

// 2. Prepare payload
var payload = @"{""name"":""John"",""action"":""update""}";
var canonical = AshService.AshCanonicalizeJson(payload);

// 3. Build proof
var proof = AshService.AshBuildProof(
    mode: AshMode.Balanced,
    binding: "POST /api/update",
    contextId: context.ContextId,
    nonce: context.Nonce,
    canonicalPayload: canonical
);

// 4. Make protected request
var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/update");
request.Headers.Add("X-ASH-Context-ID", context.ContextId);
request.Headers.Add("X-ASH-Proof", proof);
request.Content = new StringContent(payload, Encoding.UTF8, "application/json");

var response = await client.SendAsync(request);
```

## License

**ASH Source-Available License (ASAL-1.0)**

See the [LICENSE](https://github.com/3maem/ash/blob/main/LICENSE) for full terms.

## Links

- [Main Repository](https://github.com/3maem/ash)
- [NuGet Package](https://www.nuget.org/packages/Ash.Core)
