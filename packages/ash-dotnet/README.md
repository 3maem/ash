# ASH Protocol - .NET SDK

**Developed by 3maem Co. | شركة عمائم**

ASH (Authenticated Secure Hash) is a deterministic integrity verification protocol for web requests. This SDK provides request integrity protection, anti-replay mechanisms, and ASP.NET Core middleware for .NET applications.

## Installation

```bash
dotnet add package Ash.Security
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

Canonicalizes JSON to deterministic form.

```csharp
public static string AshCanonicalizeJson(string json)
```

**Rules:**
- Object keys sorted lexicographically
- No whitespace
- Unicode NFC normalized

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

## Error Codes

```csharp
public enum AshErrorCode
{
    InvalidContext,         // Invalid or missing context
    ContextExpired,         // Context has expired
    ReplayDetected,         // Replay attack detected
    IntegrityFailed,        // Proof verification failed
    EndpointMismatch,       // Binding mismatch
    CanonicalizationFailed  // Failed to canonicalize payload
}
```

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

MIT License

## Links

- [Main Repository](https://github.com/3maem/ash)
- [ASH Protocol Specification](https://github.com/3maem/ash/blob/main/SPEC.md)
- [NuGet Package](https://www.nuget.org/packages/Ash.Security)
