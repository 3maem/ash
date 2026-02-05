# ASH .NET SDK API Reference

**Version:** 2.3.4
**Package:** `Ash.Core`

## Installation

```bash
dotnet add package Ash.Core
```

## Requirements

- .NET 6.0, 7.0, or 8.0

---

## Namespaces

```csharp
using Ash;
using Ash.Core;
using Ash.Stores;
using Ash.Middleware;
```

---

## Enums

### AshMode

```csharp
public enum AshMode
{
    Minimal,   // Basic integrity checking
    Balanced,  // Recommended for most applications (default)
    Strict     // Maximum security with nonce requirement
}

public static class AshModeExtensions
{
    public static string ToModeString(this AshMode mode);
    public static AshMode FromString(string mode);
}
```

---

## Static Classes

### AshErrorCode

```csharp
public static class AshErrorCode
{
    public const string CtxNotFound = "ASH_CTX_NOT_FOUND";
    public const string CtxExpired = "ASH_CTX_EXPIRED";
    public const string CtxAlreadyUsed = "ASH_CTX_ALREADY_USED";
    public const string BindingMismatch = "ASH_BINDING_MISMATCH";
    public const string ProofMissing = "ASH_PROOF_MISSING";
    public const string ProofInvalid = "ASH_PROOF_INVALID";
    public const string CanonicalizationError = "ASH_CANONICALIZATION_ERROR";
    public const string ModeViolation = "ASH_MODE_VIOLATION";
    public const string UnsupportedContentType = "ASH_UNSUPPORTED_CONTENT_TYPE";
    public const string ScopeMismatch = "ASH_SCOPE_MISMATCH";
    public const string ChainBroken = "ASH_CHAIN_BROKEN";

    public static int GetHttpStatus(string code);
    public static string GetMessage(string code);
}
```

---

## Classes

### AshContext

```csharp
public class AshContext
{
    public string Id { get; }
    public string Binding { get; }
    public AshMode Mode { get; }
    public long IssuedAt { get; }      // Unix timestamp (ms)
    public long ExpiresAt { get; }     // Unix timestamp (ms)
    public string? Nonce { get; }
    public bool Used { get; }
    public Dictionary<string, object>? Metadata { get; }

    public bool IsExpired();
    public ContextPublicInfo ToPublicInfo();
}
```

### ContextPublicInfo

```csharp
public class ContextPublicInfo
{
    public string ContextId { get; set; }
    public long ExpiresAt { get; set; }
    public string Mode { get; set; }
    public string? Nonce { get; set; }
}
```

### AshVerifyResult

```csharp
public class AshVerifyResult
{
    public bool Valid { get; }
    public string? ErrorCode { get; }
    public string? ErrorMessage { get; }
    public Dictionary<string, object>? Metadata { get; }

    public static AshVerifyResult Success(Dictionary<string, object>? metadata = null);
    public static AshVerifyResult Failure(string code, string message);
}
```

### AshException

```csharp
public class AshException : Exception
{
    public string Code { get; }
    public int HttpStatus { get; }

    public AshException(string code, string message);
}
```

---

## AshService Class

### Constructor

```csharp
public class AshService
{
    public AshService(IContextStore store, AshMode defaultMode = AshMode.Balanced);
}
```

### Instance Methods

#### AshIssueContextAsync

```csharp
public async Task<AshContext> AshIssueContextAsync(
    string binding,
    long ttlMs,
    AshMode? mode = null,
    Dictionary<string, object>? metadata = null)
```

Issues a new context for a request.

**Example:**
```csharp
var ctx = await ash.AshIssueContextAsync(
    binding: "POST|/api/update|",
    ttlMs: 30000,
    mode: AshMode.Balanced
);
```

#### AshVerifyAsync

```csharp
public async Task<AshVerifyResult> AshVerifyAsync(
    string contextId,
    string proof,
    string binding,
    string payload,
    string contentType)
```

Verifies a request against its context and proof.

#### AshVerifyScopedAsync

```csharp
public async Task<AshVerifyResult> AshVerifyScopedAsync(
    string contextId,
    string proof,
    string binding,
    string payload,
    string contentType,
    string[] scope,
    string scopeHash)
```

Verifies a scoped request (v2.2+).

#### AshVerifyUnifiedAsync

```csharp
public async Task<AshVerifyResult> AshVerifyUnifiedAsync(
    string contextId,
    string proof,
    string binding,
    string payload,
    string contentType,
    string[] scope,
    string scopeHash,
    string? previousProof,
    string chainHash)
```

Verifies a unified request (v2.3+).

#### AshCanonicalize

```csharp
public string AshCanonicalize(string payload, string contentType)
```

Canonicalizes payload based on content type.

---

### Static Methods

#### AshCanonicalizeJson

```csharp
public static string AshCanonicalizeJson(string json)
```

Canonicalizes JSON to RFC 8785 form.

**Example:**
```csharp
var canonical = AshService.AshCanonicalizeJson(@"{""z"":1,""a"":2}");
// Result: {"a":2,"z":1}
```

#### AshCanonicalizeUrlEncoded

```csharp
public static string AshCanonicalizeUrlEncoded(string data)
```

Canonicalizes URL-encoded data.

**Example:**
```csharp
var canonical = AshService.AshCanonicalizeUrlEncoded("z=1&a=2");
// Result: a=2&z=1
```

#### AshNormalizeBinding

```csharp
public static string AshNormalizeBinding(string method, string path, string query = "")
```

Normalizes endpoint binding to `METHOD|PATH|QUERY` format.

**Example:**
```csharp
var binding = AshService.AshNormalizeBinding("post", "/api//users/", "z=1&a=2");
// Result: POST|/api/users|a=2&z=1
```

#### AshBuildProof

```csharp
public static string AshBuildProof(
    AshMode mode,
    string binding,
    string contextId,
    string? nonce,
    string canonicalPayload)
```

Builds a legacy v1 proof.

#### AshBuildProofV21

```csharp
public static string AshBuildProofV21(
    string clientSecret,
    string timestamp,
    string binding,
    string bodyHash)
```

Builds an HMAC-SHA256 proof (v2.1).

#### AshBuildProofV21Scoped

```csharp
public static string AshBuildProofV21Scoped(
    string clientSecret,
    string timestamp,
    string binding,
    string bodyHash,
    string scopeHash)
```

Builds a scoped proof (v2.2).

#### AshBuildProofV21Unified

```csharp
public static string AshBuildProofV21Unified(
    string clientSecret,
    string timestamp,
    string binding,
    string bodyHash,
    string scopeHash,
    string chainHash)
```

Builds a unified proof (v2.3).

#### AshVerifyProof

```csharp
public static bool AshVerifyProof(string expected, string actual)
```

Constant-time proof comparison.

#### AshTimingSafeEqual

```csharp
public static bool AshTimingSafeEqual(string a, string b)
```

Constant-time string comparison.

#### AshGenerateNonce

```csharp
public static string AshGenerateNonce(int bytes = 32)
```

Generates cryptographic nonce.

#### AshGenerateContextId

```csharp
public static string AshGenerateContextId()
```

Generates unique context ID.

#### AshDeriveClientSecret

```csharp
public static string AshDeriveClientSecret(string nonce, string contextId, string binding)
```

Derives client secret from nonce.

#### AshHashBody

```csharp
public static string AshHashBody(string body)
```

SHA-256 hash of body.

#### AshHashProof

```csharp
public static string AshHashProof(string proof)
```

Hash proof for chaining.

#### AshHashScopedBody

```csharp
public static string AshHashScopedBody(Dictionary<string, object> payload, string[] scope)
```

Hash scoped fields.

#### AshExtractScopedFields

```csharp
public static Dictionary<string, object> AshExtractScopedFields(
    Dictionary<string, object> payload,
    string[] scope)
```

Extract scoped fields from payload.

---

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

```csharp
public class MemoryStore : IContextStore
{
    public MemoryStore();
}
```

### RedisStore

```csharp
public class RedisStore : IContextStore
{
    public RedisStore(IDatabase redis, string prefix = "ash:ctx:");
}
```

**Example:**
```csharp
using StackExchange.Redis;

var redis = ConnectionMultiplexer.Connect("localhost:6379");
var store = new RedisStore(redis.GetDatabase());
```

---

## ASP.NET Core Middleware

### Extension Methods

```csharp
public static class AshMiddlewareExtensions
{
    public static IApplicationBuilder UseAsh(
        this IApplicationBuilder app,
        AshService ash,
        params string[] protectedPaths);

    public static IApplicationBuilder UseAsh(
        this IApplicationBuilder app,
        AshService ash,
        AshMiddlewareOptions options);
}
```

### AshMiddlewareOptions

```csharp
public class AshMiddlewareOptions
{
    public List<string> ProtectedPaths { get; set; }
    public Func<HttpContext, bool>? Skip { get; set; }
    public Func<HttpContext, AshException, Task>? OnError { get; set; }
}
```

### Usage

```csharp
var builder = WebApplication.CreateBuilder(args);

// Register services
builder.Services.AddSingleton<IContextStore, MemoryStore>();
builder.Services.AddSingleton<AshService>();

var app = builder.Build();

var ash = app.Services.GetRequiredService<AshService>();

// Apply middleware
app.UseAsh(ash, "/api/*");

// Or with options
app.UseAsh(ash, new AshMiddlewareOptions
{
    ProtectedPaths = new List<string> { "/api/*", "/secure/*" },
    Skip = ctx => ctx.Request.Headers.ContainsKey("X-Internal"),
    OnError = async (ctx, ex) =>
    {
        ctx.Response.StatusCode = ex.HttpStatus;
        await ctx.Response.WriteAsJsonAsync(new { error = ex.Code, message = ex.Message });
    }
});
```

---

## HTTP Headers

| Header | Description |
|--------|-------------|
| `X-ASH-Context-ID` | Context identifier |
| `X-ASH-Proof` | Cryptographic proof |
| `X-ASH-Mode` | Security mode |
| `X-ASH-Timestamp` | Request timestamp |
| `X-ASH-Scope` | Comma-separated scoped fields |
| `X-ASH-Scope-Hash` | Hash of scoped fields |
| `X-ASH-Chain-Hash` | Hash of previous proof |

---

## Complete Example

### Server Setup (ASP.NET Core)

```csharp
using Ash;
using Ash.Stores;
using Ash.Middleware;

var builder = WebApplication.CreateBuilder(args);

// Register ASH services
builder.Services.AddSingleton<IContextStore, MemoryStore>();
builder.Services.AddSingleton<AshService>();

var app = builder.Build();
var ash = app.Services.GetRequiredService<AshService>();

// Context issuance endpoint
app.MapPost("/ash/context", async (AshService ash) =>
{
    var ctx = await ash.AshIssueContextAsync(
        binding: "POST|/api/transfer|",
        ttlMs: 30000
    );

    return Results.Ok(new
    {
        contextId = ctx.Id,
        expiresAt = ctx.ExpiresAt,
        mode = ctx.Mode.ToModeString(),
        nonce = ctx.Nonce
    });
});

// Apply ASH middleware to protected routes
app.UseAsh(ash, "/api/*");

// Protected endpoint
app.MapPost("/api/transfer", (HttpContext ctx) =>
{
    var ashContext = ctx.Items["AshContext"] as AshContext;
    return Results.Ok(new { status = "success", contextId = ashContext?.Id });
});

app.Run();
```

### Client Usage

```csharp
using System.Net.Http;
using System.Text;
using Ash;

var client = new HttpClient();

// 1. Get context
var ctxResponse = await client.PostAsync("https://api.example.com/ash/context", null);
var context = await ctxResponse.Content.ReadFromJsonAsync<ContextResponse>();

// 2. Prepare payload
var payload = @"{""amount"":100,""to"":""account123""}";
var canonical = AshService.AshCanonicalizeJson(payload);

// 3. Build proof
var clientSecret = AshService.AshDeriveClientSecret(
    context.Nonce,
    context.ContextId,
    "POST|/api/transfer|"
);
var bodyHash = AshService.AshHashBody(canonical);
var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();

var proof = AshService.AshBuildProofV21(clientSecret, timestamp, "POST|/api/transfer|", bodyHash);

// 4. Make protected request
var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/api/transfer");
request.Headers.Add("X-ASH-Context-ID", context.ContextId);
request.Headers.Add("X-ASH-Proof", proof);
request.Headers.Add("X-ASH-Timestamp", timestamp);
request.Content = new StringContent(payload, Encoding.UTF8, "application/json");

var response = await client.SendAsync(request);
```

---

## License

ASH Source-Available License (ASAL-1.0)

See [LICENSE](../LICENSE) for full terms.
