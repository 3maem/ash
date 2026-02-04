# ASH ASP.NET Core Integration Example

This example demonstrates how to integrate ASH with ASP.NET Core for request integrity verification.

## Quick Start

```bash
# Create and run
dotnet new webapi -n AshExample
cd AshExample
dotnet add package Ash.Core
dotnet run
```

## Setup

### 1. Register Services

```csharp
// Program.cs
builder.Services.AddSingleton<IAshContextStore, AshMemoryStore>();
builder.Services.AddSingleton(new AshMiddlewareOptions
{
    ProtectedPaths = new[] { "/api/transfer", "/api/payment" },
    Mode = "balanced",
    TimestampToleranceMs = 30000
});
```

### 2. Add Middleware

```csharp
app.UseAshVerification();
```

### 3. Create Context Endpoint

```csharp
[HttpPost("context")]
public async Task<IActionResult> IssueContext([FromBody] ContextRequest request)
{
    var context = await AshContext.Create(_store, new CreateContextOptions
    {
        Binding = binding,
        TtlMs = 30000,
        IssueNonce = true
    });

    return Ok(new { contextId = context.ContextId, ... });
}
```

## Client Usage (C#)

```csharp
using Ash.Core;

// 1. Get context
var contextResponse = await httpClient.PostAsJsonAsync("/api/context", new { endpoint = "/api/transfer" });
var context = await contextResponse.Content.ReadFromJsonAsync<ContextResponse>();

// 2. Build proof
var payload = new { fromAccount = "ACC_001", toAccount = "ACC_002", amount = 100 };
var canonicalPayload = AshCanonicalizeJson(payload);
var bodyHash = AshHashBody(canonicalPayload);
var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
var proof = AshBuildProofV21(context.ClientSecret, timestamp, binding, bodyHash);

// 3. Make request
httpClient.DefaultRequestHeaders.Add("X-ASH-Context-ID", context.ContextId);
httpClient.DefaultRequestHeaders.Add("X-ASH-Timestamp", timestamp);
httpClient.DefaultRequestHeaders.Add("X-ASH-Proof", proof);

var response = await httpClient.PostAsJsonAsync("/api/transfer", payload);
```

## Production Considerations

1. **Use Redis Store**: Configure `AshRedisStore` with connection string
2. **Configure HTTPS**: Enable HTTPS redirection
3. **Add Rate Limiting**: Use `Microsoft.AspNetCore.RateLimiting`
4. **Enable Logging**: Add structured logging for audit trails

## Error Handling

ASH errors return 403 Forbidden:
```json
{
  "error": "Request verification failed",
  "code": "ASH_PROOF_MISMATCH"
}
```
