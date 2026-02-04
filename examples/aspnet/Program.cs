/**
 * ASH Integration Example: ASP.NET Core Server
 *
 * This example demonstrates how to integrate ASH with ASP.NET Core
 * for request integrity verification and anti-replay protection.
 */

using Ash.Core;
using Ash.Core.Stores;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// Register ASH store (use Redis in production)
builder.Services.AddSingleton<IAshContextStore, AshMemoryStore>();

// Register ASH middleware options
builder.Services.AddSingleton(new AshMiddlewareOptions
{
    ProtectedPaths = new[] { "/api/transfer", "/api/payment" },
    Mode = "balanced",
    TimestampToleranceMs = 30000
});

var app = builder.Build();

// Apply ASH middleware
app.UseAshVerification();

app.MapControllers();

app.MapGet("/health", () => new { status = "ok", timestamp = DateTime.UtcNow });

app.Run();

// Controllers
[ApiController]
[Route("api")]
public class AshController : ControllerBase
{
    private readonly IAshContextStore _store;

    public AshController(IAshContextStore store)
    {
        _store = store;
    }

    [HttpPost("context")]
    public async Task<IActionResult> IssueContext([FromBody] ContextRequest request)
    {
        var binding = AshNormalizeBinding("POST", request.Endpoint, "");

        var context = await AshContext.Create(_store, new CreateContextOptions
        {
            Binding = binding,
            TtlMs = request.TtlMs ?? 30000,
            Mode = "balanced",
            IssueNonce = true
        });

        var clientSecret = AshDeriveClientSecret(context.Nonce, context.ContextId, binding);

        return Ok(new
        {
            contextId = context.ContextId,
            clientSecret = clientSecret,
            expiresAt = context.ExpiresAt
        });
    }

    [HttpPost("transfer")]
    public IActionResult Transfer([FromBody] TransferRequest request)
    {
        // If we reach here, ASH verification passed
        Console.WriteLine($"Transfer: {request.Amount} from {request.FromAccount} to {request.ToAccount}");

        return Ok(new
        {
            success = true,
            message = "Transfer completed",
            transactionId = $"TXN_{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}"
        });
    }

    [HttpPost("payment")]
    public IActionResult Payment([FromBody] PaymentRequest request)
    {
        Console.WriteLine($"Payment: {request.Amount} {request.Currency} to merchant {request.MerchantId}");

        return Ok(new
        {
            success = true,
            paymentId = $"PAY_{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}"
        });
    }
}

// Request models
public record ContextRequest(string Endpoint, int? TtlMs);
public record TransferRequest(string FromAccount, string ToAccount, decimal Amount);
public record PaymentRequest(string MerchantId, decimal Amount, string Currency = "USD");
