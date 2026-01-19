using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace Ash.Middleware;

/// <summary>
/// ASP.NET Core middleware for ASH verification.
/// </summary>
public class AshMiddleware
{
    private readonly RequestDelegate _next;
    private readonly AshService _ash;
    private readonly AshMiddlewareOptions _options;

    /// <summary>
    /// Create a new ASH middleware.
    /// </summary>
    public AshMiddleware(
        RequestDelegate next,
        AshService ash,
        AshMiddlewareOptions options)
    {
        _next = next;
        _ash = ash;
        _options = options;
    }

    /// <summary>
    /// Process the request.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? "/";

        // Check if path should be protected
        var shouldVerify = _options.ProtectedPaths.Any(p =>
        {
            if (p.EndsWith("*"))
                return path.StartsWith(p.TrimEnd('*'));
            return path == p;
        });

        if (!shouldVerify)
        {
            await _next(context);
            return;
        }

        // Get headers
        var contextId = context.Request.Headers["X-ASH-Context-ID"].FirstOrDefault();
        var proof = context.Request.Headers["X-ASH-Proof"].FirstOrDefault();

        if (string.IsNullOrEmpty(contextId))
        {
            await WriteError(context, "MISSING_CONTEXT_ID", "Missing X-ASH-Context-ID header", 403);
            return;
        }

        if (string.IsNullOrEmpty(proof))
        {
            await WriteError(context, "MISSING_PROOF", "Missing X-ASH-Proof header", 403);
            return;
        }

        // Normalize binding
        var binding = AshService.AshNormalizeBinding(context.Request.Method, path);

        // Get payload
        context.Request.EnableBuffering();
        using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
        var payload = await reader.ReadToEndAsync();
        context.Request.Body.Position = 0;

        var contentType = context.Request.ContentType ?? "";

        // Verify
        var result = await _ash.AshVerifyAsync(contextId, proof, binding, payload, contentType);

        if (!result.Valid)
        {
            await WriteError(
                context,
                result.ErrorCode?.ToErrorString() ?? "VERIFICATION_FAILED",
                result.ErrorMessage ?? "Verification failed",
                403);
            return;
        }

        // Store metadata in HttpContext.Items
        context.Items["AshMetadata"] = result.Metadata;

        await _next(context);
    }

    private static async Task WriteError(HttpContext context, string code, string message, int status)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json";

        var response = new { error = code, message };
        await context.Response.WriteAsync(JsonSerializer.Serialize(response));
    }
}

/// <summary>
/// Options for ASH middleware.
/// </summary>
public class AshMiddlewareOptions
{
    /// <summary>
    /// Paths to protect with ASH verification.
    /// Supports wildcards (e.g., "/api/*").
    /// </summary>
    public List<string> ProtectedPaths { get; set; } = new();
}

/// <summary>
/// Extension methods for ASH middleware registration.
/// </summary>
public static class AshMiddlewareExtensions
{
    /// <summary>
    /// Add ASH middleware to the pipeline.
    /// </summary>
    public static IApplicationBuilder UseAsh(
        this IApplicationBuilder builder,
        AshService ash,
        AshMiddlewareOptions options)
    {
        return builder.UseMiddleware<AshMiddleware>(ash, options);
    }

    /// <summary>
    /// Add ASH middleware with protected paths.
    /// </summary>
    public static IApplicationBuilder UseAsh(
        this IApplicationBuilder builder,
        AshService ash,
        params string[] protectedPaths)
    {
        var options = new AshMiddlewareOptions
        {
            ProtectedPaths = protectedPaths.ToList()
        };
        return builder.UseMiddleware<AshMiddleware>(ash, options);
    }
}

/// <summary>
/// Marker interface for IApplicationBuilder.
/// </summary>
public interface IApplicationBuilder
{
    IApplicationBuilder UseMiddleware<T>(params object[] args);
}
