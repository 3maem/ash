using System.Text;
using System.Text.Json;
using Ash.Core.Config;
using Microsoft.AspNetCore.Http;

namespace Ash.Middleware;

/// <summary>
/// ASP.NET Core middleware for ASH verification.
///
/// Supports ASH v2.3 unified proof features:
/// - Context scoping (selective field protection)
/// - Request chaining (workflow integrity)
/// - Server-side scope policies (ENH-003)
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
        var scopeHeader = context.Request.Headers["X-ASH-Scope"].FirstOrDefault() ?? "";
        var scopeHash = context.Request.Headers["X-ASH-Scope-Hash"].FirstOrDefault() ?? "";
        var chainHash = context.Request.Headers["X-ASH-Chain-Hash"].FirstOrDefault() ?? "";

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

        // Normalize binding with query string
        var queryString = context.Request.QueryString.Value?.TrimStart('?') ?? "";
        var binding = AshService.AshNormalizeBinding(context.Request.Method, path, queryString);

        // ENH-003: Check server-side scope policy
        var policyScope = ScopePolicies.Get(binding);
        var hasPolicyScope = policyScope.Length > 0;

        // Parse client scope fields
        var clientScope = string.IsNullOrEmpty(scopeHeader)
            ? Array.Empty<string>()
            : scopeHeader.Split(',').Select(s => s.Trim()).Where(s => !string.IsNullOrEmpty(s)).ToArray();

        // Determine effective scope
        var scope = clientScope;

        // ENH-003: Server-side scope policy enforcement
        if (hasPolicyScope)
        {
            // If server has a policy, client MUST use it
            if (clientScope.Length == 0)
            {
                await WriteError(context, "SCOPE_POLICY_REQUIRED",
                    $"This endpoint requires scope headers per server policy. Required scope: {string.Join(", ", policyScope)}", 403);
                return;
            }

            // Verify client scope matches server policy
            var sortedClient = clientScope.OrderBy(s => s).ToArray();
            var sortedPolicy = policyScope.OrderBy(s => s).ToArray();

            if (!sortedClient.SequenceEqual(sortedPolicy))
            {
                await WriteError(context, "SCOPE_POLICY_VIOLATION",
                    $"Request scope does not match server policy. Expected: {string.Join(", ", policyScope)}, Received: {string.Join(", ", clientScope)}", 403);
                return;
            }

            scope = policyScope;
        }

        // Get payload
        context.Request.EnableBuffering();
        using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
        var payload = await reader.ReadToEndAsync();
        context.Request.Body.Position = 0;

        var contentType = context.Request.ContentType ?? "";

        // Verify with v2.3 options
        var options = new Dictionary<string, object>
        {
            { "scope", scope },
            { "scopeHash", scopeHash },
            { "chainHash", chainHash }
        };

        var result = await _ash.AshVerifyAsync(contextId, proof, binding, payload, contentType, options);

        if (!result.Valid)
        {
            var errorCode = result.ErrorCode?.ToErrorString() ?? "VERIFICATION_FAILED";

            // Map specific v2.3 errors
            if (scope.Length > 0 && !string.IsNullOrEmpty(scopeHash))
            {
                if (errorCode == "INTEGRITY_FAILED")
                    errorCode = "ASH_SCOPE_MISMATCH";
            }
            if (!string.IsNullOrEmpty(chainHash))
            {
                if (errorCode == "INTEGRITY_FAILED")
                    errorCode = "ASH_CHAIN_BROKEN";
            }

            await WriteError(context, errorCode, result.ErrorMessage ?? "Verification failed", 403);
            return;
        }

        // Store metadata in HttpContext.Items
        context.Items["AshMetadata"] = result.Metadata;
        context.Items["AshScope"] = scope;
        context.Items["AshScopePolicy"] = policyScope;
        context.Items["AshChainHash"] = chainHash;

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
