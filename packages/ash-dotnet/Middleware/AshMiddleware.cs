using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Ash.Core;
using Ash.Core.Config;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;

namespace Ash.Middleware;

/// <summary>
/// ASP.NET Core middleware for ASH verification.
///
/// Supports ASH v2.3 unified proof features:
/// - Context scoping (selective field protection)
/// - Request chaining (workflow integrity)
/// - Server-side scope policies (ENH-003)
/// - IP binding with X-Forwarded-For support (v2.3.4)
/// - User binding (v2.3.4)
/// - Timestamp validation
/// </summary>
public class AshMiddleware
{
    private readonly RequestDelegate _next;
    private readonly AshService _ash;
    private readonly AshMiddlewareOptions _options;
    private readonly IHostEnvironment _hostingEnvironment;

    // Validation constants
    private const int MaxContextIdLength = 256;
    private static readonly Regex ContextIdRegex = new Regex(@"^[a-zA-Z0-9_.-]+$", RegexOptions.Compiled);
    private static readonly Regex ProofRegex = new Regex(@"^[a-fA-F0-9]{64}$", RegexOptions.Compiled);

    /// <summary>
    /// Create a new ASH middleware.
    /// </summary>
    public AshMiddleware(
        RequestDelegate next,
        AshService ash,
        AshMiddlewareOptions options,
        IHostEnvironment hostingEnvironment)
    {
        _next = next;
        _ash = ash;
        _options = options;
        _hostingEnvironment = hostingEnvironment;
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
        var timestampHeader = context.Request.Headers["X-ASH-Timestamp"].FirstOrDefault();

        // Validate context_id format and length
        if (string.IsNullOrEmpty(contextId))
        {
            await WriteError(context, "ASH_CTX_NOT_FOUND", "Missing X-ASH-Context-ID header", 450);
            return;
        }

        if (contextId.Length > MaxContextIdLength)
        {
            await WriteError(context, "ASH_CTX_INVALID", "Context ID exceeds maximum length of 256 characters", 400);
            return;
        }

        if (!ContextIdRegex.IsMatch(contextId))
        {
            await WriteError(context, "ASH_CTX_INVALID", "Context ID contains invalid characters. Only alphanumeric, underscore, hyphen, and dot are allowed", 400);
            return;
        }

        // Validate proof format (exactly 64 hex chars)
        if (string.IsNullOrEmpty(proof))
        {
            await WriteError(context, "ASH_PROOF_MISSING", "Missing X-ASH-Proof header", 483);
            return;
        }

        if (!ProofRegex.IsMatch(proof))
        {
            await WriteError(context, "ASH_PROOF_INVALID", "Proof must be exactly 64 hexadecimal characters", 400);
            return;
        }

        // Validate timestamp if present or required
        if (!string.IsNullOrEmpty(timestampHeader))
        {
            if (!long.TryParse(timestampHeader, out var timestamp))
            {
                await WriteError(context, "ASH_TIMESTAMP_INVALID", "Invalid timestamp format", 400);
                return;
            }

            var currentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var age = currentTime - timestamp;

            if (age < 0)
            {
                await WriteError(context, "ASH_TIMESTAMP_FUTURE", "Timestamp is in the future", 400);
                return;
            }

            if (age > _options.MaxTimestampAgeSeconds)
            {
                await WriteError(context, "ASH_TIMESTAMP_EXPIRED", "Timestamp is too old", 400);
                return;
            }
        }
        else if (_options.MaxTimestampAgeSeconds > 0)
        {
            // Timestamp is required but not provided
            await WriteError(context, "ASH_TIMESTAMP_MISSING", "Missing X-ASH-Timestamp header", 400);
            return;
        }

        // Check EnableUnified option - reject scope/chain headers when disabled
        if (!_options.EnableUnified)
        {
            if (!string.IsNullOrEmpty(scopeHeader))
            {
                await WriteError(context, "ASH_UNIFIED_DISABLED", "Scope headers are not enabled", 400);
                return;
            }
            if (!string.IsNullOrEmpty(scopeHash))
            {
                await WriteError(context, "ASH_UNIFIED_DISABLED", "Scope hash is not enabled", 400);
                return;
            }
            if (!string.IsNullOrEmpty(chainHash))
            {
                await WriteError(context, "ASH_UNIFIED_DISABLED", "Chain hash is not enabled", 400);
                return;
            }
        }

        // Normalize binding with query string
        var queryString = context.Request.QueryString.Value?.TrimStart('?') ?? "";
        var binding = AshService.AshNormalizeBinding(context.Request.Method, path, queryString);

        // ENH-003: Check server-side scope policy
        var policyScope = ScopePolicies.AshGet(binding);
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
                await WriteError(context, "ASH_SCOPE_POLICY_REQUIRED",
                    "This endpoint requires scope headers per server policy", 400);
                return;
            }

            // Verify client scope matches server policy using byte-wise comparison
            var sortedClient = clientScope.OrderBy(s => s, ByteWiseComparer.Instance).ToArray();
            var sortedPolicy = policyScope.OrderBy(s => s, ByteWiseComparer.Instance).ToArray();

            if (!sortedClient.SequenceEqual(sortedPolicy))
            {
                await WriteError(context, "ASH_SCOPE_POLICY_VIOLATION",
                    "Request scope does not match server policy", 475);
                return;
            }

            scope = policyScope;
        }

        // Validate scope hash if provided
        if (!string.IsNullOrEmpty(scopeHash))
        {
            var computedHash = ComputeScopeHash(scope);
            if (!computedHash.Equals(scopeHash, StringComparison.OrdinalIgnoreCase))
            {
                await WriteError(context, "ASH_SCOPE_HASH_MISMATCH",
                    "Provided scope hash does not match computed hash", 400);
                return;
            }
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
            var errorCode = result.ErrorCode ?? "VERIFICATION_FAILED";

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

            // Get appropriate HTTP status code
            var httpStatus = AshErrorCode.GetHttpStatus(errorCode);

            await WriteError(context, errorCode, result.ErrorMessage ?? "Verification failed", httpStatus);
            return;
        }

        // v2.3.4: Verify IP binding if requested
        if (_options.EnforceIp)
        {
            var clientIP = AshConfig.GetClientIP(
                context.Request.Headers["X-Forwarded-For"].FirstOrDefault(),
                context.Request.Headers["X-Real-IP"].FirstOrDefault(),
                context.Connection.RemoteIpAddress?.ToString()
            );

            if (result.Metadata?.TryGetValue("ip", out var contextIPObj) == true && contextIPObj is string contextIP)
            {
                if (!string.IsNullOrEmpty(contextIP) && contextIP != clientIP)
                {
                    await WriteError(context, "ASH_BINDING_MISMATCH", "IP address mismatch", 461);
                    return;
                }
            }
        }

        // v2.3.4: Verify user binding if requested
        if (_options.EnforceUser)
        {
            string? currentUserId = null;

            if (_options.UserIdExtractor != null)
            {
                currentUserId = _options.UserIdExtractor(context);
            }
            else if (context.Items.TryGetValue("user_id", out var userIdObj) && userIdObj is string userIdStr)
            {
                currentUserId = userIdStr;
            }

            if (result.Metadata?.TryGetValue("user_id", out var contextUserIdObj) == true)
            {
                var contextUserId = contextUserIdObj?.ToString();
                if (!string.IsNullOrEmpty(contextUserId) && currentUserId != contextUserId)
                {
                    await WriteError(context, "ASH_BINDING_MISMATCH", "User mismatch", 461);
                    return;
                }
            }
        }

        // Store metadata in HttpContext.Items
        context.Items["AshMetadata"] = result.Metadata;
        context.Items["AshScope"] = scope;
        context.Items["AshScopePolicy"] = policyScope;
        context.Items["AshChainHash"] = chainHash;
        context.Items["AshClientIP"] = AshConfig.GetClientIP(
            context.Request.Headers["X-Forwarded-For"].FirstOrDefault(),
            context.Request.Headers["X-Real-IP"].FirstOrDefault(),
            context.Connection.RemoteIpAddress?.ToString()
        );

        await _next(context);
    }

    /// <summary>
    /// Compute SHA-256 hash of scope fields (sorted byte-wise).
    /// </summary>
    private static string ComputeScopeHash(string[] scope)
    {
        if (scope.Length == 0)
            return "";

        // Sort using byte-wise comparison (like Buffer.compare in JavaScript)
        var sorted = scope.OrderBy(s => s, ByteWiseComparer.Instance).ToArray();
        var combined = string.Join(",", sorted);
        var bytes = Encoding.UTF8.GetBytes(combined);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private async Task WriteError(HttpContext context, string code, string message, int status)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json";

        // In production, return generic error messages for security
        var responseMessage = _hostingEnvironment.IsProduction()
            ? GetGenericErrorMessage(code)
            : message;

        var response = new { error = code, message = responseMessage };
        await context.Response.WriteAsync(JsonSerializer.Serialize(response));
    }

    /// <summary>
    /// Get a generic error message for production environments.
    /// </summary>
    private static string GetGenericErrorMessage(string code)
    {
        return code switch
        {
            "ASH_CTX_NOT_FOUND" => "Invalid request",
            "ASH_CTX_INVALID" => "Invalid request",
            "ASH_PROOF_MISSING" => "Invalid request",
            "ASH_PROOF_INVALID" => "Invalid request",
            "ASH_TIMESTAMP_MISSING" => "Invalid request",
            "ASH_TIMESTAMP_INVALID" => "Invalid request",
            "ASH_TIMESTAMP_EXPIRED" => "Invalid request",
            "ASH_TIMESTAMP_FUTURE" => "Invalid request",
            "ASH_UNIFIED_DISABLED" => "Invalid request",
            "ASH_SCOPE_POLICY_REQUIRED" => "Invalid request",
            "ASH_SCOPE_POLICY_VIOLATION" => "Invalid request",
            "ASH_SCOPE_HASH_MISMATCH" => "Invalid request",
            "ASH_SCOPE_MISMATCH" => "Verification failed",
            "ASH_CHAIN_BROKEN" => "Verification failed",
            "ASH_BINDING_MISMATCH" => "Verification failed",
            "VERIFICATION_FAILED" => "Verification failed",
            _ => "An error occurred"
        };
    }
}

/// <summary>
/// Byte-wise string comparer that mimics JavaScript's Buffer.compare().
/// Compares strings by their UTF-8 byte representation.
/// </summary>
public sealed class ByteWiseComparer : IComparer<string>
{
    public static ByteWiseComparer Instance { get; } = new();

    public int Compare(string? x, string? y)
    {
        if (x == null && y == null) return 0;
        if (x == null) return -1;
        if (y == null) return 1;

        var xBytes = Encoding.UTF8.GetBytes(x);
        var yBytes = Encoding.UTF8.GetBytes(y);

        var minLength = Math.Min(xBytes.Length, yBytes.Length);
        for (var i = 0; i < minLength; i++)
        {
            var cmp = xBytes[i].CompareTo(yBytes[i]);
            if (cmp != 0) return cmp;
        }

        return xBytes.Length.CompareTo(yBytes.Length);
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

    /// <summary>
    /// Enable unified proof features (scoping and chaining).
    /// When false, scope/chain headers will be rejected.
    /// </summary>
    public bool EnableUnified { get; set; } = true;

    /// <summary>
    /// Maximum age of timestamp in seconds.
    /// Set to 0 to disable timestamp validation.
    /// </summary>
    public long MaxTimestampAgeSeconds { get; set; } = 0;

    /// <summary>
    /// Enforce IP address binding (v2.3.4).
    /// Verifies that the request IP matches the context IP.
    /// </summary>
    public bool EnforceIp { get; set; }

    /// <summary>
    /// Enforce user binding (v2.3.4).
    /// Verifies that the authenticated user matches the context user_id.
    /// </summary>
    public bool EnforceUser { get; set; }

    /// <summary>
    /// Custom user ID extractor for user binding (v2.3.4).
    /// If null, looks for "user_id" in HttpContext.Items.
    /// </summary>
    public Func<HttpContext, string?>? UserIdExtractor { get; set; }
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
