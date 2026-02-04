// ASH was developed by 3maem Co. | 12/31/2025

namespace Ash.Core.Config;

/// <summary>
/// ASH SDK configuration loaded from environment variables (v2.3.4).
/// </summary>
public static class AshConfig
{
    private static AshConfigData? _cachedConfig;

    /// <summary>
    /// Load configuration from environment variables.
    /// v2.3.4: Added support for proxy and rate limiting configuration.
    /// </summary>
    public static AshConfigData LoadConfig()
    {
        if (_cachedConfig != null)
        {
            return _cachedConfig;
        }

        _cachedConfig = new AshConfigData
        {
            TrustProxy = bool.TryParse(Environment.GetEnvironmentVariable("ASH_TRUST_PROXY"), out var trustProxy) && trustProxy,
            TrustedProxies = ParseProxyList(Environment.GetEnvironmentVariable("ASH_TRUSTED_PROXIES") ?? ""),
            RateLimitWindow = int.TryParse(Environment.GetEnvironmentVariable("ASH_RATE_LIMIT_WINDOW"), out var rateLimitWindow) ? rateLimitWindow : 60,
            RateLimitMax = int.TryParse(Environment.GetEnvironmentVariable("ASH_RATE_LIMIT_MAX"), out var rateLimitMax) ? rateLimitMax : 10,
            TimestampTolerance = int.TryParse(Environment.GetEnvironmentVariable("ASH_TIMESTAMP_TOLERANCE"), out var timestampTolerance) ? timestampTolerance : 30,
        };

        return _cachedConfig;
    }

    /// <summary>
    /// Reset the cached configuration (useful for testing).
    /// </summary>
    public static void ResetConfig()
    {
        _cachedConfig = null;
    }

    /// <summary>
    /// Parse comma-separated proxy list.
    /// </summary>
    private static string[] ParseProxyList(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Array.Empty<string>();
        }

        return value.Split(',')
            .Select(s => s.Trim())
            .Where(s => !string.IsNullOrEmpty(s))
            .ToArray();
    }

    /// <summary>
    /// Get client IP address with proxy support.
    /// v2.3.4: Added X-Forwarded-For handling for deployments behind proxies/CDNs.
    /// </summary>
    /// <param name="forwardedFor">X-Forwarded-For header value</param>
    /// <param name="realIP">X-Real-IP header value</param>
    /// <param name="remoteAddr">Direct remote address</param>
    /// <returns>Client IP address</returns>
    public static string GetClientIP(string? forwardedFor, string? realIP, string? remoteAddr)
    {
        var config = LoadConfig();

        // If not trusting proxies, use direct connection IP
        if (!config.TrustProxy)
        {
            return remoteAddr ?? "unknown";
        }

        // Check for X-Forwarded-For header
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            var ips = forwardedFor.Split(',');
            var clientIP = ips[0].Trim();
            if (IsValidIP(clientIP))
            {
                return clientIP;
            }
        }

        // Check for X-Real-IP header
        if (!string.IsNullOrEmpty(realIP))
        {
            if (IsValidIP(realIP.Trim()))
            {
                return realIP.Trim();
            }
        }

        // Fall back to direct connection IP
        return remoteAddr ?? "unknown";
    }

    /// <summary>
    /// Basic IP address validation.
    /// </summary>
    private static bool IsValidIP(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip))
        {
            return false;
        }

        // Check for IPv4 or IPv6 format
        return System.Net.IPAddress.TryParse(ip, out _);
    }
}

/// <summary>
/// ASH configuration data.
/// </summary>
public class AshConfigData
{
    /// <summary>
    /// Whether to trust X-Forwarded-For headers.
    /// </summary>
    public bool TrustProxy { get; set; }

    /// <summary>
    /// List of trusted proxy IP addresses.
    /// </summary>
    public string[] TrustedProxies { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Rate limit window in seconds.
    /// </summary>
    public int RateLimitWindow { get; set; }

    /// <summary>
    /// Maximum contexts per rate limit window.
    /// </summary>
    public int RateLimitMax { get; set; }

    /// <summary>
    /// Timestamp tolerance in seconds.
    /// </summary>
    public int TimestampTolerance { get; set; }
}
