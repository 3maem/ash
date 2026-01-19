// ASH was developed by 3maem Co. | 12/31/2025
// v2.1.0: Added clientSecret for cryptographic proof binding

namespace Ash.Core;

/// <summary>
/// Context as stored on server (v2.1).
/// </summary>
public sealed class StoredContext
{
    /// <summary>
    /// Unique context identifier (CSPRNG).
    /// </summary>
    public required string ContextId { get; init; }

    /// <summary>
    /// Canonical binding: 'METHOD /path'.
    /// </summary>
    public required string Binding { get; init; }

    /// <summary>
    /// Security mode.
    /// </summary>
    public required AshMode Mode { get; init; }

    /// <summary>
    /// Timestamp when context was issued (ms epoch).
    /// </summary>
    public required long IssuedAt { get; init; }

    /// <summary>
    /// Timestamp when context expires (ms epoch).
    /// </summary>
    public required long ExpiresAt { get; init; }

    /// <summary>
    /// Server-side secret nonce (NEVER expose to client).
    /// </summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// v2.1: Derived client secret (safe to expose to client).
    /// </summary>
    public string? ClientSecret { get; init; }

    /// <summary>
    /// Optional device fingerprint hash.
    /// </summary>
    public string? Fingerprint { get; init; }

    /// <summary>
    /// Client IP address for binding.
    /// </summary>
    public string? IpAddress { get; init; }

    /// <summary>
    /// Optional user ID for binding.
    /// </summary>
    public long? UserId { get; init; }

    /// <summary>
    /// Timestamp when context was consumed (null if not consumed).
    /// </summary>
    public long? ConsumedAt { get; set; }

    /// <summary>
    /// Check if context has expired.
    /// </summary>
    public bool IsExpired => ExpiresAt < DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    /// <summary>
    /// Check if context has been consumed.
    /// </summary>
    public bool IsConsumed => ConsumedAt != null;

    /// <summary>
    /// Convert to client-safe dictionary (v2.1).
    /// SECURITY: nonce is NEVER included, only clientSecret.
    /// </summary>
    public Dictionary<string, object?> ToClientDictionary()
    {
        return new Dictionary<string, object?>
        {
            ["contextId"] = ContextId,
            ["binding"] = Binding,
            ["mode"] = Mode.ToString().ToLowerInvariant(),
            ["expiresAt"] = ExpiresAt,
            ["clientSecret"] = ClientSecret
        };
    }
}
