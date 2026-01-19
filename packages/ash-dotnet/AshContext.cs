using System.Text.Json.Serialization;

namespace Ash;

/// <summary>
/// ASH context representing a one-time use token.
/// </summary>
public class AshContext
{
    /// <summary>
    /// Unique context identifier.
    /// </summary>
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Endpoint binding (e.g., "POST /api/update").
    /// </summary>
    [JsonPropertyName("binding")]
    public string Binding { get; set; } = string.Empty;

    /// <summary>
    /// Expiration timestamp (Unix milliseconds).
    /// </summary>
    [JsonPropertyName("expiresAt")]
    public long ExpiresAt { get; set; }

    /// <summary>
    /// Security mode.
    /// </summary>
    [JsonPropertyName("mode")]
    public AshMode Mode { get; set; } = AshMode.Balanced;

    /// <summary>
    /// Whether context has been used.
    /// </summary>
    [JsonPropertyName("used")]
    public bool Used { get; set; }

    /// <summary>
    /// Server-generated nonce (strict mode only).
    /// </summary>
    [JsonPropertyName("nonce")]
    public string? Nonce { get; set; }

    /// <summary>
    /// Optional metadata.
    /// </summary>
    [JsonPropertyName("metadata")]
    public Dictionary<string, object>? Metadata { get; set; }

    /// <summary>
    /// Check if context has expired.
    /// </summary>
    public bool IsExpired() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() > ExpiresAt;
}
