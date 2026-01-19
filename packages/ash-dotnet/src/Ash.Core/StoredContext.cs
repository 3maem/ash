// ASH was developed by 3maem Co. | 12/31/2025

namespace Ash.Core;

/// <summary>
/// Context as stored on server.
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
    /// Optional nonce for server-assisted mode.
    /// </summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// Timestamp when context was consumed (null if not consumed).
    /// </summary>
    public long? ConsumedAt { get; set; }
}
