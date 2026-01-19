// ASH was developed by 3maem Co. | 12/31/2025

namespace Ash.Core;

/// <summary>
/// Public context info returned to client.
/// </summary>
public sealed class ContextPublicInfo
{
    /// <summary>
    /// Opaque context ID.
    /// </summary>
    public required string ContextId { get; init; }

    /// <summary>
    /// Expiration timestamp (ms epoch).
    /// </summary>
    public required long ExpiresAt { get; init; }

    /// <summary>
    /// Security mode.
    /// </summary>
    public required AshMode Mode { get; init; }

    /// <summary>
    /// Optional nonce (if server-assisted mode).
    /// </summary>
    public string? Nonce { get; init; }
}
