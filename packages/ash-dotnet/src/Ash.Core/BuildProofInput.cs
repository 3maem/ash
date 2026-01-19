// ASH was developed by 3maem Co. | 12/31/2025

namespace Ash.Core;

/// <summary>
/// Input for building a proof.
/// </summary>
public sealed class BuildProofInput
{
    /// <summary>
    /// ASH mode.
    /// </summary>
    public required AshMode Mode { get; init; }

    /// <summary>
    /// Canonical binding: 'METHOD /path'.
    /// </summary>
    public required string Binding { get; init; }

    /// <summary>
    /// Server-issued context ID.
    /// </summary>
    public required string ContextId { get; init; }

    /// <summary>
    /// Canonicalized payload string.
    /// </summary>
    public required string CanonicalPayload { get; init; }

    /// <summary>
    /// Optional server-issued nonce.
    /// </summary>
    public string? Nonce { get; init; }
}
