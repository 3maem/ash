namespace Ash;

/// <summary>
/// Interface for ASH context storage backends.
/// </summary>
public interface IContextStore
{
    /// <summary>
    /// Create a new context.
    /// </summary>
    /// <param name="binding">Endpoint binding</param>
    /// <param name="ttlMs">Time-to-live in milliseconds</param>
    /// <param name="mode">Security mode</param>
    /// <param name="metadata">Optional metadata</param>
    /// <returns>Created context</returns>
    Task<AshContext> CreateAsync(
        string binding,
        long ttlMs,
        AshMode mode,
        Dictionary<string, object>? metadata);

    /// <summary>
    /// Get a context by ID.
    /// </summary>
    /// <param name="id">Context ID</param>
    /// <returns>Context or null if not found/expired</returns>
    Task<AshContext?> GetAsync(string id);

    /// <summary>
    /// Consume a context (mark as used).
    /// </summary>
    /// <param name="id">Context ID</param>
    /// <returns>True if consumed, false if not found or already used</returns>
    Task<bool> ConsumeAsync(string id);

    /// <summary>
    /// Clean up expired contexts.
    /// </summary>
    /// <returns>Number of contexts removed</returns>
    Task<int> CleanupAsync();
}
