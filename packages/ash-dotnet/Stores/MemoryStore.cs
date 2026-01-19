using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Ash.Stores;

/// <summary>
/// In-memory implementation of IContextStore.
///
/// Suitable for development and single-instance deployments.
/// For production with multiple instances, use Redis store.
/// </summary>
public class MemoryStore : IContextStore
{
    private readonly ConcurrentDictionary<string, AshContext> _contexts = new();

    /// <summary>
    /// Create a new context.
    /// </summary>
    public Task<AshContext> CreateAsync(
        string binding,
        long ttlMs,
        AshMode mode,
        Dictionary<string, object>? metadata)
    {
        var id = GenerateContextId();
        var nonce = mode == AshMode.Strict ? GenerateNonce() : null;

        var context = new AshContext
        {
            Id = id,
            Binding = binding,
            ExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + ttlMs,
            Mode = mode,
            Used = false,
            Nonce = nonce,
            Metadata = metadata
        };

        _contexts[id] = context;
        return Task.FromResult(context);
    }

    /// <summary>
    /// Get a context by ID.
    /// </summary>
    public Task<AshContext?> GetAsync(string id)
    {
        if (!_contexts.TryGetValue(id, out var context))
        {
            return Task.FromResult<AshContext?>(null);
        }

        if (context.IsExpired())
        {
            _contexts.TryRemove(id, out _);
            return Task.FromResult<AshContext?>(null);
        }

        return Task.FromResult<AshContext?>(context);
    }

    /// <summary>
    /// Consume a context.
    /// </summary>
    public Task<bool> ConsumeAsync(string id)
    {
        if (!_contexts.TryGetValue(id, out var context))
        {
            return Task.FromResult(false);
        }

        if (context.Used || context.IsExpired())
        {
            return Task.FromResult(false);
        }

        context.Used = true;
        return Task.FromResult(true);
    }

    /// <summary>
    /// Clean up expired contexts.
    /// </summary>
    public Task<int> CleanupAsync()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var removed = 0;

        foreach (var kvp in _contexts)
        {
            if (now > kvp.Value.ExpiresAt)
            {
                if (_contexts.TryRemove(kvp.Key, out _))
                {
                    removed++;
                }
            }
        }

        return Task.FromResult(removed);
    }

    /// <summary>
    /// Get the number of active contexts.
    /// </summary>
    public int Count => _contexts.Count;

    /// <summary>
    /// Clear all contexts.
    /// </summary>
    public void Clear() => _contexts.Clear();

    private static string GenerateContextId()
    {
        var bytes = RandomNumberGenerator.GetBytes(16);
        return "ctx_" + Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string GenerateNonce()
    {
        var bytes = RandomNumberGenerator.GetBytes(16);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
