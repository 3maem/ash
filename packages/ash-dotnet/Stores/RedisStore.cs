using System.Security.Cryptography;
using System.Text.Json;
using StackExchange.Redis;

namespace Ash.Stores;

/// <summary>
/// Redis implementation of IContextStore.
///
/// Production-ready store for distributed deployments.
/// </summary>
public class RedisStore : IContextStore
{
    private readonly IDatabase _db;
    private readonly string _keyPrefix;

    /// <summary>
    /// Create a new Redis store.
    /// </summary>
    /// <param name="connection">Redis connection multiplexer</param>
    /// <param name="keyPrefix">Key prefix for context keys</param>
    /// <param name="database">Redis database index</param>
    public RedisStore(
        IConnectionMultiplexer connection,
        string keyPrefix = "ash:ctx:",
        int database = -1)
    {
        _db = connection.GetDatabase(database);
        _keyPrefix = keyPrefix;
    }

    private string Key(string id) => _keyPrefix + id;

    /// <summary>
    /// Create a new context.
    /// </summary>
    public async Task<AshContext> CreateAsync(
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

        var json = JsonSerializer.Serialize(context);
        var ttlSeconds = TimeSpan.FromMilliseconds(ttlMs + 1000);

        await _db.StringSetAsync(Key(id), json, ttlSeconds);

        return context;
    }

    /// <summary>
    /// Get a context by ID.
    /// </summary>
    public async Task<AshContext?> GetAsync(string id)
    {
        var json = await _db.StringGetAsync(Key(id));

        if (json.IsNullOrEmpty)
        {
            return null;
        }

        var context = JsonSerializer.Deserialize<AshContext>(json!);

        if (context == null || context.IsExpired())
        {
            await _db.KeyDeleteAsync(Key(id));
            return null;
        }

        return context;
    }

    /// <summary>
    /// Consume a context.
    /// </summary>
    public async Task<bool> ConsumeAsync(string id)
    {
        var context = await GetAsync(id);

        if (context == null || context.Used)
        {
            return false;
        }

        context.Used = true;

        var remainingMs = context.ExpiresAt - DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var remainingTtl = TimeSpan.FromMilliseconds(Math.Max(1000, remainingMs));

        var json = JsonSerializer.Serialize(context);
        await _db.StringSetAsync(Key(id), json, remainingTtl);

        return true;
    }

    /// <summary>
    /// Cleanup is handled by Redis TTL.
    /// </summary>
    public Task<int> CleanupAsync() => Task.FromResult(0);

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
