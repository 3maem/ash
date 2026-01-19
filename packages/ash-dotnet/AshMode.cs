namespace Ash;

/// <summary>
/// ASH security modes.
/// </summary>
public enum AshMode
{
    /// <summary>
    /// Minimal mode - basic integrity protection.
    /// Suitable for low-risk operations.
    /// </summary>
    Minimal,

    /// <summary>
    /// Balanced mode - recommended for most operations.
    /// Good balance of security and performance.
    /// </summary>
    Balanced,

    /// <summary>
    /// Strict mode - maximum security with server nonce.
    /// Recommended for sensitive operations.
    /// </summary>
    Strict
}

/// <summary>
/// Extension methods for AshMode.
/// </summary>
public static class AshModeExtensions
{
    /// <summary>
    /// Convert mode to string representation.
    /// </summary>
    public static string ToModeString(this AshMode mode) => mode switch
    {
        AshMode.Minimal => "minimal",
        AshMode.Balanced => "balanced",
        AshMode.Strict => "strict",
        _ => throw new ArgumentOutOfRangeException(nameof(mode))
    };

    /// <summary>
    /// Parse mode from string.
    /// </summary>
    public static AshMode ParseMode(string value) => value.ToLowerInvariant() switch
    {
        "minimal" => AshMode.Minimal,
        "balanced" => AshMode.Balanced,
        "strict" => AshMode.Strict,
        _ => throw new ArgumentException($"Invalid mode: {value}", nameof(value))
    };
}
