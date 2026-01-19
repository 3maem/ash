namespace Ash;

/// <summary>
/// Result of ASH verification.
/// </summary>
public class AshVerifyResult
{
    /// <summary>
    /// Whether verification succeeded.
    /// </summary>
    public bool Valid { get; init; }

    /// <summary>
    /// Error code if verification failed.
    /// </summary>
    public AshErrorCode? ErrorCode { get; init; }

    /// <summary>
    /// Error message if verification failed.
    /// </summary>
    public string? ErrorMessage { get; init; }

    /// <summary>
    /// Context metadata (available on success).
    /// </summary>
    public Dictionary<string, object>? Metadata { get; init; }

    /// <summary>
    /// Create a successful result.
    /// </summary>
    public static AshVerifyResult Success(Dictionary<string, object>? metadata = null) =>
        new() { Valid = true, Metadata = metadata };

    /// <summary>
    /// Create a failed result.
    /// </summary>
    public static AshVerifyResult Failure(AshErrorCode code, string message) =>
        new() { Valid = false, ErrorCode = code, ErrorMessage = message };
}
