namespace Ash;

/// <summary>
/// ASH error codes.
/// </summary>
public enum AshErrorCode
{
    InvalidContext,
    ContextExpired,
    ReplayDetected,
    IntegrityFailed,
    EndpointMismatch,
    ModeViolation,
    UnsupportedContentType,
    MalformedRequest,
    CanonicalizationFailed
}

/// <summary>
/// Extension methods for AshErrorCode.
/// </summary>
public static class AshErrorCodeExtensions
{
    /// <summary>
    /// Convert error code to string representation.
    /// </summary>
    public static string ToErrorString(this AshErrorCode code) => code switch
    {
        AshErrorCode.InvalidContext => "INVALID_CONTEXT",
        AshErrorCode.ContextExpired => "CONTEXT_EXPIRED",
        AshErrorCode.ReplayDetected => "REPLAY_DETECTED",
        AshErrorCode.IntegrityFailed => "INTEGRITY_FAILED",
        AshErrorCode.EndpointMismatch => "ENDPOINT_MISMATCH",
        AshErrorCode.ModeViolation => "MODE_VIOLATION",
        AshErrorCode.UnsupportedContentType => "UNSUPPORTED_CONTENT_TYPE",
        AshErrorCode.MalformedRequest => "MALFORMED_REQUEST",
        AshErrorCode.CanonicalizationFailed => "CANONICALIZATION_FAILED",
        _ => "UNKNOWN_ERROR"
    };
}
