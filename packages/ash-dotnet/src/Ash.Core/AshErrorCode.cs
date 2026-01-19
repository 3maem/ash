// ASH was developed by 3maem Co. | 12/31/2025

namespace Ash.Core;

/// <summary>
/// Error codes returned by ASH verification.
/// </summary>
public static class AshErrorCode
{
    /// <summary>Context not found or invalid.</summary>
    public const string InvalidContext = "ASH_INVALID_CONTEXT";

    /// <summary>Context has expired.</summary>
    public const string ContextExpired = "ASH_CONTEXT_EXPIRED";

    /// <summary>Request replay detected - context already consumed.</summary>
    public const string ReplayDetected = "ASH_REPLAY_DETECTED";

    /// <summary>Proof verification failed - payload may have been tampered.</summary>
    public const string IntegrityFailed = "ASH_INTEGRITY_FAILED";

    /// <summary>Context binding does not match requested endpoint.</summary>
    public const string EndpointMismatch = "ASH_ENDPOINT_MISMATCH";

    /// <summary>Mode violation detected.</summary>
    public const string ModeViolation = "ASH_MODE_VIOLATION";

    /// <summary>Content type not supported by ASH protocol.</summary>
    public const string UnsupportedContentType = "ASH_UNSUPPORTED_CONTENT_TYPE";

    /// <summary>Malformed request.</summary>
    public const string MalformedRequest = "ASH_MALFORMED_REQUEST";

    /// <summary>Failed to canonicalize payload.</summary>
    public const string CanonicalizationFailed = "ASH_CANONICALIZATION_FAILED";
}
