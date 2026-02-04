// ASH was developed by 3maem Co. | 12/31/2025

namespace Ash.Core;

/// <summary>
/// Error codes returned by ASH verification.
///
/// v2.3.4: Uses unique HTTP status codes in the 450-499 range for ASH-specific errors.
/// This enables precise error identification, better monitoring, and targeted retry logic.
///
/// Error Categories:
/// - 450-459: Context errors
/// - 460-469: Seal/Proof errors
/// - 461, 473-479: Binding/Verification errors
/// - 480-489: Format/Protocol errors
/// </summary>
public static class AshErrorCode
{
    // Context errors (450-459)
    /// <summary>Context not found.</summary>
    public const string CtxNotFound = "ASH_CTX_NOT_FOUND";

    /// <summary>Context has expired.</summary>
    public const string CtxExpired = "ASH_CTX_EXPIRED";

    /// <summary>Context already consumed (replay detected).</summary>
    public const string CtxAlreadyUsed = "ASH_CTX_ALREADY_USED";

    // Seal/Proof errors (460-469)
    /// <summary>Proof verification failed.</summary>
    public const string ProofInvalid = "ASH_PROOF_INVALID";

    // Binding/Verification errors (461, 473-479)
    /// <summary>Context binding does not match requested endpoint.</summary>
    public const string BindingMismatch = "ASH_BINDING_MISMATCH";

    /// <summary>Scope hash mismatch (v2.2+).</summary>
    public const string ScopeMismatch = "ASH_SCOPE_MISMATCH";

    /// <summary>Chain verification failed (v2.3+).</summary>
    public const string ChainBroken = "ASH_CHAIN_BROKEN";

    // Format/Protocol errors (480-489)
    /// <summary>Timestamp validation failed.</summary>
    public const string TimestampInvalid = "ASH_TIMESTAMP_INVALID";

    /// <summary>Required proof not provided.</summary>
    public const string ProofMissing = "ASH_PROOF_MISSING";

    // Standard HTTP codes (preserved for semantic clarity)
    /// <summary>Failed to canonicalize payload.</summary>
    public const string CanonicalizationError = "ASH_CANONICALIZATION_ERROR";

    /// <summary>Mode violation detected.</summary>
    public const string ModeViolation = "ASH_MODE_VIOLATION";

    /// <summary>Content type not supported by ASH protocol.</summary>
    public const string UnsupportedContentType = "ASH_UNSUPPORTED_CONTENT_TYPE";

    /// <summary>Input validation failed.</summary>
    public const string ValidationError = "ASH_VALIDATION_ERROR";

    /// <summary>
    /// Get the recommended HTTP status code for an error code.
    ///
    /// v2.3.4: Uses unique HTTP status codes for ASH-specific errors.
    /// </summary>
    public static int GetHttpStatus(string code) => code switch
    {
        // Context errors (450-459)
        CtxNotFound => 450,
        CtxExpired => 451,
        CtxAlreadyUsed => 452,
        // Seal/Proof errors (460-469)
        ProofInvalid => 460,
        // Binding errors (461)
        BindingMismatch => 461,
        ScopeMismatch => 473,
        ChainBroken => 474,
        // Format/Protocol errors (480-489)
        TimestampInvalid => 482,
        ProofMissing => 483,
        // Standard HTTP codes (preserved for semantic clarity)
        CanonicalizationError => 422,
        ModeViolation => 400,
        UnsupportedContentType => 415,
        ValidationError => 400,
        _ => 500
    };
}
