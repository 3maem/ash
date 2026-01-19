// ASH was developed by 3maem Co. | 12/31/2025

namespace Ash.Core.Exceptions;

/// <summary>
/// Base class for all ASH exceptions.
/// </summary>
public class AshException : Exception
{
    /// <summary>
    /// The ASH error code.
    /// </summary>
    public string Code { get; }

    /// <summary>
    /// The HTTP status code associated with this error.
    /// </summary>
    public int HttpStatus { get; }

    /// <summary>
    /// Creates a new ASH exception.
    /// </summary>
    /// <param name="code">The error code.</param>
    /// <param name="httpStatus">The HTTP status code.</param>
    /// <param name="message">The error message.</param>
    public AshException(string code, int httpStatus, string? message = null)
        : base(message ?? "ASH error")
    {
        Code = code;
        HttpStatus = httpStatus;
    }

    /// <summary>
    /// Creates a new ASH exception with an inner exception.
    /// </summary>
    /// <param name="code">The error code.</param>
    /// <param name="httpStatus">The HTTP status code.</param>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public AshException(string code, int httpStatus, string? message, Exception? innerException)
        : base(message ?? "ASH error", innerException)
    {
        Code = code;
        HttpStatus = httpStatus;
    }
}

/// <summary>
/// Thrown when context is not found or invalid.
/// </summary>
public class InvalidContextException : AshException
{
    /// <summary>
    /// Creates a new InvalidContextException.
    /// </summary>
    public InvalidContextException(string? message = null)
        : base(AshErrorCode.InvalidContext, 401, message ?? "Context not found or invalid")
    {
    }
}

/// <summary>
/// Thrown when context has expired.
/// </summary>
public class ContextExpiredException : AshException
{
    /// <summary>
    /// Creates a new ContextExpiredException.
    /// </summary>
    public ContextExpiredException(string? message = null)
        : base(AshErrorCode.ContextExpired, 401, message ?? "Context has expired")
    {
    }
}

/// <summary>
/// Thrown when request replay is detected - context already consumed.
/// </summary>
public class ReplayDetectedException : AshException
{
    /// <summary>
    /// Creates a new ReplayDetectedException.
    /// </summary>
    public ReplayDetectedException(string? message = null)
        : base(AshErrorCode.ReplayDetected, 409, message ?? "Request replay detected - context already consumed")
    {
    }
}

/// <summary>
/// Thrown when proof verification fails - payload may have been tampered.
/// </summary>
public class IntegrityFailedException : AshException
{
    /// <summary>
    /// Creates a new IntegrityFailedException.
    /// </summary>
    public IntegrityFailedException(string? message = null)
        : base(AshErrorCode.IntegrityFailed, 400, message ?? "Proof verification failed - payload may have been tampered")
    {
    }
}

/// <summary>
/// Thrown when context binding does not match requested endpoint.
/// </summary>
public class EndpointMismatchException : AshException
{
    /// <summary>
    /// Creates a new EndpointMismatchException.
    /// </summary>
    public EndpointMismatchException(string? message = null)
        : base(AshErrorCode.EndpointMismatch, 400, message ?? "Context binding does not match requested endpoint")
    {
    }
}

/// <summary>
/// Thrown when canonicalization fails.
/// </summary>
public class CanonicalizationException : AshException
{
    /// <summary>
    /// Creates a new CanonicalizationException.
    /// </summary>
    public CanonicalizationException(string? message = null)
        : base(AshErrorCode.CanonicalizationFailed, 400, message ?? "Failed to canonicalize payload")
    {
    }

    /// <summary>
    /// Creates a new CanonicalizationException with an inner exception.
    /// </summary>
    public CanonicalizationException(string? message, Exception? innerException)
        : base(AshErrorCode.CanonicalizationFailed, 400, message ?? "Failed to canonicalize payload", innerException)
    {
    }
}

/// <summary>
/// Thrown when content type is not supported by ASH protocol.
/// </summary>
public class UnsupportedContentTypeException : AshException
{
    /// <summary>
    /// Creates a new UnsupportedContentTypeException.
    /// </summary>
    public UnsupportedContentTypeException(string? message = null)
        : base(AshErrorCode.UnsupportedContentType, 415, message ?? "Content type not supported by ASH protocol")
    {
    }
}
