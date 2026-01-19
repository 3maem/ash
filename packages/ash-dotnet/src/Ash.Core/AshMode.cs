// ASH was developed by 3maem Co. | 12/31/2025

namespace Ash.Core;

/// <summary>
/// Security modes for ASH protocol.
/// </summary>
public enum AshMode
{
    /// <summary>
    /// Minimal security mode - basic integrity checking.
    /// </summary>
    Minimal,

    /// <summary>
    /// Balanced security mode - recommended for most use cases.
    /// </summary>
    Balanced,

    /// <summary>
    /// Strict security mode - maximum security with server-assisted nonce.
    /// </summary>
    Strict
}
