// ASH was developed by 3maem Co. | 12/31/2025
//
// ASH Protocol Version Constants.
// Central location for all ASH version-related constants.

namespace Ash.Core;

/// <summary>
/// ASH Protocol version constants.
/// </summary>
public static class AshVersion
{
    /// <summary>
    /// Current ASH SDK version.
    /// </summary>
    public const string Version = "2.3.1";

    /// <summary>
    /// ASH v1 protocol version prefix.
    /// Used in v1 proof generation.
    /// </summary>
    public const string AshVersionPrefix = "ASHv1";

    /// <summary>
    /// ASH v2.1 protocol version prefix.
    /// Used in v2.1+ proof generation with derived client secrets.
    /// </summary>
    public const string AshVersionPrefixV21 = "ASHv2.1";
}
