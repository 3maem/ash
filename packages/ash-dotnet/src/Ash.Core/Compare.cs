// ASH was developed by 3maem Co. | 12/31/2025
//
// ASH Protocol Constant-Time Comparison.
// Prevents timing attacks during proof verification.

using System.Security.Cryptography;
using System.Text;

namespace Ash.Core;

/// <summary>
/// ASH Protocol constant-time comparison functions.
/// </summary>
public static class Compare
{
    /// <summary>
    /// Compare two strings in constant time.
    /// Uses fixed-time comparison to prevent timing attacks.
    /// Both strings are compared byte-by-byte regardless of where they differ.
    /// </summary>
    /// <param name="a">First string.</param>
    /// <param name="b">Second string.</param>
    /// <returns>True if strings are equal, False otherwise.</returns>
    public static bool TimingSafe(string a, string b)
    {
        var aBytes = Encoding.UTF8.GetBytes(a);
        var bBytes = Encoding.UTF8.GetBytes(b);
        return CryptographicOperations.FixedTimeEquals(aBytes, bBytes);
    }

    /// <summary>
    /// Compare two byte arrays in constant time.
    /// Uses fixed-time comparison to prevent timing attacks.
    /// </summary>
    /// <param name="a">First byte array.</param>
    /// <param name="b">Second byte array.</param>
    /// <returns>True if arrays are equal, False otherwise.</returns>
    public static bool TimingSafe(byte[] a, byte[] b)
    {
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    /// <summary>
    /// Compare two spans in constant time.
    /// Uses fixed-time comparison to prevent timing attacks.
    /// </summary>
    /// <param name="a">First span.</param>
    /// <param name="b">Second span.</param>
    /// <returns>True if spans are equal, False otherwise.</returns>
    public static bool TimingSafe(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        return CryptographicOperations.FixedTimeEquals(a, b);
    }
}
