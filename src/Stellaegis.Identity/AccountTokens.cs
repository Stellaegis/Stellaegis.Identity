using System.Security.Cryptography;
using System.Text;

namespace Stellaegis.Identity;

/// <summary>
/// The tokens of the links an account receives: 32 random bytes from the system's cryptographic generator, written
/// base64url — what the link carries — and kept as their SHA-256 — what the store holds.
/// </summary>
public static class AccountTokens
{
    /// <summary>The number of random bytes of a token, 256 bits.</summary>
    public const int Bytes = 32;

    /// <summary>A new token, and the hash the store keeps of it.</summary>
    public static (string Token, string Hash) New()
    {
        var token = Base64Url(RandomNumberGenerator.GetBytes(Bytes));
        return (token, Hash(token));
    }

    /// <summary>The SHA-256 of <paramref name="token"/>, in lowercase hexadecimal; a blank token hashes to nothing found.</summary>
    public static string Hash(string token)
        => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token ?? string.Empty)));

    private static string Base64Url(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
