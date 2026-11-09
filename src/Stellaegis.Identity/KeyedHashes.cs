using System.Security.Cryptography;
using System.Text;

namespace Stellaegis.Identity;

/// <summary>
/// The hashes of the short random secrets an account is given — the recovery codes —: an HMAC-SHA256 under a key
/// derived from the pepper of the host by HKDF, one key per purpose, in lowercase hexadecimal. A recovery code has
/// about 50 bits: a plain SHA-256 of it is found by trying them all, once for every account since nothing salts it,
/// while a PBKDF2 per code left made every try cost the server what a password costs. Keyed, a hash read from
/// <c>ident</c> is worth nothing without the pepper, and a try costs one HMAC; being deterministic, it is looked up
/// rather than compared.
/// </summary>
internal static class KeyedHashes
{
    /// <summary>The purpose of the hashes of recovery codes.</summary>
    public const string RecoveryCode = "Stellaegis.Identity.RecoveryCode";

    /// <summary>The hash of <paramref name="value"/> under the key of <paramref name="purpose"/>.</summary>
    public static string Of(string pepper, string purpose, string value)
    {
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, Encoding.UTF8.GetBytes(pepper), 32, salt: [], info: Encoding.UTF8.GetBytes(purpose));
        return Convert.ToHexStringLower(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value)));
    }
}
