using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// Protects the TOTP secrets of the accounts at rest: whoever reads <c>ident</c> in clear would generate the codes of
/// every second factor. AES-256-GCM in the application, so that it holds the same on every engine and the key never
/// reaches the database; the key of each slot of <see cref="MfaPolicyOptions.SecretKeys"/> derived by HKDF; the
/// account bound as associated data, so that a secret copied onto another account does not open. A protected secret
/// reads <c>{slot}:{base64(nonce, ciphertext, tag)}</c>, the slot telling which key opens it.
/// </summary>
public sealed class TotpSecretProtector(IOptions<IdentityOptions> options)
{
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private static readonly byte[] Info = Encoding.UTF8.GetBytes("Stellaegis.Identity.TotpSecret");

    private KeySlots Slots => options.Value.Mfa.SecretKeys;

    /// <summary>The slot new secrets are protected under.</summary>
    public int ActiveSlot => Slots.ActiveKeySlot;

    /// <summary>Protects <paramref name="secretBase32"/> of <paramref name="userUniqueId"/> under the active slot.</summary>
    public string Protect(Guid userUniqueId, string secretBase32)
    {
        Guard.NotWhiteSpace(secretBase32);
        var slot = Slots.ActiveKeySlot;
        var plain = Encoding.UTF8.GetBytes(secretBase32);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var cipher = new byte[plain.Length];
        var tag = new byte[TagSize];
        using (var aes = new AesGcm(KeyOf(slot), TagSize))
            aes.Encrypt(nonce, plain, cipher, tag, userUniqueId.ToByteArray());
        return string.Create(CultureInfo.InvariantCulture, $"{slot}:{Convert.ToBase64String([.. nonce, .. cipher, .. tag])}");
    }

    /// <summary>The secret <paramref name="protectedSecret"/> holds for <paramref name="userUniqueId"/>, and the slot it was protected under.</summary>
    /// <exception cref="CryptographicException">It was not protected for this account, or under a key the slots no longer hold.</exception>
    public (string SecretBase32, int Slot) Unprotect(Guid userUniqueId, string protectedSecret)
    {
        var separator = Guard.NotWhiteSpace(protectedSecret).IndexOf(':', StringComparison.Ordinal);
        if (separator < 1 || !int.TryParse(protectedSecret.AsSpan(0, separator), NumberStyles.None, CultureInfo.InvariantCulture, out var slot))
            throw new CryptographicException("The TOTP secret is not protected: it carries no slot.");
        var bytes = Convert.FromBase64String(protectedSecret[(separator + 1)..]);
        if (bytes.Length <= NonceSize + TagSize)
            throw new CryptographicException("The protected TOTP secret is too short.");
        var nonce = bytes.AsSpan(0, NonceSize);
        var cipher = bytes.AsSpan(NonceSize, bytes.Length - NonceSize - TagSize);
        var tag = bytes.AsSpan(bytes.Length - TagSize);
        var plain = new byte[cipher.Length];
        using (var aes = new AesGcm(KeyOf(slot), TagSize))
            aes.Decrypt(nonce, cipher, tag, plain, userUniqueId.ToByteArray());
        return (Encoding.UTF8.GetString(plain), slot);
    }

    private byte[] KeyOf(int slot)
    {
        var key = Slots.KeyOf(slot);
        if (string.IsNullOrEmpty(key))
            throw new CryptographicException($"No key in slot {slot} of {nameof(MfaPolicyOptions.SecretKeys)}: a TOTP secret protected under it cannot be read.");
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, Encoding.UTF8.GetBytes(key), 32, salt: [], info: Info);
    }
}
