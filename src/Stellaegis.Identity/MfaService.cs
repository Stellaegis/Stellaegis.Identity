using System.Collections.Concurrent;
using System.Security.Cryptography;
using OtpNet;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// The second factor of an account: setting an authenticator up, checking a code at login, enabling the e-mail
/// method, disabling. Time-based one-time codes follow RFC 6238, as every authenticator application does.
/// </summary>
public sealed class MfaService(IMfaStore store, TimeProvider clock)
{
    /// <summary>Generates a 20-byte secret, keeps it pending a first code, and returns it base32 for the enrollment QR code.</summary>
    public async Task<string> BeginSetupAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
    {
        var secret = Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));
        await store.SetPendingSecretAsync(userUniqueId, secret, cancellationToken);
        return secret;
    }

    /// <summary>
    /// Checks <paramref name="code"/> against the pending secret and, when it holds, makes the secret active and
    /// enables the second factor by authenticator.
    /// </summary>
    public async Task<Result> ConfirmSetupAsync(Guid userUniqueId, string code, CancellationToken cancellationToken = default)
    {
        var record = await store.GetAsync(userUniqueId, cancellationToken);
        if (record?.PendingSecret is null)
            return Result.Failure(IdentityErrors.MfaNotPending);
        if (!Verify(record.PendingSecret, code))
            return Result.Failure(IdentityErrors.InvalidMfaCode);
        await store.EnableAsync(userUniqueId, clock.GetUtcNow(), cancellationToken);
        return Result.Success();
    }

    /// <summary>Whether <paramref name="code"/> is the current code of the account's authenticator.</summary>
    public async Task<bool> ValidateCodeAsync(Guid userUniqueId, string code, CancellationToken cancellationToken = default)
    {
        var record = await store.GetAsync(userUniqueId, cancellationToken);
        return record is { IsEnabled: true, TotpSecret: { } secret } && Verify(secret, code);
    }

    /// <summary>The second factor of the account, or <see langword="null"/> when none was ever set up.</summary>
    public Task<MfaRecord?> GetStatusAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
        => store.GetAsync(userUniqueId, cancellationToken);

    /// <summary>Whether a second factor is required of the account at login.</summary>
    public async Task<bool> IsEnabledAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
        => (await store.GetAsync(userUniqueId, cancellationToken))?.IsEnabled == true;

    /// <summary>Enables the second factor by e-mail, which needs no setup.</summary>
    public Task EnableEmailAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
        => store.EnableEmailAsync(userUniqueId, clock.GetUtcNow(), cancellationToken);

    /// <summary>How the account's second factor is checked; <see cref="MfaMethod.Totp"/> when none was set up.</summary>
    public async Task<string> GetMethodAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
        => (await store.GetAsync(userUniqueId, cancellationToken))?.Method ?? MfaMethod.Totp;

    /// <summary>Disables the second factor and clears its secrets.</summary>
    public Task DisableAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
        => store.DisableAsync(userUniqueId, cancellationToken);

    /// <summary>The <c>otpauth://</c> URI the enrollment QR code encodes, for <paramref name="email"/> under <paramref name="issuer"/>.</summary>
    public static string GetOtpAuthUri(string secretBase32, string email, string issuer = "Stellaegis")
        => $"otpauth://totp/{Uri.EscapeDataString(Guard.NotWhiteSpace(issuer))}:{Uri.EscapeDataString(Guard.NotWhiteSpace(email))}"
         + $"?secret={Guard.NotWhiteSpace(secretBase32)}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits=6&period=30";

    private bool Verify(string secretBase32, string code)
    {
        if (string.IsNullOrWhiteSpace(code))
            return false;
        var totp = new Totp(Base32Encoding.ToBytes(secretBase32));
        return totp.VerifyTotp(clock.GetUtcNow().UtcDateTime, code.Trim(), out _, VerificationWindow.RfcSpecifiedNetworkDelay);
    }
}

/// <summary>
/// The one-time codes sent by e-mail during a login whose second factor is the e-mail method: kept in memory for
/// ten minutes, spent on the first match. A singleton of the process; a restart loses them, which only costs a
/// new code.
/// </summary>
public sealed class LoginOtpService(TimeProvider clock)
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);
    private readonly ConcurrentDictionary<Guid, (string Code, DateTimeOffset Expires)> _codes = new();

    /// <summary>Generates a six-digit code for the account, replacing any previous one, and returns it for the e-mail.</summary>
    public string Generate(Guid userUniqueId)
    {
        var code = RandomNumberGenerator.GetInt32(100_000, 1_000_000).ToString();
        _codes[userUniqueId] = (code, clock.GetUtcNow().Add(Lifetime));
        return code;
    }

    /// <summary>Whether <paramref name="submittedCode"/> is the account's current code; a match spends it.</summary>
    public bool Validate(Guid userUniqueId, string? submittedCode)
    {
        if (string.IsNullOrWhiteSpace(submittedCode) || !_codes.TryGetValue(userUniqueId, out var entry))
            return false;
        if (entry.Expires < clock.GetUtcNow())
        {
            _codes.TryRemove(userUniqueId, out _);
            return false;
        }
        if (!string.Equals(entry.Code, submittedCode.Trim(), StringComparison.Ordinal))
            return false;
        _codes.TryRemove(userUniqueId, out _);
        return true;
    }
}

/// <summary>
/// The recovery codes of an account: the way in when the authenticator is gone. Shown once, at generation; kept
/// as hashes only, like passwords; each spent on its first use.
/// </summary>
public sealed class RecoveryCodeService(IRecoveryCodeStore store, PasswordHasher hasher)
{
    /// <summary>How many codes a set has.</summary>
    public const int CodeCount = 8;

    // Ten symbols from a 32-symbol alphabet, without the ones that read alike: about 50 bits per code.
    private const string Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private const int CodeLength = 10;

    /// <summary>Generates a fresh set, replacing the previous one, and returns the codes to show the person once.</summary>
    public async Task<IReadOnlyList<string>> GenerateAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
    {
        var codes = new List<string>(CodeCount);
        var hashes = new List<string>(CodeCount);
        for (var i = 0; i < CodeCount; i++)
        {
            var raw = GenerateRaw();
            codes.Add($"{raw[..5]}-{raw[5..]}");
            hashes.Add(hasher.Hash(raw));
        }
        await store.ReplaceAllAsync(userUniqueId, hashes, cancellationToken);
        return codes;
    }

    /// <summary>Whether <paramref name="code"/> is one of the account's unused codes, in any case and with or without its dash; a match spends it.</summary>
    public async Task<bool> TryConsumeAsync(Guid userUniqueId, string? code, CancellationToken cancellationToken = default)
    {
        var normalized = new string((code ?? "").Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).ToArray());
        if (normalized.Length == 0)
            return false;
        foreach (var hash in await store.GetUnusedHashesAsync(userUniqueId, cancellationToken))
        {
            if (hasher.Verify(normalized, hash))
                return await store.MarkUsedAsync(userUniqueId, hash, cancellationToken);
        }
        return false;
    }

    /// <summary>How many codes the account has left.</summary>
    public Task<int> CountRemainingAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
        => store.CountUnusedAsync(userUniqueId, cancellationToken);

    private static string GenerateRaw()
    {
        Span<char> chars = stackalloc char[CodeLength];
        for (var i = 0; i < CodeLength; i++)
            chars[i] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];
        return new string(chars);
    }
}
