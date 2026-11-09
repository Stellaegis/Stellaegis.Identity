using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using OtpNet;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// The second factor of an account: setting an authenticator up, checking a code at login, enabling the e-mail
/// method, disabling — each method enabled only where <see cref="MfaPolicyOptions.AllowedMethods"/> allows it. Time-based
/// one-time codes follow RFC 6238, as every authenticator application does: a code is accepted once — the one that
/// confirmed the setup included —, never one of an earlier step, and the secret is kept protected
/// (<see cref="TotpSecretProtector"/>).
/// </summary>
public sealed class MfaService(IMfaStore store, IAuthUserStore users, TotpSecretProtector protector, IOptions<IdentityOptions> options, TimeProvider clock)
{
    /// <summary>Whether <paramref name="method"/> is one a person may enable in this installation.</summary>
    public bool Allows(string method) => options.Value.Mfa.Allows(method);

    /// <summary>Generates a 20-byte secret, keeps it protected pending a first code, and returns it base32 for the enrollment QR code.</summary>
    public async Task<string> BeginSetupAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
    {
        var secret = Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));
        await store.SetPendingSecretAsync(userUniqueId, protector.Protect(userUniqueId, secret), cancellationToken);
        return secret;
    }

    /// <summary>
    /// Checks <paramref name="code"/> against the pending secret and, when it holds, makes the secret active and
    /// enables the second factor by authenticator.
    /// </summary>
    public async Task<Result> ConfirmSetupAsync(Guid userUniqueId, string code, CancellationToken cancellationToken = default)
    {
        if (!Allows(MfaMethod.Totp))
            return Result.Failure(IdentityErrors.MfaMethodNotAllowed);
        var record = await store.GetAsync(userUniqueId, cancellationToken);
        if (record?.PendingSecret is null)
            return Result.Failure(IdentityErrors.MfaNotPending);
        var (secret, _) = protector.Unprotect(userUniqueId, record.PendingSecret);
        if (Verify(secret, code) is not { } step)
            return Result.Failure(IdentityErrors.InvalidMfaCode);
        await store.EnableAsync(userUniqueId, clock.GetUtcNow(), cancellationToken);
        await store.TryUseStepAsync(userUniqueId, step, cancellationToken);   // the code that confirmed is spent too
        await SecurityStamps.RenewAsync(users, userUniqueId, cancellationToken);
        return Result.Success();
    }

    /// <summary>
    /// Whether <paramref name="code"/> is a current code of the account's authenticator, not accepted before: a code
    /// is good once, and a code of an earlier step than the last one accepted is refused.
    /// </summary>
    public async Task<bool> ValidateCodeAsync(Guid userUniqueId, string code, CancellationToken cancellationToken = default)
    {
        var record = await store.GetAsync(userUniqueId, cancellationToken);
        if (record is not { IsEnabled: true, TotpSecret: { } stored })
            return false;
        var (secret, slot) = protector.Unprotect(userUniqueId, stored);
        if (Verify(secret, code) is not { } step || !await store.TryUseStepAsync(userUniqueId, step, cancellationToken))
            return false;
        if (slot != protector.ActiveSlot)
            await store.ReplaceTotpSecretAsync(userUniqueId, protector.Protect(userUniqueId, secret), cancellationToken);
        return true;
    }

    /// <summary>The second factor of the account, or <see langword="null"/> when none was ever set up.</summary>
    public Task<MfaRecord?> GetStatusAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
        => store.GetAsync(userUniqueId, cancellationToken);

    /// <summary>Whether a second factor is required of the account at login.</summary>
    public async Task<bool> IsEnabledAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
        => (await store.GetAsync(userUniqueId, cancellationToken))?.IsEnabled == true;

    /// <summary>Enables the second factor by e-mail, which needs no setup, where the installation allows it: <see cref="IdentityErrors.MfaMethodNotAllowed"/> otherwise.</summary>
    public async Task<Result> EnableEmailAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
    {
        if (!Allows(MfaMethod.Email))
            return Result.Failure(IdentityErrors.MfaMethodNotAllowed);
        await store.EnableEmailAsync(userUniqueId, clock.GetUtcNow(), cancellationToken);
        await SecurityStamps.RenewAsync(users, userUniqueId, cancellationToken);
        return Result.Success();
    }

    /// <summary>How the account's second factor is checked; <see cref="MfaMethod.Totp"/> when none was set up.</summary>
    public async Task<string> GetMethodAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
        => (await store.GetAsync(userUniqueId, cancellationToken))?.Method ?? MfaMethod.Totp;

    /// <summary>Disables the second factor and clears its secrets; the other sessions of the account close.</summary>
    public async Task DisableAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
    {
        await store.DisableAsync(userUniqueId, cancellationToken);
        await SecurityStamps.RenewAsync(users, userUniqueId, cancellationToken);
    }

    /// <summary>The <c>otpauth://</c> URI the enrollment QR code encodes, for <paramref name="email"/> under <paramref name="issuer"/>.</summary>
    public static string GetOtpAuthUri(string secretBase32, string email, string issuer = "Stellaegis")
        => $"otpauth://totp/{Uri.EscapeDataString(Guard.NotWhiteSpace(issuer))}:{Uri.EscapeDataString(Guard.NotWhiteSpace(email))}"
         + $"?secret={Guard.NotWhiteSpace(secretBase32)}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits=6&period=30";

    // The time step the code matches, within one step of network delay either way, or null.
    private long? Verify(string secretBase32, string code)
    {
        if (string.IsNullOrWhiteSpace(code))
            return null;
        var totp = new Totp(Base32Encoding.ToBytes(secretBase32));
        return totp.VerifyTotp(clock.GetUtcNow().UtcDateTime, code.Trim(), out var step, VerificationWindow.RfcSpecifiedNetworkDelay) ? step : null;
    }
}

/// <summary>
/// The one-time codes sent by e-mail during a login whose second step is the e-mail method — which proves the
/// mailbox, not a second factor (<see cref="AuthenticationMethods.PasswordAndEmailCode"/>) —: six digits, working for
/// <see cref="LoginCodeOptions.Lifetime"/>, spent on the first match. Kept by <see cref="ILoginCodeStore"/>, as a hash
/// under the pepper bound to the account, so that every instance of the host checks a code any of them issued.
/// </summary>
public sealed class LoginCodeService(ILoginCodeStore store, IOptions<IdentityOptions> options, TimeProvider clock)
{
    /// <summary>How long a code works, as the e-mail says it.</summary>
    public TimeSpan Lifetime => options.Value.LoginCode.Lifetime;

    /// <summary>
    /// Generates a code for the account, replacing any previous one, and returns it for the e-mail. Asked again within
    /// <see cref="LoginCodeOptions.MinimumInterval"/> of the last one, nothing is issued:
    /// <see cref="IdentityErrors.LoginCodeThrottled"/>, which a page keeps to itself.
    /// </summary>
    public async Task<Result<string>> GenerateAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
    {
        var settings = options.Value.LoginCode;
        var now = clock.GetUtcNow();
        if (settings.MinimumInterval > TimeSpan.Zero
            && await store.LastIssuedAtAsync(userUniqueId, cancellationToken) is { } last
            && last + settings.MinimumInterval > now)
            return Result.Failure<string>(IdentityErrors.LoginCodeThrottled);

        var code = RandomNumberGenerator.GetString("0123456789", 6);
        await store.SetAsync(new LoginCode
        {
            UserUniqueId = userUniqueId,
            CodeHash = Hash(userUniqueId, code),
            CreatedAt = now,
            ExpiresAt = now + settings.Lifetime,
        }, cancellationToken);
        return Result.Success(code);
    }

    /// <summary>Whether <paramref name="submittedCode"/> is the account's current code, not expired; a match spends it.</summary>
    public async Task<bool> ValidateAsync(Guid userUniqueId, string? submittedCode, CancellationToken cancellationToken = default)
        => !string.IsNullOrWhiteSpace(submittedCode)
        && await store.TryConsumeAsync(userUniqueId, Hash(userUniqueId, submittedCode.Trim()), clock.GetUtcNow(), cancellationToken);

    // The account is in the hash: a hash copied onto another account opens nothing.
    private string Hash(Guid userUniqueId, string code)
        => KeyedHashes.Of(options.Value.PasswordHasher.Pepper, KeyedHashes.LoginCode, $"{userUniqueId:N}:{code}");
}

/// <summary>
/// The recovery codes of an account: the way in when the authenticator is gone. Shown once, at generation; kept
/// as hashes only, keyed by the pepper and bound to the account; each spent on its first use.
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
            hashes.Add(Hash(userUniqueId, raw));
        }
        await store.ReplaceAllAsync(userUniqueId, hashes, cancellationToken);
        return codes;
    }

    /// <summary>
    /// Whether <paramref name="code"/> has the shape of a recovery code — ten letters or digits, in any case, with or
    /// without its dash —, which no one-time code has: what tells the two apart on one field, before any hash is
    /// derived.
    /// </summary>
    public static bool LooksLikeCode(string? code) => Normalize(code).Length == CodeLength;

    /// <summary>
    /// Whether <paramref name="code"/> is one of the account's unused codes, in any case and with or without its dash;
    /// a match spends it. One hash, looked up and spent in one write of the store.
    /// </summary>
    public Task<bool> TryConsumeAsync(Guid userUniqueId, string? code, CancellationToken cancellationToken = default)
    {
        var normalized = Normalize(code);
        return normalized.Length == 0
            ? Task.FromResult(false)
            : store.MarkUsedAsync(userUniqueId, Hash(userUniqueId, normalized), cancellationToken);
    }

    /// <summary>How many codes the account has left.</summary>
    public Task<int> CountRemainingAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
        => store.CountUnusedAsync(userUniqueId, cancellationToken);

    // The account is in the hash: the same code issued to two accounts does not hash alike, and a hash copied onto another account opens nothing.
    private string Hash(Guid userUniqueId, string normalized)
        => hasher.KeyedHash(KeyedHashes.RecoveryCode, $"{userUniqueId:N}:{normalized}");

    private static string Normalize(string? code)
        => new((code ?? "").Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).ToArray());

    private static string GenerateRaw() => RandomNumberGenerator.GetString(Alphabet, CodeLength);
}
