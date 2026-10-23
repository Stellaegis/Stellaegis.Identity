using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>One login attempt, succeeded or failed, written by <see cref="LoginService"/> and shown to the person on their security page.</summary>
public sealed class LoginEvent
{
    /// <summary>The account the attempt was for; <see cref="Guid.Empty"/> when the e-mail matched no account.</summary>
    public Guid UserUniqueId { get; set; }

    /// <summary>The e-mail the attempt used, normalized.</summary>
    public string Email { get; set; } = "";

    /// <summary>Whether the attempt succeeded.</summary>
    public bool Success { get; set; }

    /// <summary>Why it failed, when it did: one of <see cref="LoginFailureReasons"/>.</summary>
    public string? FailReason { get; set; }

    /// <summary>The address the attempt came from, when the host records it.</summary>
    public string? IpAddress { get; set; }

    /// <summary>The user agent of the attempt, when the host records it.</summary>
    public string? UserAgent { get; set; }

    /// <summary>When the attempt was recorded.</summary>
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>The reasons a login fails, as <see cref="LoginEvent.FailReason"/> records them.</summary>
public static class LoginFailureReasons
{
    /// <summary>The e-mail or the password is wrong, or the account is disabled or unknown.</summary>
    public const string InvalidCredentials = "INVALID_CREDENTIALS";

    /// <summary>The account is locked after too many failed logins.</summary>
    public const string LockedOut = "LOCKED_OUT";

    /// <summary>The account waits for its activation: it has no password yet. The person is told only that the credentials are invalid.</summary>
    public const string NotActivated = "NOT_ACTIVATED";
}

/// <summary>What an account token authorizes, once.</summary>
public enum AccountTokenPurpose
{
    /// <summary>Choosing a new password, for a person who forgot theirs.</summary>
    PasswordReset,

    /// <summary>Choosing the first password of an account an administrator created.</summary>
    Activation,
}

/// <summary>How the link of an account token reached its holder: what its use proves about the address.</summary>
public enum TokenDelivery
{
    /// <summary>Sent by e-mail by the system to the address of the account: using it proves the address.</summary>
    Email,

    /// <summary>Handed by an administrator, by any means: using it proves nothing about the address.</summary>
    Hand,
}

/// <summary>
/// A short-lived token that authorizes one act on an account — a password reset, an activation. Only the hash of the
/// token is kept: the token itself is in the link, and whoever reads the table holds nothing that works.
/// </summary>
public sealed class AccountToken
{
    /// <summary>The SHA-256 of the token, in lowercase hexadecimal (<see cref="AccountTokens.Hash"/>).</summary>
    public string TokenHash { get; set; } = "";

    /// <summary>The account the token was issued for.</summary>
    public Guid UserUniqueId { get; set; }

    /// <summary>What the token authorizes.</summary>
    public AccountTokenPurpose Purpose { get; set; }

    /// <summary>How its link reached its holder.</summary>
    public TokenDelivery Delivery { get; set; }

    /// <summary>The e-mail of the account when the token was issued.</summary>
    public string Email { get; set; } = "";

    /// <summary>When the token was issued.</summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Who asked for it: the person, for a reset; the administrator, for an activation.</summary>
    public required Actor CreatedBy { get; set; }

    /// <summary>After when the token no longer works.</summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>When the token was used, or <see langword="null"/>.</summary>
    public DateTimeOffset? ConsumedAt { get; set; }

    /// <summary>When the token was revoked — a newer one issued for the same purpose, an administrator —, or <see langword="null"/>.</summary>
    public DateTimeOffset? RevokedAt { get; set; }

    /// <summary>The address the request came from, when the host records it.</summary>
    public string? IpAddress { get; set; }

    /// <summary>Whether the token can still be used: neither consumed nor revoked, not expired at <paramref name="now"/>.</summary>
    public bool IsValidAt(DateTimeOffset now) => ConsumedAt is null && RevokedAt is null && ExpiresAt > now;
}

/// <summary>A pending or completed verification of an e-mail: one per e-mail, keyed by it.</summary>
public sealed class EmailVerification
{
    /// <summary>The e-mail being verified, normalized.</summary>
    public string Email { get; set; } = "";

    /// <summary>The code sent to the e-mail.</summary>
    public string Code { get; set; } = "";

    /// <summary>When the code was issued.</summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>After when the code no longer works.</summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>How many times a code was tried against this verification.</summary>
    public int Attempts { get; set; }

    /// <summary>Whether the e-mail was verified.</summary>
    public bool IsVerified { get; set; }

    /// <summary>The address the request came from, when the host records it.</summary>
    public string? IpAddress { get; set; }
}

/// <summary>The second factor of an account, as <see cref="IMfaStore"/> keeps it.</summary>
public sealed record MfaRecord
{
    /// <summary>The account.</summary>
    public Guid UserUniqueId { get; init; }

    /// <summary>The TOTP secret generated at setup, protected (<see cref="TotpSecretProtector"/>), until the first code confirms it.</summary>
    public string? PendingSecret { get; init; }

    /// <summary>The active TOTP secret, protected (<see cref="TotpSecretProtector"/>); set only when the second factor is enabled by authenticator.</summary>
    public string? TotpSecret { get; init; }

    /// <summary>The time step of the last code accepted, or <see langword="null"/>: a code is accepted once, and never one of an earlier step.</summary>
    public long? LastUsedStep { get; init; }

    /// <summary>Whether a second factor is required at login.</summary>
    public bool IsEnabled { get; init; }

    /// <summary>When the second factor was enabled, or <see langword="null"/>.</summary>
    public DateTimeOffset? EnabledAt { get; init; }

    /// <summary>How the second factor is checked: <see cref="MfaMethod.Totp"/> or <see cref="MfaMethod.Email"/>.</summary>
    public string Method { get; init; } = MfaMethod.Totp;
}

/// <summary>How the second factor of an account is checked.</summary>
public static class MfaMethod
{
    /// <summary>A time-based one-time code from an authenticator application.</summary>
    public const string Totp = "totp";

    /// <summary>A one-time code sent by e-mail.</summary>
    public const string Email = "email";
}
