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

    /// <summary>The password held, and the code of the second factor — one-time or recovery — is wrong.</summary>
    public const string InvalidSecondFactor = "INVALID_SECOND_FACTOR";

    /// <summary>The password typed from a session, to confirm an operation on the account, is wrong.</summary>
    public const string InvalidCurrentPassword = "INVALID_CURRENT_PASSWORD";
}

/// <summary>
/// The failed logins of an account after one more was counted (<see cref="IAuthUserStore.RecordFailedLoginAsync"/>):
/// how many in a row, and until when the account is locked out, when it is.
/// </summary>
/// <param name="FailedLoginCount">Consecutive failed logins since the last successful one, this one included.</param>
/// <param name="BlockedUntil">Until when the account is locked out, or <see langword="null"/> when it is not.</param>
public sealed record FailedLogin(int FailedLoginCount, DateTimeOffset? BlockedUntil)
{
    /// <summary>Whether the account is locked out at <paramref name="now"/>.</summary>
    public bool IsLockedOutAt(DateTimeOffset now) => BlockedUntil is { } until && until > now;
}

/// <summary>What an account token authorizes, once.</summary>
public enum AccountTokenPurpose
{
    /// <summary>Choosing a new password, for a person who forgot theirs.</summary>
    PasswordReset,

    /// <summary>Choosing the first password of an account an administrator created.</summary>
    Activation,

    /// <summary>
    /// Restoring the e-mail an account had before it was changed, from the link sent to that address: the one act
    /// its person can take when a session that was not theirs changed it. The token keeps the address to restore.
    /// </summary>
    EmailRevert,

    /// <summary>
    /// Applying a change of e-mail the new address proved by a code, from the link sent to the previous address: the
    /// account keeps the previous address until it is used. The token keeps the address to apply.
    /// </summary>
    EmailChangeApproval,
}

/// <summary>
/// A change of e-mail the new address proved: applied, with the token of the link that undoes it for the previous
/// address; or waiting, with the token of the link by which the previous address approves it
/// (<see cref="EmailChangeOptions.RequireApprovalByPrevious"/>). One of the two tokens, never both.
/// </summary>
/// <param name="PreviousEmail">The address the account had — has still, while the change waits —, where the link goes.</param>
/// <param name="NewEmail">The address the account has now, or will have once approved.</param>
/// <param name="RevertToken">The token of the link that restores <paramref name="PreviousEmail"/>, in clear this once, when the change is applied.</param>
/// <param name="ApprovalToken">The token of the link that applies the change, in clear this once, when it waits for the previous address.</param>
public sealed record EmailChanged(string PreviousEmail, string NewEmail, string? RevertToken, string? ApprovalToken)
{
    /// <summary>Whether the change waits for the approval of the previous address.</summary>
    public bool IsPending => ApprovalToken is not null;
}

/// <summary>A change of e-mail applied by the approval of the previous address.</summary>
/// <param name="PreviousEmail">The address the account had.</param>
/// <param name="NewEmail">The address the account has now.</param>
public sealed record EmailChangeApproved(string PreviousEmail, string NewEmail);

/// <summary>A change of e-mail undone: the address restored, and the token of the link by which its person chooses a new password.</summary>
/// <param name="Email">The address restored, where the reset link goes.</param>
/// <param name="ResetToken">The token of the reset link, in clear this once: only its hash is kept.</param>
public sealed record EmailReverted(string Email, string ResetToken);

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

    /// <summary>The e-mail of the account when the token was issued — for an <see cref="AccountTokenPurpose.EmailRevert"/>, the address to restore.</summary>
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

/// <summary>What a verification of an e-mail is for. A code proves the e-mail for its purpose only.</summary>
public enum EmailVerificationPurpose
{
    /// <summary>Creating an account with the e-mail: nobody asks for it, there is no account yet.</summary>
    Registration,

    /// <summary>Giving the e-mail to an account that has another, asked by that account.</summary>
    EmailChange,

    /// <summary>Proving the e-mail an account already has, never proven so far, asked by that account.</summary>
    CurrentEmail,
}

/// <summary>
/// A pending or completed verification of an e-mail: one per e-mail and purpose, keyed by both. A code proves
/// the e-mail for its purpose and its requester only — a registration pending on an address is not touched by
/// an account asking for the same address, and a code cannot serve another than who asked for it.
/// </summary>
public sealed class EmailVerification
{
    /// <summary>The e-mail being verified, normalized.</summary>
    public string Email { get; set; } = "";

    /// <summary>What the verification is for.</summary>
    public EmailVerificationPurpose Purpose { get; set; }

    /// <summary>The account that asked for it; <see langword="null"/> for a registration, which has none yet.</summary>
    public Guid? RequestedBy { get; set; }

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

/// <summary>What a person reads and changes of their own account, as <see cref="ProfileService"/> gives it.</summary>
public sealed record AccountProfile
{
    /// <summary>The identity of the account.</summary>
    public required Guid UserUniqueId { get; init; }

    /// <summary>The e-mail the person signs in with.</summary>
    public required string Email { get; init; }

    /// <summary>The name of the account.</summary>
    public required string DisplayName { get; init; }

    /// <summary>The language the person chose, or <see langword="null"/>.</summary>
    public string? Locale { get; init; }

    /// <summary>The time zone the person chose, or <see langword="null"/>.</summary>
    public string? TimeZone { get; init; }

    /// <summary>When the avatar was set, or <see langword="null"/> when the account has none.</summary>
    public DateTimeOffset? AvatarModifiedAt { get; init; }
}

/// <summary>
/// The image an account shows, as <see cref="IAvatarStore"/> keeps it: a PNG of 256 by 256 pixels, checked and
/// stripped of every chunk but the image's own before it reaches the store.
/// </summary>
public sealed record AccountAvatar
{
    /// <summary>The largest image a store keeps, in bytes.</summary>
    public const int MaxImageLength = 262144;

    /// <summary>The largest file <see cref="ProfileService.SetAvatarAsync"/> reads, before the chunks besides the image are dropped.</summary>
    public const int MaxFileLength = 4 * MaxImageLength;

    /// <summary>The account.</summary>
    public Guid UserUniqueId { get; init; }

    /// <summary>The image, a PNG.</summary>
    public required byte[] Image { get; init; }

    /// <summary>When the image was set: it versions the address it is served at.</summary>
    public DateTimeOffset ModifiedAt { get; init; }

    /// <summary>Who set it: the person, or an administrator.</summary>
    public required Actor ModifiedBy { get; init; }
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
