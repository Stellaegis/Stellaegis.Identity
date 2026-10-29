using Stellaegis.Primitives;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Identity;

/// <summary>
/// The options of the accounts module, bound from <see cref="SectionName"/> — one sub-section per concern, so
/// that <c>Stellaegis:Identity:PasswordHasher:Pepper</c> is the pepper — or configured in code, and validated when
/// the host starts.
/// <code>
/// Stellaegis:Identity:PasswordHasher:Pepper = …          (required, from a secret store)
/// Stellaegis:Identity:LoginPolicy:MaxFailedAttempts = 5
/// Stellaegis:Identity:SelfRegistration = Closed
/// </code>
/// </summary>
public sealed class IdentityOptions : IValidatableOptions
{
    /// <summary>The configuration section of the module.</summary>
    public const string SectionName = "Stellaegis:Identity";

    /// <summary>How passwords are hashed.</summary>
    public PasswordHasherOptions PasswordHasher { get; set; } = new();

    /// <summary>What a password must look like.</summary>
    public PasswordPolicy PasswordPolicy { get; set; } = new();

    /// <summary>Lockout and timing of the login.</summary>
    public LoginPolicyOptions LoginPolicy { get; set; } = new();

    /// <summary>Whether a second factor is required of everyone.</summary>
    public MfaPolicyOptions Mfa { get; set; } = new();

    /// <summary>The codes sent to verify an e-mail.</summary>
    public EmailVerificationOptions EmailVerification { get; set; } = new();

    /// <summary>The links sent to reset a password.</summary>
    public PasswordResetOptions PasswordReset { get; set; } = new();

    /// <summary>
    /// Whether anyone with a verified e-mail creates their account. <see cref="SelfRegistration.Closed"/> unless set:
    /// an administrator creates every account. An invitation is no posture: it exists when the host connects the
    /// port that answers it.
    /// </summary>
    public SelfRegistration SelfRegistration { get; set; } = SelfRegistration.Closed;

    /// <summary>The links that activate an account an administrator created.</summary>
    public ActivationOptions Activation { get; set; } = new();

    /// <summary>What a change of e-mail leaves to the previous address: the link that undoes it.</summary>
    public EmailChangeOptions EmailChange { get; set; } = new();

    /// <summary>How the links an account receives are written and delivered.</summary>
    public LinkOptions Links { get; set; } = new();

    /// <summary>How long what identifies a person is kept once it no longer serves (<see cref="IdentityRetentionService"/>).</summary>
    public RetentionOptions Retention { get; set; } = new();

    /// <summary>How a signed-in session is held against its account.</summary>
    public SessionPolicyOptions Session { get; set; } = new();

    /// <summary>
    /// The address the avatar of the signed-in person is served at, absolute — the account page's,
    /// <c>https://id.acme.test/account/avatar</c> —, which the session carries in its <c>picture</c> claim, versioned
    /// by the time the avatar was set. None unless set: the module does not know where the host maps its pages, and
    /// emits no <c>picture</c> without it. The address answers the person's own session: an application on the same
    /// site as the pages shows it, one on another site reads the avatars of others from its registry.
    /// </summary>
    public string? AvatarUrl { get; set; }

    /// <inheritdoc/>
    public string? FindError()
        => Prefix(nameof(PasswordHasher), PasswordHasher.FindError())
        ?? Prefix(nameof(PasswordPolicy), PasswordPolicy.FindError())
        ?? Prefix(nameof(LoginPolicy), LoginPolicy.FindError())
        ?? Prefix(nameof(Mfa), Mfa.FindError())
        ?? Prefix(nameof(EmailVerification), EmailVerification.FindError())
        ?? Prefix(nameof(PasswordReset), PasswordReset.FindError())
        ?? Prefix(nameof(Activation), Activation.FindError())
        ?? Prefix(nameof(EmailChange), EmailChange.FindError())
        ?? Prefix(nameof(Links), Links.FindError())
        ?? Prefix(nameof(Retention), Retention.FindError())
        ?? Prefix(nameof(Session), Session.FindError())
        ?? (AvatarUrl is null || Uri.TryCreate(AvatarUrl, UriKind.Absolute, out var avatar) && (avatar.Scheme == Uri.UriSchemeHttps || avatar.Scheme == Uri.UriSchemeHttp) && avatar.Query.Length == 0
            ? null
            : $"{nameof(AvatarUrl)} must be an absolute http(s) URL without a query, or absent.");

    private static string? Prefix(string section, string? error) => error is null ? null : $"{section}: {error}";
}

/// <summary>How passwords are hashed: PBKDF2-SHA256, a pepper, an iteration count.</summary>
public sealed class PasswordHasherOptions : IValidatableOptions
{
    /// <summary>
    /// A secret appended to every password before hashing, kept outside the database so that a dump of it is not
    /// enough to attack the hashes. Required. It cannot change without hashing every password again: there is one
    /// value, no rotation.
    /// </summary>
    public string Pepper { get; set; } = "";

    /// <summary>The PBKDF2 iterations of a new hash. 310 000 unless set, the OWASP recommendation for SHA-256; never under 1 000.</summary>
    public int Iterations { get; set; } = 310_000;

    /// <inheritdoc/>
    public string? FindError()
    {
        if (string.IsNullOrWhiteSpace(Pepper))
            return $"{nameof(Pepper)} is required: a secret of the host, never a committed value.";
        if (Iterations < 1_000)
            return $"{nameof(Iterations)} must be at least 1000.";
        return null;
    }
}

/// <summary>What a password must look like.</summary>
public sealed class PasswordPolicy : IValidatableOptions
{
    /// <summary>The shortest password accepted. 8 unless set.</summary>
    public int MinLength { get; set; } = 8;

    /// <summary>The longest password accepted. 128 unless set.</summary>
    public int MaxLength { get; set; } = 128;

    /// <summary>Whether an uppercase letter is required. Yes unless set.</summary>
    public bool RequireUppercase { get; set; } = true;

    /// <summary>Whether a lowercase letter is required. Yes unless set.</summary>
    public bool RequireLowercase { get; set; } = true;

    /// <summary>Whether a digit is required. Yes unless set.</summary>
    public bool RequireDigit { get; set; } = true;

    /// <summary>Whether a character that is neither a letter nor a digit is required. Yes unless set.</summary>
    public bool RequireSpecialChar { get; set; } = true;

    /// <inheritdoc/>
    public string? FindError()
    {
        if (MinLength < 1)
            return $"{nameof(MinLength)} must be at least 1.";
        if (MaxLength < MinLength)
            return $"{nameof(MaxLength)} must not be under {nameof(MinLength)}.";
        return null;
    }
}

/// <summary>Lockout and timing of the login.</summary>
public sealed class LoginPolicyOptions : IValidatableOptions
{
    /// <summary>Consecutive failed logins before the account is locked. 5 unless set.</summary>
    public int MaxFailedAttempts { get; set; } = 5;

    /// <summary>How long the account stays locked. 15 minutes unless set.</summary>
    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>The least time a login attempt takes to answer, so that its duration tells nothing. 300 ms unless set.</summary>
    public TimeSpan MinResponseTime { get; set; } = TimeSpan.FromMilliseconds(300);

    /// <inheritdoc/>
    public string? FindError()
    {
        if (MaxFailedAttempts < 1)
            return $"{nameof(MaxFailedAttempts)} must be at least 1.";
        if (LockoutDuration <= TimeSpan.Zero)
            return $"{nameof(LockoutDuration)} must be positive.";
        if (MinResponseTime < TimeSpan.Zero)
            return $"{nameof(MinResponseTime)} must not be negative.";
        return null;
    }
}

/// <summary>
/// Whether a second factor is required of everyone, and which methods the installation allows. When it is required,
/// a person whose password holds but who has no second factor is asked to set one up before the login completes,
/// <see cref="LoginStep.RequiresMfaSetup"/>; otherwise the second factor is the person's own choice, among the
/// methods allowed.
/// </summary>
public sealed class MfaPolicyOptions : IValidatableOptions
{
    /// <summary>Whether every account must have a second factor. No unless set.</summary>
    public bool RequireForAllUsers { get; set; }

    /// <summary>
    /// The methods a person may enable, among <see cref="MfaMethod.All"/>: the authenticator alone unless set. The
    /// code by e-mail goes through the mailbox, the channel of a reset link, so whoever holds the mailbox holds the
    /// account already: an installation opens it knowingly, <c>Mfa:AllowedMethods:0 = totp</c>,
    /// <c>Mfa:AllowedMethods:1 = email</c>. An account whose method is no longer allowed keeps it; the pages offer the
    /// allowed ones only. The authenticator stays allowed while <see cref="RequireForAllUsers"/> is set: the enrollment
    /// asked at the login offers nothing else.
    /// </summary>
    public List<string> AllowedMethods { get; set; } = [MfaMethod.Totp];

    /// <summary>Whether <paramref name="method"/> is one a person may enable here.</summary>
    public bool Allows(string method) => AllowedMethods.Contains(Guard.NotWhiteSpace(method), StringComparer.Ordinal);

    /// <summary>
    /// The keys the TOTP secrets are protected with at rest (<see cref="TotpSecretProtector"/>), in two slots for a
    /// rotation without a cut: required, from a secret store, like the pepper. A secret read under the other slot is
    /// protected again under the active one at its next use.
    /// <code>
    /// Stellaegis:Identity:Mfa:SecretKeys:ActiveKeySlot = 1
    /// Stellaegis:Identity:Mfa:SecretKeys:Keys:1 = …
    /// </code>
    /// </summary>
    public KeySlots SecretKeys { get; set; } = new();

    /// <inheritdoc/>
    public string? FindError()
    {
        if (SecretKeys.FindError() is { } error)
            return $"{nameof(SecretKeys)}: {error}";
        if (AllowedMethods.Count == 0)
            return $"{nameof(AllowedMethods)} names at least one method: {string.Join(", ", MfaMethod.All)}.";
        if (AllowedMethods.FirstOrDefault(method => !MfaMethod.All.Contains(method, StringComparer.Ordinal)) is { } unknown)
            return $"{nameof(AllowedMethods)} names '{unknown}', which is not a method: {string.Join(", ", MfaMethod.All)}.";
        if (RequireForAllUsers && !Allows(MfaMethod.Totp))
            return $"{nameof(AllowedMethods)} includes {MfaMethod.Totp} while {nameof(RequireForAllUsers)} is set: the enrollment asked at the login offers the authenticator only.";
        return null;
    }
}

/// <summary>The codes sent to verify an e-mail.</summary>
public sealed class EmailVerificationOptions : IValidatableOptions
{
    /// <summary>How many digits a code has. 6 unless set; between 4 and 10.</summary>
    public int CodeLength { get; set; } = 6;

    /// <summary>How long a code works. 15 minutes unless set.</summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>How many wrong codes are tried before the verification is spent. 5 unless set.</summary>
    public int MaxAttempts { get; set; } = 5;

    /// <summary>
    /// The least time between two codes to one e-mail for one purpose, whoever asks. One minute unless set; zero for
    /// none. A request inside it issues nothing, <c>Verification.Throttled</c>, and the pages say what they always
    /// say: the code sent still works. Against a mailbox flooded with codes, and against a code the person waits for
    /// being replaced by one a stranger asked.
    /// </summary>
    public TimeSpan MinimumInterval { get; set; } = TimeSpan.FromMinutes(1);

    /// <inheritdoc/>
    public string? FindError()
    {
        if (CodeLength is < 4 or > 10)
            return $"{nameof(CodeLength)} must be between 4 and 10.";
        if (Lifetime <= TimeSpan.Zero)
            return $"{nameof(Lifetime)} must be positive.";
        if (MaxAttempts < 1)
            return $"{nameof(MaxAttempts)} must be at least 1.";
        if (MinimumInterval < TimeSpan.Zero)
            return $"{nameof(MinimumInterval)} cannot be negative.";
        return null;
    }
}

/// <summary>The links sent to reset a password.</summary>
public sealed class PasswordResetOptions : IValidatableOptions
{
    /// <summary>How long a reset link works. One hour unless set.</summary>
    public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// The least time between two reset links to one account, whoever asks. One minute unless set; zero for none. A
    /// request inside it issues nothing, and the caller says what it always says: the link sent still works. Against
    /// a mailbox flooded with links, and against a link the person waits for being revoked by one a stranger asked.
    /// </summary>
    public TimeSpan MinimumInterval { get; set; } = TimeSpan.FromMinutes(1);

    /// <inheritdoc/>
    public string? FindError()
    {
        if (TokenLifetime <= TimeSpan.Zero)
            return $"{nameof(TokenLifetime)} must be positive.";
        if (MinimumInterval < TimeSpan.Zero)
            return $"{nameof(MinimumInterval)} cannot be negative.";
        return null;
    }
}

/// <summary>The links that activate an account an administrator created, without a password.</summary>
public sealed class ActivationOptions : IValidatableOptions
{
    /// <summary>How long an activation link works. Seven days unless set.</summary>
    public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromDays(7);

    /// <inheritdoc/>
    public string? FindError() => TokenLifetime <= TimeSpan.Zero ? $"{nameof(TokenLifetime)} must be positive." : null;
}

/// <summary>
/// What the previous address has to say to a change of e-mail, chosen at the installation. Either the change waits for
/// its approval — nothing applies without the link it receives, a lost mailbox goes through an administrator —, the
/// posture unless set; or the change applies and the previous address is told, with the link that restores it, removes
/// the password and closes every session. Both links live longer than a reset's: the person reads that mailbox when
/// they read it.
/// </summary>
public sealed class EmailChangeOptions : IValidatableOptions
{
    /// <summary>
    /// Whether a change of e-mail applies only once the previous address approved it by the link it received. Yes
    /// unless set: a session that is not the person's changes nothing then. No lets the change apply at once, the
    /// previous address told with the link that undoes it. An account whose mailbox is lost is changed by an
    /// administrator, <c>POST identity/users/{id}/email</c>, either way.
    /// </summary>
    public bool RequireApprovalByPrevious { get; set; } = true;

    /// <summary>How long the link that approves the change works. Seven days unless set.</summary>
    public TimeSpan ApprovalLifetime { get; set; } = TimeSpan.FromDays(7);

    /// <summary>How long the link that restores the previous e-mail works. Seven days unless set.</summary>
    public TimeSpan RevertLifetime { get; set; } = TimeSpan.FromDays(7);

    /// <inheritdoc/>
    public string? FindError()
    {
        if (ApprovalLifetime <= TimeSpan.Zero)
            return $"{nameof(ApprovalLifetime)} must be positive.";
        if (RevertLifetime <= TimeSpan.Zero)
            return $"{nameof(RevertLifetime)} must be positive.";
        return null;
    }
}

/// <summary>How the links an account receives — a reset, an activation, the restoring of an e-mail — are written and delivered.</summary>
public sealed class LinkOptions : IValidatableOptions
{
    /// <summary>
    /// The address the pages are reached at, <c>https://id.acme.example</c>, which the links start with. The address
    /// of the request that issues a link unless set: set it when the pages are served by another host, or behind a
    /// proxy that rewrites the address. An installation that runs outside a request needs it.
    /// </summary>
    public string? PublicBaseUrl { get; set; }

    /// <summary>
    /// Whether an administrator may receive a link to hand it over by the means of their choice, rather than have it
    /// sent by e-mail — for an installation without a mail server, or a person reached otherwise. Such a link proves
    /// nothing about the address. No unless set: handing links over is an opening the host declares.
    /// </summary>
    public bool HandDelivery { get; set; }

    /// <summary>The base the links start with, without its trailing slash, or <see langword="null"/> when none is set.</summary>
    public Uri? PublicBase => string.IsNullOrWhiteSpace(PublicBaseUrl) ? null : new Uri(PublicBaseUrl.TrimEnd('/'), UriKind.Absolute);

    /// <inheritdoc/>
    public string? FindError()
    {
        if (string.IsNullOrWhiteSpace(PublicBaseUrl))
            return null;
        return Uri.TryCreate(PublicBaseUrl, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp)
            ? null
            : $"{nameof(PublicBaseUrl)} must be an absolute http or https address.";
    }
}

/// <summary>How a signed-in session — the cookie of the pages — lasts, and is held against its account.</summary>
public sealed class SessionPolicyOptions : IValidatableOptions
{
    /// <summary>
    /// How long a session lasts without a request, after which the person signs in again: the cookie expires, and each
    /// request within the lifetime renews it. Fourteen days unless set — the default of ASP.NET Core, written here so
    /// that it is a decision, not an inheritance. A cookie the person did not ask to keep ends with the browser too.
    /// </summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromDays(14);

    /// <summary>
    /// How long a session goes without its account being read again. Once elapsed, the next request reads it: a session
    /// whose account is gone, deleted or blocked is closed, and the others carry the account as it is now. A session
    /// older than the interval is read again on its first request. Five minutes unless set; <see cref="TimeSpan.Zero"/>
    /// reads the account on every request.
    /// </summary>
    public TimeSpan ValidationInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <inheritdoc/>
    public string? FindError()
    {
        if (Lifetime <= TimeSpan.Zero)
            return $"{nameof(Lifetime)} must be positive.";
        if (ValidationInterval < TimeSpan.Zero)
            return $"{nameof(ValidationInterval)} is zero or positive.";
        return null;
    }
}

/// <summary>
/// How long what identifies a person is kept once it no longer serves: the trace of the logins, which holds an
/// address and a browser, and the tokens and verifications past their expiry. Each duration may be raised, not
/// lowered under its default: the trace answers who tried what, the tokens a "this link is invalid" told by a person.
/// </summary>
public sealed class RetentionOptions : IValidatableOptions
{
    /// <summary>The least the trace of the logins is kept: 180 days, the low end of what a security log keeps.</summary>
    public static readonly TimeSpan MinimumLoginEvents = TimeSpan.FromDays(180);

    /// <summary>The least a token or a verification is kept past its expiry: 30 days.</summary>
    public static readonly TimeSpan MinimumExpired = TimeSpan.FromDays(30);

    /// <summary>How long the trace of the logins is kept. <see cref="MinimumLoginEvents"/> unless set, and never less.</summary>
    public TimeSpan LoginEvents { get; set; } = MinimumLoginEvents;

    /// <summary>How long a token or a verification is kept past its expiry. <see cref="MinimumExpired"/> unless set, and never less.</summary>
    public TimeSpan Expired { get; set; } = MinimumExpired;

    /// <inheritdoc/>
    public string? FindError()
    {
        if (LoginEvents < MinimumLoginEvents)
            return $"{nameof(LoginEvents)} must be at least {MinimumLoginEvents.TotalDays} days.";
        if (Expired < MinimumExpired)
            return $"{nameof(Expired)} must be at least {MinimumExpired.TotalDays} days.";
        return null;
    }
}

/// <summary>Whether anyone with a verified e-mail creates their account.</summary>
public enum SelfRegistration
{
    /// <summary>Nobody registers alone: an administrator creates every account. The posture of an enterprise installation.</summary>
    Closed,

    /// <summary>Anyone with a verified e-mail registers. Being registered grants nothing (n° 1).</summary>
    Open,
}
