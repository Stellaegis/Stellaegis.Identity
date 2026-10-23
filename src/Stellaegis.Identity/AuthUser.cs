using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// An account of the application: who can sign in, with which e-mail and which password. The second factor and
/// the recovery codes are kept apart, by <see cref="IMfaStore"/> and <see cref="IRecoveryCodeStore"/>.
/// </summary>
public sealed class AuthUser
{
    /// <summary>The identity of the account, which its <c>sub</c> claim carries. Never reused.</summary>
    public Guid UserUniqueId { get; set; }

    /// <summary>The e-mail the person signs in with, lowercase and trimmed. Unique among the accounts.</summary>
    public string Email { get; set; } = "";

    /// <summary>The name shown to the person and to others.</summary>
    public string DisplayName { get; set; } = "";

    /// <summary>The password, as <see cref="PasswordHasher"/> stores it: <c>pbkdf2_sha256$iterations$salt$hash</c>.</summary>
    /// <remarks>
    /// <see langword="null"/> while the account waits for its activation: an administrator created it without a
    /// password, and the person chooses one by the link they received. Such an account does not sign in.
    /// </remarks>
    public string? PasswordHash { get; set; }

    /// <summary>Whether the account has a password: created by its person, or activated.</summary>
    public bool IsActivated => PasswordHash is not null;

    /// <summary>Whether the person may sign in. An administrator disables an account; a disabled account is blocked at the door.</summary>
    public bool IsEnabled { get; set; }

    /// <summary>Consecutive failed logins since the last successful one.</summary>
    public int FailedLoginCount { get; set; }

    /// <summary>When the last failed login happened, or <see langword="null"/>.</summary>
    public DateTimeOffset? FailedLoginLast { get; set; }

    /// <summary>Until when the account is locked after too many failed logins, or <see langword="null"/>. A lockout is not a block at the door.</summary>
    public DateTimeOffset? BlockedUntil { get; set; }

    /// <summary>When the account was created.</summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Who created the account: the person themselves, or an administrator.</summary>
    public required Actor CreatedBy { get; set; }

    /// <summary>When the account was last changed.</summary>
    public DateTimeOffset ModifiedAt { get; set; }

    /// <summary>Who last changed the account.</summary>
    public required Actor ModifiedBy { get; set; }

    /// <summary>When the person last signed in, or <see langword="null"/> if they never did.</summary>
    public DateTimeOffset? LastLogin { get; set; }

    /// <summary>Whether the account was deleted. A deleted account stays, so that its identity is never reused, and is blocked at the door.</summary>
    public bool IsDeleted { get; set; }

    /// <summary>When the account was deleted, or <see langword="null"/>.</summary>
    public DateTimeOffset? DeletedAt { get; set; }

    /// <summary>Who deleted the account, or <see langword="null"/>.</summary>
    public Actor? DeletedBy { get; set; }

    /// <summary>
    /// Whether the account is blocked at the door: disabled, or deleted. A lockout after failed logins
    /// (<see cref="BlockedUntil"/>) is a matter of the login, not a block: it is deliberately left out. This is the
    /// one predicate the local source of blocked accounts and the administration share.
    /// </summary>
    public bool IsBlockedAtDoor => !IsEnabled || IsDeleted;

    /// <summary>The subject of the account, as its <c>sub</c> claim carries it: the id in the <c>N</c> format.</summary>
    public string Subject => UserUniqueId.ToString("N");

    /// <summary>The account as an actor, for what the person does to their own account.</summary>
    public Actor AsActor() => Actor.Parse(Subject);
}
