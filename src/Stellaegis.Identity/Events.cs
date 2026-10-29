using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// Published when an account is created — by the person themselves, or by an administrator. A registry of the
/// application's users projects it; the host connects the subscription.
/// </summary>
public sealed record UserRegisteredEvent : IEvent
{
    /// <inheritdoc/>
    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>The identity of the account, which its <c>sub</c> claim carries.</summary>
    public required Guid UserUniqueId { get; init; }

    /// <summary>The e-mail of the account, normalized.</summary>
    public required string Email { get; init; }

    /// <summary>The display name of the account.</summary>
    public required string DisplayName { get; init; }
}

/// <summary>
/// Published when what others see of an account changes: its name, or its avatar. A registry that keeps a copy of
/// them for the people who share a compartment with the person refreshes it; the host connects the subscription,
/// and reads the image from <see cref="IAvatarStore"/> when it needs it.
/// </summary>
public sealed record UserProfileChangedEvent : IEvent
{
    /// <inheritdoc/>
    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>The identity of the account, which its <c>sub</c> claim carries.</summary>
    public required Guid UserUniqueId { get; init; }

    /// <summary>The display name of the account.</summary>
    public required string DisplayName { get; init; }

    /// <summary>When the avatar was set, or <see langword="null"/> when the account has none.</summary>
    public DateTimeOffset? AvatarModifiedAt { get; init; }
}

/// <summary>
/// Published when an account stops being admitted: disabled by an administrator, or deleted. A resource server
/// that caches the blocked accounts refuses the subject from then on; an issuer revokes its tokens.
/// </summary>
public sealed record UserBlockedEvent : IEvent
{
    /// <inheritdoc/>
    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>The identity of the account, which its <c>sub</c> claim carries.</summary>
    public required Guid UserUniqueId { get; init; }

    /// <summary>Why the account was blocked, for the journal: <c>disabled</c> or <c>deleted</c>.</summary>
    public required string Reason { get; init; }
}

/// <summary>
/// Published when the password of an account changes — chosen anew by its person, reset by a link, or removed by the
/// link that undoes a change of e-mail. What was issued on the former password is no longer the person's: an issuer
/// revokes the refresh tokens and the authorizations of the subject, so that whoever held the former password keeps
/// nothing that goes on; a host closes its other sessions when it can tell them apart.
/// </summary>
public sealed record UserPasswordChangedEvent : IEvent
{
    /// <summary>The <see cref="Reason"/> of a password the person changed, the current one confirmed.</summary>
    public const string ChangedReason = "changed";

    /// <summary>The <see cref="Reason"/> of a password reset by the link sent to the address of the account.</summary>
    public const string ResetReason = "reset";

    /// <summary>The <see cref="Reason"/> of a password removed by the link that undid a change of e-mail: the account waits for a new one.</summary>
    public const string RemovedReason = "removed";

    /// <inheritdoc/>
    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>The identity of the account, which its <c>sub</c> claim carries.</summary>
    public required Guid UserUniqueId { get; init; }

    /// <summary>How the password changed, for the journal: <see cref="ChangedReason"/>, <see cref="ResetReason"/> or <see cref="RemovedReason"/>.</summary>
    public required string Reason { get; init; }
}

/// <summary>Published when a disabled account is enabled again.</summary>
public sealed record UserUnblockedEvent : IEvent
{
    /// <inheritdoc/>
    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>The identity of the account, which its <c>sub</c> claim carries.</summary>
    public required Guid UserUniqueId { get; init; }
}
