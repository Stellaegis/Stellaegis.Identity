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

/// <summary>Published when a disabled account is enabled again.</summary>
public sealed record UserUnblockedEvent : IEvent
{
    /// <inheritdoc/>
    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>The identity of the account, which its <c>sub</c> claim carries.</summary>
    public required Guid UserUniqueId { get; init; }
}
