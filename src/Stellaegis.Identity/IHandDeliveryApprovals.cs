using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// The approval, by a second person, of a password reset link handed over to an administrator for an account that is
/// active — the way back for a person who lost both their mailbox and their password. Handed over, the link gives its
/// holder the account: one administrator alone never gets it. Identity declares the port; the host's rights system
/// implements it — <c>Stellaegis.Registry</c>, by its validations. Without it, such a link is refused.
/// </summary>
/// <remarks>
/// Pulled, never pushed: the administrator asks (<see cref="RequestAsync"/>), a second person approves through the
/// implementation's own channel, the administrator asks again with the approval, which is spent once
/// (<see cref="TryConsumeAsync"/>). An activation link is handed over without it: the account has nothing to protect
/// until its person chose a password.
/// </remarks>
public interface IHandDeliveryApprovals
{
    /// <summary>Opens a request to hand a reset link of <paramref name="subject"/> over to <paramref name="requestedBy"/>, and returns its identifier.</summary>
    Task<Guid> RequestAsync(Subject subject, Actor requestedBy, CancellationToken cancellationToken = default);

    /// <summary>
    /// Whether <paramref name="approval"/> was approved by another person than <paramref name="requestedBy"/>, for that
    /// subject and that requester, and not spent yet: <see langword="true"/> spends it. The check and the spending are
    /// one, so that an approval hands one link over.
    /// </summary>
    Task<bool> TryConsumeAsync(Guid approval, Subject subject, Actor requestedBy, CancellationToken cancellationToken = default);
}
