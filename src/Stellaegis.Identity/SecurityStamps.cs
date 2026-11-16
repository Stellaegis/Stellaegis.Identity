using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// The security stamp of an account, the mechanism of ASP.NET Core Identity: a random value that changes with
/// whatever must close the other sessions of the account — a new password, a block, a change of the second factor or
/// of the e-mail. A session carries the stamp of its sign-in, <see cref="ClaimType"/>, and is held against the account
/// at every reading: another stamp, or none, closes it. A token issuer keeps it for the code and the refresh token,
/// and the admission of the accounts holds a refresh against the account the same way.
/// </summary>
public static class SecurityStamps
{
    /// <summary>
    /// The claim a session carries its stamp in, <c>stellaegis.security_stamp</c>, <see cref="SessionClaims.SecurityStamp"/>
    /// of Primitives: in the cookie, and kept by a token issuer for the code and the refresh token, never in a token a
    /// client or a service reads.
    /// </summary>
    public const string ClaimType = SessionClaims.SecurityStamp;

    /// <summary>A new stamp: 128 random bits, in lowercase hexadecimal.</summary>
    public static string New() => Guid.NewGuid().ToString("N");

    // Renews the stamp of the account — its other sessions close at their next reading, its refresh tokens are refused —
    // and publishes UserSecurityStampRenewedEvent, so that a host revokes the access tokens already issued at once.
    internal static async Task<bool> RenewAsync(
        IAuthUserStore users, IEventPublisher events, TimeProvider clock, Guid userUniqueId, string reason, CancellationToken cancellationToken)
    {
        if (!await users.RenewSecurityStampAsync(userUniqueId, New(), cancellationToken))
            return false;
        await events.PublishAsync(new UserSecurityStampRenewedEvent { OccurredAt = clock.GetUtcNow(), UserUniqueId = userUniqueId, Reason = reason }, cancellationToken);
        return true;
    }
}
