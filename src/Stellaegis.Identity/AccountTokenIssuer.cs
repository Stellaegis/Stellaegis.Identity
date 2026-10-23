using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>Issues an account token the one way: the outstanding ones of the same purpose revoked, the hash alone kept.</summary>
internal static class AccountTokenIssuer
{
    /// <summary>
    /// Issues a token for <paramref name="user"/>, revoking the ones of <paramref name="purpose"/> still usable, and
    /// returns the token — the hash alone is kept, so that this is the one moment it exists in clear.
    /// </summary>
    public static async Task<string> IssueAsync(
        this IAccountTokenStore tokens, AuthUser user, AccountTokenPurpose purpose, TokenDelivery delivery, Actor createdBy,
        DateTimeOffset now, TimeSpan lifetime, string? ipAddress, CancellationToken cancellationToken)
    {
        var (token, hash) = AccountTokens.New();
        await tokens.RevokeOutstandingAsync(user.UserUniqueId, purpose, now, cancellationToken).ConfigureAwait(false);
        await tokens.CreateAsync(new AccountToken
        {
            TokenHash = hash,
            UserUniqueId = user.UserUniqueId,
            Purpose = purpose,
            Delivery = delivery,
            Email = user.Email,
            CreatedAt = now,
            CreatedBy = createdBy,
            ExpiresAt = now.Add(lifetime),
            IpAddress = ipAddress,
        }, cancellationToken).ConfigureAwait(false);
        return token;
    }
}
