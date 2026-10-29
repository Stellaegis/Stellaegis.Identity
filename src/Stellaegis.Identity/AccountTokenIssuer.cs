using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>Issues an account token the one way: the outstanding ones of the same purpose revoked, the hash alone kept.</summary>
internal static class AccountTokenIssuer
{
    /// <summary>
    /// Issues a token for <paramref name="user"/>, revoking the ones of <paramref name="purpose"/> still usable unless
    /// <paramref name="keepOutstanding"/> — a link that undoes a change must survive the next change —, and returns
    /// the token — the hash alone is kept, so that this is the one moment it exists in clear. The token keeps the
    /// address of the account, or <paramref name="email"/> when the purpose is about another one — the address a
    /// change of e-mail applies.
    /// </summary>
    public static async Task<string> IssueAsync(
        this IAccountTokenStore tokens, AuthUser user, AccountTokenPurpose purpose, TokenDelivery delivery, Actor createdBy,
        DateTimeOffset now, TimeSpan lifetime, string? ipAddress, CancellationToken cancellationToken, bool keepOutstanding = false, string? email = null)
    {
        var (token, hash) = AccountTokens.New();
        if (!keepOutstanding)
            await tokens.RevokeOutstandingAsync(user.UserUniqueId, purpose, now, cancellationToken).ConfigureAwait(false);
        await tokens.CreateAsync(new AccountToken
        {
            TokenHash = hash,
            UserUniqueId = user.UserUniqueId,
            Purpose = purpose,
            Delivery = delivery,
            Email = email ?? user.Email,
            CreatedAt = now,
            CreatedBy = createdBy,
            ExpiresAt = now.Add(lifetime),
            IpAddress = ipAddress,
        }, cancellationToken).ConfigureAwait(false);
        return token;
    }
}
