using Microsoft.Extensions.Logging;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// A person choosing the first password of the account an administrator created for them, by the link they
/// received: good once, for a while. Nobody else ever chose or knew that password.
/// </summary>
public sealed class ActivationService(
    IAuthUserStore users,
    IAccountTokenStore tokens,
    PasswordHasher hasher,
    PasswordStrengthEvaluator passwords,
    TimeProvider clock,
    ILogger<ActivationService> logger)
{
    /// <summary>
    /// Whether <paramref name="token"/> can still activate its account: to show the form, or refuse the link. Reading
    /// it spends nothing — the scanners of mail systems and the previews of messaging applications open links ahead.
    /// </summary>
    public async Task<bool> ValidateTokenAsync(string token, CancellationToken cancellationToken = default)
        => await FindAsync(token, cancellationToken) is { } stored
            && stored.IsValidAt(clock.GetUtcNow())
            && await users.GetByUniqueIdAsync(stored.UserUniqueId, cancellationToken) is { IsEnabled: true, IsActivated: false };

    /// <summary>
    /// Sets the first password of the account <paramref name="token"/> was issued for; the token is spent first, so
    /// that two uses at once cannot both succeed. The person is the author of the change.
    /// </summary>
    public async Task<Result> ActivateAsync(string token, string password, CancellationToken cancellationToken = default)
    {
        var stored = await FindAsync(token, cancellationToken);
        if (stored is null || stored.ConsumedAt is not null || stored.RevokedAt is not null)
            return Result.Failure(IdentityErrors.InvalidActivationToken);
        var now = clock.GetUtcNow();
        if (stored.ExpiresAt < now)
            return Result.Failure(IdentityErrors.ActivationTokenExpired);
        var user = await users.GetByUniqueIdAsync(stored.UserUniqueId, cancellationToken);
        if (user is null || !user.IsEnabled || user.IsActivated)
            return Result.Failure(IdentityErrors.InvalidActivationToken);
        var violations = passwords.Violations(password);
        if (violations.Count > 0)
            return Result.Failure(IdentityErrors.PasswordRejected(violations));
        if (!await tokens.TryConsumeAsync(stored.TokenHash, now, cancellationToken))
            return Result.Failure(IdentityErrors.InvalidActivationToken);

        user.PasswordHash = hasher.Hash(password);
        user.ModifiedAt = now;
        user.ModifiedBy = user.AsActor();
        await users.UpdateAsync(user, cancellationToken);
        logger.LogInformation("Account {UserUniqueId} activated", user.UserUniqueId);
        return Result.Success();
    }

    private async Task<AccountToken?> FindAsync(string token, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(token))
            return null;
        var stored = await tokens.GetAsync(AccountTokens.Hash(token), cancellationToken);
        return stored?.Purpose == AccountTokenPurpose.Activation ? stored : null;
    }
}
