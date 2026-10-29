using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>A person who forgot their password: a link sent to their e-mail, good once, for a while.</summary>
public sealed class PasswordResetService(
    IAuthUserStore users,
    IAccountTokenStore tokens,
    PasswordHasher hasher,
    PasswordStrengthEvaluator passwords,
    IEventPublisher events,
    IOptions<IdentityOptions> options,
    TimeProvider clock,
    ILogger<PasswordResetService> logger)
{
    /// <summary>
    /// Issues a reset token for the account of <paramref name="email"/>, which the host puts in a link and sends
    /// there; <see langword="null"/> when no enabled account has that e-mail, or when the e-mail of the account was
    /// never proven — a mistyped address would hand the account to whoever holds it. The caller shows the same
    /// message either way, so that the answer does not say which e-mails have an account. A newer token revokes the
    /// previous ones; only its hash is kept. Asked again within <see cref="PasswordResetOptions.MinimumInterval"/> of
    /// the last one, whoever asked it, nothing is issued and <see langword="null"/> is answered too: the link sent
    /// still works, and a stranger neither floods the mailbox nor revokes the link the person waits for.
    /// </summary>
    public async Task<string?> RequestResetAsync(string email, string? ipAddress = null, CancellationToken cancellationToken = default)
    {
        var normalized = Emails.Normalize(email);
        var user = await users.GetByEmailAsync(normalized, cancellationToken);
        if (user is null || !user.IsEnabled)
            return null;
        if (!user.EmailVerified)
        {
            logger.LogWarning("Password reset of {UserUniqueId} not sent: its e-mail was never verified", user.UserUniqueId);
            return null;
        }
        var now = clock.GetUtcNow();
        var interval = options.Value.PasswordReset.MinimumInterval;
        if (interval > TimeSpan.Zero
            && await tokens.LastIssuedAtAsync(user.UserUniqueId, AccountTokenPurpose.PasswordReset, cancellationToken) is { } last
            && last + interval > now)
        {
            logger.LogInformation("Password reset of {UserUniqueId} not sent again: one was issued less than {Interval} ago", user.UserUniqueId, interval);
            return null;
        }
        var token = await tokens.IssueAsync(
            user, AccountTokenPurpose.PasswordReset, TokenDelivery.Email, user.AsActor(),
            now, options.Value.PasswordReset.TokenLifetime, ipAddress, cancellationToken);
        logger.LogInformation("Password reset requested for {UserUniqueId}", user.UserUniqueId);
        return token;
    }

    /// <summary>
    /// Whether <paramref name="token"/> can still be used: to show the form, or refuse the link. Reading it spends
    /// nothing — the scanners of mail systems and the previews of messaging applications open links ahead.
    /// </summary>
    public async Task<bool> ValidateTokenAsync(string token, CancellationToken cancellationToken = default)
        => await FindAsync(token, cancellationToken) is { } stored && stored.IsValidAt(clock.GetUtcNow());

    /// <summary>
    /// Sets the new password of the account <paramref name="token"/> was issued for; the token is spent first, so
    /// that two uses at once cannot both succeed. A lockout in progress ends with it, and
    /// <see cref="UserPasswordChangedEvent"/> says the former password is no longer the person's.
    /// </summary>
    public async Task<Result> ResetPasswordAsync(string token, string newPassword, CancellationToken cancellationToken = default)
    {
        var stored = await FindAsync(token, cancellationToken);
        if (stored is null || stored.ConsumedAt is not null || stored.RevokedAt is not null)
            return Result.Failure(IdentityErrors.InvalidResetToken);
        var now = clock.GetUtcNow();
        if (stored.ExpiresAt < now)
            return Result.Failure(IdentityErrors.ResetTokenExpired);
        var user = await users.GetByUniqueIdAsync(stored.UserUniqueId, cancellationToken);
        if (user is null || !user.IsEnabled)
            return Result.Failure(IdentityErrors.InvalidResetToken);
        if (await passwords.RefuseAsync(newPassword, cancellationToken) is { } refused)
            return Result.Failure(refused);
        if (!await tokens.TryConsumeAsync(stored.TokenHash, now, cancellationToken))
            return Result.Failure(IdentityErrors.InvalidResetToken);

        user.PasswordHash = hasher.Hash(newPassword);
        user.EmailVerified |= stored.Delivery == TokenDelivery.Email;   // the link reached the address the system sent it to
        user.FailedLoginCount = 0;
        user.BlockedUntil = null;
        user.ModifiedAt = now;
        user.ModifiedBy = user.AsActor();
        await users.UpdateAsync(user, cancellationToken);
        await events.PublishAsync(new UserPasswordChangedEvent { OccurredAt = now, UserUniqueId = user.UserUniqueId, Reason = UserPasswordChangedEvent.ResetReason }, cancellationToken);
        logger.LogInformation("Password of {UserUniqueId} reset", user.UserUniqueId);
        return Result.Success();
    }

    private async Task<AccountToken?> FindAsync(string token, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(token))
            return null;
        var stored = await tokens.GetAsync(AccountTokens.Hash(token), cancellationToken);
        return stored?.Purpose == AccountTokenPurpose.PasswordReset ? stored : null;
    }
}
