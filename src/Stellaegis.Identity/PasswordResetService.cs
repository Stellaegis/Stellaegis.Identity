using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>A person who forgot their password: a link sent to their e-mail, good once, for a while.</summary>
public sealed class PasswordResetService(
    IAuthUserStore users,
    IPasswordResetStore tokens,
    PasswordHasher hasher,
    PasswordStrengthEvaluator passwords,
    IOptions<IdentityOptions> options,
    TimeProvider clock,
    ILogger<PasswordResetService> logger)
{
    /// <summary>
    /// Issues a reset token for the account of <paramref name="email"/>, which the host puts in a link and sends
    /// there; <see langword="null"/> when no enabled account has that e-mail. The caller shows the same message
    /// either way, so that the answer does not say which e-mails have an account.
    /// </summary>
    public async Task<Guid?> RequestResetAsync(string email, string? ipAddress = null, CancellationToken cancellationToken = default)
    {
        var normalized = Emails.Normalize(email);
        var user = await users.GetByEmailAsync(normalized, cancellationToken);
        if (user is null || !user.IsEnabled)
            return null;
        var now = clock.GetUtcNow();
        var token = new PasswordResetToken
        {
            Token = Guid.NewGuid(),
            UserUniqueId = user.UserUniqueId,
            Email = normalized,
            CreatedAt = now,
            ExpiresAt = now.Add(options.Value.PasswordReset.TokenLifetime),
            IpAddress = ipAddress,
        };
        await tokens.CreateAsync(token, cancellationToken);
        logger.LogInformation("Password reset requested for {UserUniqueId}", user.UserUniqueId);
        return token.Token;
    }

    /// <summary>Whether <paramref name="token"/> can still be used: to show the form, or refuse the link.</summary>
    public async Task<bool> ValidateTokenAsync(Guid token, CancellationToken cancellationToken = default)
        => (await tokens.GetByTokenAsync(token, cancellationToken))?.IsValidAt(clock.GetUtcNow()) is true;

    /// <summary>Sets the new password of the account <paramref name="token"/> was issued for, and spends the token; a lockout in progress ends with it.</summary>
    public async Task<Result> ResetPasswordAsync(Guid token, string newPassword, CancellationToken cancellationToken = default)
    {
        var stored = await tokens.GetByTokenAsync(token, cancellationToken);
        if (stored is null || stored.ConsumedAt is not null)
            return Result.Failure(IdentityErrors.InvalidResetToken);
        var now = clock.GetUtcNow();
        if (stored.ExpiresAt < now)
            return Result.Failure(IdentityErrors.ResetTokenExpired);
        var user = await users.GetByUniqueIdAsync(stored.UserUniqueId, cancellationToken);
        if (user is null || !user.IsEnabled)
            return Result.Failure(IdentityErrors.InvalidResetToken);
        var violations = passwords.Violations(newPassword);
        if (violations.Count > 0)
            return Result.Failure(IdentityErrors.PasswordRejected(violations));

        user.PasswordHash = hasher.Hash(newPassword);
        user.FailedLoginCount = 0;
        user.BlockedUntil = null;
        user.ModifiedAt = now;
        user.ModifiedBy = user.AsActor();
        await users.UpdateAsync(user, cancellationToken);
        await tokens.ConsumeAsync(token, now, cancellationToken);
        logger.LogInformation("Password of {UserUniqueId} reset", user.UserUniqueId);
        return Result.Success();
    }
}
