using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>What a person does to their own account: changing the password or the e-mail, deleting it.</summary>
public sealed class AccountService(
    IAuthUserStore users,
    EmailVerificationService emailVerification,
    PasswordHasher hasher,
    PasswordStrengthEvaluator passwords,
    IEventPublisher events,
    TimeProvider clock,
    ILogger<AccountService> logger)
{
    /// <summary>Changes the password, once the current one is confirmed; a lockout in progress ends with it.</summary>
    public async Task<Result> ChangePasswordAsync(Guid userUniqueId, string currentPassword, string newPassword, CancellationToken cancellationToken = default)
    {
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null || !user.IsEnabled)
            return Result.Failure(IdentityErrors.AccountNotFound);
        if (!hasher.Verify(currentPassword, user.PasswordHash))
            return Result.Failure(IdentityErrors.InvalidCurrentPassword);
        var violations = passwords.Violations(newPassword);
        if (violations.Count > 0)
            return Result.Failure(IdentityErrors.PasswordRejected(violations));

        user.PasswordHash = hasher.Hash(newPassword);
        user.FailedLoginCount = 0;
        user.BlockedUntil = null;
        user.ModifiedAt = clock.GetUtcNow();
        user.ModifiedBy = user.AsActor();
        await users.UpdateAsync(user, cancellationToken);
        logger.LogInformation("Password of {UserUniqueId} changed", userUniqueId);
        return Result.Success();
    }

    /// <summary>
    /// Starts a change of e-mail by issuing a code for the new one, which the host sends there. The caller shows
    /// the same message whatever the outcome, so that the answer does not say which e-mails have an account.
    /// </summary>
    public async Task<Result<string>> RequestEmailChangeAsync(Guid userUniqueId, string newEmail, string? ipAddress = null, CancellationToken cancellationToken = default)
    {
        var normalized = Emails.Normalize(newEmail);
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null || !user.IsEnabled)
            return Result.Failure<string>(IdentityErrors.AccountNotFound);
        if (string.Equals(user.Email, normalized, StringComparison.Ordinal))
            return Result.Failure<string>(IdentityErrors.SameEmail);
        if (await users.GetByEmailAsync(normalized, cancellationToken) is not null)
            return Result.Failure<string>(IdentityErrors.EmailTaken);

        // A verification left by an abandoned registration on this e-mail would otherwise stand in the way.
        await emailVerification.CleanupAsync(normalized, cancellationToken);
        var issued = await emailVerification.RequestVerificationAsync(normalized, ipAddress, cancellationToken);
        if (issued.IsFailure)
            return issued;
        logger.LogInformation("E-mail change of {UserUniqueId} requested", userUniqueId);
        return issued;
    }

    /// <summary>Completes the change of e-mail once <paramref name="code"/> proves the new one. The host then renews the session.</summary>
    public async Task<Result> ConfirmEmailChangeAsync(Guid userUniqueId, string newEmail, string? code, CancellationToken cancellationToken = default)
    {
        var normalized = Emails.Normalize(newEmail);
        var verified = await emailVerification.VerifyCodeAsync(normalized, code, cancellationToken);
        if (verified.IsFailure)
            return verified;
        // Checked again: another account may have taken the e-mail between the request and the code.
        if (await users.GetByEmailAsync(normalized, cancellationToken) is not null)
            return Result.Failure(IdentityErrors.EmailTaken);
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null || !user.IsEnabled)
            return Result.Failure(IdentityErrors.AccountNotFound);

        user.Email = normalized;
        user.EmailVerified = true;
        user.ModifiedAt = clock.GetUtcNow();
        user.ModifiedBy = user.AsActor();
        await users.UpdateAsync(user, cancellationToken);
        await emailVerification.CleanupAsync(normalized, cancellationToken);
        logger.LogInformation("E-mail of {UserUniqueId} changed", userUniqueId);
        return Result.Success();
    }

    /// <summary>
    /// Starts the verification of the account's current e-mail, never proven, by issuing a code the host sends there.
    /// </summary>
    public async Task<Result<string>> RequestEmailVerificationAsync(Guid userUniqueId, string? ipAddress = null, CancellationToken cancellationToken = default)
    {
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null || !user.IsEnabled)
            return Result.Failure<string>(IdentityErrors.AccountNotFound);
        if (user.EmailVerified)
            return Result.Failure<string>(IdentityErrors.EmailAlreadyVerified);
        await emailVerification.CleanupAsync(user.Email, cancellationToken);
        return await emailVerification.RequestVerificationAsync(user.Email, ipAddress, cancellationToken);
    }

    /// <summary>Marks the account's current e-mail verified once <paramref name="code"/> proves it.</summary>
    public async Task<Result> ConfirmEmailVerificationAsync(Guid userUniqueId, string? code, CancellationToken cancellationToken = default)
    {
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null || !user.IsEnabled)
            return Result.Failure(IdentityErrors.AccountNotFound);
        var verified = await emailVerification.VerifyCodeAsync(user.Email, code, cancellationToken);
        if (verified.IsFailure)
            return verified;
        user.EmailVerified = true;
        user.ModifiedAt = clock.GetUtcNow();
        user.ModifiedBy = user.AsActor();
        await users.UpdateAsync(user, cancellationToken);
        await emailVerification.CleanupAsync(user.Email, cancellationToken);
        logger.LogInformation("E-mail of {UserUniqueId} verified", userUniqueId);
        return Result.Success();
    }

    /// <summary>Whether <paramref name="password"/> is the account's, to confirm an operation that changes nothing by itself.</summary>
    public async Task<bool> VerifyCurrentPasswordAsync(Guid userUniqueId, string password, CancellationToken cancellationToken = default)
    {
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        return user is { IsEnabled: true } && hasher.Verify(password, user.PasswordHash);
    }

    /// <summary>Deletes the account, once the password is confirmed. The host ends the session; an issuer revokes the tokens on the event.</summary>
    public async Task<Result> DeleteAccountAsync(Guid userUniqueId, string currentPassword, CancellationToken cancellationToken = default)
    {
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null || !user.IsEnabled)
            return Result.Failure(IdentityErrors.AccountNotFound);
        if (!hasher.Verify(currentPassword, user.PasswordHash))
            return Result.Failure(IdentityErrors.InvalidCurrentPassword);
        if (!await users.SoftDeleteAsync(userUniqueId, user.AsActor(), cancellationToken))
            return Result.Failure(IdentityErrors.AccountNotFound);
        await events.PublishAsync(new UserBlockedEvent { OccurredAt = clock.GetUtcNow(), UserUniqueId = userUniqueId, Reason = AccountAdministrationService.DeletedReason }, cancellationToken);
        logger.LogInformation("Account {UserUniqueId} deleted by its owner", userUniqueId);
        return Result.Success();
    }
}
