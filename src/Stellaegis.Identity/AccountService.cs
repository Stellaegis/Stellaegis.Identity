using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// What a person does to their own account: changing the password or the e-mail, deleting it; and undoing a change of
/// e-mail from the link the previous address received.
/// </summary>
public sealed class AccountService(
    IAuthUserStore users,
    IAccountTokenStore tokens,
    IMfaStore mfa,
    IRecoveryCodeStore recoveryCodes,
    EmailVerificationService emailVerification,
    PasswordHasher hasher,
    PasswordStrengthEvaluator passwords,
    IEventPublisher events,
    IOptions<IdentityOptions> options,
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

    /// <summary>
    /// Completes the change of e-mail once <paramref name="code"/> proves the new one, and issues the token of the
    /// link that undoes it, for the host to send to the previous address with the notice. The host then signs the
    /// session out: it carries the previous address.
    /// </summary>
    public async Task<Result<EmailChanged>> ConfirmEmailChangeAsync(Guid userUniqueId, string newEmail, string? code, CancellationToken cancellationToken = default)
    {
        var normalized = Emails.Normalize(newEmail);
        var verified = await emailVerification.VerifyCodeAsync(normalized, code, cancellationToken);
        if (verified.IsFailure)
            return Result.Failure<EmailChanged>(verified.Error!);
        // Checked again: another account may have taken the e-mail between the request and the code.
        if (await users.GetByEmailAsync(normalized, cancellationToken) is not null)
            return Result.Failure<EmailChanged>(IdentityErrors.EmailTaken);
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null || !user.IsEnabled)
            return Result.Failure<EmailChanged>(IdentityErrors.AccountNotFound);

        var now = clock.GetUtcNow();
        var previous = user.Email;
        // Issued before the change, so that the token keeps the address to restore; kept beside the earlier ones, so
        // that a second change does not kill the link of the first — the earliest link restores the earliest address.
        var revert = await tokens.IssueAsync(user, AccountTokenPurpose.EmailRevert, TokenDelivery.Email, user.AsActor(), now, options.Value.EmailChange.RevertLifetime, null, cancellationToken, keepOutstanding: true);
        user.Email = normalized;
        user.EmailVerified = true;
        user.ModifiedAt = now;
        user.ModifiedBy = user.AsActor();
        await users.UpdateAsync(user, cancellationToken);
        await emailVerification.CleanupAsync(normalized, cancellationToken);
        logger.LogInformation("E-mail of {UserUniqueId} changed", userUniqueId);
        return Result.Success(new EmailChanged(previous, normalized, revert));
    }

    /// <summary>
    /// The address <paramref name="token"/> would restore, when it can still be used, or <see langword="null"/>: to
    /// show the page, or refuse the link. Reading it spends nothing.
    /// </summary>
    public async Task<string?> ValidateRevertTokenAsync(string token, CancellationToken cancellationToken = default)
        => await FindRevertAsync(token, cancellationToken) is { } stored
            && stored.IsValidAt(clock.GetUtcNow())
            && await users.GetByUniqueIdAsync(stored.UserUniqueId, cancellationToken) is { IsEnabled: true }
            ? stored.Email
            : null;

    /// <summary>
    /// Undoes the change of e-mail <paramref name="token"/> was issued for — the act of a person whose session was not
    /// theirs: the previous address is restored, the password removed, since whoever changed the address knew it, the
    /// reset links and the other links of this kind revoked, a second factor enrolled since the change removed. The
    /// sessions close at their next reading: an account without a password keeps none. A reset token is issued for
    /// the host to send to the restored address, by which the person chooses a new password.
    /// </summary>
    public async Task<Result<EmailReverted>> RevertEmailChangeAsync(string token, CancellationToken cancellationToken = default)
    {
        var stored = await FindRevertAsync(token, cancellationToken);
        if (stored is null || stored.ConsumedAt is not null || stored.RevokedAt is not null)
            return Result.Failure<EmailReverted>(IdentityErrors.InvalidRevertToken);
        var now = clock.GetUtcNow();
        if (stored.ExpiresAt < now)
            return Result.Failure<EmailReverted>(IdentityErrors.RevertTokenExpired);
        var user = await users.GetByUniqueIdAsync(stored.UserUniqueId, cancellationToken);
        if (user is null || !user.IsEnabled)
            return Result.Failure<EmailReverted>(IdentityErrors.InvalidRevertToken);
        if (!string.Equals(user.Email, stored.Email, StringComparison.Ordinal) && await users.GetByEmailAsync(stored.Email, cancellationToken) is not null)
            return Result.Failure<EmailReverted>(IdentityErrors.EmailTaken);
        if (!await tokens.TryConsumeAsync(stored.TokenHash, now, cancellationToken))
            return Result.Failure<EmailReverted>(IdentityErrors.InvalidRevertToken);

        user.Email = stored.Email;
        user.EmailVerified = true;   // the link reached it
        user.PasswordHash = null;
        user.FailedLoginCount = 0;
        user.FailedLoginLast = null;
        user.BlockedUntil = null;
        user.ModifiedAt = now;
        user.ModifiedBy = user.AsActor();
        await users.UpdateAsync(user, cancellationToken);
        await tokens.RevokeOutstandingAsync(user.UserUniqueId, AccountTokenPurpose.EmailRevert, now, cancellationToken);
        if (await mfa.GetAsync(user.UserUniqueId, cancellationToken) is { IsEnabled: true, EnabledAt: { } enabledAt } && enabledAt >= stored.CreatedAt)
        {
            await mfa.DisableAsync(user.UserUniqueId, cancellationToken);
            await recoveryCodes.DeleteAllAsync(user.UserUniqueId, cancellationToken);
        }
        var reset = await tokens.IssueAsync(user, AccountTokenPurpose.PasswordReset, TokenDelivery.Email, user.AsActor(), now, options.Value.PasswordReset.TokenLifetime, null, cancellationToken);
        logger.LogWarning("E-mail of {UserUniqueId} restored by its previous address: the password is removed", user.UserUniqueId);
        return Result.Success(new EmailReverted(user.Email, reset));
    }

    private async Task<AccountToken?> FindRevertAsync(string token, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(token))
            return null;
        var stored = await tokens.GetAsync(AccountTokens.Hash(token), cancellationToken);
        return stored?.Purpose == AccountTokenPurpose.EmailRevert ? stored : null;
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
