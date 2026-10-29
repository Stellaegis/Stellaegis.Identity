using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// What a person does to their own account: changing the password or the e-mail, deleting it; and undoing a change of
/// e-mail from the link the previous address received. A password typed from a session to confirm one of these is a
/// login attempt, and counts as one: it is refused while the account is locked out, a wrong one counts toward the
/// lockout and is traced, and the answer takes <see cref="LoginPolicyOptions.MinResponseTime"/> at least.
/// </summary>
public sealed class AccountService(
    IAuthUserStore users,
    IAccountTokenStore tokens,
    IMfaStore mfa,
    IRecoveryCodeStore recoveryCodes,
    FailedLoginCounter failures,
    EmailVerificationService emailVerification,
    PasswordHasher hasher,
    PasswordStrengthEvaluator passwords,
    IEventPublisher events,
    IOptions<IdentityOptions> options,
    TimeProvider clock,
    ILogger<AccountService> logger)
{
    /// <summary>Changes the password, once the current one is confirmed; the failed logins are forgotten with it.</summary>
    public async Task<Result> ChangePasswordAsync(Guid userUniqueId, string currentPassword, string newPassword, string? ipAddress = null, CancellationToken cancellationToken = default)
    {
        var confirmed = await ConfirmPasswordAsync(userUniqueId, currentPassword, ipAddress, cancellationToken);
        if (confirmed.IsFailure)
            return Result.Failure(confirmed.Error!);
        if (await passwords.RefuseAsync(newPassword, cancellationToken) is { } refused)
            return Result.Failure(refused);

        var user = confirmed.Value;
        var now = clock.GetUtcNow();
        user.PasswordHash = hasher.Hash(newPassword);
        user.FailedLoginCount = 0;
        user.FailedLoginLast = null;
        user.BlockedUntil = null;
        user.ModifiedAt = now;
        user.ModifiedBy = user.AsActor();
        await users.UpdateAsync(user, cancellationToken);
        await events.PublishAsync(new UserPasswordChangedEvent { OccurredAt = now, UserUniqueId = userUniqueId, Reason = UserPasswordChangedEvent.ChangedReason }, cancellationToken);
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

        // A registration pending on this e-mail keeps its own verification: this one is the account's.
        var issued = await emailVerification.RequestVerificationAsync(normalized, EmailVerificationPurpose.EmailChange, userUniqueId, ipAddress, cancellationToken);
        if (issued.IsFailure)
            return issued;
        logger.LogInformation("E-mail change of {UserUniqueId} requested", userUniqueId);
        return issued;
    }

    /// <summary>
    /// Takes the change of e-mail once <paramref name="code"/> proves the new one. When the previous address must
    /// approve it (<see cref="EmailChangeOptions.RequireApprovalByPrevious"/>), the change waits: the token of the
    /// approval link is issued for the host to send there, and the account keeps its address — a newer request replaces
    /// the link. Otherwise the change applies, and the token of the link that undoes it is issued for the notice to
    /// the previous address; the host then signs the session out, which carries the previous address.
    /// </summary>
    public async Task<Result<EmailChanged>> ConfirmEmailChangeAsync(Guid userUniqueId, string newEmail, string? code, CancellationToken cancellationToken = default)
    {
        var normalized = Emails.Normalize(newEmail);
        var verified = await emailVerification.VerifyCodeAsync(normalized, EmailVerificationPurpose.EmailChange, userUniqueId, code, cancellationToken);
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
        if (options.Value.EmailChange.RequireApprovalByPrevious)
        {
            var approval = await tokens.IssueAsync(user, AccountTokenPurpose.EmailChangeApproval, TokenDelivery.Email, user.AsActor(), now, options.Value.EmailChange.ApprovalLifetime, null, cancellationToken, email: normalized);
            await emailVerification.CleanupAsync(normalized, EmailVerificationPurpose.EmailChange, cancellationToken);
            logger.LogInformation("E-mail change of {UserUniqueId} waits for the approval of its previous address", userUniqueId);
            return Result.Success(new EmailChanged(previous, normalized, null, approval));
        }
        // Issued before the change, so that the token keeps the address to restore; kept beside the earlier ones, so
        // that a second change does not kill the link of the first — the earliest link restores the earliest address.
        var revert = await tokens.IssueAsync(user, AccountTokenPurpose.EmailRevert, TokenDelivery.Email, user.AsActor(), now, options.Value.EmailChange.RevertLifetime, null, cancellationToken, keepOutstanding: true);
        user.Email = normalized;
        user.EmailVerified = true;
        user.ModifiedAt = now;
        user.ModifiedBy = user.AsActor();
        await users.UpdateAsync(user, cancellationToken);
        await emailVerification.CleanupAsync(normalized, EmailVerificationPurpose.EmailChange, cancellationToken);
        logger.LogInformation("E-mail of {UserUniqueId} changed", userUniqueId);
        return Result.Success(new EmailChanged(previous, normalized, revert, null));
    }

    /// <summary>
    /// The change <paramref name="token"/> would apply — the address the account has, the one it would have —, when it
    /// can still be used, or <see langword="null"/>: to show the page, or refuse the link. Reading it spends nothing.
    /// </summary>
    public async Task<EmailChangeApproved?> ValidateApprovalTokenAsync(string token, CancellationToken cancellationToken = default)
        => await FindAsync(token, AccountTokenPurpose.EmailChangeApproval, cancellationToken) is { } stored
            && stored.IsValidAt(clock.GetUtcNow())
            && await users.GetByUniqueIdAsync(stored.UserUniqueId, cancellationToken) is { IsEnabled: true } user
            ? new EmailChangeApproved(user.Email, stored.Email)
            : null;

    /// <summary>
    /// Applies the change of e-mail <paramref name="token"/> was issued for, by the approval of the previous address:
    /// the account takes the new address, proven by its code. The host then closes the session of the browser that
    /// holds the link, if it has one: it carries the previous address.
    /// </summary>
    public async Task<Result<EmailChangeApproved>> ApproveEmailChangeAsync(string token, CancellationToken cancellationToken = default)
    {
        var stored = await FindAsync(token, AccountTokenPurpose.EmailChangeApproval, cancellationToken);
        if (stored is null || stored.ConsumedAt is not null || stored.RevokedAt is not null)
            return Result.Failure<EmailChangeApproved>(IdentityErrors.InvalidApprovalToken);
        var now = clock.GetUtcNow();
        if (stored.ExpiresAt < now)
            return Result.Failure<EmailChangeApproved>(IdentityErrors.ApprovalTokenExpired);
        var user = await users.GetByUniqueIdAsync(stored.UserUniqueId, cancellationToken);
        if (user is null || !user.IsEnabled)
            return Result.Failure<EmailChangeApproved>(IdentityErrors.InvalidApprovalToken);
        // Checked again: another account may have taken the address while the approval waited.
        if (await users.GetByEmailAsync(stored.Email, cancellationToken) is not null)
            return Result.Failure<EmailChangeApproved>(IdentityErrors.EmailTaken);
        if (!await tokens.TryConsumeAsync(stored.TokenHash, now, cancellationToken))
            return Result.Failure<EmailChangeApproved>(IdentityErrors.InvalidApprovalToken);

        var previous = user.Email;
        user.Email = stored.Email;
        user.EmailVerified = true;   // proven by the code of the request
        user.ModifiedAt = now;
        user.ModifiedBy = user.AsActor();
        await users.UpdateAsync(user, cancellationToken);
        logger.LogInformation("E-mail of {UserUniqueId} changed, approved by its previous address", user.UserUniqueId);
        return Result.Success(new EmailChangeApproved(previous, user.Email));
    }

    /// <summary>
    /// The address <paramref name="token"/> would restore, when it can still be used, or <see langword="null"/>: to
    /// show the page, or refuse the link. Reading it spends nothing.
    /// </summary>
    public async Task<string?> ValidateRevertTokenAsync(string token, CancellationToken cancellationToken = default)
        => await FindAsync(token, AccountTokenPurpose.EmailRevert, cancellationToken) is { } stored
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
        var stored = await FindAsync(token, AccountTokenPurpose.EmailRevert, cancellationToken);
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
        await events.PublishAsync(new UserPasswordChangedEvent { OccurredAt = now, UserUniqueId = user.UserUniqueId, Reason = UserPasswordChangedEvent.RemovedReason }, cancellationToken);
        logger.LogWarning("E-mail of {UserUniqueId} restored by its previous address: the password is removed", user.UserUniqueId);
        return Result.Success(new EmailReverted(user.Email, reset));
    }

    // A password typed from a session is as much a guess as one typed at the login: same lockout, same count, same
    // trace, same time to answer. The account, when it holds, for the operation to go on with.
    private async Task<Result<AuthUser>> ConfirmPasswordAsync(Guid userUniqueId, string? password, string? ipAddress, CancellationToken cancellationToken)
    {
        var started = Stopwatch.StartNew();
        var policy = options.Value.LoginPolicy;
        try
        {
            var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
            if (user is null || !user.IsEnabled)
                return Result.Failure<AuthUser>(IdentityErrors.AccountNotFound);
            var now = clock.GetUtcNow();
            if (user.BlockedUntil is { } until && until > now)
            {
                await failures.TraceAsync(user.UserUniqueId, user.Email, false, LoginFailureReasons.LockedOut, ipAddress, null, now, cancellationToken);
                return Result.Failure<AuthUser>(IdentityErrors.LockedOut);
            }
            if (string.IsNullOrEmpty(password) || !hasher.Verify(password, user.PasswordHash))
            {
                return Result.Failure<AuthUser>(await failures.CountAsync(user, LoginFailureReasons.InvalidCurrentPassword, ipAddress, null, now, cancellationToken)
                    ? IdentityErrors.LockedOut
                    : IdentityErrors.InvalidCurrentPassword);
            }
            return Result.Success(user);
        }
        finally
        {
            var elapsed = started.Elapsed;
            if (elapsed < policy.MinResponseTime)
                await Task.Delay(policy.MinResponseTime - elapsed, clock, cancellationToken);
        }
    }

    private async Task<AccountToken?> FindAsync(string token, AccountTokenPurpose purpose, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(token))
            return null;
        var stored = await tokens.GetAsync(AccountTokens.Hash(token), cancellationToken);
        return stored?.Purpose == purpose ? stored : null;
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
        return await emailVerification.RequestVerificationAsync(user.Email, EmailVerificationPurpose.CurrentEmail, userUniqueId, ipAddress, cancellationToken);
    }

    /// <summary>Marks the account's current e-mail verified once <paramref name="code"/> proves it.</summary>
    public async Task<Result> ConfirmEmailVerificationAsync(Guid userUniqueId, string? code, CancellationToken cancellationToken = default)
    {
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null || !user.IsEnabled)
            return Result.Failure(IdentityErrors.AccountNotFound);
        var verified = await emailVerification.VerifyCodeAsync(user.Email, EmailVerificationPurpose.CurrentEmail, userUniqueId, code, cancellationToken);
        if (verified.IsFailure)
            return verified;
        user.EmailVerified = true;
        user.ModifiedAt = clock.GetUtcNow();
        user.ModifiedBy = user.AsActor();
        await users.UpdateAsync(user, cancellationToken);
        await emailVerification.CleanupAsync(user.Email, EmailVerificationPurpose.CurrentEmail, cancellationToken);
        logger.LogInformation("E-mail of {UserUniqueId} verified", userUniqueId);
        return Result.Success();
    }

    /// <summary>
    /// Confirms that <paramref name="password"/> is the account's, for an operation that changes nothing by itself:
    /// <see cref="IdentityErrors.InvalidCurrentPassword"/> when it is not, <see cref="IdentityErrors.LockedOut"/> while
    /// the account is locked out — a wrong one counted like a wrong password at the login.
    /// </summary>
    public async Task<Result> VerifyCurrentPasswordAsync(Guid userUniqueId, string? password, string? ipAddress = null, CancellationToken cancellationToken = default)
    {
        var confirmed = await ConfirmPasswordAsync(userUniqueId, password, ipAddress, cancellationToken);
        return confirmed.IsFailure ? Result.Failure(confirmed.Error!) : Result.Success();
    }

    /// <summary>Deletes the account, once the password is confirmed. The host ends the session; an issuer revokes the tokens on the event.</summary>
    public async Task<Result> DeleteAccountAsync(Guid userUniqueId, string currentPassword, string? ipAddress = null, CancellationToken cancellationToken = default)
    {
        var confirmed = await ConfirmPasswordAsync(userUniqueId, currentPassword, ipAddress, cancellationToken);
        if (confirmed.IsFailure)
            return Result.Failure(confirmed.Error!);
        var user = confirmed.Value;
        if (!await users.SoftDeleteAsync(userUniqueId, user.AsActor(), cancellationToken))
            return Result.Failure(IdentityErrors.AccountNotFound);
        await events.PublishAsync(new UserBlockedEvent { OccurredAt = clock.GetUtcNow(), UserUniqueId = userUniqueId, Reason = AccountAdministrationService.DeletedReason }, cancellationToken);
        logger.LogInformation("Account {UserUniqueId} deleted by its owner", userUniqueId);
        return Result.Success();
    }
}
