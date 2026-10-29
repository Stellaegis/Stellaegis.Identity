using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// What an administrator — or the installation — does to accounts: creating one, blocking and unblocking,
/// deleting, resetting the failed logins or the second factor, issuing the link of an activation or of a reset.
/// Each write names the actor who made it; none depends on the registration posture. The routes of
/// <c>Stellaegis.Identity.AspNetCore</c> call it under the operations of <see cref="IdentityOperations"/>.
/// </summary>
/// <remarks>
/// An administrator never chooses nor learns a password: an account is created without one, and its person chooses
/// it by an activation link; a forgotten password is reset by a link too. The link is sent by e-mail, or handed over
/// when the host declares it — the token is returned, and its delivery recorded, for the caller to do either.
/// </remarks>
public sealed class AccountAdministrationService(
    IAuthUserStore users,
    IMfaStore mfa,
    IRecoveryCodeStore recoveryCodes,
    IAccountTokenStore tokens,
    IEventPublisher events,
    IOptions<IdentityOptions> options,
    TimeProvider clock,
    ILogger<AccountAdministrationService> logger)
{
    /// <summary>The <see cref="UserBlockedEvent.Reason"/> of an account disabled by an administrator.</summary>
    public const string DisabledReason = "disabled";

    /// <summary>The <see cref="UserBlockedEvent.Reason"/> of an account deleted.</summary>
    public const string DeletedReason = "deleted";

    /// <summary>
    /// Creates an enabled account without a password, by <paramref name="actor"/>, and issues its activation token,
    /// delivered by <paramref name="delivery"/>: the caller sends its link by e-mail, or hands it over. The account
    /// does not sign in until its person chose a password by that link.
    /// </summary>
    public async Task<Result<PendingAccount>> CreateAsync(string email, string displayName, TokenDelivery delivery, Actor actor, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(actor);
        var normalized = Emails.Normalize(email);
        if (await users.GetByEmailAsync(normalized, cancellationToken) is not null)
            return Result.Failure<PendingAccount>(IdentityErrors.EmailTaken);

        var now = clock.GetUtcNow();
        var user = new AuthUser
        {
            UserUniqueId = Guid.NewGuid(),
            Email = normalized,
            DisplayName = Guard.NotWhiteSpace(displayName).Trim(),
            PasswordHash = null,
            IsEnabled = true,
            EmailVerified = false,
            CreatedAt = now,
            CreatedBy = actor,
            ModifiedAt = now,
            ModifiedBy = actor,
        };
        await users.CreateAsync(user, cancellationToken);
        var token = await tokens.IssueAsync(user, AccountTokenPurpose.Activation, delivery, actor, now, options.Value.Activation.TokenLifetime, null, cancellationToken);
        await events.PublishAsync(new UserRegisteredEvent { OccurredAt = now, UserUniqueId = user.UserUniqueId, Email = normalized, DisplayName = user.DisplayName }, cancellationToken);
        logger.LogInformation("Account {UserUniqueId} created by {Actor}, waiting for its activation", user.UserUniqueId, actor);
        return Result.Success(new PendingAccount(user.UserUniqueId, normalized, token));
    }

    /// <summary>
    /// Issues a new activation token for an account that still waits for its activation — the first link expired,
    /// or went astray —, revoking the previous one.
    /// </summary>
    public async Task<Result<IssuedToken>> IssueActivationAsync(Guid userUniqueId, TokenDelivery delivery, Actor actor, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(actor);
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null || user.IsDeleted)
            return Result.Failure<IssuedToken>(IdentityErrors.AccountNotFound);
        if (!user.IsEnabled)
            return Result.Failure<IssuedToken>(IdentityErrors.AccountBlocked);
        if (user.IsActivated)
            return Result.Failure<IssuedToken>(IdentityErrors.AccountAlreadyActivated);
        var token = await tokens.IssueAsync(user, AccountTokenPurpose.Activation, delivery, actor, clock.GetUtcNow(), options.Value.Activation.TokenLifetime, null, cancellationToken);
        logger.LogInformation("Activation of {UserUniqueId} issued again by {Actor}", userUniqueId, actor);
        return Result.Success(new IssuedToken(user.Email, token));
    }

    /// <summary>
    /// Issues a password reset token for an active account, by <paramref name="actor"/>, revoking the previous one:
    /// the person chooses the new password by its link. The administrator never sets it.
    /// </summary>
    public async Task<Result<IssuedToken>> IssuePasswordResetAsync(Guid userUniqueId, TokenDelivery delivery, Actor actor, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(actor);
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null || user.IsDeleted)
            return Result.Failure<IssuedToken>(IdentityErrors.AccountNotFound);
        if (!user.IsEnabled)
            return Result.Failure<IssuedToken>(IdentityErrors.AccountBlocked);
        if (!user.IsActivated)
            return Result.Failure<IssuedToken>(IdentityErrors.AccountNotActivated);
        // A reset link by e-mail to an address never proven could reach whoever holds a mistyped one.
        if (delivery == TokenDelivery.Email && !user.EmailVerified)
            return Result.Failure<IssuedToken>(IdentityErrors.EmailNotVerified);
        var token = await tokens.IssueAsync(user, AccountTokenPurpose.PasswordReset, delivery, actor, clock.GetUtcNow(), options.Value.PasswordReset.TokenLifetime, null, cancellationToken);
        logger.LogInformation("Password reset of {UserUniqueId} issued by {Actor}", userUniqueId, actor);
        return Result.Success(new IssuedToken(user.Email, token));
    }

    /// <summary>
    /// Changes the e-mail of the account, by <paramref name="actor"/>: the way out for a person whose mailbox is lost,
    /// when a change asks the approval of the previous address. The new address is not proven — the person verifies
    /// it from their account page —, and a change of e-mail waiting for an approval is dropped.
    /// </summary>
    public async Task<Result> ChangeEmailAsync(Guid userUniqueId, string email, Actor actor, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(actor);
        var normalized = Emails.Normalize(email);
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null)
            return Result.Failure(IdentityErrors.AccountNotFound);
        if (string.Equals(user.Email, normalized, StringComparison.Ordinal))
            return Result.Failure(IdentityErrors.SameEmail);
        if (await users.GetByEmailAsync(normalized, cancellationToken) is not null)
            return Result.Failure(IdentityErrors.EmailTaken);

        var now = clock.GetUtcNow();
        user.Email = normalized;
        user.EmailVerified = false;
        user.ModifiedAt = now;
        user.ModifiedBy = actor;
        await users.UpdateAsync(user, cancellationToken);
        await tokens.RevokeOutstandingAsync(userUniqueId, AccountTokenPurpose.EmailChangeApproval, now, cancellationToken);
        logger.LogInformation("E-mail of {UserUniqueId} changed by {Actor}, not proven", userUniqueId, actor);
        return Result.Success();
    }

    /// <summary>Disables the account: it is blocked at the door from now on. Already disabled, nothing changes.</summary>
    public async Task<Result> BlockAsync(Guid userUniqueId, Actor actor, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(actor);
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null)
            return Result.Failure(IdentityErrors.AccountNotFound);
        if (user.IsEnabled)
        {
            var now = clock.GetUtcNow();
            user.IsEnabled = false;
            user.ModifiedAt = now;
            user.ModifiedBy = actor;
            await users.UpdateAsync(user, cancellationToken);
            await events.PublishAsync(new UserBlockedEvent { OccurredAt = now, UserUniqueId = userUniqueId, Reason = DisabledReason }, cancellationToken);
            logger.LogInformation("Account {UserUniqueId} blocked by {Actor}", userUniqueId, actor);
        }
        return Result.Success();
    }

    /// <summary>Enables the account again. Already enabled, nothing changes.</summary>
    public async Task<Result> UnblockAsync(Guid userUniqueId, Actor actor, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(actor);
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null)
            return Result.Failure(IdentityErrors.AccountNotFound);
        if (!user.IsEnabled)
        {
            var now = clock.GetUtcNow();
            user.IsEnabled = true;
            user.ModifiedAt = now;
            user.ModifiedBy = actor;
            await users.UpdateAsync(user, cancellationToken);
            await events.PublishAsync(new UserUnblockedEvent { OccurredAt = now, UserUniqueId = userUniqueId }, cancellationToken);
            logger.LogInformation("Account {UserUniqueId} unblocked by {Actor}", userUniqueId, actor);
        }
        return Result.Success();
    }

    /// <summary>Deletes the account: it stays, blocked at the door, so that its identity is never reused.</summary>
    public async Task<Result> DeleteAsync(Guid userUniqueId, Actor actor, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(actor);
        if (!await users.SoftDeleteAsync(userUniqueId, actor, cancellationToken))
            return Result.Failure(IdentityErrors.AccountNotFound);
        await events.PublishAsync(new UserBlockedEvent { OccurredAt = clock.GetUtcNow(), UserUniqueId = userUniqueId, Reason = DeletedReason }, cancellationToken);
        logger.LogInformation("Account {UserUniqueId} deleted by {Actor}", userUniqueId, actor);
        return Result.Success();
    }

    /// <summary>Ends a lockout and forgets the failed logins.</summary>
    public async Task<Result> ResetFailedLoginsAsync(Guid userUniqueId, Actor actor, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(actor);
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null)
            return Result.Failure(IdentityErrors.AccountNotFound);
        user.FailedLoginCount = 0;
        user.FailedLoginLast = null;
        user.BlockedUntil = null;
        user.ModifiedAt = clock.GetUtcNow();
        user.ModifiedBy = actor;
        await users.UpdateAsync(user, cancellationToken);
        logger.LogInformation("Failed logins of {UserUniqueId} reset by {Actor}", userUniqueId, actor);
        return Result.Success();
    }

    /// <summary>Removes the second factor and the recovery codes, for a person who lost both.</summary>
    public async Task<Result> ResetMfaAsync(Guid userUniqueId, Actor actor, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(actor);
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null)
            return Result.Failure(IdentityErrors.AccountNotFound);
        await mfa.DisableAsync(userUniqueId, cancellationToken);
        await recoveryCodes.DeleteAllAsync(userUniqueId, cancellationToken);
        logger.LogInformation("Second factor of {UserUniqueId} reset by {Actor}", userUniqueId, actor);
        return Result.Success();
    }
}

/// <summary>An account just created, waiting for its activation, and the token of its activation link.</summary>
/// <param name="UserUniqueId">The identity of the account.</param>
/// <param name="Email">Its e-mail, normalized, where an e-mailed link goes.</param>
/// <param name="ActivationToken">The token, in clear this once: only its hash is kept.</param>
public sealed record PendingAccount(Guid UserUniqueId, string Email, string ActivationToken);

/// <summary>A token issued for an account, and where an e-mailed link goes.</summary>
/// <param name="Email">The e-mail of the account.</param>
/// <param name="Token">The token, in clear this once: only its hash is kept.</param>
public sealed record IssuedToken(string Email, string Token);

/// <summary>The blocked accounts read from the local <see cref="IAuthUserStore"/>, for a host that holds the accounts.</summary>
internal sealed class LocalBlockedUsersSource(IAuthUserStore users) : IBlockedUsersSource
{
    public async Task<IReadOnlyCollection<string>> GetBlockedSubjectsAsync(CancellationToken cancellationToken = default)
        => (await users.ListBlockedAsync(cancellationToken)).Select(user => user.Subject).ToList();
}
