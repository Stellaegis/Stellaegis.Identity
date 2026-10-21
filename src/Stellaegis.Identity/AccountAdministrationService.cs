using Microsoft.Extensions.Logging;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// What an administrator — or the installation — does to accounts: creating one, blocking and unblocking,
/// deleting, resetting the failed logins, the second factor or the password. Each write names the actor who
/// made it; none depends on the registration posture. The routes of <c>Stellaegis.Identity.AspNetCore</c> call
/// it under the operations of <see cref="IdentityOperations"/>.
/// </summary>
public sealed class AccountAdministrationService(
    IAuthUserStore users,
    IMfaStore mfa,
    IRecoveryCodeStore recoveryCodes,
    PasswordHasher hasher,
    PasswordStrengthEvaluator passwords,
    IEventPublisher events,
    TimeProvider clock,
    ILogger<AccountAdministrationService> logger)
{
    /// <summary>The <see cref="UserBlockedEvent.Reason"/> of an account disabled by an administrator.</summary>
    public const string DisabledReason = "disabled";

    /// <summary>The <see cref="UserBlockedEvent.Reason"/> of an account deleted.</summary>
    public const string DeletedReason = "deleted";

    /// <summary>Creates an enabled account, by <paramref name="actor"/>, and returns its id.</summary>
    public async Task<Result<Guid>> CreateAsync(string email, string displayName, string password, Actor actor, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(actor);
        var normalized = Emails.Normalize(email);
        if (await users.GetByEmailAsync(normalized, cancellationToken) is not null)
            return Result.Failure<Guid>(IdentityErrors.EmailTaken);
        var violations = passwords.Violations(password);
        if (violations.Count > 0)
            return Result.Failure<Guid>(IdentityErrors.PasswordRejected(violations));

        var id = Guid.NewGuid();
        var now = clock.GetUtcNow();
        await users.CreateAsync(new AuthUser
        {
            UserUniqueId = id,
            Email = normalized,
            DisplayName = Guard.NotWhiteSpace(displayName).Trim(),
            PasswordHash = hasher.Hash(password),
            IsEnabled = true,
            CreatedAt = now,
            CreatedBy = actor,
            ModifiedAt = now,
            ModifiedBy = actor,
        }, cancellationToken);
        await events.PublishAsync(new UserRegisteredEvent { OccurredAt = now, UserUniqueId = id, Email = normalized, DisplayName = displayName.Trim() }, cancellationToken);
        logger.LogInformation("Account {UserUniqueId} created by {Actor}", id, actor);
        return Result.Success(id);
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

    /// <summary>Sets a new password without the current one; a lockout in progress ends with it.</summary>
    public async Task<Result> ChangePasswordAsync(Guid userUniqueId, string newPassword, Actor actor, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(actor);
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null)
            return Result.Failure(IdentityErrors.AccountNotFound);
        var violations = passwords.Violations(newPassword);
        if (violations.Count > 0)
            return Result.Failure(IdentityErrors.PasswordRejected(violations));
        user.PasswordHash = hasher.Hash(newPassword);
        user.FailedLoginCount = 0;
        user.BlockedUntil = null;
        user.ModifiedAt = clock.GetUtcNow();
        user.ModifiedBy = actor;
        await users.UpdateAsync(user, cancellationToken);
        logger.LogInformation("Password of {UserUniqueId} changed by {Actor}", userUniqueId, actor);
        return Result.Success();
    }
}

/// <summary>The blocked accounts read from the local <see cref="IAuthUserStore"/>, for a host that holds the accounts.</summary>
internal sealed class LocalBlockedUsersSource(IAuthUserStore users) : IBlockedUsersSource
{
    public async Task<IReadOnlyCollection<string>> GetBlockedSubjectsAsync(CancellationToken cancellationToken = default)
        => (await users.ListBlockedAsync(cancellationToken)).Select(user => user.Subject).ToList();
}
