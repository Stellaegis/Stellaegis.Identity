using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// A person creating their own account, once their e-mail is verified and when the
/// <see cref="IdentityOptions.SelfRegistration"/> allows it. An administrator creating an account goes through
/// <see cref="AccountAdministrationService"/>, whatever the posture.
/// </summary>
public sealed class RegistrationService(
    IAuthUserStore users,
    EmailVerificationService emailVerification,
    PasswordHasher hasher,
    PasswordStrengthEvaluator passwords,
    IEventPublisher events,
    IOptions<IdentityOptions> options,
    TimeProvider clock,
    ILogger<RegistrationService> logger)
{
    /// <summary>
    /// Creates the account of <paramref name="email"/>, whose ownership was verified, and returns its id, when the
    /// application takes registrations (<see cref="IdentityOptions.SelfRegistration"/>). The account is its own
    /// creator.
    /// </summary>
    public async Task<Result<Guid>> CreateAccountAsync(string email, string displayName, string password, CancellationToken cancellationToken = default)
    {
        if (await passwords.RefuseAsync(password, cancellationToken) is { } refused)
            return Result.Failure<Guid>(refused);
        return await CreateAccountFromHashAsync(email, displayName, hasher.Hash(password), cancellationToken);
    }

    /// <summary>
    /// <see cref="CreateAccountAsync"/>, from the hash of a password checked against the policy and hashed when it was
    /// typed: what a page does at its first step, so that the password waits for the code of the e-mail as a hash and
    /// never in clear.
    /// </summary>
    public async Task<Result<Guid>> CreateAccountFromHashAsync(string email, string displayName, string passwordHash, CancellationToken cancellationToken = default)
    {
        Guard.NotWhiteSpace(passwordHash);
        if (options.Value.SelfRegistration != SelfRegistration.Open)
            return Result.Failure<Guid>(IdentityErrors.RegistrationClosed);

        var normalized = Emails.Normalize(email);
        if (!await emailVerification.IsEmailVerifiedAsync(normalized, cancellationToken))
            return Result.Failure<Guid>(IdentityErrors.EmailNotVerified);
        if (await users.GetByEmailAsync(normalized, cancellationToken) is not null)
            return Result.Failure<Guid>(IdentityErrors.EmailTaken);

        var id = Guid.NewGuid();
        var self = Actor.Parse(id.ToString("N"));
        var now = clock.GetUtcNow();
        await users.CreateAsync(new AuthUser
        {
            UserUniqueId = id,
            Email = normalized,
            DisplayName = Guard.NotWhiteSpace(displayName).Trim(),
            PasswordHash = passwordHash,
            IsEnabled = true,
            EmailVerified = true,
            CreatedAt = now,
            CreatedBy = self,
            ModifiedAt = now,
            ModifiedBy = self,
        }, cancellationToken);
        await emailVerification.CleanupAsync(normalized, cancellationToken);
        await events.PublishAsync(new UserRegisteredEvent { OccurredAt = now, UserUniqueId = id, Email = normalized, DisplayName = displayName.Trim() }, cancellationToken);

        logger.LogInformation("Account {UserUniqueId} registered by {Email}", id, normalized);
        return Result.Success(id);
    }
}
