using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// A person creating their own account, once their e-mail is verified and when the
/// <see cref="RegistrationOptions.Posture"/> allows it. An administrator creating an account goes through
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
    /// Creates the account of <paramref name="email"/>, whose ownership was verified, and returns its id. The
    /// account is its own creator. <paramref name="invited"/> says the host has checked an invitation, which the
    /// <see cref="RegistrationPosture.ByInvitation"/> posture requires.
    /// </summary>
    public async Task<Result<Guid>> CreateAccountAsync(string email, string displayName, string password, bool invited = false, CancellationToken cancellationToken = default)
    {
        switch (options.Value.Registration.Posture)
        {
            case RegistrationPosture.Closed:
                return Result.Failure<Guid>(IdentityErrors.RegistrationClosed);
            case RegistrationPosture.ByInvitation when !invited:
                return Result.Failure<Guid>(IdentityErrors.RegistrationByInvitation);
        }

        var normalized = Emails.Normalize(email);
        if (!await emailVerification.IsEmailVerifiedAsync(normalized, cancellationToken))
            return Result.Failure<Guid>(IdentityErrors.EmailNotVerified);
        if (await users.GetByEmailAsync(normalized, cancellationToken) is not null)
            return Result.Failure<Guid>(IdentityErrors.EmailTaken);
        var violations = passwords.Violations(password);
        if (violations.Count > 0)
            return Result.Failure<Guid>(IdentityErrors.PasswordRejected(violations));

        var id = Guid.NewGuid();
        var self = Actor.Parse(id.ToString("N"));
        var now = clock.GetUtcNow();
        await users.CreateAsync(new AuthUser
        {
            UserUniqueId = id,
            Email = normalized,
            DisplayName = Guard.NotWhiteSpace(displayName).Trim(),
            PasswordHash = hasher.Hash(password),
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
