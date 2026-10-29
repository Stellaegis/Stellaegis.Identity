using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Stellaegis.Identity;

/// <summary>
/// What a failed attempt against an account costs it, wherever it was made — a wrong password at the login or from a
/// session, a wrong second factor —: the count and the lockout by the store, in one write; the trace; and the notice to
/// the person, through the host's mailer when it has one, the once the lockout starts. The login, the second factor and
/// the confirmation of a password go through it, so that the three count the same way; a host that checks a password
/// of its own counts through it too.
/// </summary>
public sealed class FailedLoginCounter(
    IAuthUserStore users,
    ILoginEventStore loginEvents,
    IOptions<IdentityOptions> options,
    ILogger<FailedLoginCounter> logger,
    IIdentityMailer? mailer = null)
{
    /// <summary>
    /// Counts the attempt against <paramref name="user"/> for <paramref name="reason"/>, traces it, and tells the
    /// person when it starts a lockout. Whether the account is locked out now.
    /// </summary>
    public async Task<bool> CountAsync(AuthUser user, string reason, string? ipAddress, string? userAgent, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var policy = options.Value.LoginPolicy;
        var failed = await users.RecordFailedLoginAsync(user.UserUniqueId, now, policy.MaxFailedAttempts, policy.LockoutDuration, cancellationToken);
        await TraceAsync(user.UserUniqueId, user.Email, false, reason, ipAddress, userAgent, now, cancellationToken);
        if (failed?.IsLockedOutAt(now) != true)
            return false;

        // Told once per lockout: the count passes the maximum exactly once, attempts under a lockout being refused
        // before they count. A lockout that follows an expired one starts above the maximum, and is not told again.
        if (failed.FailedLoginCount == policy.MaxFailedAttempts)
        {
            logger.LogWarning("Account {UserUniqueId} locked out until {Until} after {Count} failed attempts, the last one {Reason}", user.UserUniqueId, failed.BlockedUntil, failed.FailedLoginCount, reason);
            if (mailer is not null)
            {
                try
                {
                    await mailer.SendAccountLockedAsync(user.Email, failed.BlockedUntil!.Value, cancellationToken);
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    logger.LogError(exception, "The notice that the account {UserUniqueId} is locked out was not sent", user.UserUniqueId);
                }
            }
        }
        return true;
    }

    /// <summary>Records an attempt, succeeded or not, in the trace the person reads on their security page.</summary>
    public Task TraceAsync(Guid userUniqueId, string email, bool success, string? failReason, string? ipAddress, string? userAgent, DateTimeOffset now, CancellationToken cancellationToken)
        => loginEvents.AddAsync(new LoginEvent
        {
            UserUniqueId = userUniqueId,
            Email = email,
            Success = success,
            FailReason = failReason,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            CreatedAt = now,
        }, cancellationToken);
}
