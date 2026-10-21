using System.Diagnostics;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// Verifies a person's credentials, enforces the lockout, keeps the attempt from telling whether the account
/// exists, and builds the principal the host signs in. Everything sensitive to a login is here, so that a page or
/// a controller only calls <see cref="AuthenticateAsync"/>.
/// </summary>
public sealed class LoginService(
    IAuthUserStore users,
    ILoginEventStore loginEvents,
    MfaService mfa,
    PasswordHasher hasher,
    IOptions<IdentityOptions> options,
    TimeProvider clock,
    ILogger<LoginService> logger)
{
    /// <summary>The authentication type of the principal unless the host says otherwise: the cookie scheme's.</summary>
    public const string DefaultAuthenticationType = "Cookies";

    /// <summary>
    /// Verifies <paramref name="password"/> for the account of <paramref name="email"/>, and says what the caller
    /// does next: sign the principal in, ask a one-time code, ask to set a second factor up, or show the error.
    /// A wrong e-mail and a wrong password get the same answer, in the same time.
    /// </summary>
    /// <param name="email">The e-mail of the account, in any case.</param>
    /// <param name="password">The password, in clear.</param>
    /// <param name="authenticationType">The authentication type of the principal; <see cref="DefaultAuthenticationType"/> unless set.</param>
    /// <param name="ipAddress">The address of the attempt, kept in its <see cref="LoginEvent"/>.</param>
    /// <param name="userAgent">The user agent of the attempt, kept in its <see cref="LoginEvent"/>.</param>
    /// <param name="cancellationToken">Cancels the attempt.</param>
    public async Task<LoginResult> AuthenticateAsync(
        string? email,
        string? password,
        string authenticationType = DefaultAuthenticationType,
        string? ipAddress = null,
        string? userAgent = null,
        CancellationToken cancellationToken = default)
    {
        var started = Stopwatch.StartNew();
        var policy = options.Value.LoginPolicy;
        try
        {
            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
                return LoginResult.Failure(IdentityErrors.InvalidCredentials);

            var normalized = Emails.Normalize(email);
            var user = await users.GetByEmailAsync(normalized, cancellationToken);
            var now = clock.GetUtcNow();

            // Always derive a key, so that an unknown account costs as much as a wrong password.
            var verified = hasher.VerifyOrDummy(password, user?.PasswordHash);

            if (user is null || !user.IsEnabled)
            {
                await RecordAsync(Guid.Empty, normalized, false, LoginFailureReasons.InvalidCredentials, ipAddress, userAgent, now, cancellationToken);
                return LoginResult.Failure(IdentityErrors.InvalidCredentials);
            }

            if (user.BlockedUntil is { } until && until > now)
            {
                logger.LogWarning("Login refused for {Email}: locked until {Until}", user.Email, until);
                await RecordAsync(user.UserUniqueId, normalized, false, LoginFailureReasons.LockedOut, ipAddress, userAgent, now, cancellationToken);
                return LoginResult.Failure(IdentityErrors.LockedOut, LoginStep.LockedOut);
            }

            if (!verified)
            {
                user.FailedLoginCount++;
                user.FailedLoginLast = now;
                if (user.FailedLoginCount >= policy.MaxFailedAttempts)
                    user.BlockedUntil = now.Add(policy.LockoutDuration);
                await users.UpdateAsync(user, cancellationToken);
                await RecordAsync(user.UserUniqueId, normalized, false, LoginFailureReasons.InvalidCredentials, ipAddress, userAgent, now, cancellationToken);
                return LoginResult.Failure(IdentityErrors.InvalidCredentials);
            }

            user.FailedLoginCount = 0;
            user.FailedLoginLast = null;
            user.BlockedUntil = null;
            user.LastLogin = now;
            await users.UpdateAsync(user, cancellationToken);
            await RecordAsync(user.UserUniqueId, normalized, true, null, ipAddress, userAgent, now, cancellationToken);

            if (await mfa.IsEnabledAsync(user.UserUniqueId, cancellationToken))
            {
                logger.LogInformation("Second factor required for {Email}", user.Email);
                return LoginResult.MfaRequired(user.UserUniqueId, user.Email);
            }
            if (options.Value.Mfa.RequireForAllUsers)
            {
                logger.LogInformation("Second factor to set up for {Email}, as the policy requires", user.Email);
                return LoginResult.MfaSetupRequired(user.UserUniqueId, user.Email);
            }

            logger.LogInformation("Login of {Email}", user.Email);
            return LoginResult.Success(BuildPrincipal(user, authenticationType));
        }
        finally
        {
            var elapsed = started.Elapsed;
            if (elapsed < policy.MinResponseTime)
                await Task.Delay(policy.MinResponseTime - elapsed, clock, cancellationToken);
        }
    }

    /// <summary>
    /// The principal of an account whose credentials were verified already — after the one-time code of a second
    /// factor, for instance —, or <see langword="null"/> when the account is gone or disabled since.
    /// </summary>
    public async Task<ClaimsPrincipal?> CreatePrincipalAsync(Guid userUniqueId, string authenticationType = DefaultAuthenticationType, CancellationToken cancellationToken = default)
    {
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        return user is null || user.IsBlockedAtDoor ? null : BuildPrincipal(user, authenticationType);
    }

    private static ClaimsPrincipal BuildPrincipal(AuthUser user, string authenticationType)
    {
        Guard.NotWhiteSpace(authenticationType);
        var subject = user.Subject;
        Claim[] claims =
        [
            new(ClaimTypes.NameIdentifier, subject),
            new("sub", subject),
            new("email", user.Email),
            new("name", user.DisplayName),
        ];
        return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType));
    }

    private Task RecordAsync(Guid userUniqueId, string email, bool success, string? failReason, string? ipAddress, string? userAgent, DateTimeOffset now, CancellationToken cancellationToken)
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

/// <summary>How the module writes an e-mail before comparing or storing it: trimmed, lowercase.</summary>
public static class Emails
{
    /// <summary>The normalized form of <paramref name="email"/>.</summary>
    public static string Normalize(string email) => Guard.NotWhiteSpace(email).Trim().ToLowerInvariant();
}
