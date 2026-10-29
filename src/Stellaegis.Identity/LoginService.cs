using System.Diagnostics;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// Verifies a person's credentials, enforces the lockout, keeps the attempt from telling whether the account
/// exists, and builds the principal the host signs in. Everything sensitive to a login is here, so that a page or
/// a controller only calls <see cref="AuthenticateAsync"/>, then <see cref="CompleteWithSecondFactorAsync"/> when a
/// second factor is due.
/// </summary>
public sealed class LoginService(
    IAuthUserStore users,
    ILoginEventStore loginEvents,
    MfaService mfa,
    LoginOtpService loginCodes,
    RecoveryCodeService recoveryCodes,
    PasswordHasher hasher,
    IOptions<IdentityOptions> options,
    TimeProvider clock,
    ILogger<LoginService> logger,
    IAvatarStore? avatars = null)
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
                await RecordAsync(user?.UserUniqueId ?? Guid.Empty, normalized, false, LoginFailureReasons.InvalidCredentials, ipAddress, userAgent, now, cancellationToken);
                return LoginResult.Failure(IdentityErrors.InvalidCredentials);
            }

            // An account without a password is refused for that reason, not only because the dummy hash fails; the
            // person is told what anyone is told, so that the answer does not say an account waits at this address.
            if (!user.IsActivated)
            {
                await RecordAsync(user.UserUniqueId, normalized, false, LoginFailureReasons.NotActivated, ipAddress, userAgent, now, cancellationToken);
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
                await users.RecordFailedLoginAsync(user.UserUniqueId, now, policy.MaxFailedAttempts, policy.LockoutDuration, cancellationToken);
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
            return LoginResult.Success(await BuildPrincipalAsync(user, AuthenticationMethods.PasswordOnly, now, authenticationType, cancellationToken));
        }
        finally
        {
            await PadAsync(started, policy, cancellationToken);
        }
    }

    /// <summary>
    /// Completes a login whose password held and awaits its second factor (<see cref="LoginStep.RequiresMfa"/>) by
    /// <paramref name="code"/>: the one-time code of the account's method — authenticator or e-mail —, or a recovery
    /// code, told apart by its shape. A wrong code counts as a failed login and locks the account out like a wrong
    /// password does; a locked account is refused before the code is read. Succeeds with the principal to sign in,
    /// saying how the person proved who they are.
    /// </summary>
    /// <param name="userUniqueId">The account whose password held.</param>
    /// <param name="code">The code typed, one-time or recovery.</param>
    /// <param name="authenticationType">The authentication type of the principal; <see cref="DefaultAuthenticationType"/> unless set.</param>
    /// <param name="ipAddress">The address of the attempt, kept in its <see cref="LoginEvent"/> when it fails.</param>
    /// <param name="userAgent">The user agent of the attempt, kept in its <see cref="LoginEvent"/> when it fails.</param>
    /// <param name="cancellationToken">Cancels the attempt.</param>
    public async Task<LoginResult> CompleteWithSecondFactorAsync(
        Guid userUniqueId,
        string? code,
        string authenticationType = DefaultAuthenticationType,
        string? ipAddress = null,
        string? userAgent = null,
        CancellationToken cancellationToken = default)
    {
        var started = Stopwatch.StartNew();
        var policy = options.Value.LoginPolicy;
        try
        {
            var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
            if (user is null || user.IsBlockedAtDoor)
                return LoginResult.Failure(IdentityErrors.AccountBlocked);
            var now = clock.GetUtcNow();
            if (user.BlockedUntil is { } until && until > now)
            {
                await RecordAsync(user.UserUniqueId, user.Email, false, LoginFailureReasons.LockedOut, ipAddress, userAgent, now, cancellationToken);
                return LoginResult.Failure(IdentityErrors.LockedOut, LoginStep.LockedOut);
            }

            var methods = await VerifySecondFactorAsync(user.UserUniqueId, code, cancellationToken);
            if (methods is null)
            {
                var failed = await users.RecordFailedLoginAsync(user.UserUniqueId, now, policy.MaxFailedAttempts, policy.LockoutDuration, cancellationToken);
                await RecordAsync(user.UserUniqueId, user.Email, false, LoginFailureReasons.InvalidSecondFactor, ipAddress, userAgent, now, cancellationToken);
                if (failed?.IsLockedOutAt(now) == true)
                {
                    logger.LogWarning("Login of {UserUniqueId} locked after too many wrong second factors", user.UserUniqueId);
                    return LoginResult.Failure(IdentityErrors.LockedOut, LoginStep.LockedOut);
                }
                return LoginResult.Failure(IdentityErrors.InvalidMfaCode);
            }

            // The wrong codes of this login are forgotten with its success, as the wrong passwords were with the password's.
            if (user.FailedLoginCount > 0)
            {
                user.FailedLoginCount = 0;
                user.FailedLoginLast = null;
                await users.UpdateAsync(user, cancellationToken);
            }
            logger.LogInformation("Login of {Email} completed by its second factor", user.Email);
            return LoginResult.Success(await BuildPrincipalAsync(user, methods, now, authenticationType, cancellationToken));
        }
        finally
        {
            await PadAsync(started, policy, cancellationToken);
        }
    }

    // A recovery code is recognized by its shape and tried alone: each try costs a hash per code left, which a
    // one-time code must not pay — nor let an attacker make the server pay.
    private async Task<IReadOnlyCollection<string>?> VerifySecondFactorAsync(Guid userUniqueId, string? code, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(code))
            return null;
        if (RecoveryCodeService.LooksLikeCode(code))
            return await recoveryCodes.TryConsumeAsync(userUniqueId, code, cancellationToken) ? AuthenticationMethods.PasswordAndRecoveryCode : null;
        var held = await mfa.GetMethodAsync(userUniqueId, cancellationToken) == MfaMethod.Email
            ? loginCodes.Validate(userUniqueId, code)
            : await mfa.ValidateCodeAsync(userUniqueId, code, cancellationToken);
        return held ? AuthenticationMethods.PasswordAndCode : null;
    }

    private async Task PadAsync(Stopwatch started, LoginPolicyOptions policy, CancellationToken cancellationToken)
    {
        var elapsed = started.Elapsed;
        if (elapsed < policy.MinResponseTime)
            await Task.Delay(policy.MinResponseTime - elapsed, clock, cancellationToken);
    }

    /// <summary>
    /// The principal of an account whose credentials were verified already — after the one-time code of a second
    /// factor, for instance —, saying by <paramref name="methods"/> how (<see cref="AuthenticationMethods"/>) and that
    /// it was now (<see cref="AuthenticationTime"/>), or <see langword="null"/> when the account is gone or disabled since.
    /// </summary>
    public async Task<ClaimsPrincipal?> CreatePrincipalAsync(
        Guid userUniqueId, IReadOnlyCollection<string> methods, string authenticationType = DefaultAuthenticationType, CancellationToken cancellationToken = default)
    {
        Guard.Satisfies(Guard.NotNull(methods), m => m.Count > 0, "A principal says how the person proved who they are.");
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        return user is null || user.IsBlockedAtDoor ? null : await BuildPrincipalAsync(user, methods, clock.GetUtcNow(), authenticationType, cancellationToken);
    }

    /// <summary>
    /// The principal of a session that goes on, its account read again as it is now — a name or a language changed —,
    /// keeping from <paramref name="session"/> how and when the person proved who they are; <see langword="null"/> when
    /// the account is gone or disabled since, or when the session says neither whose it is nor how it was proved.
    /// A session that does not say when keeps saying nothing: an older session is not given the time of its renewal.
    /// </summary>
    public async Task<ClaimsPrincipal?> RenewPrincipalAsync(
        ClaimsPrincipal session, string authenticationType = DefaultAuthenticationType, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(session);
        var methods = session.FindAll(AuthenticationMethods.ClaimType).Select(claim => claim.Value).ToList();
        if (methods.Count == 0 || !Guid.TryParse(session.FindFirst("sub")?.Value, out var userUniqueId))
            return null;
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        return user is null || user.IsBlockedAtDoor
            ? null
            : await BuildPrincipalAsync(user, methods, AuthenticationTime.Of(session), authenticationType, cancellationToken);
    }

    private async Task<ClaimsPrincipal> BuildPrincipalAsync(
        AuthUser user, IReadOnlyCollection<string> methods, DateTimeOffset? authenticatedAt, string authenticationType, CancellationToken cancellationToken)
    {
        Guard.NotWhiteSpace(authenticationType);
        var subject = user.Subject;
        List<Claim> claims =
        [
            new(ClaimTypes.NameIdentifier, subject),
            new("sub", subject),
            new("email", user.Email),
            new("name", user.DisplayName),
        ];
        if (user.Locale is { } locale)
            claims.Add(new Claim(ProfileClaims.Locale, locale));
        if (user.TimeZone is { } timeZone)
            claims.Add(new Claim(ProfileClaims.TimeZone, timeZone));
        // The address is versioned by the time the avatar was set, so that a client caching it sees a new one.
        if (options.Value.AvatarUrl is { } url && avatars is not null
            && await avatars.GetModifiedAtAsync(user.UserUniqueId, cancellationToken) is { } setAt)
            claims.Add(new Claim(ProfileClaims.Picture, $"{url}?v={setAt.ToUnixTimeMilliseconds()}"));
        claims.AddRange(methods.Select(method => new Claim(AuthenticationMethods.ClaimType, method)));
        if (authenticatedAt is { } at)
            claims.Add(AuthenticationTime.ToClaim(at));
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
