using System.Security.Claims;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>What the caller of <see cref="LoginService"/> must do next.</summary>
public enum LoginStep
{
    /// <summary>The credentials hold: <see cref="LoginResult.Principal"/> is the person, to sign in.</summary>
    Succeeded,

    /// <summary>The credentials hold, and a one-time code is required to complete the login.</summary>
    RequiresMfa,

    /// <summary>The credentials hold, the policy requires a second factor, and the account has none yet: enroll one.</summary>
    RequiresMfaSetup,

    /// <summary>The login failed: wrong credentials, unknown or disabled account.</summary>
    Failed,

    /// <summary>The account is locked after too many failed logins.</summary>
    LockedOut,
}

/// <summary>The outcome of a login attempt.</summary>
public sealed class LoginResult
{
    private LoginResult(LoginStep step, ClaimsPrincipal? principal, Error? error, Guid userUniqueId, string email)
    {
        Step = step;
        Principal = principal;
        Error = error;
        UserUniqueId = userUniqueId;
        Email = email;
    }

    /// <summary>What the caller must do next.</summary>
    public LoginStep Step { get; }

    /// <summary>Whether the login completed.</summary>
    public bool Succeeded => Step == LoginStep.Succeeded;

    /// <summary>The person, when <see cref="Step"/> is <see cref="LoginStep.Succeeded"/>.</summary>
    public ClaimsPrincipal? Principal { get; }

    /// <summary>Why the login failed, when <see cref="Step"/> is <see cref="LoginStep.Failed"/> or <see cref="LoginStep.LockedOut"/>.</summary>
    public Error? Error { get; }

    /// <summary>The account, when a second factor is required or must be set up.</summary>
    public Guid UserUniqueId { get; }

    /// <summary>The e-mail of the account, when a second factor is required — to send a code — or must be set up — to build the enrollment code.</summary>
    public string Email { get; }

    /// <summary>The login completed.</summary>
    public static LoginResult Success(ClaimsPrincipal principal) => new(LoginStep.Succeeded, Guard.NotNull(principal), null, Guid.Empty, "");

    /// <summary>The login failed for <paramref name="error"/>.</summary>
    public static LoginResult Failure(Error error, LoginStep step = LoginStep.Failed) => new(step, null, Guard.NotNull(error), Guid.Empty, "");

    /// <summary>A one-time code is required to complete the login.</summary>
    public static LoginResult MfaRequired(Guid userUniqueId, string email) => new(LoginStep.RequiresMfa, null, null, userUniqueId, email);

    /// <summary>A second factor must be set up before the login completes.</summary>
    public static LoginResult MfaSetupRequired(Guid userUniqueId, string email) => new(LoginStep.RequiresMfaSetup, null, null, userUniqueId, email);
}
