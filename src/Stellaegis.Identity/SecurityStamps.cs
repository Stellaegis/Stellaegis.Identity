namespace Stellaegis.Identity;

/// <summary>
/// The security stamp of an account, the mechanism of ASP.NET Core Identity: a random value that changes with
/// whatever must close the other sessions of the account — a new password, a block, a change of the second factor or
/// of the e-mail. A session carries the stamp of its sign-in, <see cref="ClaimType"/>, and is held against the account
/// at every reading: another stamp, or none, closes it.
/// </summary>
public static class SecurityStamps
{
    /// <summary>The claim a session carries its stamp in, <c>stellaegis.security_stamp</c>: the cookie's only, never copied into a token.</summary>
    public const string ClaimType = "stellaegis.security_stamp";

    /// <summary>A new stamp: 128 random bits, in lowercase hexadecimal.</summary>
    public static string New() => Guid.NewGuid().ToString("N");

    // Renews the stamp of the account: its other sessions close at their next reading.
    internal static Task<bool> RenewAsync(IAuthUserStore users, Guid userUniqueId, CancellationToken cancellationToken)
        => users.RenewSecurityStampAsync(userUniqueId, New(), cancellationToken);
}
