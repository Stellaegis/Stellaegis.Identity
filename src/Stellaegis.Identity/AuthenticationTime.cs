using System.Globalization;
using System.Security.Claims;

namespace Stellaegis.Identity;

/// <summary>
/// When a person proved who they are, as the session says it in its <c>auth_time</c> claim — seconds since the epoch,
/// as OpenID Connect writes it —, which an issuer carries into its tokens. It is set at the login and kept for the
/// whole session: a new reading of the account does not move it, so that an application asking for a recent
/// authentication is answered by the login, not by the last request.
/// </summary>
public static class AuthenticationTime
{
    /// <summary>The claim type, <c>auth_time</c>.</summary>
    public const string ClaimType = "auth_time";

    // The last second a DateTimeOffset holds, 9999-12-31T23:59:59Z.
    private const long MaxSeconds = 253402300799;

    /// <summary>The claim saying the person authenticated at <paramref name="at"/>, to the second.</summary>
    public static Claim ToClaim(DateTimeOffset at)
        => new(ClaimType, at.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64);

    /// <summary>When the person of <paramref name="principal"/> authenticated, or <see langword="null"/> when it does not say — a session older than the claim.</summary>
    public static DateTimeOffset? Of(ClaimsPrincipal principal)
        => long.TryParse(principal.FindFirst(ClaimType)?.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) && seconds <= MaxSeconds
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;
}
