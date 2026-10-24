namespace Stellaegis.Identity;

/// <summary>
/// The claims of the profile a session carries, under the names of OpenID Connect Core § 5.1, so that an issuer
/// carries them into its tokens unchanged.
/// </summary>
public static class ProfileClaims
{
    /// <summary>The language the person chose, a culture name: <c>locale</c>.</summary>
    public const string Locale = "locale";

    /// <summary>The time zone the person chose, an IANA name: <c>zoneinfo</c>.</summary>
    public const string TimeZone = "zoneinfo";

    /// <summary>The address of the avatar: <c>picture</c>.</summary>
    public const string Picture = "picture";
}
