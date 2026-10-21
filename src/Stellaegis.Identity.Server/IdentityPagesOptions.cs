using System.Globalization;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Identity.Server;

/// <summary>
/// What the pages show of the application, bound from <see cref="SectionName"/> or configured in code, and
/// validated when the host starts. This is the first of the four ways a host makes the pages its own, from the
/// lightest to the heaviest:
/// <list type="number">
/// <item><description><b>Options</b>: the name of the application, its logo, a support link, the culture, here.</description></item>
/// <item><description><b>Texts</b>: every text of the pages is a resource, in English and in French; <see cref="Texts"/>
/// replaces one or several of them per culture, from the configuration, without touching a file.</description></item>
/// <item><description><b>Styles</b>: the stylesheet of the package is built on CSS variables, so a host overrides
/// them in a stylesheet of its own and names it in <see cref="StylesheetPath"/>; or serves its own file at the
/// same path, which wins over the package's.</description></item>
/// <item><description><b>Pages and layouts</b>: ASP.NET Core resolves a page in the host first, then in the
/// libraries. A host that places <c>Pages/Shared/_Layout.cshtml</c>, <c>_AuthLayout.cshtml</c>,
/// <c>_AccountLayout.cshtml</c> or any page — <c>Pages/Login.cshtml</c> — at the same path replaces the package's,
/// page by page, and keeps every page it did not touch.</description></item>
/// </list>
/// <code>
/// Stellaegis:Identity:Pages:ApplicationName = Durand SA
/// Stellaegis:Identity:Pages:Culture = fr
/// Stellaegis:Identity:Pages:Texts:fr:Login.Title = Bienvenue
/// </code>
/// </summary>
public sealed class IdentityPagesOptions : IValidatableOptions
{
    /// <summary>The configuration section of the pages.</summary>
    public const string SectionName = "Stellaegis:Identity:Pages";

    /// <summary>Where the stylesheet and the logo of the package are served from.</summary>
    public const string ContentPath = "/_content/Stellaegis.Identity.Server";

    /// <summary>The name of the application, shown on every page and named as the issuer of the authenticator codes. Required.</summary>
    public string ApplicationName { get; set; } = "Stellaegis";

    /// <summary>The path of the logo shown on the pages — the package's unless set; empty for none.</summary>
    public string? LogoPath { get; set; } = ContentPath + "/logo.svg";

    /// <summary>
    /// The stylesheet of the pages — the package's unless set. One built on the same CSS variables restyles the
    /// pages without touching them.
    /// </summary>
    public string StylesheetPath { get; set; } = ContentPath + "/identity.css";

    /// <summary>A link offered to a person who cannot sign in — the help desk, a mail address as <c>mailto:</c>. None unless set.</summary>
    public string? SupportUrl { get; set; }

    /// <summary>
    /// The culture of the pages, <c>fr</c> or <c>en-GB</c>: the texts and the dates follow it. Unless set, the
    /// pages follow the culture of the request, which the host's request localization decides, or the culture of
    /// the process when the host decides nothing.
    /// </summary>
    public string? Culture { get; set; }

    /// <summary>
    /// The name of a rate limiting policy of the host applied to every page — <c>identity_auth</c> in the
    /// Stellaegis framework, ten requests a minute —, which the host registers and enables itself. None unless
    /// set.
    /// </summary>
    public string? RateLimitingPolicy { get; set; }

    /// <summary>Whether <c>/</c> sends a person to their account, or to the login page. No unless set: the host usually has a root of its own.</summary>
    public bool RedirectRoot { get; set; }

    /// <summary>Where a person lands after signing in when nothing says where they came from. <c>/account</c> unless set.</summary>
    public string DefaultReturnUrl { get; set; } = "/account";

    /// <summary>Whether a person can reset a forgotten password by e-mail. Yes unless set; a host whose accounts come from elsewhere turns it off.</summary>
    public bool PasswordResetEnabled { get; set; } = true;

    /// <summary>
    /// Texts replaced per culture, keyed by the culture then by the key of the text, which the resource files of
    /// the package list: <c>Texts:fr:Login.Title</c>. The culture <c>*</c> applies to every culture.
    /// </summary>
    public Dictionary<string, Dictionary<string, string>> Texts { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc/>
    public string? FindError()
    {
        if (string.IsNullOrWhiteSpace(ApplicationName))
            return $"{nameof(ApplicationName)} is required.";
        if (string.IsNullOrWhiteSpace(StylesheetPath) || !IsPath(StylesheetPath))
            return $"{nameof(StylesheetPath)} must be an absolute path or an http(s) URL.";
        if (!string.IsNullOrEmpty(LogoPath) && !IsPath(LogoPath))
            return $"{nameof(LogoPath)} must be an absolute path or an http(s) URL, or empty for no logo.";
        if (!string.IsNullOrEmpty(SupportUrl) && !IsPath(SupportUrl) && !SupportUrl.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
            return $"{nameof(SupportUrl)} must be an absolute path, an http(s) URL or a mailto: address.";
        if (!string.IsNullOrEmpty(Culture) && !IsCulture(Culture))
            return $"{nameof(Culture)} must name a known culture, such as fr or en-GB.";
        if (string.IsNullOrWhiteSpace(DefaultReturnUrl) || !DefaultReturnUrl.StartsWith('/'))
            return $"{nameof(DefaultReturnUrl)} must be a local path.";
        if (RateLimitingPolicy is not null && string.IsNullOrWhiteSpace(RateLimitingPolicy))
            return $"{nameof(RateLimitingPolicy)} must name a policy, or be absent.";
        return null;
    }

    private static bool IsPath(string value)
        => value.StartsWith('/') && !value.StartsWith("//", StringComparison.Ordinal)
        || Uri.TryCreate(value, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);

    private static bool IsCulture(string name)
    {
        try
        {
            return !string.IsNullOrEmpty(CultureInfo.GetCultureInfo(name, predefinedOnly: true).Name);
        }
        catch (CultureNotFoundException)
        {
            return false;
        }
    }
}
