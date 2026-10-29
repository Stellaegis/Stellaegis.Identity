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
/// Stellaegis:Identity:Pages:DefaultCulture = fr
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
    /// The culture imposed on the pages, <c>fr</c> or <c>en-GB</c>: the texts and the dates follow it, whatever the
    /// person chose. Unless set, the pages follow the person: the language of their account, the one asked by the
    /// application they sign in to, the one chosen on the pages, the browser's — the first the pages have texts
    /// for —, then <see cref="DefaultCulture"/>.
    /// </summary>
    public string? Culture { get; set; }

    /// <summary>
    /// The culture of the pages when nothing the person said is one they have texts for, <c>fr</c> for instance.
    /// Unless set, the culture of the request. <see cref="Culture"/>, when set, wins over it.
    /// </summary>
    public string? DefaultCulture { get; set; }

    /// <summary>
    /// The rate limiting the package applies to its own pages, whatever the host set up: every POST counted against
    /// the address of the client and against the e-mail the form names, refused over the limit. On unless turned off.
    /// </summary>
    public PagesRateLimitingOptions RateLimiting { get; set; } = new();

    /// <summary>
    /// The name of a rate limiting policy of the host applied to every page, GETs included, which the host registers
    /// and enables itself by <c>AddRateLimiter</c> and <c>UseRateLimiter</c>. None unless set; in addition to
    /// <see cref="RateLimiting"/>, which a host that limits the pages by its own policy may turn off.
    /// </summary>
    public string? RateLimitingPolicy { get; set; }

    /// <summary>Whether <c>/</c> sends a person to their account, or to the login page. No unless set: the host usually has a root of its own.</summary>
    public bool RedirectRoot { get; set; }

    /// <summary>Where a person lands after signing in when nothing says where they came from. <c>/account</c> unless set.</summary>
    public string DefaultReturnUrl { get; set; } = "/account";

    /// <summary>
    /// The rounding of an avatar's corners, in percent of its side: 50 makes a circle, 0 a square. 50 unless set. The
    /// image keeps its corners; the rounding is applied where it is shown, at every size.
    /// </summary>
    public int AvatarCornerRadius { get; set; } = 50;

    /// <summary>
    /// Whether the avatar editor offers to take a Gravatar. No unless set. The image is asked of Gravatar
    /// (Automattic) by the person's browser, on their gesture, from an address they choose, then cropped and exported
    /// by the editor like a file: the server makes no call. A host that sets a Content-Security-Policy allows
    /// <c>https://gravatar.com</c> in <c>img-src</c>.
    /// </summary>
    public bool GravatarImport { get; set; }

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
        if (!string.IsNullOrEmpty(DefaultCulture) && !IsCulture(DefaultCulture))
            return $"{nameof(DefaultCulture)} must name a known culture, such as fr or en-GB.";
        if (string.IsNullOrWhiteSpace(DefaultReturnUrl) || !IsLocalPath(DefaultReturnUrl))
            return $"{nameof(DefaultReturnUrl)} must be a local path.";
        if (AvatarCornerRadius is < 0 or > 50)
            return $"{nameof(AvatarCornerRadius)} is a percent of the side, from 0 for a square to 50 for a circle.";
        if (RateLimitingPolicy is not null && string.IsNullOrWhiteSpace(RateLimitingPolicy))
            return $"{nameof(RateLimitingPolicy)} must name a policy, or be absent.";
        if (RateLimiting.FindError() is { } limiting)
            return $"{nameof(RateLimiting)}:{limiting}";
        return null;
    }

    private static bool IsPath(string value)
        => IsLocalPath(value)
        || Uri.TryCreate(value, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);

    // One slash, then anything but another or a backslash: "//host" and "/\host" are addresses of another host to a browser.
    private static bool IsLocalPath(string value)
        => value.StartsWith('/') && !value.StartsWith("//", StringComparison.Ordinal) && !value.StartsWith("/\\", StringComparison.Ordinal);

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

/// <summary>
/// The rate limiting the package applies to its own pages, whatever the host set up — a host that set up none opens
/// nothing. Every POST of the pages counts, GETs never: against the address of the client, and against the e-mail
/// the form names when it names one — the one the person signs in as, registers with, asks a code or a link for.
/// Over either limit the page answers 429 with the seconds to wait, and nothing is tried. Behind a proxy, the
/// address of the client is the proxy's unless the host enables <c>ForwardedHeaders</c>: every client then shares
/// one count, and the e-mail is what still tells the targets apart.
/// </summary>
public sealed class PagesRateLimitingOptions : IValidatableOptions
{
    /// <summary>Whether the package limits its pages itself. Yes unless set; a host that limits them by a policy of its own may turn it off.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>How many POSTs one client address may send to the pages in <see cref="Window"/>. 60 unless set.</summary>
    public int RequestsPerClient { get; set; } = 60;

    /// <summary>How many POSTs may name one e-mail in <see cref="Window"/>, from every client together. 10 unless set.</summary>
    public int RequestsPerEmail { get; set; } = 10;

    /// <summary>The window the counts slide over. One minute unless set.</summary>
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);

    /// <inheritdoc/>
    public string? FindError()
    {
        if (!Enabled)
            return null;
        if (RequestsPerClient < 1)
            return $"{nameof(RequestsPerClient)} must be at least 1.";
        if (RequestsPerEmail < 1)
            return $"{nameof(RequestsPerEmail)} must be at least 1.";
        if (Window <= TimeSpan.Zero)
            return $"{nameof(Window)} must be positive.";
        return null;
    }
}
