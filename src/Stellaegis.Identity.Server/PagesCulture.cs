using System.Globalization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Localization;
using Microsoft.Extensions.Options;

namespace Stellaegis.Identity.Server;

/// <summary>
/// The culture the pages are read in. <see cref="IdentityPagesOptions.Culture"/> imposes one when it is set;
/// otherwise the first of these that the pages have texts for:
/// <list type="number">
/// <item><description>the language of the signed-in person's account, the <c>locale</c> of the session;</description></item>
/// <item><description>the <c>ui_locales</c> of the request, or of the authorization request the page will return to;</description></item>
/// <item><description>the choice made on the pages, in the culture cookie of ASP.NET Core;</description></item>
/// <item><description>the culture the host's request localization decided, or the browser's <c>Accept-Language</c> when the host decides none;</description></item>
/// <item><description><see cref="IdentityPagesOptions.DefaultCulture"/>.</description></item>
/// </list>
/// With none of them, the pages keep the culture of the request.
/// </summary>
/// <remarks>
/// The pages have texts in English and in French, and in every culture the host gives texts for in
/// <see cref="IdentityPagesOptions.Texts"/>: a culture without texts would show English words under its dates and
/// numbers. The cookie is ASP.NET Core's own, <see cref="CookieRequestCultureProvider.DefaultCookieName"/>, so that a
/// host whose request localization reads it shows its own pages in the language chosen here.
/// </remarks>
internal sealed class PagesCulture(IOptions<IdentityPagesOptions> options)
{
    private static readonly string[] PackageLanguages = ["en", "fr"];

    /// <summary>The cultures the pages have texts for, those of the package first.</summary>
    public IReadOnlyList<CultureInfo> Supported
        => [.. PackageLanguages.Concat(options.Value.Texts.Keys.Where(key => key != "*"))
            .Select(Known).OfType<CultureInfo>()
            .DistinctBy(culture => culture.Name, StringComparer.OrdinalIgnoreCase)];

    /// <summary>The culture of the pages for <paramref name="http"/>, or <see langword="null"/> to keep the request's.</summary>
    public CultureInfo? Resolve(HttpContext http)
    {
        var o = options.Value;
        if (!string.IsNullOrEmpty(o.Culture))
            return CultureInfo.GetCultureInfo(o.Culture);
        foreach (var candidate in Candidates(http))
        {
            if (Supports(candidate) is { } culture)
                return culture;
        }
        return string.IsNullOrEmpty(o.DefaultCulture) ? null : CultureInfo.GetCultureInfo(o.DefaultCulture);
    }

    /// <summary>The supported culture <paramref name="name"/> names, or <see langword="null"/>.</summary>
    public CultureInfo? Supports(string? name)
    {
        if (Known(name) is not { } culture)
            return null;
        var texts = options.Value.Texts;
        return PackageLanguages.Contains(culture.TwoLetterISOLanguageName, StringComparer.Ordinal)
            || texts.ContainsKey(culture.Name) || texts.ContainsKey(culture.TwoLetterISOLanguageName)
            ? culture
            : null;
    }

    private static IEnumerable<string?> Candidates(HttpContext http)
    {
        yield return http.User.FindFirst(ProfileClaims.Locale)?.Value;

        foreach (var locale in UiLocales(http))
            yield return locale;

        if (CookieRequestCultureProvider.ParseCookieValue(http.Request.Cookies[CookieRequestCultureProvider.DefaultCookieName] ?? "") is { } chosen)
        {
            foreach (var culture in chosen.UICultures)
                yield return culture.Value;
        }

        if (http.Features.Get<IRequestCultureFeature>() is { } decided)
        {
            yield return decided.RequestCulture.UICulture.Name;
            yield break;
        }
        var accepted = http.Request.GetTypedHeaders().AcceptLanguage
            .Where(language => language.Quality is not 0)
            .OrderByDescending(language => language.Quality ?? 1);
        foreach (var language in accepted)
            yield return language.Value.Value;
    }

    // ui_locales is a space-separated list (OpenID Connect Core § 3.1.2.1), on the request itself or on the
    // authorization request a login page returns to.
    private static IEnumerable<string> UiLocales(HttpContext http)
    {
        var query = http.Request.Query;
        IEnumerable<string?> lists = [query["ui_locales"], ReturnQuery(query["return_url"]), ReturnQuery(query["ReturnUrl"])];
        return lists.SelectMany(list => (list ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries));
    }

    private static string? ReturnQuery(string? returnUrl)
    {
        if (string.IsNullOrEmpty(returnUrl) || returnUrl.IndexOf('?') is var mark && mark < 0)
            return null;
        return Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(returnUrl[mark..]).TryGetValue("ui_locales", out var values)
            ? values.ToString()
            : null;
    }

    private static CultureInfo? Known(string? name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 35)
            return null;
        try
        {
            var culture = CultureInfo.GetCultureInfo(name, predefinedOnly: true);
            return string.IsNullOrEmpty(culture.Name) ? null : culture;
        }
        catch (CultureNotFoundException)
        {
            return null;
        }
    }
}
