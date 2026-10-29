using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Stellaegis.Identity.AspNetCore;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>
/// The language chosen on the pages: kept in the culture cookie of ASP.NET Core for whoever is not signed in, and in
/// the account of whoever is — whose session is signed in again so that the next page shows it.
/// </summary>
[NotRateLimited]
internal sealed class LanguageModel(PagesCulture cultures, ProfileService profiles, CookieSignIn signIn) : PageModel
{
    private static readonly TimeSpan Kept = TimeSpan.FromDays(365);

    public IActionResult OnGet() => NotFound();

    public async Task<IActionResult> OnPostAsync(string? culture, string? back, CancellationToken cancellationToken)
    {
        if (cultures.Supports(culture) is not { } chosen)
            return BadRequest();

        Response.Cookies.Append(
            CookieRequestCultureProvider.DefaultCookieName,
            CookieRequestCultureProvider.MakeCookieValue(new RequestCulture(chosen)),
            new CookieOptions { MaxAge = Kept, IsEssential = true, HttpOnly = true, SameSite = SameSiteMode.Lax, Secure = true, Path = "/" });

        if (this.UserId() is { } userId && await profiles.GetAsync(userId, cancellationToken) is { IsSuccess: true, Value: { } profile }
            && !string.Equals(profile.Locale, chosen.Name, StringComparison.Ordinal)
            && (await profiles.UpdateAsync(userId, profile.DisplayName, chosen.Name, profile.TimeZone, cancellationToken)).IsSuccess)
        {
            await signIn.RefreshAsync(HttpContext, cancellationToken);
        }
        return LocalRedirect(Links.Local(Url, back) ?? IdentityCookie.LoginPath);
    }
}
