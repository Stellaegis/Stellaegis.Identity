using System.Globalization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Stellaegis.Identity.AspNetCore;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>The account of the signed-in person: their profile, changed in place, and the way out.</summary>
[Authorize]
internal sealed class AccountIndexModel(CookieSignIn signIn, ProfileService profiles, PagesCulture cultures, IdentityTexts texts) : PageModel
{
    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string Email { get; private set; } = "";

    /// <summary>The version of the avatar, which its address carries; <see langword="null"/> when the account has none.</summary>
    public long? AvatarVersion { get; private set; }

    public IReadOnlyList<CultureInfo> Languages => cultures.Supported;

    public IReadOnlyList<string> TimeZones => TimeZoneNames.Suggested;

    public sealed class InputModel
    {
        public string? DisplayName { get; set; }

        public string? Locale { get; set; }

        public string? TimeZone { get; set; }
    }

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        if (this.UserId() is not { } userId || (await profiles.GetAsync(userId, cancellationToken)).Value is not { } profile)
            return Forbid();
        Show(profile);
        Input = new InputModel { DisplayName = profile.DisplayName, Locale = profile.Locale, TimeZone = profile.TimeZone };
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (this.UserId() is not { } userId || (await profiles.GetAsync(userId, cancellationToken)).Value is not { } current)
            return Forbid();
        Show(current);
        var displayName = (Input.DisplayName ?? "").Trim();
        if (displayName.Length is < 2 or > 100)
            ModelState.AddModelError("Input.DisplayName", texts["Field.DisplayName.Invalid"]);
        if (!string.IsNullOrEmpty(Input.Locale) && cultures.Supports(Input.Locale) is null)
            ModelState.AddModelError("Input.Locale", texts.Describe(IdentityErrors.InvalidLocale));
        if (!ModelState.IsValid)
            return Page();

        var changed = await profiles.UpdateAsync(userId, displayName, Input.Locale, Input.TimeZone?.Trim(), cancellationToken);
        if (changed.IsFailure)
        {
            ModelState.AddModelError(string.Empty, texts.Describe(changed.Error!));
            return Page();
        }
        await signIn.RefreshAsync(HttpContext, cancellationToken);
        TempData["Notice"] = "Account.Profile.Saved";
        return Redirect("/account");
    }

    private void Show(AccountProfile profile)
    {
        Email = profile.Email;
        AvatarVersion = profile.AvatarModifiedAt?.ToUnixTimeMilliseconds();
    }

    public async Task<IActionResult> OnPostLogoutAsync()
    {
        await signIn.SignOutAsync(HttpContext);
        return Redirect(IdentityCookie.LoginPath);
    }
}
