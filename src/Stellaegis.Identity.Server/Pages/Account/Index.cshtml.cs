using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Stellaegis.Identity.AspNetCore;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>The account of the signed-in person, and the way out.</summary>
[Authorize]
internal sealed class AccountIndexModel(CookieSignIn signIn) : PageModel
{
    public string DisplayName { get; private set; } = "";

    public string Email { get; private set; } = "";

    public void OnGet()
    {
        DisplayName = this.UserName();
        Email = this.UserEmail();
    }

    public async Task<IActionResult> OnPostLogoutAsync()
    {
        await signIn.SignOutAsync(HttpContext);
        return Redirect(IdentityCookie.LoginPath);
    }
}
