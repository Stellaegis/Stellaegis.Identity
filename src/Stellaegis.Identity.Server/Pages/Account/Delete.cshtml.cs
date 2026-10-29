using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Stellaegis.Identity.AspNetCore;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>The person deletes their account, the password confirmed: the session ends, an issuer revokes the tokens on the event.</summary>
[Authorize]
internal sealed class AccountDeleteModel(AccountService account, CookieSignIn signIn, IdentityTexts texts) : PageModel
{
    [BindProperty]
    public string? Password { get; set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (this.UserId() is not { } userId)
            return Forbid();
        if (string.IsNullOrEmpty(Password))
        {
            ModelState.AddModelError(nameof(Password), texts["Field.CurrentPassword.Required"]);
            return Page();
        }
        var result = await account.DeleteAccountAsync(userId, Password!, this.ClientAddress(), cancellationToken);
        if (result.IsFailure)
        {
            ModelState.AddModelError(string.Empty, texts.Describe(result.Error!));
            return Page();
        }
        await signIn.SignOutAsync(HttpContext);
        TempData["Notice"] = "Login.AccountDeleted";
        return Redirect(IdentityCookie.LoginPath);
    }
}
