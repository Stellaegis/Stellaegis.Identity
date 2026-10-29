using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>The person changes their password, the current one confirmed.</summary>
[Authorize]
internal sealed class AccountPasswordModel(AccountService account, PasswordRules passwords, IdentityTexts texts) : PageModel
{
    [BindProperty]
    public InputModel Input { get; set; } = new();

    public IReadOnlyList<string> Rules => passwords.Describe();

    public sealed class InputModel
    {
        public string? CurrentPassword { get; set; }

        public string? NewPassword { get; set; }

        public string? ConfirmPassword { get; set; }
    }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (this.UserId() is not { } userId)
            return Forbid();
        if (string.IsNullOrEmpty(Input.CurrentPassword))
            ModelState.AddModelError("Input.CurrentPassword", texts["Field.CurrentPassword.Required"]);
        foreach (var violation in passwords.Violations(Input.NewPassword))
            ModelState.AddModelError("Input.NewPassword", violation);
        if (!string.Equals(Input.NewPassword, Input.ConfirmPassword, StringComparison.Ordinal))
            ModelState.AddModelError("Input.ConfirmPassword", texts["Field.ConfirmPassword.Mismatch"]);
        if (!ModelState.IsValid)
            return Page();

        var result = await account.ChangePasswordAsync(userId, Input.CurrentPassword!, Input.NewPassword ?? "", this.ClientAddress(), cancellationToken);
        if (result.IsFailure)
        {
            ModelState.AddModelError(string.Empty, texts.Describe(result.Error!));
            return Page();
        }
        TempData["Notice"] = "Account.Password.Changed";
        return Redirect("/account/password");
    }
}
