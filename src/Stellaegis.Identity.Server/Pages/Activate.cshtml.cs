using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>
/// The first password of an account an administrator created, from the link its person received; the link works
/// once, for a while. The page names neither the account nor who created it, before the form is sent.
/// </summary>
internal sealed class ActivateModel(ActivationService activation, PasswordRules passwords, IdentityTexts texts) : PageModel
{
    [BindProperty(SupportsGet = true)]
    public string? Token { get; set; }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public bool TokenInvalid { get; private set; }

    public bool Done { get; private set; }

    public IReadOnlyList<string> Rules => passwords.Describe();

    public sealed class InputModel
    {
        public string? NewPassword { get; set; }

        public string? ConfirmPassword { get; set; }
    }

    public async Task<IActionResult> OnGetAsync(bool done = false, CancellationToken cancellationToken = default)
    {
        this.KeepTokenFromReferrers();
        if (done)
        {
            Done = true;
            return Page();
        }
        TokenInvalid = string.IsNullOrWhiteSpace(Token) || !await activation.ValidateTokenAsync(Token, cancellationToken);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        this.KeepTokenFromReferrers();
        if (string.IsNullOrWhiteSpace(Token))
        {
            TokenInvalid = true;
            return Page();
        }
        foreach (var violation in passwords.Violations(Input.NewPassword))
            ModelState.AddModelError("Input.NewPassword", violation);
        if (!string.Equals(Input.NewPassword, Input.ConfirmPassword, StringComparison.Ordinal))
            ModelState.AddModelError("Input.ConfirmPassword", texts["Field.ConfirmPassword.Mismatch"]);
        if (!ModelState.IsValid)
            return Page();

        var result = await activation.ActivateAsync(Token, Input.NewPassword ?? "", cancellationToken);
        if (result.IsFailure)
        {
            ModelState.AddModelError(string.Empty, texts.Describe(result.Error!));
            return Page();
        }
        return Redirect("/activate?done=true");
    }
}
