using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>The new password, from the link a person received; the link works once, for a while.</summary>
internal sealed class ResetPasswordModel(PasswordResetService reset, PasswordRules passwords, IdentityTexts texts, IOptions<IdentityPagesOptions> pages) : PageModel
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
        if (!pages.Value.PasswordResetEnabled)
            return NotFound();
        if (done)
        {
            Done = true;
            return Page();
        }
        TokenInvalid = !Guid.TryParse(Token, out var token) || !await reset.ValidateTokenAsync(token, cancellationToken);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (!pages.Value.PasswordResetEnabled)
            return NotFound();
        if (!Guid.TryParse(Token, out var token))
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

        var result = await reset.ResetPasswordAsync(token, Input.NewPassword ?? "", cancellationToken);
        if (result.IsFailure)
        {
            ModelState.AddModelError(string.Empty, texts.Describe(result.Error!));
            return Page();
        }
        return Redirect("/reset-password?done=true");
    }
}
