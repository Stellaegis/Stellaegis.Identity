using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>
/// The second factor of the person: by authenticator or by e-mail, among the methods the installation allows, enabled
/// or disabled, the password confirmed either way — enabling the e-mail method on an authenticator replaces the
/// stronger factor by the weaker one.
/// </summary>
[Authorize]
internal sealed class AccountMfaModel(MfaService mfa, AccountService account, IdentityTexts texts, IIdentityMailer? mailer = null) : PageModel
{
    [BindProperty]
    public string? Password { get; set; }

    public bool IsEnabled { get; private set; }

    public DateTimeOffset? EnabledAt { get; private set; }

    public string Method { get; private set; } = MfaMethod.Totp;

    /// <summary>Whether the installation lets a person enroll an authenticator.</summary>
    public bool AllowsAuthenticator => mfa.Allows(MfaMethod.Totp);

    /// <summary>Whether the installation lets a person take the code by e-mail.</summary>
    public bool AllowsEmail => mfa.Allows(MfaMethod.Email);

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        if (this.UserId() is not { } userId)
            return Forbid();
        await LoadAsync(userId, cancellationToken);
        return Page();
    }

    public async Task<IActionResult> OnPostEnableEmailAsync(CancellationToken cancellationToken)
    {
        if (this.UserId() is not { } userId)
            return Forbid();
        if (mailer is null)
        {
            ModelState.AddModelError(string.Empty, texts["Account.Mfa.EmailNoMailer"]);
            await LoadAsync(userId, cancellationToken);
            return Page();
        }
        if (!await PasswordHoldsAsync(userId, cancellationToken))
            return Page();
        var enabled = await mfa.EnableEmailAsync(userId, cancellationToken);
        if (enabled.IsFailure)
        {
            ModelState.AddModelError(string.Empty, texts.Describe(enabled.Error!));
            await LoadAsync(userId, cancellationToken);
            return Page();
        }
        TempData["Notice"] = "Account.Mfa.EmailEnabled";
        return Redirect("/account/mfa");
    }

    public async Task<IActionResult> OnPostDisableAsync(CancellationToken cancellationToken)
    {
        if (this.UserId() is not { } userId)
            return Forbid();
        if (!await PasswordHoldsAsync(userId, cancellationToken))
            return Page();
        await mfa.DisableAsync(userId, cancellationToken);
        TempData["Notice"] = "Account.Mfa.Disabled";
        return Redirect("/account/mfa");
    }

    // The page is loaded again for a refusal: the form is shown with the error.
    private async Task<bool> PasswordHoldsAsync(Guid userId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(Password))
            ModelState.AddModelError(nameof(Password), texts["Field.CurrentPassword.Required"]);
        else if (await account.VerifyCurrentPasswordAsync(userId, Password, this.ClientAddress(), cancellationToken) is { IsFailure: true } refused)
            ModelState.AddModelError(nameof(Password), texts.Describe(refused.Error!));
        if (ModelState.IsValid)
            return true;
        await LoadAsync(userId, cancellationToken);
        return false;
    }

    private async Task LoadAsync(Guid userId, CancellationToken cancellationToken)
    {
        var record = await mfa.GetStatusAsync(userId, cancellationToken);
        IsEnabled = record?.IsEnabled == true;
        EnabledAt = record?.EnabledAt;
        Method = record?.Method ?? MfaMethod.Totp;
    }
}
