using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>
/// The person enrolls an authenticator, their password confirmed with the first code — an authenticator enrolled from a
/// taken session would lock its owner out —; the recovery codes follow, shown once.
/// </summary>
[Authorize]
internal sealed class AccountMfaSetupModel(MfaService mfa, AccountService account, RecoveryCodeService recoveryCodes, IdentityTexts texts, IOptions<IdentityPagesOptions> pages) : PageModel
{
    internal const string CodesTempDataKey = "RecoveryCodes";

    [BindProperty]
    public string? Code { get; set; }

    [BindProperty]
    public string? Password { get; set; }

    public MfaEnrollment Enrollment { get; private set; } = new("", "");

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        if (this.UserId() is not { } userId)
            return Forbid();
        if (await mfa.IsEnabledAsync(userId, cancellationToken))
            return Redirect("/account/mfa");
        var secret = await mfa.BeginSetupAsync(userId, cancellationToken);
        Enrollment = MfaEnrollment.Of(secret, this.UserEmail(), pages.Value.ApplicationName);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (this.UserId() is not { } userId)
            return Forbid();
        if (await mfa.IsEnabledAsync(userId, cancellationToken))
            return Redirect("/account/mfa");

        if (string.IsNullOrEmpty(Password))
            ModelState.AddModelError(nameof(Password), texts["Field.CurrentPassword.Required"]);
        else if (!await account.VerifyCurrentPasswordAsync(userId, Password, cancellationToken))
            ModelState.AddModelError(nameof(Password), texts["Field.Password.Wrong"]);
        var confirmed = !ModelState.IsValid
            ? Result.Failure(IdentityErrors.InvalidCurrentPassword)
            : string.IsNullOrWhiteSpace(Code)
                ? Result.Failure(IdentityErrors.InvalidMfaCode)
                : await mfa.ConfirmSetupAsync(userId, Code!, cancellationToken);
        if (confirmed.IsFailure)
        {
            if (confirmed.Error != IdentityErrors.InvalidCurrentPassword)
                ModelState.AddModelError(nameof(Code), texts["MfaSetup.CodeInvalid"]);
            var record = await mfa.GetStatusAsync(userId, cancellationToken);
            var secret = record?.PendingSecret ?? await mfa.BeginSetupAsync(userId, cancellationToken);
            Enrollment = MfaEnrollment.Of(secret, this.UserEmail(), pages.Value.ApplicationName);
            return Page();
        }

        var codes = await recoveryCodes.GenerateAsync(userId, cancellationToken);
        TempData[CodesTempDataKey] = string.Join(' ', codes);
        TempData["Notice"] = "Account.Mfa.AppEnabled";
        return Redirect("/account/mfa/recovery-codes");
    }
}
