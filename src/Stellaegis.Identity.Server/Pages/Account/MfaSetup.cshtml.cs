using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>The person enrolls an authenticator; the recovery codes follow, shown once.</summary>
[Authorize]
internal sealed class AccountMfaSetupModel(MfaService mfa, RecoveryCodeService recoveryCodes, IdentityTexts texts, IOptions<IdentityPagesOptions> pages) : PageModel
{
    internal const string CodesTempDataKey = "RecoveryCodes";

    [BindProperty]
    public string? Code { get; set; }

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

        var confirmed = string.IsNullOrWhiteSpace(Code)
            ? Result.Failure(IdentityErrors.InvalidMfaCode)
            : await mfa.ConfirmSetupAsync(userId, Code!, cancellationToken);
        if (confirmed.IsFailure)
        {
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
