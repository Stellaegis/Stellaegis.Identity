using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>The recovery codes: a fresh set shown exactly once, how many are left, a new set that voids the previous one.</summary>
[Authorize]
internal sealed class AccountRecoveryCodesModel(MfaService mfa, RecoveryCodeService recoveryCodes) : PageModel
{
    public IReadOnlyList<string> Codes { get; private set; } = [];

    public int Remaining { get; private set; }

    public bool MfaEnabled { get; private set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        if (this.UserId() is not { } userId)
            return Forbid();
        if (TempData[AccountMfaSetupModel.CodesTempDataKey] is string joined && joined.Length > 0)
            Codes = joined.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        await LoadAsync(userId, cancellationToken);
        return Page();
    }

    public async Task<IActionResult> OnPostRegenerateAsync(CancellationToken cancellationToken)
    {
        if (this.UserId() is not { } userId)
            return Forbid();
        if (!await mfa.IsEnabledAsync(userId, cancellationToken))
            return Redirect("/account/mfa");
        var codes = await recoveryCodes.GenerateAsync(userId, cancellationToken);
        TempData[AccountMfaSetupModel.CodesTempDataKey] = string.Join(' ', codes);
        return Redirect("/account/mfa/recovery-codes");
    }

    private async Task LoadAsync(Guid userId, CancellationToken cancellationToken)
    {
        MfaEnabled = await mfa.IsEnabledAsync(userId, cancellationToken);
        Remaining = await recoveryCodes.CountRemainingAsync(userId, cancellationToken);
    }
}
