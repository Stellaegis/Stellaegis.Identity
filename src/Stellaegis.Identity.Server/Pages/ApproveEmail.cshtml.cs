using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Stellaegis.Identity.AspNetCore;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>
/// The change of e-mail of an account, approved from the link its previous address received: nothing applied until
/// here, the account keeps its address. The link works once, for a while; reading the page spends nothing. The browser
/// that holds the link is signed out, if it holds a session: it carries the previous address.
/// </summary>
internal sealed class ApproveEmailModel(AccountService account, CookieSignIn signIn) : PageModel
{
    [BindProperty(SupportsGet = true)]
    public string? Token { get; set; }

    /// <summary>The change the link applies, shown before the act.</summary>
    public EmailChangeApproved? Change { get; private set; }

    public bool TokenInvalid { get; private set; }

    public bool Done { get; private set; }

    public async Task<IActionResult> OnGetAsync(bool done = false, CancellationToken cancellationToken = default)
    {
        this.KeepTokenFromReferrers();
        if (done)
        {
            Done = true;
            return Page();
        }
        Change = string.IsNullOrWhiteSpace(Token) ? null : await account.ValidateApprovalTokenAsync(Token, cancellationToken);
        TokenInvalid = Change is null;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        this.KeepTokenFromReferrers();
        var approved = string.IsNullOrWhiteSpace(Token)
            ? Stellaegis.Primitives.Result.Failure<EmailChangeApproved>(IdentityErrors.InvalidApprovalToken)
            : await account.ApproveEmailChangeAsync(Token, cancellationToken);
        if (approved.IsFailure)
        {
            TokenInvalid = true;
            return Page();
        }
        await signIn.SignOutAsync(HttpContext);
        return Redirect("/approve-email?done=true");
    }
}
