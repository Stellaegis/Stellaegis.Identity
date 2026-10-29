using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Identity.AspNetCore;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>
/// The e-mail an account had before a change, restored from the link its previous address received: the one act of a
/// person whose session was not theirs. The password goes with the change, every session closes, and a link to choose
/// a new password is sent to the restored address. The link works once, for a while; reading the page spends nothing.
/// </summary>
internal sealed class RevertEmailModel(
    AccountService account,
    CookieSignIn signIn,
    IOptions<IdentityOptions> identity,
    ILogger<RevertEmailModel> logger,
    IIdentityMailer? mailer = null) : PageModel
{
    [BindProperty(SupportsGet = true)]
    public string? Token { get; set; }

    /// <summary>The address the link restores, shown before the act.</summary>
    public string? Email { get; private set; }

    public bool TokenInvalid { get; private set; }

    public bool Done { get; private set; }

    public bool SendFailed { get; private set; }

    public async Task<IActionResult> OnGetAsync(bool done = false, bool sendFailed = false, CancellationToken cancellationToken = default)
    {
        this.KeepTokenFromReferrers();
        if (done)
        {
            Done = true;
            SendFailed = sendFailed;
            return Page();
        }
        Email = string.IsNullOrWhiteSpace(Token) ? null : await account.ValidateRevertTokenAsync(Token, cancellationToken);
        TokenInvalid = Email is null;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        this.KeepTokenFromReferrers();
        var reverted = string.IsNullOrWhiteSpace(Token)
            ? Stellaegis.Primitives.Result.Failure<EmailReverted>(IdentityErrors.InvalidRevertToken)
            : await account.RevertEmailChangeAsync(Token, cancellationToken);
        if (reverted.IsFailure)
        {
            TokenInvalid = true;
            return Page();
        }

        // The browser that holds the link may hold a session of the account: it is closed with the others.
        await signIn.SignOutAsync(HttpContext);
        var sent = false;
        if (mailer is not null)
        {
            try
            {
                var reset = IdentityLinks.Of(identity.Value.Links, Request, IdentityLinks.ResetPasswordPath, reverted.Value.ResetToken);
                await mailer.SendPasswordResetLinkAsync(reverted.Value.Email, reset, identity.Value.PasswordReset.TokenLifetime, cancellationToken);
                sent = true;
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                logger.LogError(exception, "The reset link of a restored e-mail was not sent");
            }
        }
        return Redirect(sent ? "/revert-email?done=true" : "/revert-email?done=true&sendFailed=true");
    }
}
