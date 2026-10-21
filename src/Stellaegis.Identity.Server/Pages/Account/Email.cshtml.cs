using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Identity.AspNetCore;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>
/// The person changes their e-mail: a code is sent to the new one, and the change is done once the code is
/// typed. The cookie still carries the old e-mail then: the person signs in again.
/// </summary>
[Authorize]
internal sealed class AccountEmailModel(
    AccountService account,
    CookieSignIn signIn,
    PendingStates pending,
    IdentityTexts texts,
    IOptions<IdentityOptions> identity,
    ILogger<AccountEmailModel> logger,
    IIdentityMailer? mailer = null) : PageModel
{
    [BindProperty]
    public string? NewEmail { get; set; }

    [BindProperty]
    public string? Code { get; set; }

    public string CurrentEmail { get; private set; } = "";

    public string? Pending { get; private set; }

    public void OnGet()
    {
        CurrentEmail = this.UserEmail();
        Pending = ReadPending();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        CurrentEmail = this.UserEmail();
        if (this.UserId() is not { } userId)
            return Forbid();
        if (mailer is null)
        {
            ModelState.AddModelError(string.Empty, texts["Account.Email.NoMailer"]);
            return Page();
        }
        if (string.IsNullOrWhiteSpace(NewEmail) || !new EmailAddressAttribute().IsValid(NewEmail))
        {
            ModelState.AddModelError(nameof(NewEmail), texts["Field.Email.Invalid"]);
            return Page();
        }

        var email = Emails.Normalize(NewEmail!);
        var issued = await account.RequestEmailChangeAsync(userId, email, this.ClientAddress(), cancellationToken);
        if (issued.IsFailure)
        {
            ModelState.AddModelError(string.Empty, texts.Describe(issued.Error!));
            return Page();
        }
        try
        {
            await mailer.SendVerificationCodeAsync(email, issued.Value, identity.Value.EmailVerification.Lifetime, cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            logger.LogError(exception, "The verification code of {Email} was not sent", email);
            ModelState.AddModelError(string.Empty, texts["VerifyEmail.SendFailed"]);
            return Page();
        }
        pending.Write(HttpContext, PendingStates.EmailChange, email);
        return Redirect("/account/email");
    }

    public async Task<IActionResult> OnPostConfirmAsync(CancellationToken cancellationToken)
    {
        CurrentEmail = this.UserEmail();
        if (this.UserId() is not { } userId)
            return Forbid();
        Pending = ReadPending();
        if (Pending is null)
            return Redirect("/account/email");
        if (string.IsNullOrWhiteSpace(Code))
        {
            ModelState.AddModelError(nameof(Code), texts["Field.Code.Required"]);
            return Page();
        }

        var result = await account.ConfirmEmailChangeAsync(userId, Pending, Code, cancellationToken);
        if (result.IsFailure)
        {
            ModelState.AddModelError(string.Empty, texts.Describe(result.Error!));
            return Page();
        }
        pending.Clear(HttpContext, PendingStates.EmailChange);
        await signIn.SignOutAsync(HttpContext);
        TempData["Notice"] = "Login.EmailChanged";
        return Redirect(IdentityCookie.LoginPath);
    }

    public IActionResult OnPostCancel()
    {
        pending.Clear(HttpContext, PendingStates.EmailChange);
        return Redirect("/account/email");
    }

    private string? ReadPending()
        => pending.Read(HttpContext, PendingStates.EmailChange) is { Length: 1 } parts && parts[0].Length > 0 ? parts[0] : null;
}
