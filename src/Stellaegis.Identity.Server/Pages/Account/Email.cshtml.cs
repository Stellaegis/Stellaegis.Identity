using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Identity.AspNetCore;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>
/// The person changes their e-mail, their password confirmed first: a code is sent to the new one, the change is done
/// once the code is typed, and the previous address is told. The cookie still carries the old e-mail then: the person
/// signs in again. An e-mail never proven — the account was activated by a link handed over — is verified the same
/// way, the code sent to the current one, without the password: it changes nothing.
/// </summary>
[Authorize]
internal sealed class AccountEmailModel(
    AccountService account,
    IAuthUserStore users,
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
    public string? Password { get; set; }

    [BindProperty]
    public string? Code { get; set; }

    public string CurrentEmail { get; private set; } = "";

    public string? Pending { get; private set; }

    public bool CurrentVerified { get; private set; }

    /// <summary>Whether the code pending proves the current e-mail rather than a new one.</summary>
    public bool VerifyingCurrent => Pending is not null && string.Equals(Pending, CurrentEmail, StringComparison.Ordinal);

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        CurrentEmail = this.UserEmail();
        Pending = ReadPending();
        CurrentVerified = await IsCurrentVerifiedAsync(cancellationToken);
    }

    public async Task<IActionResult> OnPostVerifyAsync(CancellationToken cancellationToken)
    {
        CurrentEmail = this.UserEmail();
        if (this.UserId() is not { } userId)
            return Forbid();
        if (mailer is null)
        {
            ModelState.AddModelError(string.Empty, texts["Account.Email.NoMailer"]);
            return Page();
        }
        var issued = await account.RequestEmailVerificationAsync(userId, this.ClientAddress(), cancellationToken);
        if (issued.IsFailure)
        {
            ModelState.AddModelError(string.Empty, texts.Describe(issued.Error!));
            CurrentVerified = await IsCurrentVerifiedAsync(cancellationToken);
            return Page();
        }
        try
        {
            await mailer.SendVerificationCodeAsync(CurrentEmail, issued.Value, identity.Value.EmailVerification.Lifetime, cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            logger.LogError(exception, "The verification code of {Email} was not sent", CurrentEmail);
            ModelState.AddModelError(string.Empty, texts["VerifyEmail.SendFailed"]);
            return Page();
        }
        pending.Write(HttpContext, PendingStates.EmailChange, CurrentEmail);
        return Redirect("/account/email");
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
            ModelState.AddModelError(nameof(NewEmail), texts["Field.Email.Invalid"]);
        if (string.IsNullOrEmpty(Password))
            ModelState.AddModelError(nameof(Password), texts["Field.CurrentPassword.Required"]);
        else if (await account.VerifyCurrentPasswordAsync(userId, Password, this.ClientAddress(), cancellationToken) is { IsFailure: true } refused)
            ModelState.AddModelError(nameof(Password), texts.Describe(refused.Error!));
        if (!ModelState.IsValid)
        {
            CurrentVerified = await IsCurrentVerifiedAsync(cancellationToken);
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

        if (VerifyingCurrent)
        {
            var verified = await account.ConfirmEmailVerificationAsync(userId, Code, cancellationToken);
            if (verified.IsFailure)
            {
                ModelState.AddModelError(string.Empty, texts.Describe(verified.Error!));
                return Page();
            }
            pending.Clear(HttpContext, PendingStates.EmailChange);
            return Redirect("/account/email");
        }

        var result = await account.ConfirmEmailChangeAsync(userId, Pending, Code, cancellationToken);
        if (result.IsFailure)
        {
            ModelState.AddModelError(string.Empty, texts.Describe(result.Error!));
            return Page();
        }
        if (mailer is not null)
        {
            try
            {
                var revert = IdentityLinks.Of(identity.Value.Links, Request, IdentityLinks.RevertEmailPath, result.Value.RevertToken);
                await mailer.SendEmailChangedAsync(result.Value.PreviousEmail, result.Value.NewEmail, revert, identity.Value.EmailChange.RevertLifetime, cancellationToken);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                logger.LogError(exception, "The notice that the e-mail of {UserUniqueId} changed was not sent to its previous address", userId);
            }
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

    private async Task<bool> IsCurrentVerifiedAsync(CancellationToken cancellationToken)
        => this.UserId() is { } userId && await users.GetByUniqueIdAsync(userId, cancellationToken) is { EmailVerified: true };

    private string? ReadPending()
        => pending.Read(HttpContext, PendingStates.EmailChange) is { Length: 1 } parts && parts[0].Length > 0 ? parts[0] : null;
}
