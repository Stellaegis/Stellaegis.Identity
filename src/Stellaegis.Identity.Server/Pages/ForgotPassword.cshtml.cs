using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Identity.AspNetCore;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>
/// A person forgot their password: a link sent to the e-mail of the account, when there is one. The page says the
/// same thing either way, so that it does not tell which e-mails have an account.
/// </summary>
internal sealed class ForgotPasswordModel(
    PasswordResetService reset,
    IdentityTexts texts,
    IOptions<IdentityOptions> identity,
    IOptions<IdentityPagesOptions> pages,
    ILogger<ForgotPasswordModel> logger,
    IIdentityMailer? mailer = null) : PageModel
{
    [BindProperty]
    public string? Email { get; set; }

    public bool Sent { get; private set; }

    public int LifetimeHours => Math.Max(1, (int)Math.Round(identity.Value.PasswordReset.TokenLifetime.TotalHours));

    public IActionResult OnGet(bool sent = false)
    {
        if (!pages.Value.PasswordResetEnabled)
            return NotFound();
        Sent = sent;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (!pages.Value.PasswordResetEnabled)
            return NotFound();
        if (mailer is null)
            throw new InvalidOperationException($"The password reset is enabled and no {nameof(IIdentityMailer)} is registered.");
        if (string.IsNullOrWhiteSpace(Email) || !new EmailAddressAttribute().IsValid(Email))
        {
            ModelState.AddModelError(nameof(Email), texts["Field.Email.Invalid"]);
            return Page();
        }

        var email = Emails.Normalize(Email!);
        if (await reset.RequestResetAsync(email, this.ClientAddress(), cancellationToken) is { } token)
        {
            var link = IdentityLinks.Of(identity.Value.Links, Request, IdentityLinks.ResetPasswordPath, token);
            try
            {
                await mailer.SendPasswordResetLinkAsync(email, link, identity.Value.PasswordReset.TokenLifetime, cancellationToken);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                logger.LogError(exception, "The password reset link of {Email} was not sent", email);
            }
        }
        return Redirect("/forgot-password?sent=true");
    }
}
