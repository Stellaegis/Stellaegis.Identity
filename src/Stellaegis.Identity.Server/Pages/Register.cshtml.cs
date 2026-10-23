using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>
/// A person registers, when the posture is open: the form, then a code sent to the e-mail, then the account on
/// the next page. The registration waits in a protected cookie for fifteen minutes. The answer is the same whether
/// the e-mail has an account already or not: its owner is told by e-mail, nobody else learns anything.
/// </summary>
internal sealed class RegisterModel(
    IAuthUserStore users,
    EmailVerificationService verification,
    PasswordRules passwords,
    PendingStates pending,
    IdentityTexts texts,
    IOptions<IdentityOptions> identity,
    ILogger<RegisterModel> logger,
    IIdentityMailer? mailer = null) : PageModel
{
    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string? ReturnUrl { get; private set; }

    public bool Open => identity.Value.SelfRegistration == SelfRegistration.Open;

    public PasswordPolicy Policy => passwords.Policy;

    public IReadOnlyList<string> Rules => passwords.Describe();

    public sealed class InputModel
    {
        public string? Email { get; set; }

        public string? DisplayName { get; set; }

        public string? Password { get; set; }

        public string? ConfirmPassword { get; set; }
    }

    public IActionResult OnGet([FromQuery(Name = Links.ReturnUrlParameter)] string? returnUrl = null)
    {
        ReturnUrl = Links.Local(Url, returnUrl);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync([FromQuery(Name = Links.ReturnUrlParameter)] string? returnUrl = null, CancellationToken cancellationToken = default)
    {
        ReturnUrl = Links.Local(Url, returnUrl);
        if (!Open)
            return Page();
        if (mailer is null)
            throw new InvalidOperationException($"The registration is open and no {nameof(IIdentityMailer)} is registered.");

        if (string.IsNullOrWhiteSpace(Input.Email) || !new EmailAddressAttribute().IsValid(Input.Email))
            ModelState.AddModelError("Input.Email", texts["Field.Email.Invalid"]);
        var displayName = (Input.DisplayName ?? "").Trim();
        if (displayName.Length is < 2 or > 100)
            ModelState.AddModelError("Input.DisplayName", texts["Field.DisplayName.Invalid"]);
        foreach (var violation in passwords.Violations(Input.Password))
            ModelState.AddModelError("Input.Password", violation);
        if (!string.Equals(Input.Password, Input.ConfirmPassword, StringComparison.Ordinal))
            ModelState.AddModelError("Input.ConfirmPassword", texts["Field.ConfirmPassword.Mismatch"]);
        if (!ModelState.IsValid)
            return Page();

        var email = Emails.Normalize(Input.Email!);
        var address = this.ClientAddress();
        if (await users.GetByEmailAsync(email, cancellationToken) is not null)
        {
            try
            {
                await mailer.SendAccountAlreadyExistsAsync(email, cancellationToken);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                logger.LogError(exception, "The notice that {Email} has an account already was not sent", email);
            }
        }
        else
        {
            var issued = await verification.RequestVerificationAsync(email, address, cancellationToken);
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
                TempData["SendFailed"] = true;
            }
        }

        pending.Write(HttpContext, PendingStates.Registration, email, displayName, Input.Password ?? "", ReturnUrl ?? "");
        return Redirect("/verify-email");
    }
}
