using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>The code that proves the e-mail of a registration, then the account.</summary>
internal sealed class VerifyEmailModel(
    EmailVerificationService verification,
    RegistrationService registration,
    ProfileService profiles,
    PendingStates pending,
    IdentityTexts texts,
    IOptions<IdentityOptions> identity,
    ILogger<VerifyEmailModel> logger,
    IIdentityMailer? mailer = null) : PageModel, INamesAnEmail
{
    [BindProperty]
    public string? Code { get; set; }

    public string Email { get; private set; } = "";

    public string? ReturnUrl { get; private set; }

    string? INamesAnEmail.NamedEmail => pending.Read(HttpContext, PendingStates.Registration) is { Length: 5 } parts ? parts[0] : null;

    public IActionResult OnGet()
    {
        if (ReadPending() is not { } state)
            return Redirect("/register");
        (Email, ReturnUrl) = (state.Email, state.ReturnUrl);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (ReadPending() is not { } state)
            return Redirect("/register");
        (Email, ReturnUrl) = (state.Email, state.ReturnUrl);
        if (string.IsNullOrWhiteSpace(Code))
        {
            ModelState.AddModelError(nameof(Code), texts["Field.Code.Required"]);
            return Page();
        }

        var verified = await verification.VerifyCodeAsync(state.Email, EmailVerificationPurpose.Registration, null, Code, cancellationToken);
        if (verified.IsFailure)
        {
            ModelState.AddModelError(string.Empty, texts.Describe(verified.Error!));
            return Page();
        }
        var created = await registration.CreateAccountFromHashAsync(state.Email, state.DisplayName, state.PasswordHash, cancellationToken);
        if (created.IsFailure)
        {
            ModelState.AddModelError(string.Empty, texts.Describe(created.Error!));
            return Page();
        }

        if (state.TimeZone is { } timeZone)
            await profiles.UpdateAsync(created.Value, state.DisplayName, null, timeZone, cancellationToken);
        pending.Clear(HttpContext, PendingStates.Registration);
        TempData["Notice"] = "Login.Registered";
        return Redirect(Links.WithReturnUrl("/login", ReturnUrl));
    }

    public async Task<IActionResult> OnPostResendAsync(CancellationToken cancellationToken)
    {
        if (ReadPending() is not { } state)
            return Redirect("/register");
        (Email, ReturnUrl) = (state.Email, state.ReturnUrl);
        if (mailer is null)
            throw new InvalidOperationException($"The registration is open and no {nameof(IIdentityMailer)} is registered.");

        // A code asked again too soon is not sent, and the page says what it always says: the one sent still works.
        var issued = await verification.RequestVerificationAsync(state.Email, EmailVerificationPurpose.Registration, null, this.ClientAddress(), cancellationToken);
        if (issued.IsFailure && issued.Error == IdentityErrors.VerificationThrottled)
        {
            TempData["Resent"] = true;
            return Redirect("/verify-email");
        }
        if (issued.IsFailure)
        {
            ModelState.AddModelError(string.Empty, texts.Describe(issued.Error!));
            return Page();
        }
        try
        {
            await mailer.SendVerificationCodeAsync(state.Email, issued.Value, identity.Value.EmailVerification.Lifetime, cancellationToken);
            TempData["Resent"] = true;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            logger.LogError(exception, "The verification code of {Email} was not sent again", state.Email);
            TempData["SendFailed"] = true;
        }
        return Redirect("/verify-email");
    }

    private (string Email, string DisplayName, string PasswordHash, string? ReturnUrl, string? TimeZone)? ReadPending()
    {
        if (pending.Read(HttpContext, PendingStates.Registration) is not { Length: 5 } parts || parts[0].Length == 0)
            return null;
        return (parts[0], parts[1], parts[2], Links.Local(Url, parts[3]), parts[4].Length == 0 ? null : parts[4]);
    }
}
