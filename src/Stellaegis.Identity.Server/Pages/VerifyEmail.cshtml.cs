using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>The code that proves the e-mail of a registration, then the account.</summary>
internal sealed class VerifyEmailModel(
    EmailVerificationService verification,
    RegistrationService registration,
    PendingStates pending,
    IdentityTexts texts,
    IOptions<IdentityOptions> identity,
    ILogger<VerifyEmailModel> logger,
    IIdentityMailer? mailer = null) : PageModel
{
    [BindProperty]
    public string? Code { get; set; }

    public string Email { get; private set; } = "";

    public string? ReturnUrl { get; private set; }

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

        var verified = await verification.VerifyCodeAsync(state.Email, Code, cancellationToken);
        if (verified.IsFailure)
        {
            ModelState.AddModelError(string.Empty, texts.Describe(verified.Error!));
            return Page();
        }
        var created = await registration.CreateAccountAsync(state.Email, state.DisplayName, state.Password, cancellationToken: cancellationToken);
        if (created.IsFailure)
        {
            ModelState.AddModelError(string.Empty, texts.Describe(created.Error!));
            return Page();
        }

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

        var issued = await verification.RequestVerificationAsync(state.Email, this.ClientAddress(), cancellationToken);
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

    private (string Email, string DisplayName, string Password, string? ReturnUrl)? ReadPending()
    {
        if (pending.Read(HttpContext, PendingStates.Registration) is not { Length: 4 } parts || parts[0].Length == 0)
            return null;
        return (parts[0], parts[1], parts[2], Links.Local(Url, parts[3]));
    }
}
