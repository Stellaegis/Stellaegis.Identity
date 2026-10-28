using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Identity.AspNetCore;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>
/// A person signs in: the password is checked by <see cref="LoginService"/>, then the cookie is set, or the
/// second factor is asked on the next page, or set up when the policy requires one the person has not.
/// </summary>
internal sealed class LoginModel(
    LoginService login,
    MfaService mfa,
    LoginOtpService loginCodes,
    CookieSignIn signIn,
    PendingStates pending,
    IdentityTexts texts,
    IOptions<IdentityOptions> identity,
    IOptions<IdentityPagesOptions> pages,
    ILogger<LoginModel> logger,
    IIdentityMailer? mailer = null) : PageModel
{
    private static readonly TimeSpan LoginCodeLifetime = TimeSpan.FromMinutes(10);

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string? ReturnUrl { get; private set; }

    public bool RegistrationOpen => identity.Value.SelfRegistration == SelfRegistration.Open;

    public bool PasswordResetEnabled => pages.Value.PasswordResetEnabled;

    public sealed class InputModel
    {
        public string? Email { get; set; }

        public string? Password { get; set; }

        public bool RememberMe { get; set; }
    }

    /// <summary>The session already open in this browser, which the page shows rather than following it; <see langword="null"/> without one.</summary>
    public OpenSession? Session { get; private set; }

    /// <summary>Where the open session continues to: the way back, or the default one.</summary>
    public string ContinueUrl => ReturnUrl ?? pages.Value.DefaultReturnUrl;

    public sealed record OpenSession(string Name, string Email, string? Picture);

    public IActionResult OnGet([FromQuery(Name = Links.ReturnUrlParameter)] string? returnUrl = null)
    {
        ReturnUrl = Links.Local(Url, returnUrl);
        // An open session is shown, not followed: on a shared computer, or with an account kept for testing, the one
        // it names is not always the one meant.
        if (User.Identity?.IsAuthenticated == true)
            Session = new OpenSession(User.FindFirst("name")?.Value ?? "", User.FindFirst("email")?.Value ?? "", User.FindFirst(ProfileClaims.Picture)?.Value);
        return Page();
    }

    /// <summary>Closes the open session and shows the form, the way back kept.</summary>
    public async Task<IActionResult> OnPostSwitchAsync([FromQuery(Name = Links.ReturnUrlParameter)] string? returnUrl = null)
    {
        await signIn.SignOutAsync(HttpContext);
        return Redirect(Links.WithReturnUrl(IdentityCookie.LoginPath, Links.Local(Url, returnUrl)));
    }

    public async Task<IActionResult> OnPostAsync([FromQuery(Name = Links.ReturnUrlParameter)] string? returnUrl = null, CancellationToken cancellationToken = default)
    {
        ReturnUrl = Links.Local(Url, returnUrl);
        if (string.IsNullOrWhiteSpace(Input.Email) || string.IsNullOrEmpty(Input.Password))
        {
            ModelState.AddModelError(string.Empty, texts["Login.Required"]);
            return Page();
        }

        var result = await login.AuthenticateAsync(Input.Email, Input.Password, IdentityCookie.Scheme, this.ClientAddress(), this.ClientAgent(), cancellationToken);
        switch (result.Step)
        {
            case LoginStep.RequiresMfa:
            {
                var method = await mfa.GetMethodAsync(result.UserUniqueId, cancellationToken);
                if (method == MfaMethod.Email)
                {
                    if (mailer is null)
                    {
                        logger.LogError("The second factor of {UserUniqueId} is by e-mail, and no mailer is registered", result.UserUniqueId);
                        ModelState.AddModelError(string.Empty, texts["Login.CodeNotSent"]);
                        return Page();
                    }
                    await mailer.SendLoginCodeAsync(result.Email, loginCodes.Generate(result.UserUniqueId), LoginCodeLifetime, cancellationToken);
                }
                pending.Write(HttpContext, PendingStates.Mfa, result.UserUniqueId.ToString("N"), ReturnUrl ?? "", method);
                return Redirect("/login/mfa");
            }
            case LoginStep.RequiresMfaSetup:
                pending.Write(HttpContext, PendingStates.MfaSetup, result.UserUniqueId.ToString("N"), ReturnUrl ?? "", result.Email);
                return Redirect("/login/mfa-setup");
            case LoginStep.Succeeded:
                await signIn.SignInAsync(HttpContext, result.Principal!, Input.RememberMe);
                return LocalRedirect(ReturnUrl ?? pages.Value.DefaultReturnUrl);
            default:
                ModelState.AddModelError(string.Empty, texts.Describe(result.Error!));
                return Page();
        }
    }
}
