using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using Stellaegis.Identity.AspNetCore;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>
/// The second factor of a login whose password held: the code of the authenticator or of the e-mail, or a
/// recovery code when the authenticator is gone, checked by <see cref="LoginService"/> — which counts a wrong one
/// as a failed login. The pending login lives in a protected cookie for ten minutes, and leaves with a lockout.
/// </summary>
internal sealed class LoginMfaModel(
    LoginService login,
    CookieSignIn signIn,
    PendingStates pending,
    IdentityTexts texts,
    IOptions<IdentityPagesOptions> pages) : PageModel
{
    [BindProperty]
    public string? Code { get; set; }

    public bool ByEmail { get; private set; }

    public IActionResult OnGet()
    {
        if (ReadPending() is not { } state)
            return Redirect(IdentityCookie.LoginPath);
        ByEmail = state.Method == MfaMethod.Email;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (ReadPending() is not { } state)
            return Redirect(IdentityCookie.LoginPath);
        ByEmail = state.Method == MfaMethod.Email;
        if (string.IsNullOrWhiteSpace(Code))
        {
            ModelState.AddModelError(nameof(Code), texts["Mfa.CodeRequired"]);
            return Page();
        }

        var result = await login.CompleteWithSecondFactorAsync(state.UserUniqueId, Code, IdentityCookie.Scheme, this.ClientAddress(), this.ClientAgent(), cancellationToken);
        switch (result.Step)
        {
            case LoginStep.Succeeded:
                pending.Clear(HttpContext, PendingStates.Mfa);
                await signIn.SignInAsync(HttpContext, result.Principal!);
                return LocalRedirect(state.ReturnUrl.Length > 0 ? state.ReturnUrl : pages.Value.DefaultReturnUrl);
            case LoginStep.LockedOut:
                pending.Clear(HttpContext, PendingStates.Mfa);
                ModelState.AddModelError(string.Empty, texts.Describe(result.Error!));
                return Page();
            default:
                if (result.Error == IdentityErrors.AccountBlocked)
                {
                    pending.Clear(HttpContext, PendingStates.Mfa);
                    return Redirect(IdentityCookie.LoginPath);
                }
                ModelState.AddModelError(nameof(Code), texts["Mfa.CodeInvalid"]);
                return Page();
        }
    }

    private (Guid UserUniqueId, string ReturnUrl, string Method)? ReadPending()
    {
        if (pending.Read(HttpContext, PendingStates.Mfa) is not { Length: 3 } parts || !Guid.TryParse(parts[0], out var id))
            return null;
        return (id, Links.Local(Url, parts[1]) ?? "", parts[2]);
    }
}
