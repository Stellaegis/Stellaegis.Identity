using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;
using Stellaegis.Identity.AspNetCore;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>
/// The second factor a login must set up, when the policy requires one of everyone and the person has none: the
/// password held, the person is not signed in, and nothing lets them skip this. Once the authenticator is
/// confirmed, the recovery codes are shown once, and the login completes.
/// </summary>
internal sealed class LoginMfaSetupModel(
    MfaService mfa,
    RecoveryCodeService recoveryCodes,
    CookieSignIn signIn,
    PendingStates pending,
    IdentityTexts texts,
    IOptions<IdentityPagesOptions> pages) : PageModel
{
    [BindProperty]
    public string? Code { get; set; }

    public MfaEnrollment Enrollment { get; private set; } = new("", "");

    public bool ShowCodes { get; private set; }

    public IReadOnlyList<string> Codes { get; private set; } = [];

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        if (ReadPending() is not { } state)
            return Redirect(IdentityCookie.LoginPath);
        var secret = await mfa.BeginSetupAsync(state.UserUniqueId, cancellationToken);
        Enrollment = MfaEnrollment.Of(secret, state.Email, pages.Value.ApplicationName);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (ReadPending() is not { } state)
            return Redirect(IdentityCookie.LoginPath);

        var confirmed = string.IsNullOrWhiteSpace(Code)
            ? Result.Failure(IdentityErrors.InvalidMfaCode)
            : await mfa.ConfirmSetupAsync(state.UserUniqueId, Code!, cancellationToken);
        if (confirmed.IsFailure)
        {
            ModelState.AddModelError(nameof(Code), texts["MfaSetup.CodeInvalid"]);
            var record = await mfa.GetStatusAsync(state.UserUniqueId, cancellationToken);
            var secret = record?.PendingSecret ?? await mfa.BeginSetupAsync(state.UserUniqueId, cancellationToken);
            Enrollment = MfaEnrollment.Of(secret, state.Email, pages.Value.ApplicationName);
            return Page();
        }

        Codes = await recoveryCodes.GenerateAsync(state.UserUniqueId, cancellationToken);
        ShowCodes = true;
        return Page();
    }

    /// <summary>Completes the login once the codes were shown. A forged post skips nothing: the login completes only when the second factor is enabled.</summary>
    public async Task<IActionResult> OnPostContinueAsync(CancellationToken cancellationToken)
    {
        if (ReadPending() is not { } state)
            return Redirect(IdentityCookie.LoginPath);
        if (!await mfa.IsEnabledAsync(state.UserUniqueId, cancellationToken))
            return Redirect("/login/mfa-setup");

        pending.Clear(HttpContext, PendingStates.MfaSetup);
        // The authenticator was just enrolled by a code it generated: a second factor used for this login.
        var signedIn = await signIn.SignInAsync(HttpContext, state.UserUniqueId, AuthenticationMethods.PasswordAndCode, cancellationToken: cancellationToken);
        if (signedIn.IsFailure)
            return Redirect(IdentityCookie.LoginPath);
        return LocalRedirect(state.ReturnUrl.Length > 0 ? state.ReturnUrl : pages.Value.DefaultReturnUrl);
    }

    private (Guid UserUniqueId, string ReturnUrl, string Email)? ReadPending()
    {
        if (pending.Read(HttpContext, PendingStates.MfaSetup) is not { Length: 3 } parts || !Guid.TryParse(parts[0], out var id))
            return null;
        return (id, Links.Local(Url, parts[1]) ?? "", parts[2]);
    }
}

/// <summary>What a page shows to enroll an authenticator: the <c>otpauth://</c> URI the QR code renders, and the key for a manual entry.</summary>
/// <param name="OtpAuthUri">The URI the authenticator reads from the QR code.</param>
/// <param name="SecretKey">The key, in base32, typed by hand when the QR code cannot be scanned.</param>
internal sealed record MfaEnrollment(string OtpAuthUri, string SecretKey)
{
    /// <summary>The enrollment of <paramref name="secretBase32"/> for <paramref name="email"/>, issued by <paramref name="issuer"/>.</summary>
    public static MfaEnrollment Of(string secretBase32, string email, string issuer)
        => new(MfaService.GetOtpAuthUri(secretBase32, email, issuer), secretBase32);
}
