using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Stellaegis.Identity.AspNetCore;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>
/// An invitation, from the link a person received: accepted under the account signed in when it carries the address
/// invited, or under an account created here at that address. The page names nothing the invitation carries — neither
/// the compartment, nor who invited, nor the roles — and reads the token without spending it until the person
/// submits. Without the host's <see cref="IInvitationAcceptance"/>, it is not there.
/// </summary>
internal sealed class InvitationModel(InvitationService invitations, PasswordRules passwords, IdentityTexts texts) : PageModel
{
    /// <summary>What the page offers the person.</summary>
    public enum Step
    {
        /// <summary>The token opens nothing.</summary>
        Invalid,

        /// <summary>The account signed in carries the address invited: it accepts.</summary>
        Accept,

        /// <summary>The account signed in carries another address: it does not accept.</summary>
        OtherAccount,

        /// <summary>An account holds the address invited, not signed in: its person signs in first.</summary>
        SignIn,

        /// <summary>No account holds the address invited: one is created there.</summary>
        Create,
    }

    [BindProperty(SupportsGet = true)]
    public string? Token { get; set; }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public Step Current { get; private set; }

    public IReadOnlyList<string> Rules => passwords.Describe();

    public PasswordPolicy Policy => passwords.Policy;

    /// <summary>The login page, coming back here once signed in.</summary>
    public string SignInPath => Links.WithReturnUrl(IdentityCookie.LoginPath, $"/invitation?token={Uri.EscapeDataString(Token ?? "")}");

    public sealed class InputModel
    {
        public string? DisplayName { get; set; }

        public string? Password { get; set; }

        public string? ConfirmPassword { get; set; }
    }

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        if (!invitations.IsOpen)
            return NotFound();
        this.KeepTokenFromReferrers();
        Current = await StepAsync(cancellationToken);
        return Page();
    }

    public async Task<IActionResult> OnPostAcceptAsync(CancellationToken cancellationToken)
    {
        if (!invitations.IsOpen)
            return NotFound();
        this.KeepTokenFromReferrers();
        if (this.UserId() is not { } userId)
            return Redirect(SignInPath);
        var accepted = await invitations.AcceptAsync(Token, userId, cancellationToken);
        if (accepted.IsFailure)
        {
            Current = await StepAsync(cancellationToken);
            ModelState.AddModelError(string.Empty, IsAddressUnproven(accepted) ? texts["Invitation.ProveAddressFirst"] : texts.Describe(accepted.Error!));
            return Page();
        }
        TempData["Notice"] = "Invitation.Accepted";
        return Redirect("/account");
    }

    public async Task<IActionResult> OnPostCreateAsync(CancellationToken cancellationToken)
    {
        if (!invitations.IsOpen)
            return NotFound();
        this.KeepTokenFromReferrers();
        Current = await StepAsync(cancellationToken);
        if (Current != Step.Create)
            return Page();
        foreach (var violation in passwords.Violations(Input.Password))
            ModelState.AddModelError("Input.Password", violation);
        if (!string.Equals(Input.Password, Input.ConfirmPassword, StringComparison.Ordinal))
            ModelState.AddModelError("Input.ConfirmPassword", texts["Field.ConfirmPassword.Mismatch"]);
        if (!ModelState.IsValid)
            return Page();

        var created = await invitations.CreateAccountAsync(Token, Input.DisplayName, Input.Password ?? "", cancellationToken);
        if (created.IsFailure)
        {
            ModelState.AddModelError(string.Empty, texts.Describe(created.Error!));
            return Page();
        }
        // The account exists; the invitation is accepted for it, or waits for its address to be proven — a link handed
        // over proves nothing —, or no longer holds: the account then stays, granted nothing.
        var accepted = await invitations.AcceptAsync(Token, created.Value, cancellationToken);
        TempData["Notice"] = accepted.IsSuccess ? "Invitation.CreatedAndAccepted"
            : IsAddressUnproven(accepted) ? "Invitation.CreatedAddressUnproven"
            : "Invitation.CreatedNotAccepted";
        return Redirect(IdentityCookie.LoginPath);
    }

    /// <summary>
    /// Whether the acceptance waits for the address of the account to be proven: the invitation still holds, and its
    /// link opened again accepts it once the address is verified from the account.
    /// </summary>
    private static bool IsAddressUnproven(Primitives.Result accepted)
        => accepted.Error?.Code == IdentityErrors.EmailNotVerifiedCode;

    private async Task<Step> StepAsync(CancellationToken cancellationToken)
    {
        if (await invitations.FindAsync(Token, cancellationToken) is not { } offer)
            return Step.Invalid;
        if (this.UserId() is not null)
            return string.Equals(Emails.Normalize(this.UserEmail()), offer.Email, StringComparison.Ordinal) ? Step.Accept : Step.OtherAccount;
        return await invitations.HasAccountAsync(offer.Email, cancellationToken) ? Step.SignIn : Step.Create;
    }
}
