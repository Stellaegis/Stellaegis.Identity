using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OtpNet;
using Stellaegis.Identity.AspNetCore;
using Stellaegis.Identity.InMemory;
using Stellaegis.Identity.Server;

namespace Stellaegis.Identity.Tests;

/// <summary>The pages, on the test server: a person signs in, registers, resets a password, manages their account.</summary>
public sealed class PagesTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private const string Email = "jane@acme.test";
    private const string Password = "Correct-Horse-9";

    [Fact]
    public async Task The_login_page_renders_with_its_antiforgery_token_the_application_and_the_stylesheet()
    {
        await using var app = await PagesTestHost.StartAsync(Ct, pages: o => o.SupportUrl = "mailto:help@acme.test");
        var browser = new Browser(app);

        var page = await browser.GetAsync("/login", Ct);

        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Contains("__RequestVerificationToken", browser.Html);
        Assert.Contains("Acme", browser.Html);
        Assert.Contains("/_content/Stellaegis.Identity.Server/identity.css", browser.Html);
        Assert.Contains("mailto:help@acme.test", browser.Html);
        Assert.Contains("Sign in", browser.Html);
        Assert.Contains("lang=\"en\"", browser.Html);
        // Refused to any frame: a page laid under a decoy would have the person click unknowing.
        Assert.Contains("frame-ancestors 'none'", page.Headers.GetValues("Content-Security-Policy"));
        Assert.Equal("DENY", page.Headers.GetValues("X-Frame-Options").Single());
    }

    [Fact]
    public async Task Signing_in_by_the_form_sets_the_cookie_reaches_the_account_and_signing_out_removes_it()
    {
        await using var app = await PagesTestHost.StartAsync(Ct);
        await app.CreateAccountAsync(Email, Password, Ct);
        var browser = new Browser(app);

        var challenged = await browser.GetAsync("/account", Ct);
        Assert.Equal(HttpStatusCode.Redirect, challenged.StatusCode);
        Assert.StartsWith("http://localhost/login?return_url=", challenged.Headers.Location!.ToString());

        var signedIn = await browser.PostFormAsync("/login?return_url=%2Faccount%2Fsecurity", new Dictionary<string, string>
        {
            ["Input.Email"] = Email,
            ["Input.Password"] = Password,
        }, Ct);
        Assert.Equal(HttpStatusCode.Redirect, signedIn.StatusCode);
        Assert.Equal("/account/security", signedIn.Headers.Location!.ToString());
        Assert.True(browser.HasCookie(IdentityCookie.CookieName));

        var security = await browser.GetAsync("/account/security", Ct);
        Assert.Equal(HttpStatusCode.OK, security.StatusCode);
        Assert.Contains("Signed in", browser.Html);
        Assert.Contains(Email, browser.Html);

        var loggedOut = await browser.PostFormAsync("/account", new Dictionary<string, string>(), Ct, postPath: "/account?handler=Logout");
        Assert.Equal(HttpStatusCode.Redirect, loggedOut.StatusCode);
        Assert.Equal("/login", loggedOut.Headers.Location!.ToString());
        Assert.False(browser.HasCookie(IdentityCookie.CookieName));
    }

    [Fact]
    public async Task The_login_page_shows_an_open_session_and_continues_it_or_switches_to_another_account()
    {
        await using var app = await PagesTestHost.StartAsync(Ct);
        await app.CreateAccountAsync(Email, Password, Ct);
        await app.CreateAccountAsync("tester@acme.test", Password, Ct);
        var browser = new Browser(app);
        await browser.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = Email, ["Input.Password"] = Password }, Ct);

        // An open session is shown rather than followed, the way back on its "Continue".
        const string Login = "/login?return_url=%2Faccount%2Fsecurity";
        var shown = await browser.GetAsync(Login, Ct);
        Assert.Equal(HttpStatusCode.OK, shown.StatusCode);
        Assert.Contains("A session is already open in this browser.", browser.Html);
        Assert.Contains(Email, browser.Html);
        Assert.Contains("href=\"/account/security\"", browser.Html);
        Assert.Contains("action=\"/login?return_url=%2Faccount%2Fsecurity&amp;handler=Switch\"", browser.Html);
        Assert.DoesNotContain("Input.Password", browser.Html);

        var switched = await browser.PostFormAsync(Login, new Dictionary<string, string>(), Ct, postPath: "/login?return_url=%2Faccount%2Fsecurity&handler=Switch");
        Assert.Equal(HttpStatusCode.Redirect, switched.StatusCode);
        Assert.Equal(Login, switched.Headers.Location!.ToString());
        Assert.False(browser.HasCookie(IdentityCookie.CookieName));

        var other = await browser.PostFormAsync(Login, new Dictionary<string, string> { ["Input.Email"] = "tester@acme.test", ["Input.Password"] = Password }, Ct);
        Assert.Equal("/account/security", other.Headers.Location!.ToString());
        await browser.GetAsync("/account/security", Ct);
        Assert.Contains("tester@acme.test", browser.Html);
        Assert.DoesNotContain(Email, browser.Html);
    }

    [Fact]
    public async Task A_locked_account_is_told_what_anyone_is_told_and_its_person_is_told_by_email_once()
    {
        await using var app = await PagesTestHost.StartAsync(Ct);
        await app.CreateAccountAsync(Email, Password, Ct);
        var browser = new Browser(app);
        for (var i = 0; i < 5; i++)
            await browser.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = Email, ["Input.Password"] = "wrong" }, Ct);
        Assert.Equal(InMemoryIdentityMailer.AccountLocked, app.Mailer().LastTo(Email)!.Kind);

        var locked = await browser.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = Email, ["Input.Password"] = Password }, Ct);
        Assert.Equal(HttpStatusCode.OK, locked.StatusCode);
        Assert.Contains("Wrong e-mail or password.", browser.Html);
        Assert.DoesNotContain("locked", browser.Html);
        Assert.False(browser.HasCookie(IdentityCookie.CookieName));
        Assert.Single(app.Mailer().Sent, mail => mail.Kind == InMemoryIdentityMailer.AccountLocked);
    }

    [Fact]
    public async Task A_wrong_password_shows_the_error_in_the_language_of_the_pages()
    {
        await using var english = await PagesTestHost.StartAsync(Ct);
        await english.CreateAccountAsync(Email, Password, Ct);
        var browser = new Browser(english);
        var refused = await browser.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = Email, ["Input.Password"] = "wrong" }, Ct);
        Assert.Equal(HttpStatusCode.OK, refused.StatusCode);
        Assert.Contains("Wrong e-mail or password.", browser.Html);
        Assert.False(browser.HasCookie(IdentityCookie.CookieName));

        await using var french = await PagesTestHost.StartAsync(Ct, pages: o => o.Culture = "fr");
        await french.CreateAccountAsync(Email, Password, Ct);
        var navigateur = new Browser(french);
        await navigateur.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = Email, ["Input.Password"] = "wrong" }, Ct);
        Assert.Contains("Adresse e-mail ou mot de passe incorrect.", navigateur.Html);
        Assert.Contains("lang=\"fr\"", navigateur.Html);
    }

    [Fact]
    public async Task A_second_factor_is_asked_on_its_page_and_a_policy_sends_to_its_set_up()
    {
        await using var app = await PagesTestHost.StartAsync(Ct);
        var id = await app.CreateAccountAsync(Email, Password, Ct);
        string secret;
        using (var scope = app.Services.CreateScope())
        {
            var mfa = scope.ServiceProvider.GetRequiredService<MfaService>();
            secret = await mfa.BeginSetupAsync(id, Ct);
            Assert.True((await mfa.ConfirmSetupAsync(id, Code(secret), Ct)).IsSuccess);
        }
        var browser = new Browser(app);

        var halfway = await browser.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = Email, ["Input.Password"] = Password }, Ct);
        Assert.Equal(HttpStatusCode.Redirect, halfway.StatusCode);
        Assert.Equal("/login/mfa", halfway.Headers.Location!.ToString());
        Assert.False(browser.HasCookie(IdentityCookie.CookieName));

        var wrong = await browser.PostFormAsync("/login/mfa", new Dictionary<string, string> { ["Code"] = "000000" }, Ct);
        Assert.Equal(HttpStatusCode.OK, wrong.StatusCode);
        Assert.Contains("Wrong or expired code", browser.Html);

        // The code of the setup is spent: the login takes the next one.
        var done = await browser.PostFormAsync("/login/mfa", new Dictionary<string, string> { ["Code"] = Code(secret, next: true) }, Ct);
        Assert.Equal(HttpStatusCode.Redirect, done.StatusCode);
        Assert.Equal("/account", done.Headers.Location!.ToString());
        Assert.True(browser.HasCookie(IdentityCookie.CookieName));
        await browser.GetAsync("/test/amr", Ct);
        Assert.Equal("pwd otp mfa", browser.Html);

        // A recovery code is a second factor, not a code generated for this login: the session says so.
        string recovery;
        using (var scope = app.Services.CreateScope())
            recovery = (await scope.ServiceProvider.GetRequiredService<RecoveryCodeService>().GenerateAsync(id, Ct))[0];
        var again = new Browser(app);
        await again.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = Email, ["Input.Password"] = Password }, Ct);
        await again.PostFormAsync("/login/mfa", new Dictionary<string, string> { ["Code"] = recovery }, Ct);
        await again.GetAsync("/test/amr", Ct);
        Assert.Equal("pwd mfa", again.Html);

        await using var strict = await PagesTestHost.StartAsync(Ct, identity: o => o.Mfa.RequireForAllUsers = true);
        await strict.CreateAccountAsync(Email, Password, Ct);
        var other = new Browser(strict);
        var toSetUp = await other.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = Email, ["Input.Password"] = Password }, Ct);
        Assert.Equal("/login/mfa-setup", toSetUp.Headers.Location!.ToString());
        var setUp = await other.GetAsync("/login/mfa-setup", Ct);
        Assert.Equal(HttpStatusCode.OK, setUp.StatusCode);
        Assert.Contains("data-qr=\"otpauth://totp/Acme", other.Html);
    }

    [Fact]
    public async Task A_closed_registration_shows_it_and_creates_nothing()
    {
        await using var app = await PagesTestHost.StartAsync(Ct, identity: o => o.SelfRegistration = SelfRegistration.Closed);
        var browser = new Browser(app);

        var page = await browser.GetAsync("/register", Ct);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Contains("Registration is closed", browser.Html);
        Assert.DoesNotContain("Input_Password", browser.Html);

        var login = await browser.GetAsync("/login", Ct);
        Assert.DoesNotContain("/register", browser.Html);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
    }

    [Fact]
    public async Task An_open_registration_sends_a_code_and_the_code_creates_the_account()
    {
        await using var app = await PagesTestHost.StartAsync(Ct);
        var browser = new Browser(app);

        var sent = await browser.PostFormAsync("/register", new Dictionary<string, string>
        {
            ["Input.Email"] = "New@Acme.test",
            ["Input.DisplayName"] = "Newcomer",
            ["Input.Password"] = Password,
            ["Input.ConfirmPassword"] = Password,
        }, Ct);
        Assert.Equal(HttpStatusCode.Redirect, sent.StatusCode);
        Assert.Equal("/verify-email", sent.Headers.Location!.ToString());
        var mail = app.Mailer().LastTo("new@acme.test");
        Assert.NotNull(mail);
        Assert.Equal(InMemoryIdentityMailer.VerificationCode, mail.Kind);

        var wrong = await browser.PostFormAsync("/verify-email", new Dictionary<string, string> { ["Code"] = "0000" }, Ct);
        Assert.Equal(HttpStatusCode.OK, wrong.StatusCode);
        Assert.Contains("Wrong code", browser.Html);

        var created = await browser.PostFormAsync("/verify-email", new Dictionary<string, string> { ["Code"] = mail.Code! }, Ct);
        Assert.Equal(HttpStatusCode.Redirect, created.StatusCode);
        Assert.Equal("/login", created.Headers.Location!.ToString());
        var login = await browser.GetAsync("/login", Ct);
        Assert.Contains("Your account is created", browser.Html);

        var signedIn = await browser.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = "new@acme.test", ["Input.Password"] = Password }, Ct);
        Assert.Equal(HttpStatusCode.Redirect, signedIn.StatusCode);
        Assert.True(browser.HasCookie(IdentityCookie.CookieName));

        // The same e-mail again: the same answer, and a notice to its owner instead of a code.
        var again = await new Browser(app).PostFormAsync("/register", new Dictionary<string, string>
        {
            ["Input.Email"] = "new@acme.test",
            ["Input.DisplayName"] = "Impostor",
            ["Input.Password"] = Password,
            ["Input.ConfirmPassword"] = Password,
        }, Ct);
        Assert.Equal("/verify-email", again.Headers.Location!.ToString());
        Assert.Equal(InMemoryIdentityMailer.AccountAlreadyExists, app.Mailer().LastTo("new@acme.test")!.Kind);
    }

    [Fact]
    public async Task A_forgotten_password_is_reset_by_the_link_sent()
    {
        await using var app = await PagesTestHost.StartAsync(Ct);
        await app.CreateAccountAsync(Email, Password, Ct);
        var browser = new Browser(app);

        var unknown = await browser.PostFormAsync("/forgot-password", new Dictionary<string, string> { ["Email"] = "nobody@acme.test" }, Ct);
        Assert.Equal("/forgot-password?sent=true", unknown.Headers.Location!.ToString());
        Assert.Null(app.Mailer().LastTo("nobody@acme.test"));

        var asked = await browser.PostFormAsync("/forgot-password", new Dictionary<string, string> { ["Email"] = Email }, Ct);
        Assert.Equal("/forgot-password?sent=true", asked.Headers.Location!.ToString());
        var mail = app.Mailer().LastTo(Email);
        Assert.NotNull(mail?.Link);
        Assert.StartsWith("http://localhost/reset-password?token=", mail.Link.ToString());

        // A scanner or a preview opens the link ahead: opening it spends nothing, and the page sends no referrer.
        var preview = await browser.GetAsync(mail.Link.PathAndQuery, Ct);
        Assert.Equal(HttpStatusCode.OK, preview.StatusCode);
        Assert.Equal("no-referrer", preview.Headers.GetValues("Referrer-Policy").Single());
        var form = await browser.GetAsync(mail.Link.PathAndQuery, Ct);
        Assert.Equal(HttpStatusCode.OK, form.StatusCode);
        Assert.Contains("Input_NewPassword", browser.Html);
        var reset = await browser.PostFormAsync(mail.Link.PathAndQuery, new Dictionary<string, string>
        {
            ["Token"] = mail.Link.Query["?token=".Length..],
            ["Input.NewPassword"] = "Another-Horse-7",
            ["Input.ConfirmPassword"] = "Another-Horse-7",
        }, Ct);
        Assert.Equal("/reset-password?done=true", reset.Headers.Location!.ToString());

        var spent = await browser.GetAsync(mail.Link.PathAndQuery, Ct);
        Assert.Contains("Invalid link", browser.Html);
        Assert.Equal(HttpStatusCode.OK, spent.StatusCode);

        var signedIn = await browser.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = Email, ["Input.Password"] = "Another-Horse-7" }, Ct);
        Assert.Equal(HttpStatusCode.Redirect, signedIn.StatusCode);
        Assert.True(browser.HasCookie(IdentityCookie.CookieName));
    }

    [Fact]
    public async Task An_account_created_by_an_administrator_is_activated_by_its_link_and_then_signs_in()
    {
        await using var app = await PagesTestHost.StartAsync(Ct);
        string token;
        using (var scope = app.Services.CreateScope())
            token = (await scope.ServiceProvider.GetRequiredService<AccountAdministrationService>().CreateAsync(Email, "Jane", TokenDelivery.Hand, Stellaegis.Primitives.Actor.Parse("admin"), Ct)).Value.ActivationToken;
        var browser = new Browser(app);
        var path = $"/activate?token={Uri.EscapeDataString(token)}";

        // Opened ahead by a scanner, the link still works; the page names nobody, and sends no referrer.
        var preview = await browser.GetAsync(path, Ct);
        Assert.Equal("no-referrer", preview.Headers.GetValues("Referrer-Policy").Single());
        Assert.DoesNotContain(Email, browser.Html);
        await browser.GetAsync(path, Ct);
        Assert.Contains("Input_NewPassword", browser.Html);

        var activated = await browser.PostFormAsync(path, new Dictionary<string, string>
        {
            ["Token"] = token,
            ["Input.NewPassword"] = Password,
            ["Input.ConfirmPassword"] = Password,
        }, Ct);
        Assert.Equal("/activate?done=true", activated.Headers.Location!.ToString());

        await browser.GetAsync(path, Ct);
        Assert.Contains("Invalid link", browser.Html);

        var signedIn = await browser.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = Email, ["Input.Password"] = Password }, Ct);
        Assert.Equal(HttpStatusCode.Redirect, signedIn.StatusCode);
        Assert.True(browser.HasCookie(IdentityCookie.CookieName));
    }

    [Fact]
    public async Task A_page_of_the_host_at_the_same_path_wins_over_the_package_s()
    {
        await using var app = await PagesTestHost.StartAsync(Ct, hostPagesFirst: true);
        var browser = new Browser(app);

        var login = await browser.GetAsync("/login", Ct);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.Contains("HOST LOGIN PAGE", browser.Html);

        var register = await browser.GetAsync("/register", Ct);
        Assert.Equal(HttpStatusCode.OK, register.StatusCode);
        Assert.Contains("Create an account", browser.Html);
    }

    [Fact]
    public async Task Texts_replaced_in_the_options_show_instead_of_the_resources()
    {
        await using var app = await PagesTestHost.StartAsync(Ct, pages: o => o.Texts["en"] = new Dictionary<string, string> { ["Login.Heading"] = "Welcome back" });
        var browser = new Browser(app);

        await browser.GetAsync("/login", Ct);

        Assert.Contains("Welcome back", browser.Html);
        Assert.Contains("Sign in", browser.Html);
    }

    [Fact]
    public async Task Invalid_options_fail_the_start()
    {
        var exception = await Assert.ThrowsAnyAsync<Exception>(() => PagesTestHost.StartAsync(Ct, pages: o => o.SupportUrl = "not a url"));
        Assert.Contains("SupportUrl", (exception as OptionsValidationException)?.Message ?? exception.Message);

        var culture = await Assert.ThrowsAnyAsync<Exception>(() => PagesTestHost.StartAsync(Ct, pages: o => o.Culture = "zz-NOWHERE"));
        Assert.Contains("Culture", culture.Message);

        // "//evil.test" starts with a slash and is another host to a browser.
        var elsewhere = await Assert.ThrowsAnyAsync<Exception>(() => PagesTestHost.StartAsync(Ct, pages: o => o.DefaultReturnUrl = "//evil.test/account"));
        Assert.Contains("DefaultReturnUrl", elsewhere.Message);
    }

    [Fact]
    public async Task Without_a_mailer_the_pages_that_send_refuse_to_start_and_the_others_start()
    {
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => PagesTestHost.StartAsync(Ct, mailer: false));
        Assert.Contains(nameof(IIdentityMailer), exception.Message);
        Assert.Contains("self-registration is open", exception.Message);

        await using var app = await PagesTestHost.StartAsync(Ct, mailer: false,
            identity: o => o.SelfRegistration = SelfRegistration.Closed,
            pages: o => o.PasswordResetEnabled = false);
        var browser = new Browser(app);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/login", Ct)).StatusCode);
        Assert.DoesNotContain("/forgot-password", browser.Html);
        Assert.Equal(HttpStatusCode.NotFound, (await browser.GetAsync("/forgot-password", Ct)).StatusCode);
    }

    [Fact]
    public async Task An_address_never_proven_is_verified_from_the_account_page_by_a_code()
    {
        await using var app = await PagesTestHost.StartAsync(Ct);
        using (var scope = app.Services.CreateScope())
        {
            var created = await scope.ServiceProvider.GetRequiredService<AccountAdministrationService>().CreateAsync(Email, "Jane", TokenDelivery.Hand, Stellaegis.Primitives.Actor.Parse("admin"), Ct);
            await scope.ServiceProvider.GetRequiredService<ActivationService>().ActivateAsync(created.Value.ActivationToken, Password, Ct);
        }
        var browser = new Browser(app);
        await browser.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = Email, ["Input.Password"] = Password }, Ct);

        await browser.GetAsync("/account/email", Ct);
        Assert.Contains("This address was never verified", browser.Html);

        var asked = await browser.PostFormAsync("/account/email", new Dictionary<string, string>(), Ct, postPath: "/account/email?handler=Verify");
        Assert.Equal("/account/email", asked.Headers.Location!.ToString());
        var mail = app.Mailer().LastTo(Email)!;
        Assert.Equal(InMemoryIdentityMailer.VerificationCode, mail.Kind);

        var confirmed = await browser.PostFormAsync("/account/email", new Dictionary<string, string> { ["Code"] = mail.Code! }, Ct, postPath: "/account/email?handler=Confirm");
        Assert.Equal("/account/email", confirmed.Headers.Location!.ToString());   // still signed in: the address did not change
        await browser.GetAsync("/account/email", Ct);
        Assert.Contains("This address is verified.", browser.Html);
    }

    [Fact]
    public async Task The_account_pages_change_the_password_and_enroll_an_authenticator()
    {
        await using var app = await PagesTestHost.StartAsync(Ct, identity: o => o.Mfa.AllowedMethods = [MfaMethod.Totp, MfaMethod.Email]);
        await app.CreateAccountAsync(Email, Password, Ct);
        var browser = new Browser(app);
        await browser.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = Email, ["Input.Password"] = Password }, Ct);

        var weak = await browser.PostFormAsync("/account/password", new Dictionary<string, string>
        {
            ["Input.CurrentPassword"] = Password,
            ["Input.NewPassword"] = "short",
            ["Input.ConfirmPassword"] = "short",
        }, Ct);
        Assert.Equal(HttpStatusCode.OK, weak.StatusCode);
        Assert.Contains("At least 8 characters.", browser.Html);

        var changed = await browser.PostFormAsync("/account/password", new Dictionary<string, string>
        {
            ["Input.CurrentPassword"] = Password,
            ["Input.NewPassword"] = "Another-Horse-7",
            ["Input.ConfirmPassword"] = "Another-Horse-7",
        }, Ct);
        Assert.Equal("/account/password", changed.Headers.Location!.ToString());
        await browser.GetAsync("/account/password", Ct);
        Assert.Contains("Your password is changed.", browser.Html);

        // Enabling a second factor asks the password: from a taken session, neither the e-mail method nor an authenticator.
        var unconfirmed = await browser.PostFormAsync("/account/mfa", new Dictionary<string, string>(), Ct, postPath: "/account/mfa?handler=EnableEmail");
        Assert.Equal(HttpStatusCode.OK, unconfirmed.StatusCode);
        Assert.Contains("Enter your current password.", browser.Html);
        var wrong = await browser.PostFormAsync("/account/mfa/setup", html => new Dictionary<string, string> { ["Code"] = "000000", ["Password"] = "nope" }, Ct);
        Assert.Equal(HttpStatusCode.OK, wrong.StatusCode);
        Assert.Contains("The current password is wrong.", browser.Html);
        Assert.DoesNotContain("Wrong code.", browser.Html);

        // Each reading of the page keeps the secret it showed: the code is computed from the page the form is posted from.
        var enrolled = await browser.PostFormAsync("/account/mfa/setup", html =>
        {
            var secret = System.Text.RegularExpressions.Regex.Match(html, "class=\"auth-secret\">([A-Z2-7]+)<").Groups[1].Value;
            Assert.False(string.IsNullOrEmpty(secret));
            return new Dictionary<string, string> { ["Code"] = Code(secret), ["Password"] = "Another-Horse-7" };
        }, Ct);
        Assert.Equal("/account/mfa/recovery-codes", enrolled.Headers.Location!.ToString());
        await browser.GetAsync("/account/mfa/recovery-codes", Ct);
        Assert.Contains("Keep these recovery codes now.", browser.Html);
        await browser.GetAsync("/account/mfa", Ct);
        Assert.Contains("Enabled, by authenticator app", browser.Html);
    }

    [Fact]
    public async Task The_code_by_email_is_offered_only_where_the_installation_allows_it()
    {
        await using var app = await PagesTestHost.StartAsync(Ct);   // the authenticator alone, unless set
        await app.CreateAccountAsync(Email, Password, Ct);
        var browser = new Browser(app);
        await browser.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = Email, ["Input.Password"] = Password }, Ct);

        await browser.GetAsync("/account/mfa", Ct);
        Assert.Contains("/account/mfa/setup", browser.Html);
        Assert.DoesNotContain("handler=EnableEmail", browser.Html);
        Assert.DoesNotContain("Code by e-mail", browser.Html);

        // Posted anyway, with the password: refused by the service, not by the page alone.
        var refused = await browser.PostFormAsync("/account/mfa", new Dictionary<string, string> { ["Password"] = Password }, Ct, postPath: "/account/mfa?handler=EnableEmail");
        Assert.Equal(HttpStatusCode.OK, refused.StatusCode);
        Assert.Contains("This method is not available here.", browser.Html);
        using var scope = app.Services.CreateScope();
        var id = (await scope.ServiceProvider.GetRequiredService<IAuthUserStore>().GetByEmailAsync(Email, Ct))!.UserUniqueId;
        Assert.False(await scope.ServiceProvider.GetRequiredService<MfaService>().IsEnabledAsync(id, Ct));
    }

    [Fact]
    public async Task A_change_of_email_waits_for_the_approval_of_the_previous_address()
    {
        await using var app = await PagesTestHost.StartAsync(Ct);   // the posture unless set
        await app.CreateAccountAsync(Email, Password, Ct);
        var browser = new Browser(app);
        await browser.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = Email, ["Input.Password"] = Password }, Ct);

        await browser.PostFormAsync("/account/email", new Dictionary<string, string> { ["NewEmail"] = "jane.doe@acme.test", ["Password"] = Password }, Ct);
        var code = app.Mailer().LastTo("jane.doe@acme.test")!.Code!;
        var confirmed = await browser.PostFormAsync("/account/email", new Dictionary<string, string> { ["Code"] = code }, Ct, postPath: "/account/email?handler=Confirm");
        Assert.Equal("/account/email", confirmed.Headers.Location!.ToString());   // still signed in: nothing applied
        await browser.GetAsync("/account/email", Ct);
        Assert.Contains($"A link was sent to {Email}.", browser.Html);
        Assert.Contains($"Current e-mail: {Email}", browser.Html);
        var approval = app.Mailer().LastTo(Email)!;
        Assert.Equal(InMemoryIdentityMailer.EmailChangeApproval, approval.Kind);
        Assert.Equal("jane.doe@acme.test", approval.Code);

        var approvalPath = approval.Link!.PathAndQuery;
        var token = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(approval.Link.Query)["token"].ToString();
        await browser.GetAsync(approvalPath, Ct);
        Assert.Contains("Approve this change", browser.Html);
        Assert.Contains("jane.doe@acme.test", browser.Html);
        var approved = await browser.PostFormAsync(approvalPath, new Dictionary<string, string> { ["Token"] = token }, Ct);
        Assert.Equal("/approve-email?done=true", approved.Headers.Location!.ToString());
        Assert.False(browser.HasCookie(IdentityCookie.CookieName));   // the session carried the previous address
        using var scope = app.Services.CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IAuthUserStore>();
        Assert.Null(await store.GetByEmailAsync(Email, Ct));
        Assert.True((await store.GetByEmailAsync("jane.doe@acme.test", Ct))!.EmailVerified);
        await browser.GetAsync(approvalPath, Ct);
        Assert.Contains("Invalid link", browser.Html);   // spent
    }

    [Fact]
    public async Task Changing_the_email_needs_the_password_and_tells_the_previous_address()
    {
        await using var app = await PagesTestHost.StartAsync(Ct, identity: o => o.EmailChange.RequireApprovalByPrevious = false);
        await app.CreateAccountAsync(Email, Password, Ct);
        var browser = new Browser(app);
        await browser.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = Email, ["Input.Password"] = Password }, Ct);

        var unconfirmed = await browser.PostFormAsync("/account/email", new Dictionary<string, string> { ["NewEmail"] = "jane.doe@acme.test" }, Ct);
        Assert.Equal(HttpStatusCode.OK, unconfirmed.StatusCode);
        Assert.Contains("Enter your current password.", browser.Html);
        var wrong = await browser.PostFormAsync("/account/email", new Dictionary<string, string> { ["NewEmail"] = "jane.doe@acme.test", ["Password"] = "nope" }, Ct);
        Assert.Equal(HttpStatusCode.OK, wrong.StatusCode);
        Assert.Contains("The current password is wrong.", browser.Html);
        Assert.Null(app.Mailer().LastTo("jane.doe@acme.test"));

        var asked = await browser.PostFormAsync("/account/email", new Dictionary<string, string> { ["NewEmail"] = "jane.doe@acme.test", ["Password"] = Password }, Ct);
        Assert.Equal("/account/email", asked.Headers.Location!.ToString());
        var mail = app.Mailer().LastTo("jane.doe@acme.test")!;
        Assert.Equal(InMemoryIdentityMailer.VerificationCode, mail.Kind);

        var confirmed = await browser.PostFormAsync("/account/email", new Dictionary<string, string> { ["Code"] = mail.Code! }, Ct, postPath: "/account/email?handler=Confirm");
        Assert.Equal("/login", confirmed.Headers.Location!.ToString());   // the session carried the old address: signed out
        var notice = app.Mailer().LastTo(Email)!;
        Assert.Equal(InMemoryIdentityMailer.EmailChanged, notice.Kind);
        Assert.Equal("jane.doe@acme.test", notice.Code);
        using (var scope = app.Services.CreateScope())
            Assert.NotNull(await scope.ServiceProvider.GetRequiredService<IAuthUserStore>().GetByEmailAsync("jane.doe@acme.test", Ct));

        // The notice carries the link that undoes the change: the address comes back, the password goes, a reset link follows.
        var revertPath = notice.Link!.PathAndQuery;
        var token = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(notice.Link.Query)["token"].ToString();
        await browser.GetAsync(revertPath, Ct);
        Assert.Contains("Restore this address", browser.Html);
        Assert.Contains(Email, browser.Html);
        var reverted = await browser.PostFormAsync(revertPath, new Dictionary<string, string> { ["Token"] = token }, Ct);
        Assert.Equal("/revert-email?done=true", reverted.Headers.Location!.ToString());
        await browser.GetAsync("/revert-email?done=true", Ct);
        Assert.Contains("Address restored", browser.Html);
        Assert.Equal(InMemoryIdentityMailer.PasswordResetLink, app.Mailer().LastTo(Email)!.Kind);
        using (var scope = app.Services.CreateScope())
        {
            var restored = await scope.ServiceProvider.GetRequiredService<IAuthUserStore>().GetByEmailAsync(Email, Ct);
            Assert.NotNull(restored);
            Assert.Null(restored.PasswordHash);
        }
        await browser.GetAsync(revertPath, Ct);
        Assert.Contains("Invalid link", browser.Html);   // spent
    }

    private static string Code(string secretBase32, bool next = false)
        => new Totp(Base32Encoding.ToBytes(secretBase32)).ComputeTotp(DateTime.UtcNow.AddSeconds(next ? 30 : 0));
}
