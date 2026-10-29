using System.Net;
using Stellaegis.Identity.AspNetCore;
using Stellaegis.Identity.InMemory;

namespace Stellaegis.Identity.Tests;

/// <summary>
/// The pages refuse what comes too fast: too many POSTs from one client or naming one e-mail, a code or a link asked
/// again too soon. On the test server every browser has the same address, so the client is one throughout.
/// </summary>
public sealed class RateLimitingTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private const string Email = "jane@acme.test";
    private const string Password = "Correct-Horse-9";

    private static Dictionary<string, string> Login(string email) => new() { ["Input.Email"] = email, ["Input.Password"] = "wrong" };

    private static Dictionary<string, string> Forgot(string email) => new() { ["Email"] = email };

    [Fact]
    public async Task The_posts_naming_one_email_are_refused_past_their_limit_whatever_the_page()
    {
        await using var app = await PagesTestHost.StartAsync(Ct, pages: o => o.RateLimiting.RequestsPerEmail = 2);
        await app.CreateAccountAsync(Email, Password, Ct);
        var browser = new Browser(app);

        Assert.Equal(HttpStatusCode.OK, (await browser.PostFormAsync("/login", Login(Email), Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.PostFormAsync("/login", Login("Jane@Acme.test"), Ct)).StatusCode);   // the same address, normalized

        var refused = await browser.PostFormAsync("/login", Login(Email), Ct);
        Assert.Equal(HttpStatusCode.TooManyRequests, refused.StatusCode);
        Assert.True(refused.Headers.RetryAfter is { Delta: { } wait } && wait > TimeSpan.Zero, "Retry-After names the wait.");
        Assert.Contains("Too many attempts. Try again in", browser.Html);
        Assert.Contains("__RequestVerificationToken", browser.Html);   // the page again, not a bare status
        Assert.False(browser.HasCookie(IdentityCookie.CookieName));

        // The count is the e-mail's: another page naming it is refused too, another e-mail is not.
        Assert.Equal(HttpStatusCode.TooManyRequests, (await browser.PostFormAsync("/forgot-password", Forgot(Email), Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.PostFormAsync("/login", Login("john@acme.test"), Ct)).StatusCode);
    }

    [Fact]
    public async Task The_posts_of_one_client_are_refused_past_their_limit_and_gets_never_count()
    {
        await using var app = await PagesTestHost.StartAsync(Ct, pages: o => o.RateLimiting.RequestsPerClient = 3);
        var browser = new Browser(app);
        for (var i = 0; i < 5; i++)
            Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/login", Ct)).StatusCode);
        for (var i = 0; i < 3; i++)
            Assert.Equal(HttpStatusCode.Redirect, (await browser.PostFormAsync("/forgot-password", Forgot($"person{i}@acme.test"), Ct)).StatusCode);

        var refused = await browser.PostFormAsync("/forgot-password", Forgot("person4@acme.test"), Ct);
        Assert.Equal(HttpStatusCode.TooManyRequests, refused.StatusCode);
        Assert.Contains("Too many attempts", browser.Html);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/register", Ct)).StatusCode);

        // Choosing a language is never counted.
        var language = await browser.PostFormAsync("/login", new Dictionary<string, string> { ["culture"] = "fr", ["back"] = "/login" }, Ct, postPath: "/language");
        Assert.Equal(HttpStatusCode.Redirect, language.StatusCode);
    }

    [Fact]
    public async Task Turned_off_the_package_limits_nothing()
    {
        await using var app = await PagesTestHost.StartAsync(Ct, pages: o =>
        {
            o.RateLimiting.Enabled = false;
            o.RateLimiting.RequestsPerClient = 1;
            o.RateLimiting.RequestsPerEmail = 1;
        });
        var browser = new Browser(app);
        for (var i = 0; i < 3; i++)
            Assert.Equal(HttpStatusCode.Redirect, (await browser.PostFormAsync("/forgot-password", Forgot(Email), Ct)).StatusCode);
    }

    [Fact]
    public async Task A_code_or_a_link_asked_again_too_soon_is_not_sent_and_the_page_says_what_it_always_says()
    {
        await using var app = await PagesTestHost.StartAsync(Ct, identity: o =>
        {
            o.EmailVerification.MinimumInterval = TimeSpan.FromMinutes(1);
            o.PasswordReset.MinimumInterval = TimeSpan.FromMinutes(1);
        });
        await app.CreateAccountAsync(Email, Password, Ct);
        var browser = new Browser(app);

        for (var i = 0; i < 2; i++)
            Assert.Equal("/forgot-password?sent=true", (await browser.PostFormAsync("/forgot-password", Forgot(Email), Ct)).Headers.Location!.ToString());
        Assert.Single(app.Mailer().Sent, mail => mail.Email == Email && mail.Kind == InMemoryIdentityMailer.PasswordResetLink);

        var registering = new Dictionary<string, string>
        {
            ["Input.Email"] = "new@acme.test",
            ["Input.DisplayName"] = "Newcomer",
            ["Input.Password"] = Password,
            ["Input.ConfirmPassword"] = Password,
        };
        Assert.Equal("/verify-email", (await browser.PostFormAsync("/register", registering, Ct)).Headers.Location!.ToString());
        var resent = await browser.PostFormAsync("/verify-email", new Dictionary<string, string>(), Ct, postPath: "/verify-email?handler=Resend");
        Assert.Equal("/verify-email", resent.Headers.Location!.ToString());
        await browser.GetAsync("/verify-email", Ct);
        Assert.Contains("A new code was sent.", browser.Html);
        Assert.Single(app.Mailer().Sent, mail => mail.Email == "new@acme.test");
    }
}
