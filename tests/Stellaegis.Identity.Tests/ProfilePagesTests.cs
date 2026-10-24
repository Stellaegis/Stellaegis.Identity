using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Identity.AspNetCore;

namespace Stellaegis.Identity.Tests;

/// <summary>The profile of the signed-in person, on the account page and through the route of one's own account.</summary>
public sealed class ProfilePagesTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private const string Email = "jane@acme.test";
    private const string Password = "Correct-Horse-9";

    private static async Task<Browser> SignedInAsync(Microsoft.AspNetCore.Builder.WebApplication app)
    {
        var browser = new Browser(app);
        await browser.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = Email, ["Input.Password"] = Password }, Ct);
        Assert.True(browser.HasCookie(IdentityCookie.CookieName));
        return browser;
    }

    private static async Task<AuthUser> AccountAsync(Microsoft.AspNetCore.Builder.WebApplication app, Guid id)
    {
        using var scope = app.Services.CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<IAuthUserStore>().GetByUniqueIdAsync(id, Ct))!;
    }

    [Fact]
    public async Task The_account_page_shows_the_profile_and_saves_it_and_the_session_follows()
    {
        await using var app = await PagesTestHost.StartAsync(Ct, pages: o => o.Culture = null);
        var id = await app.CreateAccountAsync(Email, Password, Ct);
        var browser = await SignedInAsync(app);

        await browser.GetAsync("/account", Ct);
        Assert.Contains("value=\"Jane\"", browser.Html);
        Assert.Contains("<option value=\"Europe/Paris\">", browser.Html);

        var saved = await browser.PostFormAsync("/account", new Dictionary<string, string>
        {
            ["Input.DisplayName"] = "Jane Doe",
            ["Input.Locale"] = "fr",
            ["Input.TimeZone"] = "Europe/Brussels",
        }, Ct);

        Assert.Equal(HttpStatusCode.Redirect, saved.StatusCode);
        var account = await AccountAsync(app, id);
        Assert.Equal(("Jane Doe", "fr", "Europe/Brussels"), (account.DisplayName, account.Locale, account.TimeZone));
        await browser.GetAsync("/account", Ct);
        Assert.Contains("<html lang=\"fr\"", browser.Html);
        Assert.Contains("Profil enregistr", browser.Html);   // Razor encodes the accent
        Assert.Contains("<option value=\"fr\" lang=\"fr\" selected=\"selected\">", browser.Html);
    }

    [Fact]
    public async Task A_profile_that_does_not_hold_is_refused_on_the_page_and_nothing_changes()
    {
        await using var app = await PagesTestHost.StartAsync(Ct);
        var id = await app.CreateAccountAsync(Email, Password, Ct);
        var browser = await SignedInAsync(app);

        var name = await browser.PostFormAsync("/account", new Dictionary<string, string> { ["Input.DisplayName"] = "J" }, Ct);
        Assert.Equal(HttpStatusCode.OK, name.StatusCode);
        Assert.Contains("The display name has 2 to 100 characters.", browser.Html);

        await browser.PostFormAsync("/account", new Dictionary<string, string> { ["Input.DisplayName"] = "Jane", ["Input.TimeZone"] = "Paris" }, Ct);
        Assert.Contains("This time zone is not recognized.", browser.Html);

        Assert.Null((await AccountAsync(app, id)).TimeZone);
    }

    [Fact]
    public async Task A_registration_keeps_the_time_zone_of_the_browser()
    {
        await using var app = await PagesTestHost.StartAsync(Ct);
        var browser = new Browser(app);
        await browser.PostFormAsync("/register", new Dictionary<string, string>
        {
            ["Input.Email"] = "new@acme.test",
            ["Input.DisplayName"] = "Newcomer",
            ["Input.Password"] = Password,
            ["Input.ConfirmPassword"] = Password,
            ["Input.TimeZone"] = "America/Montreal",
        }, Ct);
        await browser.PostFormAsync("/verify-email", new Dictionary<string, string> { ["Code"] = app.Mailer().LastTo("new@acme.test")!.Code! }, Ct);

        using var scope = app.Services.CreateScope();
        var account = await scope.ServiceProvider.GetRequiredService<IAuthUserStore>().GetByEmailAsync("new@acme.test", Ct);
        Assert.Equal("America/Montreal", account!.TimeZone);
    }

    [Fact]
    public async Task A_registration_without_a_time_zone_or_with_a_wrong_one_keeps_none()
    {
        await using var app = await PagesTestHost.StartAsync(Ct);
        var browser = new Browser(app);
        await browser.PostFormAsync("/register", new Dictionary<string, string>
        {
            ["Input.Email"] = "new@acme.test",
            ["Input.DisplayName"] = "Newcomer",
            ["Input.Password"] = Password,
            ["Input.ConfirmPassword"] = Password,
            ["Input.TimeZone"] = "Romance Standard Time",
        }, Ct);
        await browser.PostFormAsync("/verify-email", new Dictionary<string, string> { ["Code"] = app.Mailer().LastTo("new@acme.test")!.Code! }, Ct);

        using var scope = app.Services.CreateScope();
        Assert.Null((await scope.ServiceProvider.GetRequiredService<IAuthUserStore>().GetByEmailAsync("new@acme.test", Ct))!.TimeZone);
    }

    [Fact]
    public async Task The_route_of_one_s_own_account_reads_and_replaces_the_profile_and_refuses_what_does_not_hold()
    {
        await using var app = await PagesTestHost.StartAsync(Ct);
        var id = await app.CreateAccountAsync(Email, Password, Ct);

        var anonymous = await new Browser(app).SendJsonAsync(HttpMethod.Get, "/identity/account/profile", null, Ct);
        Assert.NotEqual(HttpStatusCode.OK, anonymous.StatusCode);

        var browser = await SignedInAsync(app);
        var read = await browser.SendJsonAsync(HttpMethod.Get, "/identity/account/profile", null, Ct);
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);
        using (var profile = JsonDocument.Parse(browser.Html))
            Assert.Equal("Jane", profile.RootElement.GetProperty("displayName").GetString());

        var replaced = await browser.SendJsonAsync(HttpMethod.Put, "/identity/account/profile",
            new IdentityAccountEndpoints.ProfileChange("Jane Doe", "en-GB", "Europe/Paris"), Ct);
        Assert.Equal(HttpStatusCode.OK, replaced.StatusCode);
        Assert.Equal(("Jane Doe", "en-GB", "Europe/Paris"), await ProfileOfAsync(app, id));

        var refused = await browser.SendJsonAsync(HttpMethod.Put, "/identity/account/profile",
            new IdentityAccountEndpoints.ProfileChange("Jane", "en-gb", null), Ct);
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Contains(IdentityErrors.InvalidLocaleCode, browser.Html);
        Assert.Equal(("Jane Doe", "en-GB", "Europe/Paris"), await ProfileOfAsync(app, id));
    }

    private static async Task<(string, string?, string?)> ProfileOfAsync(Microsoft.AspNetCore.Builder.WebApplication app, Guid id)
    {
        var account = await AccountAsync(app, id);
        return (account.DisplayName, account.Locale, account.TimeZone);
    }
}
