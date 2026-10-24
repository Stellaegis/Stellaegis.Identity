using System.Globalization;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Localization;
using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Identity.AspNetCore;

namespace Stellaegis.Identity.Tests;

/// <summary>The language the pages are read in, when the host imposes none.</summary>
public sealed class LanguageTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private const string Email = "jane@acme.test";
    private const string Password = "Correct-Horse-9";

    private static Task<WebApplication> StartAsync(Action<Server.IdentityPagesOptions>? pages = null, Action<WebApplication>? beforePages = null)
        => PagesTestHost.StartAsync(Ct, pages: o =>
        {
            o.Culture = null;
            pages?.Invoke(o);
        }, beforePages: beforePages);

    private static string Language(Browser browser)
        => System.Text.RegularExpressions.Regex.Match(browser.Html, "<html lang=\"([a-z]+)\"").Groups[1].Value;

    [Fact]
    public async Task The_browser_s_first_language_with_texts_wins_then_the_default_of_the_host()
    {
        await using var app = await StartAsync(o => o.DefaultCulture = "fr");
        var browser = new Browser(app) { AcceptLanguage = "de-DE, en;q=0.8, fr;q=0.5" };

        await browser.GetAsync("/login", Ct);
        Assert.Equal("en", Language(browser));

        browser.AcceptLanguage = "de-DE, it;q=0.8";
        await browser.GetAsync("/login", Ct);
        Assert.Equal("fr", Language(browser));
    }

    [Fact]
    public async Task The_language_an_application_asks_for_wins_over_the_browser_s()
    {
        await using var app = await StartAsync();
        var browser = new Browser(app) { AcceptLanguage = "en" };

        await browser.GetAsync("/login?return_url=" + Uri.EscapeDataString("/connect/authorize?client_id=app&ui_locales=de fr"), Ct);

        Assert.Equal("fr", Language(browser));
    }

    [Fact]
    public async Task The_language_chosen_on_the_pages_is_kept_in_the_culture_cookie_and_wins_over_the_browser_s()
    {
        await using var app = await StartAsync();
        var browser = new Browser(app) { AcceptLanguage = "en" };
        await browser.GetAsync("/login", Ct);
        Assert.Contains("class=\"language-picker\"", browser.Html);

        var chosen = await browser.PostFormAsync("/login?return_url=%2Faccount", new Dictionary<string, string>
        {
            ["culture"] = "fr",
            ["back"] = "/login?return_url=%2Faccount",
        }, Ct, postPath: "/language");

        Assert.Equal(HttpStatusCode.Redirect, chosen.StatusCode);
        Assert.Equal("/login?return_url=%2Faccount", chosen.Headers.Location!.ToString());
        Assert.True(browser.HasCookie(CookieRequestCultureProvider.DefaultCookieName));
        await browser.GetAsync("/login", Ct);
        Assert.Equal("fr", Language(browser));
    }

    [Fact]
    public async Task A_language_without_texts_or_a_foreign_way_back_is_not_followed()
    {
        await using var app = await StartAsync();
        var browser = new Browser(app);

        var refused = await browser.PostFormAsync("/login", new Dictionary<string, string> { ["culture"] = "de" }, Ct, postPath: "/language");
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.False(browser.HasCookie(CookieRequestCultureProvider.DefaultCookieName));

        var foreign = await browser.PostFormAsync("/login", new Dictionary<string, string> { ["culture"] = "fr", ["back"] = "https://evil.test/" }, Ct, postPath: "/language");
        Assert.Equal(IdentityCookie.LoginPath, foreign.Headers.Location!.ToString());
    }

    [Fact]
    public async Task The_language_of_the_account_wins_and_a_choice_made_signed_in_is_written_to_it()
    {
        await using var app = await StartAsync();
        var id = await app.CreateAccountAsync(Email, Password, Ct);
        using (var scope = app.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<ProfileService>().UpdateAsync(id, "Jane", "fr", null, Ct);
        var browser = new Browser(app) { AcceptLanguage = "en" };
        await browser.PostFormAsync("/login", new Dictionary<string, string> { ["culture"] = "en", ["back"] = "/login" }, Ct, postPath: "/language");

        await browser.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = Email, ["Input.Password"] = Password }, Ct);
        await browser.GetAsync("/account", Ct);
        Assert.Equal("fr", Language(browser));

        var chosen = await browser.PostFormAsync("/account", new Dictionary<string, string> { ["culture"] = "en", ["back"] = "/account" }, Ct, postPath: "/language");
        Assert.Equal("/account", chosen.Headers.Location!.ToString());
        using (var scope = app.Services.CreateScope())
            Assert.Equal("en", (await scope.ServiceProvider.GetRequiredService<IAuthUserStore>().GetByUniqueIdAsync(id, Ct))!.Locale);
        await browser.GetAsync("/account", Ct);
        Assert.Equal("en", Language(browser));
        await browser.GetAsync("/test/amr", Ct);
        Assert.Equal("pwd", browser.Html);
    }

    [Fact]
    public async Task The_culture_the_host_s_request_localization_decided_stands_for_the_browser()
    {
        await using var app = await StartAsync(beforePages: host => host.UseRequestLocalization(new RequestLocalizationOptions
        {
            DefaultRequestCulture = new RequestCulture("en"),
            SupportedCultures = [new CultureInfo("en"), new CultureInfo("fr")],
            SupportedUICultures = [new CultureInfo("en"), new CultureInfo("fr")],
            RequestCultureProviders = [new QueryStringRequestCultureProvider()],
        }));
        var browser = new Browser(app) { AcceptLanguage = "en" };

        await browser.GetAsync("/login?culture=fr", Ct);

        Assert.Equal("fr", Language(browser));
    }

    [Fact]
    public async Task A_culture_the_host_imposes_wins_and_offers_no_choice()
    {
        await using var app = await StartAsync(o => o.Culture = "fr");
        var browser = new Browser(app) { AcceptLanguage = "en" };

        await browser.GetAsync("/login?return_url=" + Uri.EscapeDataString("/connect/authorize?ui_locales=en"), Ct);

        Assert.Equal("fr", Language(browser));
        Assert.DoesNotContain("language-picker", browser.Html);
    }
}
