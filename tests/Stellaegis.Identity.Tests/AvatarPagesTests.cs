using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Identity.AspNetCore;
using Stellaegis.Identity.Server;

namespace Stellaegis.Identity.Tests;

/// <summary>The avatar of the signed-in person on the pages, and the address the session carries.</summary>
public sealed class AvatarPagesTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private const string Email = "jane@acme.test";
    private const string Password = "Correct-Horse-9";

    private static string DataUrl(byte[] png) => "data:image/png;base64," + Convert.ToBase64String(png);

    private static async Task<Browser> SignedInAsync(Microsoft.AspNetCore.Builder.WebApplication app)
    {
        var browser = new Browser(app);
        await browser.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = Email, ["Input.Password"] = Password }, Ct);
        return browser;
    }

    [Fact]
    public async Task An_avatar_sent_by_the_editor_is_kept_served_to_its_person_and_removed()
    {
        await using var app = await PagesTestHost.StartAsync(Ct);
        var id = await app.CreateAccountAsync(Email, Password, Ct);
        var browser = await SignedInAsync(app);
        Assert.Equal(HttpStatusCode.NotFound, (await browser.GetAsync("/account/avatar", Ct)).StatusCode);

        var sent = await browser.PostFormAsync("/account", new Dictionary<string, string> { ["Image"] = DataUrl(ProfileTests.Png(256, 256)) }, Ct, postPath: "/account/avatar");
        Assert.Equal(HttpStatusCode.Redirect, sent.StatusCode);
        await browser.GetAsync("/account", Ct);
        Assert.Contains("The avatar is saved.", browser.Html);
        Assert.Matches(@"<img class=""account-avatar"" src=""/account/avatar\?v=[0-9]+""", browser.Html);

        var served = await browser.GetAsync("/account/avatar", Ct);
        Assert.Equal(HttpStatusCode.OK, served.StatusCode);
        Assert.Equal("image/png", served.Content.Headers.ContentType!.MediaType);
        Assert.Equal("nosniff", served.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Contains("private", served.Headers.CacheControl!.ToString());
        Assert.Contains("sandbox", served.Headers.GetValues("Content-Security-Policy").Single());

        var removed = await browser.PostFormAsync("/account", new Dictionary<string, string>(), Ct, postPath: "/account/avatar?handler=Remove");
        Assert.Equal(HttpStatusCode.Redirect, removed.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await browser.GetAsync("/account/avatar", Ct)).StatusCode);
        using var scope = app.Services.CreateScope();
        Assert.Null(await scope.ServiceProvider.GetRequiredService<IAvatarStore>().GetAsync(id, Ct));
    }

    [Fact]
    public async Task An_image_that_is_not_a_png_of_256_pixels_is_refused_and_said_on_the_account_page()
    {
        await using var app = await PagesTestHost.StartAsync(Ct);
        await app.CreateAccountAsync(Email, Password, Ct);
        var browser = await SignedInAsync(app);

        foreach (var image in new[] { DataUrl(ProfileTests.Png(512, 512)), "data:image/svg+xml;base64,PHN2Zy8+", "data:image/png;base64,not base64", "" })
        {
            await browser.PostFormAsync("/account", new Dictionary<string, string> { ["Image"] = image }, Ct, postPath: "/account/avatar");
            await browser.GetAsync("/account", Ct);
            Assert.Contains("The image must be a PNG of 256", browser.Html);
        }
        Assert.Equal(HttpStatusCode.NotFound, (await browser.GetAsync("/account/avatar", Ct)).StatusCode);
    }

    [Fact]
    public async Task The_avatar_is_nobody_else_s_and_needs_a_session()
    {
        await using var app = await PagesTestHost.StartAsync(Ct);
        await app.CreateAccountAsync(Email, Password, Ct);
        var jane = await SignedInAsync(app);
        await jane.PostFormAsync("/account", new Dictionary<string, string> { ["Image"] = DataUrl(ProfileTests.Png(256, 256)) }, Ct, postPath: "/account/avatar");

        var anonymous = await new Browser(app).GetAsync("/account/avatar", Ct);
        Assert.Equal(HttpStatusCode.Redirect, anonymous.StatusCode);

        await app.CreateAccountAsync("john@acme.test", Password, Ct);
        var john = new Browser(app);
        await john.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = "john@acme.test", ["Input.Password"] = Password }, Ct);
        Assert.Equal(HttpStatusCode.NotFound, (await john.GetAsync("/account/avatar", Ct)).StatusCode);
    }

    [Fact]
    public async Task The_gravatar_is_offered_only_when_the_host_turns_it_on_with_the_address_of_the_account()
    {
        await using var closed = await PagesTestHost.StartAsync(Ct);
        await closed.CreateAccountAsync(Email, Password, Ct);
        var browser = await SignedInAsync(closed);
        await browser.GetAsync("/account", Ct);
        Assert.Contains("data-avatar-editor", browser.Html);
        Assert.DoesNotContain("data-avatar-gravatar", browser.Html);

        await using var open = await PagesTestHost.StartAsync(Ct, pages: o => { o.GravatarImport = true; o.AvatarCornerRadius = 20; });
        await open.CreateAccountAsync(Email, Password, Ct);
        browser = await SignedInAsync(open);
        await browser.GetAsync("/account", Ct);
        Assert.Contains("value=\"jane@acme.test\" autocomplete=\"off\" data-avatar-gravatar-email", browser.Html);
        Assert.Contains("Gravatar (Automattic)", browser.Html);
        Assert.Contains("--si-avatar-radius: 20%", browser.Html);
    }

    [Fact]
    public async Task The_session_carries_the_address_of_the_avatar_when_the_host_declares_it()
    {
        using var declared = new TestHost(o => o.AvatarUrl = "https://id.acme.test/account/avatar");
        var id = await declared.CreateUserAsync();
        var login = declared.Get<LoginService>();
        Assert.Null((await login.CreatePrincipalAsync(id, [AuthenticationMethods.Password]))!.FindFirst(ProfileClaims.Picture));

        await declared.Get<ProfileService>().SetAvatarAsync(id, ProfileTests.Png(256, 256));
        var picture = (await login.CreatePrincipalAsync(id, [AuthenticationMethods.Password]))!.FindFirst("picture")!.Value;
        Assert.Equal($"https://id.acme.test/account/avatar?v={declared.Clock.Now.ToUnixTimeMilliseconds()}", picture);

        using var undeclared = new TestHost();
        var other = await undeclared.CreateUserAsync();
        await undeclared.Get<ProfileService>().SetAvatarAsync(other, ProfileTests.Png(256, 256));
        Assert.Null((await undeclared.Get<LoginService>().CreatePrincipalAsync(other, [AuthenticationMethods.Password]))!.FindFirst("picture"));
    }

    [Theory]
    [InlineData("/account/avatar")]
    [InlineData("ftp://id.acme.test/avatar")]
    [InlineData("https://id.acme.test/avatar?size=64")]
    public void An_address_of_the_avatar_that_is_not_absolute_http_is_refused(string url)
    {
        var options = new IdentityOptions { PasswordHasher = { Pepper = "p" }, Mfa = { SecretKeys = new Primitives.KeySlots { Keys = { [1] = "k" } } } };
        Assert.Null(options.FindError());
        options.AvatarUrl = url;
        Assert.Contains("AvatarUrl", options.FindError());
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(51)]
    public void A_rounding_outside_a_square_and_a_circle_is_refused(int radius)
        => Assert.Contains("AvatarCornerRadius", new IdentityPagesOptions { AvatarCornerRadius = radius }.FindError());
}
