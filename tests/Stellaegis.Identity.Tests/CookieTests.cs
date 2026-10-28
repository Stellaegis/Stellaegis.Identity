using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Identity.AspNetCore;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;

namespace Stellaegis.Identity.Tests;

/// <summary>The cookie a person is signed in with, through a login route written as a page would be.</summary>
public sealed class CookieTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed record Credentials(string Email, string Password);

    /// <summary>
    /// The host, on <paramref name="clock"/> when given, its cookie protected by <paramref name="protection"/> — two
    /// hosts sharing it read each other's cookies, as an installation whose database was installed again under the
    /// same keys does —, its session read again after <paramref name="validationInterval"/>.
    /// </summary>
    private static async Task<WebApplication> StartAsync(
        TestClock? clock = null, IDataProtectionProvider? protection = null, TimeSpan? validationInterval = null, Action<CookieAuthenticationOptions>? configure = null)
    {
        var builder = WebTestHost.Builder();
        if (clock is not null)
            builder.Services.AddSingleton<TimeProvider>(clock);
        if (validationInterval is { } interval)
            builder.Services.Configure<IdentityOptions>(options => options.Session.ValidationInterval = interval);
        builder.Services.AddStellaegisIdentityCookie(options =>
        {
            if (protection is not null)
                options.DataProtectionProvider = protection;
            configure?.Invoke(options);
        });
        builder.Services.AddAuthorization();
        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapPost("/login", async (Credentials credentials, LoginService login, CookieSignIn signIn, HttpContext http, CancellationToken ct) =>
        {
            var result = await login.AuthenticateAsync(credentials.Email, credentials.Password, cancellationToken: ct);
            if (!result.Succeeded)
                return Results.Unauthorized();
            await signIn.SignInAsync(http, result.Principal!);
            return Results.NoContent();
        });
        app.MapPost("/login/{id:guid}", async (Guid id, CookieSignIn signIn, HttpContext http, CancellationToken ct) =>
            (await signIn.SignInAsync(http, id, AuthenticationMethods.PasswordAndCode, cancellationToken: ct)).ToHttpResult());
        app.MapPost("/logout", async (CookieSignIn signIn, HttpContext http) =>
        {
            await signIn.SignOutAsync(http);
            return Results.NoContent();
        });
        app.MapGet("/me", (HttpContext http) => Results.Text(http.User.FindFirst("sub")!.Value)).RequireAuthorization();
        app.MapGet("/amr", (HttpContext http) => Results.Text(string.Join(' ', http.User.FindAll(AuthenticationMethods.ClaimType).Select(c => c.Value)))).RequireAuthorization();
        app.MapGet("/name", (HttpContext http) => Results.Text(http.User.FindFirst("name")!.Value)).RequireAuthorization();
        app.MapGet("/auth-time", (HttpContext http) => Results.Text(http.User.FindFirst(AuthenticationTime.ClaimType)!.Value)).RequireAuthorization();
        await app.StartAsync(Ct);
        return app;
    }

    [Fact]
    public async Task Signing_in_sets_the_cookie_the_pages_rely_on_and_signing_out_removes_it()
    {
        await using var app = await StartAsync();
        var id = await app.CreateAccountAsync("jane@acme.test", ct: Ct);
        var client = app.GetTestClient();

        var challenged = await client.GetAsync("/me", Ct);
        Assert.Equal(HttpStatusCode.Redirect, challenged.StatusCode);
        Assert.StartsWith("http://localhost/login?return_url=", challenged.Headers.Location!.ToString());

        var login = await client.PostAsJsonAsync("/login", new Credentials("jane@acme.test", "Correct-Horse-9"), Ct);
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        var cookie = Assert.Single(login.Headers.GetValues("Set-Cookie"));
        Assert.StartsWith($"{IdentityCookie.CookieName}=", cookie);
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", cookie, StringComparison.OrdinalIgnoreCase);

        using var me = new HttpRequestMessage(HttpMethod.Get, "/me");
        me.Headers.Add("Cookie", cookie.Split(';')[0]);
        var answered = await client.SendAsync(me, Ct);
        Assert.Equal(HttpStatusCode.OK, answered.StatusCode);
        Assert.Equal(id.ToString("N"), await answered.Content.ReadAsStringAsync(Ct));

        // The cookie carries how the person proved who they are: a password alone here.
        using var amr = new HttpRequestMessage(HttpMethod.Get, "/amr");
        amr.Headers.Add("Cookie", cookie.Split(';')[0]);
        Assert.Equal("pwd", await (await client.SendAsync(amr, Ct)).Content.ReadAsStringAsync(Ct));

        using var logout = new HttpRequestMessage(HttpMethod.Post, "/logout");
        logout.Headers.Add("Cookie", cookie.Split(';')[0]);
        var loggedOut = await client.SendAsync(logout, Ct);
        Assert.Equal(HttpStatusCode.NoContent, loggedOut.StatusCode);
        var removed = Assert.Single(loggedOut.Headers.GetValues("Set-Cookie"));
        Assert.StartsWith($"{IdentityCookie.CookieName}=;", removed);
        Assert.Contains("expires=Thu, 01 Jan 1970", removed);
    }

    [Fact]
    public async Task Wrong_credentials_and_a_blocked_account_do_not_sign_in()
    {
        await using var app = await StartAsync();
        var id = await app.CreateAccountAsync("jane@acme.test", ct: Ct);
        var client = app.GetTestClient();

        var wrong = await client.PostAsJsonAsync("/login", new Credentials("jane@acme.test", "wrong"), Ct);
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.False(wrong.Headers.Contains("Set-Cookie"));

        var byId = await client.PostAsync($"/login/{id:N}", null, Ct);
        Assert.Equal(HttpStatusCode.NoContent, byId.StatusCode);
        using (var amr = new HttpRequestMessage(HttpMethod.Get, "/amr"))
        {
            amr.Headers.Add("Cookie", byId.Headers.GetValues("Set-Cookie").Single().Split(';')[0]);
            Assert.Equal("pwd otp mfa", await (await client.SendAsync(amr, Ct)).Content.ReadAsStringAsync(Ct));
        }

        var administration = app.Administration(out var scope);
        using (scope)
            Assert.True((await administration.BlockAsync(id, Actor.Parse("admin"), Ct)).IsSuccess);
        var blocked = await client.PostAsync($"/login/{id:N}", null, Ct);
        Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);
        Assert.Equal(IdentityErrors.AccountBlockedCode, await blocked.CodeOfAsync(Ct));
        Assert.False(blocked.Headers.Contains("Set-Cookie"));
    }

    private static async Task<string> SignInAsync(HttpClient client)
    {
        var login = await client.PostAsJsonAsync("/login", new Credentials("jane@acme.test", "Correct-Horse-9"), Ct);
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        return login.Headers.GetValues("Set-Cookie").Single().Split(';')[0];
    }

    private static async Task<HttpResponseMessage> GetAsync(HttpClient client, string path, string cookie)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Add("Cookie", cookie);
        return await client.SendAsync(request, Ct);
    }

    private static void AssertClosed(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith("http://localhost/login?return_url=", response.Headers.Location!.ToString());
        Assert.StartsWith($"{IdentityCookie.CookieName}=;", Assert.Single(response.Headers.GetValues("Set-Cookie")));
    }

    [Fact]
    public async Task A_session_whose_account_is_deleted_is_closed_once_the_validation_interval_elapsed()
    {
        var clock = new TestClock();
        await using var app = await StartAsync(clock);
        var id = await app.CreateAccountAsync("jane@acme.test", ct: Ct);
        var client = app.GetTestClient();
        var cookie = await SignInAsync(client);

        var administration = app.Administration(out var scope);
        using (scope)
            Assert.True((await administration.DeleteAsync(id, Actor.Parse("admin"), Ct)).IsSuccess);

        // Within the interval the cookie is trusted as it is: five minutes unless the host sets otherwise.
        clock.Advance(TimeSpan.FromMinutes(4));
        Assert.Equal(HttpStatusCode.OK, (await GetAsync(client, "/me", cookie)).StatusCode);

        clock.Advance(TimeSpan.FromMinutes(2));
        AssertClosed(await GetAsync(client, "/me", cookie));
    }

    [Fact]
    public async Task A_cookie_older_than_the_interval_naming_an_unknown_account_is_refused_at_its_first_request()
    {
        // The database was installed again under the same keys: the cookie still opens, its account is gone.
        var clock = new TestClock();
        var protection = new EphemeralDataProtectionProvider();
        string cookie;
        await using (var before = await StartAsync(clock, protection))
        {
            await before.CreateAccountAsync("jane@acme.test", ct: Ct);
            cookie = await SignInAsync(before.GetTestClient());
        }

        await using var after = await StartAsync(clock, protection);
        clock.Advance(TimeSpan.FromDays(3));
        AssertClosed(await GetAsync(after.GetTestClient(), "/me", cookie));
    }

    [Fact]
    public async Task Reading_the_account_again_issues_the_cookie_again_with_the_account_as_it_is_now()
    {
        var clock = new TestClock();
        await using var app = await StartAsync(clock);
        var id = await app.CreateAccountAsync("jane@acme.test", ct: Ct);
        var client = app.GetTestClient();
        var signedInAt = clock.Now;
        var cookie = await SignInAsync(client);
        using (var scope = app.Services.CreateScope())
            Assert.True((await scope.ServiceProvider.GetRequiredService<ProfileService>().UpdateAsync(id, "Jane Doe", null, null, Ct)).IsSuccess);

        var within = await GetAsync(client, "/name", cookie);
        Assert.Equal("Jane", await within.Content.ReadAsStringAsync(Ct));
        Assert.False(within.Headers.Contains("Set-Cookie"));

        clock.Advance(TimeSpan.FromMinutes(6));
        var read = await GetAsync(client, "/name", cookie);
        Assert.Equal("Jane Doe", await read.Content.ReadAsStringAsync(Ct));
        var renewed = Assert.Single(read.Headers.GetValues("Set-Cookie")).Split(';')[0];

        // The renewed cookie keeps how and when the person proved who they are, and starts a new interval.
        clock.Advance(TimeSpan.FromMinutes(4));
        var kept = await GetAsync(client, "/amr", renewed);
        Assert.Equal("pwd", await kept.Content.ReadAsStringAsync(Ct));
        Assert.False(kept.Headers.Contains("Set-Cookie"));
        Assert.Equal(signedInAt.ToUnixTimeSeconds().ToString(), await (await GetAsync(client, "/auth-time", renewed)).Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task A_zero_interval_reads_the_account_on_every_request()
    {
        await using var app = await StartAsync(validationInterval: TimeSpan.Zero);
        var id = await app.CreateAccountAsync("jane@acme.test", ct: Ct);
        var client = app.GetTestClient();
        var cookie = await SignInAsync(client);
        Assert.Equal(HttpStatusCode.OK, (await GetAsync(client, "/me", cookie)).StatusCode);

        var administration = app.Administration(out var scope);
        using (scope)
            Assert.True((await administration.BlockAsync(id, Actor.Parse("admin"), Ct)).IsSuccess);
        AssertClosed(await GetAsync(client, "/me", cookie));
    }

    [Fact]
    public async Task The_validation_the_host_sets_runs_after_the_account_was_read_and_only_when_it_holds()
    {
        var seen = new List<string>();
        await using var app = await StartAsync(validationInterval: TimeSpan.Zero, configure: options =>
            options.Events.OnValidatePrincipal = context =>
            {
                seen.Add(context.Principal!.FindFirst("name")!.Value);
                return Task.CompletedTask;
            });
        var id = await app.CreateAccountAsync("jane@acme.test", ct: Ct);
        var client = app.GetTestClient();
        var cookie = await SignInAsync(client);
        using (var scope = app.Services.CreateScope())
            Assert.True((await scope.ServiceProvider.GetRequiredService<ProfileService>().UpdateAsync(id, "Jane Doe", null, null, Ct)).IsSuccess);

        Assert.Equal(HttpStatusCode.OK, (await GetAsync(client, "/me", cookie)).StatusCode);
        Assert.Equal(["Jane Doe"], seen);

        var administration = app.Administration(out var blocking);
        using (blocking)
            Assert.True((await administration.BlockAsync(id, Actor.Parse("admin"), Ct)).IsSuccess);
        AssertClosed(await GetAsync(client, "/me", cookie));
        Assert.Equal(["Jane Doe"], seen);
    }
}
