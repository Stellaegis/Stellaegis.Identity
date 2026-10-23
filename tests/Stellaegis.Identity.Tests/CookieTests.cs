using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Builder;
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

    private static async Task<WebApplication> StartAsync()
    {
        var builder = WebTestHost.Builder();
        builder.Services.AddStellaegisIdentityCookie();
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
}
