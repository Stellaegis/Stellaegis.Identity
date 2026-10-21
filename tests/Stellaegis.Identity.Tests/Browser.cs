using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Identity.AspNetCore;
using Stellaegis.Identity.InMemory;
using Stellaegis.Identity.Server;
using Stellaegis.Identity.Tests.HostPages.Pages;

namespace Stellaegis.Identity.Tests;

/// <summary>A web host of the pages, assembled in memory on the test server, with the in-memory mailer unless told otherwise.</summary>
internal static class PagesTestHost
{
    public static async Task<WebApplication> StartAsync(
        CancellationToken ct,
        Action<IdentityPagesOptions>? pages = null,
        Action<IdentityOptions>? identity = null,
        bool mailer = true,
        bool hostPagesFirst = false)
    {
        var builder = WebTestHost.Builder();
        if (identity is not null)
            builder.Services.Configure(identity);
        if (hostPagesFirst)
            builder.Services.AddRazorPages().AddApplicationPart(typeof(HostLoginModel).Assembly);
        builder.Services.AddStellaegisIdentityCookie();
        builder.Services.AddStellaegisIdentityPages(options =>
        {
            options.ApplicationName = "Acme";
            options.Culture = "en";
            pages?.Invoke(options);
        });
        if (mailer)
            builder.Services.AddStellaegisInMemoryIdentityMailer();
        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapStellaegisIdentityPages();
        await app.StartAsync(ct);
        return app;
    }

    public static InMemoryIdentityMailer Mailer(this WebApplication app) => app.Services.GetRequiredService<InMemoryIdentityMailer>();
}

/// <summary>
/// A browser of the test server: keeps the cookies the pages set, reads the antiforgery token of a page, posts a
/// form. Redirects are not followed, so that a test reads where a page sends the person.
/// </summary>
internal sealed class Browser(WebApplication app)
{
    private static readonly Regex TokenPattern = new("name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"", RegexOptions.Compiled);

    private readonly HttpClient _client = app.GetTestClient();
    private readonly Dictionary<string, string> _cookies = new(StringComparer.Ordinal);

    public string Html { get; private set; } = "";

    public bool HasCookie(string name) => _cookies.ContainsKey(name);

    public async Task<HttpResponseMessage> GetAsync(string path, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        return await SendAsync(request, ct);
    }

    /// <summary>Gets <paramref name="path"/>, reads its antiforgery token, and posts <paramref name="fields"/> to <paramref name="postPath"/> (<paramref name="path"/> unless set) with it.</summary>
    public Task<HttpResponseMessage> PostFormAsync(string path, IDictionary<string, string> fields, CancellationToken ct, string? postPath = null)
        => PostFormAsync(path, _ => fields, ct, postPath);

    /// <summary>As <see cref="PostFormAsync(string, IDictionary{string, string}, CancellationToken, string?)"/>, the fields built from the page just read — when the page shows what the form needs.</summary>
    public async Task<HttpResponseMessage> PostFormAsync(string path, Func<string, IDictionary<string, string>> fields, CancellationToken ct, string? postPath = null)
    {
        var page = await GetAsync(path, ct);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        var token = TokenPattern.Match(Html).Groups[1].Value;
        Assert.False(string.IsNullOrEmpty(token), "The page carries no antiforgery token.");
        var form = new Dictionary<string, string>(fields(Html)) { ["__RequestVerificationToken"] = token };
        using var request = new HttpRequestMessage(HttpMethod.Post, postPath ?? path) { Content = new FormUrlEncodedContent(form) };
        return await SendAsync(request, ct);
    }

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        if (_cookies.Count > 0)
            request.Headers.Add("Cookie", string.Join("; ", _cookies.Select(pair => $"{pair.Key}={pair.Value}")));
        var response = await _client.SendAsync(request, ct);
        if (response.Headers.TryGetValues("Set-Cookie", out var setCookies))
        {
            foreach (var setCookie in setCookies)
            {
                var first = setCookie.Split(';')[0];
                var separator = first.IndexOf('=');
                var name = first[..separator];
                var value = first[(separator + 1)..];
                if (value.Length == 0 || setCookie.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase))
                    _cookies.Remove(name);
                else
                    _cookies[name] = value;
            }
        }
        Html = await response.Content.ReadAsStringAsync(ct);
        return response;
    }
}
