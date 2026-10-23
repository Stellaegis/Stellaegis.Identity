using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Identity.Tests;

/// <summary>
/// A web host of the accounts assembled in memory on the test server, with an authentication read from headers —
/// <c>X-Actor</c> for the subject, <c>X-Grants</c> for the operations granted, or <c>Authorization: Bearer</c> with
/// every operation granted, for a service — and one policy per operation, as a host with rights of its own has.
/// </summary>
internal static class WebTestHost
{
    public const string Pepper = "test-pepper";

    public static WebApplicationBuilder Builder(ApplicationFrame? frame = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddStellaegisFrame(frame ?? ApplicationFrame.WithoutCompartments);
        builder.Services.AddStellaegisIdentityInMemory(options =>
        {
            options.PasswordHasher.Pepper = Pepper;
            options.PasswordHasher.Iterations = 1000;
            options.LoginPolicy.MinResponseTime = TimeSpan.Zero;
            options.Registration.Posture = RegistrationPosture.Open;
        });
        builder.Services.AddStellaegisLocalBlockedUsersSource();
        return builder;
    }

    /// <summary>The header authentication, and one policy per operation of the module requiring its grant.</summary>
    public static WebApplicationBuilder WithHeaderAuthentication(this WebApplicationBuilder builder)
    {
        builder.Services.AddAuthentication(HeaderAuthentication.SchemeName)
            .AddScheme<AuthenticationSchemeOptions, HeaderAuthentication>(HeaderAuthentication.SchemeName, null);
        builder.Services.AddAuthorization(options =>
        {
            foreach (var operation in IdentityOperations.All)
                options.AddPolicy(operation.ToString(), policy => policy.RequireClaim(HeaderAuthentication.GrantClaim, operation.ToString()));
        });
        return builder;
    }

    /// <summary>An enabled account created by the administration, before or after the host started.</summary>
    public static async Task<Guid> CreateAccountAsync(this WebApplication app, string email, string password = "Correct-Horse-9", CancellationToken ct = default)
    {
        using var scope = app.Services.CreateScope();
        var created = await scope.ServiceProvider.GetRequiredService<AccountAdministrationService>().CreateAsync(email, "Jane", TokenDelivery.Email, Actor.Parse("admin"), ct);
        Assert.True(created.IsSuccess, created.Error?.ToString());
        var activated = await scope.ServiceProvider.GetRequiredService<ActivationService>().ActivateAsync(created.Value.ActivationToken, password, ct);
        Assert.True(activated.IsSuccess, activated.Error?.ToString());
        return created.Value.UserUniqueId;
    }

    public static AccountAdministrationService Administration(this WebApplication app, out IServiceScope scope)
    {
        scope = app.Services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<AccountAdministrationService>();
    }

    /// <summary>A client of the host calling as <paramref name="actor"/>, holding <paramref name="grants"/>.</summary>
    public static HttpClient ClientAs(this WebApplication app, string? actor, params string[] grants)
    {
        var client = app.GetTestClient();
        if (actor is not null)
            client.DefaultRequestHeaders.Add(HeaderAuthentication.ActorHeader, actor);
        if (grants.Length > 0)
            client.DefaultRequestHeaders.Add(HeaderAuthentication.GrantsHeader, string.Join(",", grants));
        return client;
    }

    public static async Task<string?> CodeOfAsync(this HttpResponseMessage response, CancellationToken ct)
    {
        var problem = await response.Content.ReadFromJsonAsync<ProblemBody>(ct);
        return problem?.Code;
    }

    private sealed record ProblemBody(string? Code);

    internal sealed class HeaderAuthentication(
        IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        public const string SchemeName = "Header";
        public const string ActorHeader = "X-Actor";
        public const string GrantsHeader = "X-Grants";
        public const string GrantClaim = "grant";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string? subject = null;
            IEnumerable<string> grants = [];
            if (Request.Headers.TryGetValue(ActorHeader, out var actor))
            {
                subject = actor.ToString();
                grants = Request.Headers.TryGetValue(GrantsHeader, out var granted)
                    ? granted.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    : [];
            }
            else if (AuthenticationHeaderValue.TryParse(Request.Headers.Authorization, out var bearer) && bearer.Scheme == "Bearer" && bearer.Parameter is { } token)
            {
                subject = token;
                grants = IdentityOperations.All.Select(operation => operation.ToString());
            }
            if (subject is null)
                return Task.FromResult(AuthenticateResult.NoResult());

            var claims = new List<Claim> { new("sub", subject) };
            claims.AddRange(grants.Select(grant => new Claim(GrantClaim, grant)));
            var identity = new ClaimsIdentity(claims, SchemeName);
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
        }
    }
}
