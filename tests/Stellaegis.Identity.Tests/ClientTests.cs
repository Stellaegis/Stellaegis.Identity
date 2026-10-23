using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Identity.AspNetCore;
using Stellaegis.Identity.Client;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;

namespace Stellaegis.Identity.Tests;

/// <summary>The HTTP source of the blocked accounts, against the administration routes of a host holding the accounts.</summary>
public sealed class ClientTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed class StaticToken(string? token) : IIdentityClientTokenProvider
    {
        public ValueTask<string?> GetTokenAsync(CancellationToken cancellationToken = default) => ValueTask.FromResult(token);
    }

    private static async Task<WebApplication> StartHostAsync()
    {
        var builder = WebTestHost.Builder().WithHeaderAuthentication();
        builder.Services.AddStellaegisIdentityAdministration();
        builder.Services.AddStellaegisInMemoryIdentityMailer();
        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGroup("/api/admin").MapIdentityAdminEndpoints().RequireAuthorizationPerOperation(operation => operation.ToString());
        await app.StartAsync(Ct);
        return app;
    }

    private static IBlockedUsersSource SourceOf(WebApplication host, string? token)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IIdentityClientTokenProvider>(new StaticToken(token));
        services.AddStellaegisIdentityClient(options => options.BaseUrl = "http://localhost/api/admin/identity")
            .ConfigurePrimaryHttpMessageHandler(() => host.GetTestServer().CreateHandler());
        return services.BuildServiceProvider().GetRequiredService<IBlockedUsersSource>();
    }

    [Fact]
    public async Task The_http_source_reads_the_blocked_accounts_of_the_host_with_its_token()
    {
        await using var host = await StartHostAsync();
        var jane = await host.CreateAccountAsync("jane@acme.test", ct: Ct);
        var john = await host.CreateAccountAsync("john@acme.test", ct: Ct);
        var administration = host.Administration(out var scope);
        using (scope)
            Assert.True((await administration.BlockAsync(john, Actor.Parse("admin"), Ct)).IsSuccess);

        var blocked = await SourceOf(host, "service").GetBlockedSubjectsAsync(Ct);

        Assert.Equal([john.ToString("N")], blocked);
        Assert.DoesNotContain(jane.ToString("N"), blocked);
    }

    [Fact]
    public async Task Without_a_token_the_host_refuses_and_the_source_says_so()
    {
        await using var host = await StartHostAsync();

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() => SourceOf(host, null).GetBlockedSubjectsAsync(Ct));

        Assert.Equal(HttpStatusCode.Unauthorized, exception.StatusCode);
    }

    [Fact]
    public void The_options_take_the_form_of_the_family()
    {
        Assert.Equal("Stellaegis:Identity:Client", IdentityClientOptions.SectionName);
        Assert.Contains("BaseUrl", new IdentityClientOptions().FindError());
        Assert.Null(new IdentityClientOptions { BaseUrl = "https://identity.internal/api/admin/identity" }.FindError());
    }
}
