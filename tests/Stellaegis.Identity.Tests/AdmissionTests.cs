using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Stellaegis.Identity.AspNetCore;
using Stellaegis.Primitives;

namespace Stellaegis.Identity.Tests;

/// <summary>The admission of actors on a resource server: a blocked account is refused whatever its credentials say.</summary>
public sealed class AdmissionTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static WebApplication Build(TimeSpan? reconcileInterval = null, bool withSource = true)
    {
        var builder = WebTestHost.Builder().WithHeaderAuthentication();
        if (!withSource)
            builder.Services.RemoveAll<IBlockedUsersSource>();
        builder.Services.AddStellaegisIdentityAdmission(options => options.ReconcileInterval = reconcileInterval ?? TimeSpan.Zero);
        var app = builder.Build();
        app.UseAuthentication();
        app.UseStellaegisIdentityAdmission();
        app.UseAuthorization();
        app.MapGet("/ping", () => "pong").RequireAuthorization();
        return app;
    }

    [Fact]
    public async Task A_blocked_account_is_refused_at_the_door_read_at_startup_and_admitted_again_by_the_host()
    {
        await using var app = Build();
        var jane = await app.CreateAccountAsync("jane@acme.test", ct: Ct);
        var john = await app.CreateAccountAsync("john@acme.test", ct: Ct);
        var administration = app.Administration(out var scope);
        using (scope)
            Assert.True((await administration.BlockAsync(john, Actor.Parse("admin"), Ct)).IsSuccess);
        await app.StartAsync(Ct);

        Assert.Equal(HttpStatusCode.OK, (await app.ClientAs(jane.ToString("N")).GetAsync("/ping", Ct)).StatusCode);
        var refused = await app.ClientAs(john.ToString("N")).GetAsync("/ping", Ct);
        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        Assert.Equal(IdentityErrors.AccountBlockedCode, await refused.CodeOfAsync(Ct));

        // The host's subscription to UserUnblockedEvent and UserBlockedEvent, in the events' absence here.
        var accounts = app.Services.GetRequiredService<BlockedAccounts>();
        accounts.Unblock(john);
        Assert.Equal(HttpStatusCode.OK, (await app.ClientAs(john.ToString("N")).GetAsync("/ping", Ct)).StatusCode);
        accounts.Block(jane);
        Assert.Equal(HttpStatusCode.Unauthorized, (await app.ClientAs(jane.ToString("N")).GetAsync("/ping", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await app.ClientAs(null).GetAsync("/ping", Ct)).StatusCode);
    }

    [Fact]
    public async Task The_periodic_reading_catches_a_block_no_event_told()
    {
        await using var app = Build(reconcileInterval: TimeSpan.FromMilliseconds(50));
        var jane = await app.CreateAccountAsync("jane@acme.test", ct: Ct);
        await app.StartAsync(Ct);
        var client = app.ClientAs(jane.ToString("N"));
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/ping", Ct)).StatusCode);

        var administration = app.Administration(out var scope);
        using (scope)
            Assert.True((await administration.BlockAsync(jane, Actor.Parse("admin"), Ct)).IsSuccess);

        var status = HttpStatusCode.OK;
        for (var attempt = 0; attempt < 100 && status == HttpStatusCode.OK; attempt++)
        {
            await Task.Delay(50, Ct);
            status = (await client.GetAsync("/ping", Ct)).StatusCode;
        }
        Assert.Equal(HttpStatusCode.Unauthorized, status);
    }

    [Fact]
    public async Task An_admission_without_a_source_of_the_blocked_accounts_fails_the_startup()
    {
        await using var app = Build(withSource: false);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => app.StartAsync(Ct));

        Assert.Contains("AddStellaegisLocalBlockedUsersSource", exception.Message);
    }

    [Fact]
    public void Enabling_the_middleware_without_registering_the_admission_fails()
    {
        var builder = WebTestHost.Builder().WithHeaderAuthentication();
        var app = builder.Build();

        var exception = Assert.Throws<InvalidOperationException>(() => app.UseStellaegisIdentityAdmission());

        Assert.Contains("AddStellaegisIdentityAdmission", exception.Message);
    }

    [Fact]
    public void The_options_refuse_a_negative_interval()
    {
        Assert.Null(new IdentityAdmissionOptions().FindError());
        Assert.Null(new IdentityAdmissionOptions { ReconcileInterval = TimeSpan.Zero }.FindError());
        Assert.Contains("ReconcileInterval", new IdentityAdmissionOptions { ReconcileInterval = TimeSpan.FromSeconds(-1) }.FindError());
    }
}
