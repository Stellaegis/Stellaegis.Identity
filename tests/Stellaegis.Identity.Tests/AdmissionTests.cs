using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Stellaegis.Identity.AspNetCore;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;

namespace Stellaegis.Identity.Tests;

/// <summary>The admission of actors on a resource server: a blocked account is refused whatever its credentials say.</summary>
public sealed class AdmissionTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static ClaimsPrincipal PrincipalOf(string subject)
        => new(new ClaimsIdentity([new Claim("sub", subject)], "test"));

    private static WebApplication Build(TimeSpan? reconcileInterval = null, bool withSource = true)
    {
        var builder = WebTestHost.Builder().WithHeaderAuthentication();
        if (!withSource)
            builder.Services.RemoveAll<IBlockedUsersSource>();
        builder.Services.AddStellaegisIdentityAdmission(options => options.ReconcileInterval = reconcileInterval ?? TimeSpan.Zero);
        var app = builder.Build();
        app.UseAuthentication();
        app.UseStellaegisActorAdmission();   // of Primitives: every admission registered, the blocked accounts included
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
    public async Task The_blocked_accounts_are_an_admission_a_token_issuer_asks_apart_from_the_pipeline()
    {
        await using var app = Build();
        var john = await app.CreateAccountAsync("john@acme.test", ct: Ct);
        await app.StartAsync(Ct);
        app.Services.GetRequiredService<BlockedAccounts>().Block(john);
        var admissions = app.Services.GetRequiredService<IActorAdmissions>();

        var refused = await admissions.AdmitAsync(PrincipalOf(john.ToString("N")), Ct);
        var admitted = await admissions.AdmitAsync(PrincipalOf(Guid.NewGuid().ToString("N")), Ct);

        Assert.Equal(IdentityErrors.AccountBlockedCode, refused.Error!.Code);
        Assert.True(admitted.IsSuccess);
        Assert.Single(app.Services.GetServices<IActorAdmission>());
    }

    [Fact]
    public void The_former_middleware_still_fails_without_the_registration_and_enables_the_admission_once()
    {
        var builder = WebTestHost.Builder().WithHeaderAuthentication();
        var app = builder.Build();
#pragma warning disable CS0618 // kept for the hosts of the 5.0.0
        var exception = Assert.Throws<InvalidOperationException>(() => app.UseStellaegisIdentityAdmission());
#pragma warning restore CS0618

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
