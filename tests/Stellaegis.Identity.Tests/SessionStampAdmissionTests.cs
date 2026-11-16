using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Stellaegis.Identity.AspNetCore;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;

namespace Stellaegis.Identity.Tests;

/// <summary>
/// The stamp of the session held against the account at a token request, as a token issuer asks it: the principal of
/// the code or the refresh token, marked by the issuer, carrying the stamp it kept since the authorization.
/// </summary>
public sealed class SessionStampAdmissionTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<WebApplication> StartAsync()
    {
        var builder = WebTestHost.Builder().WithHeaderAuthentication();
        builder.Services.AddStellaegisIdentityAdmission(options => options.ReconcileInterval = TimeSpan.Zero);
        var app = builder.Build();
        app.UseAuthentication();
        app.UseStellaegisActorAdmission();
        app.UseAuthorization();
        await app.StartAsync(Ct);
        return app;
    }

    private static ClaimsPrincipal Principal(Guid subject, string? stamp, string? request = SessionClaims.RefreshTokenRequest)
    {
        var claims = new List<Claim> { new("sub", subject.ToString("N")) };
        if (stamp is not null)
            claims.Add(new Claim(SessionClaims.SecurityStamp, stamp));
        if (request is not null)
            claims.Add(new Claim(SessionClaims.TokenRequest, request));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
    }

    private static async Task<string> StampOfAsync(WebApplication app, Guid userUniqueId)
    {
        using var scope = app.Services.CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<IAuthUserStore>().GetByUniqueIdAsync(userUniqueId, Ct))!.SecurityStamp;
    }

    private static Task<Result> AdmitAsync(WebApplication app, ClaimsPrincipal principal)
        => app.Services.GetRequiredService<IActorAdmissions>().AdmitAsync(principal, Ct).AsTask();

    [Fact]
    public async Task A_token_request_is_admitted_while_the_stamp_holds_and_refused_once_it_changed_though_no_event_said_so()
    {
        await using var app = await StartAsync();
        var jane = await app.CreateAccountAsync("jane@acme.test", ct: Ct);
        var stamp = await StampOfAsync(app, jane);

        Assert.True((await AdmitAsync(app, Principal(jane, stamp))).IsSuccess);
        Assert.True((await AdmitAsync(app, Principal(jane, stamp, SessionClaims.AuthorizationCodeRequest))).IsSuccess);

        // One of the changes of the stamp that publishes no event: the address set by an administrator.
        var administration = app.Administration(out var scope);
        using (scope)
            Assert.True((await administration.ChangeEmailAsync(jane, "jane.doe@acme.test", Actor.Parse("admin"), Ct)).IsSuccess);

        var refused = await AdmitAsync(app, Principal(jane, stamp));
        Assert.Equal(IdentityErrors.SessionStaleCode, refused.Error?.Code);
        Assert.Equal(IdentityErrors.SessionStaleCode, (await AdmitAsync(app, Principal(jane, stamp, SessionClaims.AuthorizationCodeRequest))).Error?.Code);
        Assert.True((await AdmitAsync(app, Principal(jane, await StampOfAsync(app, jane)))).IsSuccess);   // a new authorization, a new stamp
    }

    [Fact]
    public async Task A_token_request_that_keeps_no_stamp_is_refused_and_one_issued_before_is_among_them()
    {
        await using var app = await StartAsync();
        var jane = await app.CreateAccountAsync("jane@acme.test", ct: Ct);

        Assert.Equal(IdentityErrors.SessionStaleCode, (await AdmitAsync(app, Principal(jane, stamp: null))).Error?.Code);
    }

    [Fact]
    public async Task Without_the_mark_nothing_is_held_against_the_account_as_at_the_door()
    {
        await using var app = await StartAsync();
        var jane = await app.CreateAccountAsync("jane@acme.test", ct: Ct);

        Assert.True((await AdmitAsync(app, Principal(jane, "not-the-stamp", request: null))).IsSuccess);
        Assert.True((await AdmitAsync(app, Principal(jane, stamp: null, request: null))).IsSuccess);
    }

    [Fact]
    public async Task A_token_request_for_an_account_blocked_or_gone_is_refused()
    {
        await using var app = await StartAsync();
        var jane = await app.CreateAccountAsync("jane@acme.test", ct: Ct);
        var stamp = await StampOfAsync(app, jane);
        var administration = app.Administration(out var scope);
        using (scope)
            Assert.True((await administration.DeleteAsync(jane, Actor.Parse("admin"), Ct)).IsSuccess);

        Assert.Equal(IdentityErrors.AccountBlockedCode, (await AdmitAsync(app, Principal(jane, stamp))).Error?.Code);
        Assert.Equal(IdentityErrors.AccountBlockedCode, (await AdmitAsync(app, Principal(Guid.NewGuid(), "a-stamp"))).Error?.Code);
    }

    [Fact]
    public async Task A_subject_that_is_not_an_account_id_is_not_the_accounts_to_judge()
    {
        await using var app = await StartAsync();
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", @"ACME\jane"), new Claim(SessionClaims.TokenRequest, SessionClaims.RefreshTokenRequest)], "test"));

        Assert.True((await AdmitAsync(app, principal)).IsSuccess);
    }

    [Fact]
    public async Task A_host_that_marks_a_token_request_without_holding_the_accounts_refuses_it()
    {
        await using var provider = new ServiceCollection().BuildServiceProvider();
        var admission = new SessionStampAdmission(provider.GetRequiredService<IServiceScopeFactory>(), NullLogger<SessionStampAdmission>.Instance);

        var refused = await admission.AdmitAsync(Principal(Guid.NewGuid(), "a-stamp"), Ct);

        Assert.Equal(IdentityErrors.SessionStaleCode, refused.Error?.Code);
    }

    [Fact]
    public void The_claim_of_the_cookie_is_the_one_the_issuer_keeps()
        => Assert.Equal(SessionClaims.SecurityStamp, SecurityStamps.ClaimType);
}
