using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Identity.AspNetCore;
using Stellaegis.Primitives;

namespace Stellaegis.Identity.Tests;

/// <summary>
/// The invitations of a host's rights system, as the port sees them: a token per address, which an acceptance spends,
/// recording who accepted and whether the address was proven; or refused, as a change since would refuse it.
/// </summary>
internal sealed class TestInvitations : IInvitationAcceptance
{
    private readonly Dictionary<string, InvitationOffer> _offers = [];

    public List<(string Token, Subject Subject, bool EmailVerified)> Accepted { get; } = [];

    public bool Refuses { get; set; }

    public string Invite(string email, bool sentByEmail = true)
    {
        var token = Guid.NewGuid().ToString("N");
        _offers[token] = new InvitationOffer(email, sentByEmail);
        return token;
    }

    public Task<InvitationOffer?> FindAsync(string token, CancellationToken cancellationToken = default)
        => Task.FromResult(_offers.GetValueOrDefault(token));

    public Task<Result> AcceptAsync(string token, Subject subject, bool emailVerified, CancellationToken cancellationToken = default)
    {
        if (Refuses || !_offers.Remove(token))
            return Task.FromResult(Result.Failure(Error.Conflict("Invitation.Refused", "No longer valid.")));
        Accepted.Add((token, subject, emailVerified));
        return Task.FromResult(Result.Success());
    }
}

/// <summary>Accepting an invitation, under an account or with one created from it.</summary>
public sealed class InvitationTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static TestHost Host(TestInvitations invitations)
        => new(o => o.SelfRegistration = SelfRegistration.Closed, services => services.AddSingleton<IInvitationAcceptance>(invitations));

    [Fact]
    public async Task Without_the_port_no_invitation_opens_anything()
    {
        using var host = new TestHost();
        var service = host.Get<InvitationService>();

        Assert.False(service.IsOpen);
        Assert.Null(await service.FindAsync("anything", Ct));
        Assert.Equal(IdentityErrors.InvitationInvalid, (await service.CreateAccountAsync("anything", "Jane", "Correct-Horse-9", Ct)).Error);
    }

    [Fact]
    public async Task An_account_created_from_an_invitation_is_its_persons_at_the_address_invited_whatever_the_registration()
    {
        var invitations = new TestInvitations();
        using var host = Host(invitations);
        var service = host.Get<InvitationService>();
        var byEmail = invitations.Invite("Jane@Acme.test");
        var byHand = invitations.Invite("john@acme.test", sentByEmail: false);

        Assert.Equal(IdentityErrors.InvalidDisplayName, (await service.CreateAccountAsync(byEmail, " ", "Correct-Horse-9", Ct)).Error);
        Assert.True((await service.CreateAccountAsync(byEmail, "Jane", "password", Ct)).IsFailure);   // the password rules hold
        var jane = (await service.CreateAccountAsync(byEmail, " Jane ", "Correct-Horse-9", Ct)).Value;
        var account = (await host.Get<IAuthUserStore>().GetByUniqueIdAsync(jane, Ct))!;
        Assert.Equal("jane@acme.test", account.Email);
        Assert.Equal("Jane", account.DisplayName);
        Assert.True(account.EmailVerified);   // the link reached the address
        Assert.Equal(account.AsActor(), account.CreatedBy);
        Assert.Contains(host.Events.Events, e => e is UserRegisteredEvent registered && registered.UserUniqueId == jane);
        Assert.True((await host.Get<LoginService>().AuthenticateAsync("jane@acme.test", "Correct-Horse-9", cancellationToken: Ct)).Succeeded);

        var john = (await service.CreateAccountAsync(byHand, "John", "Correct-Horse-9", Ct)).Value;
        Assert.False((await host.Get<IAuthUserStore>().GetByUniqueIdAsync(john, Ct))!.EmailVerified);   // handed over: proves nothing

        Assert.Equal(IdentityErrors.EmailTaken, (await service.CreateAccountAsync(invitations.Invite("jane@acme.test"), "Jane", "Correct-Horse-9", Ct)).Error);
        Assert.Equal(IdentityErrors.InvitationInvalid, (await service.CreateAccountAsync("unknown", "Jane", "Correct-Horse-9", Ct)).Error);
    }

    [Fact]
    public async Task An_invitation_is_accepted_under_the_account_of_its_address_proven_only()
    {
        var invitations = new TestInvitations();
        using var host = Host(invitations);
        var service = host.Get<InvitationService>();
        var jane = await host.CreateUserAsync();
        var john = await host.CreateUserAsync("john@acme.test", displayName: "John");
        var users = host.Get<IAuthUserStore>();
        var unproven = (await users.GetByUniqueIdAsync(jane, Ct))!;
        unproven.EmailVerified = false;   // activated by a link handed over: the address is not proven
        await users.UpdateAsync(unproven, Ct);

        var token = invitations.Invite("jane@acme.test", sentByEmail: false);
        Assert.Equal(IdentityErrors.InvitationOtherAddress, (await service.AcceptAsync(token, john, Ct)).Error);
        Assert.Equal(IdentityErrors.EmailNotVerified, (await service.AcceptAsync(token, jane, Ct)).Error);   // handed over, unproven
        Assert.Empty(invitations.Accepted);

        token = invitations.Invite("jane@acme.test");
        Assert.True((await service.AcceptAsync(token, jane, Ct)).IsSuccess);
        var accepted = Assert.Single(invitations.Accepted);
        Assert.Equal(Subject.Parse(jane.ToString("N")), accepted.Subject);
        Assert.True(accepted.EmailVerified);
        Assert.True((await host.Get<IAuthUserStore>().GetByUniqueIdAsync(jane, Ct))!.EmailVerified);   // the link proved it
        Assert.Equal(IdentityErrors.InvitationInvalid, (await service.AcceptAsync(token, jane, Ct)).Error);   // spent

        invitations.Refuses = true;
        Assert.True((await service.AcceptAsync(invitations.Invite("john@acme.test"), john, Ct)).IsFailure);
    }

    // ── The page ───────────────────────────────────────────────────────────────

    private static Task<WebApplication> StartPagesAsync(TestInvitations? invitations)
        => PagesTestHost.StartAsync(Ct, services: invitations is null ? null : services => services.AddSingleton<IInvitationAcceptance>(invitations));

    [Fact]
    public async Task Without_the_port_the_page_is_not_there()
    {
        await using var app = await StartPagesAsync(null);
        Assert.Equal(HttpStatusCode.NotFound, (await new Browser(app).GetAsync("/invitation?token=anything", Ct)).StatusCode);
    }

    [Fact]
    public async Task A_person_without_an_account_creates_it_at_the_address_invited_and_signs_in_after()
    {
        var invitations = new TestInvitations();
        await using var app = await StartPagesAsync(invitations);
        var browser = new Browser(app);
        var token = invitations.Invite("jane@acme.test");

        var invalid = await browser.GetAsync("/invitation?token=unknown", Ct);
        Assert.Contains("Invalid invitation", browser.Html);
        Assert.Equal("no-referrer", invalid.Headers.GetValues("Referrer-Policy").Single());

        var created = await browser.PostFormAsync($"/invitation?token={token}", _ => new Dictionary<string, string>
        {
            ["Token"] = token, ["Input.DisplayName"] = "Jane", ["Input.Password"] = "Correct-Horse-9", ["Input.ConfirmPassword"] = "Correct-Horse-9",
        }, Ct, postPath: "/invitation?handler=Create");
        Assert.Equal(HttpStatusCode.Redirect, created.StatusCode);
        Assert.Equal("/login", created.Headers.Location!.ToString());
        var accepted = Assert.Single(invitations.Accepted);
        Assert.True(accepted.EmailVerified);
    }

    [Fact]
    public async Task A_person_who_creates_the_account_from_a_link_handed_over_proves_the_address_then_accepts()
    {
        var invitations = new TestInvitations();
        await using var app = await StartPagesAsync(invitations);
        var browser = new Browser(app);
        var token = invitations.Invite("jane@acme.test", sentByEmail: false);
        Dictionary<string, string> Accept(string _) => new() { ["Token"] = token };

        // The account is created; a link handed over proves nothing, so the invitation waits — and the page says so,
        // not that it no longer holds.
        var created = await browser.PostFormAsync($"/invitation?token={token}", _ => new Dictionary<string, string>
        {
            ["Token"] = token, ["Input.DisplayName"] = "Jane", ["Input.Password"] = "Correct-Horse-9", ["Input.ConfirmPassword"] = "Correct-Horse-9",
        }, Ct, postPath: "/invitation?handler=Create");
        Assert.Equal("/login", created.Headers.Location!.ToString());
        Assert.Empty(invitations.Accepted);
        await browser.GetAsync("/login", Ct);
        Assert.Contains("The invitation still holds", browser.Html);
        Assert.DoesNotContain("no longer holds", browser.Html);

        // Signed in, the link opened again before the address is proven says what to do.
        await browser.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = "jane@acme.test", ["Input.Password"] = "Correct-Horse-9" }, Ct);
        await browser.PostFormAsync($"/invitation?token={token}", Accept, Ct, postPath: "/invitation?handler=Accept");
        Assert.Contains("is not proven yet", browser.Html);
        Assert.Empty(invitations.Accepted);

        // The address proven from the account, the same link accepts.
        await browser.PostFormAsync("/account/email", new Dictionary<string, string>(), Ct, postPath: "/account/email?handler=Verify");
        var mail = app.Mailer().LastTo("jane@acme.test")!;
        await browser.PostFormAsync("/account/email", new Dictionary<string, string> { ["Code"] = mail.Code! }, Ct, postPath: "/account/email?handler=Confirm");
        var done = await browser.PostFormAsync($"/invitation?token={token}", Accept, Ct, postPath: "/invitation?handler=Accept");
        Assert.Equal("/account", done.Headers.Location!.ToString());
        var accepted = Assert.Single(invitations.Accepted);
        Assert.True(accepted.EmailVerified);
    }

    [Fact]
    public async Task A_person_with_an_account_signs_in_then_accepts_and_another_account_does_not()
    {
        var invitations = new TestInvitations();
        await using var app = await StartPagesAsync(invitations);
        await app.CreateAccountAsync("jane@acme.test", ct: Ct);
        await app.CreateAccountAsync("john@acme.test", ct: Ct);
        var token = invitations.Invite("jane@acme.test");

        var stranger = new Browser(app);
        await stranger.GetAsync($"/invitation?token={token}", Ct);
        Assert.Contains($"/login?return_url={Uri.EscapeDataString($"/invitation?token={token}")}", stranger.Html);

        var john = new Browser(app);
        await john.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = "john@acme.test", ["Input.Password"] = "Correct-Horse-9" }, Ct);
        await john.GetAsync($"/invitation?token={token}", Ct);
        Assert.Contains("only the account of that address accepts it", john.Html);

        var jane = new Browser(app);
        await jane.PostFormAsync("/login", new Dictionary<string, string> { ["Input.Email"] = "jane@acme.test", ["Input.Password"] = "Correct-Horse-9" }, Ct);
        Assert.True(jane.HasCookie(IdentityCookie.CookieName));
        var done = await jane.PostFormAsync($"/invitation?token={token}", _ => new Dictionary<string, string> { ["Token"] = token }, Ct, postPath: "/invitation?handler=Accept");
        Assert.Equal(HttpStatusCode.Redirect, done.StatusCode);
        Assert.Equal("/account", done.Headers.Location!.ToString());
        Assert.Single(invitations.Accepted);
    }
}
