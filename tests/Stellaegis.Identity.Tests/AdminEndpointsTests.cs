using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Stellaegis.Identity.AspNetCore;
using Stellaegis.Identity.InMemory;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;

namespace Stellaegis.Identity.Tests;

/// <summary>The administration routes, under the operations a host grants.</summary>
public sealed class AdminEndpointsTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly string[] Everything = IdentityOperations.All.Select(operation => operation.ToString()).ToArray();

    private static async Task<WebApplication> StartAsync(Action<WebApplication> map, ApplicationFrame? frame = null, Action<WebApplicationBuilder>? configure = null)
    {
        var builder = WebTestHost.Builder(frame).WithHeaderAuthentication();
        builder.Services.AddStellaegisIdentityAdministration();
        builder.Services.AddStellaegisInMemoryIdentityMailer();
        configure?.Invoke(builder);
        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        map(app);
        await app.StartAsync(Ct);
        return app;
    }

    // A host whose administrators reach every account: the opening is declared.
    private static void MapPerOperation(WebApplication app)
        => app.MapGroup("/api/admin").MapIdentityAdminEndpoints().RequireAuthorizationPerOperation(operation => operation.ToString()).AllowAnyResource();

    // A host whose rights system decides on the person: the gestures on an account are asked about it.
    private static void MapDecidedOnTheAccount(WebApplication app)
        => app.MapGroup("/api/admin").MapIdentityAdminEndpoints().RequireAuthorizationPerOperation(operation => operation.ToString());

    [Fact]
    public async Task An_administrator_holding_the_operations_runs_the_life_of_an_account()
    {
        await using var app = await StartAsync(MapPerOperation);
        var client = app.ClientAs("admin", Everything);

        var created = await client.PostAsJsonAsync("/api/admin/identity/users", new CreateAccountRequest("Jane@Acme.test", "Jane"), Ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var answer = (await created.Content.ReadFromJsonAsync<AccountCreated>(Ct))!;
        var id = answer.UserUniqueId;
        Assert.NotEqual(Guid.Empty, id);
        Assert.Null(answer.ActivationLink);   // sent by e-mail, never shown to the administrator
        var stored = await app.Services.GetRequiredService<IAuthUserStore>().GetByUniqueIdAsync(id, Ct);
        Assert.Equal(Actor.Parse("admin"), stored!.CreatedBy);
        Assert.Null(stored.PasswordHash);
        var mail = app.Services.GetRequiredService<InMemoryIdentityMailer>().LastTo("jane@acme.test")!;
        Assert.Equal(InMemoryIdentityMailer.ActivationLink, mail.Kind);
        Assert.StartsWith("http://localhost/activate?token=", mail.Link!.ToString());
        Assert.False((await client.GetFromJsonAsync<AccountSummary>($"/api/admin/identity/users/{id:N}", Ct))!.IsActivated);

        var duplicate = await client.PostAsJsonAsync("/api/admin/identity/users", new CreateAccountRequest("jane@acme.test", "Jane"), Ct);
        Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);
        Assert.Equal(IdentityErrors.EmailTakenCode, await duplicate.CodeOfAsync(Ct));
        var malformed = await client.PostAsJsonAsync("/api/admin/identity/users", new CreateAccountRequest("jane@acme\r\nBcc: all@acme.test", "Jane"), Ct);
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
        Assert.Equal("Account.Invalid", await malformed.CodeOfAsync(Ct));

        var page = await client.GetFromJsonAsync<AccountPage>("/api/admin/identity/users?skip=0&take=10", Ct);
        Assert.Equal(1, page!.TotalCount);
        Assert.Equal("jane@acme.test", Assert.Single(page.Items).Email);

        var lookup = await client.PostAsJsonAsync("/api/admin/identity/users/lookup", new LookupAccountsRequest([id, Guid.NewGuid()]), Ct);
        Assert.Equal(id, Assert.Single((await lookup.Content.ReadFromJsonAsync<AccountList>(Ct))!.Items).UserUniqueId);

        var one = await client.GetFromJsonAsync<AccountSummary>($"/api/admin/identity/users/{id:N}", Ct);
        Assert.True(one!.IsEnabled);
        Assert.False(one.MfaEnabled);

        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync($"/api/admin/identity/users/{id:N}/block", null, Ct)).StatusCode);
        Assert.Contains(id.ToString("N"), (await client.GetFromJsonAsync<string[]>("/api/admin/identity/security/blocked-users", Ct))!);
        Assert.False((await client.GetFromJsonAsync<AccountSummary>($"/api/admin/identity/users/{id:N}", Ct))!.IsEnabled);
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync($"/api/admin/identity/users/{id:N}/unblock", null, Ct)).StatusCode);
        Assert.Empty((await client.GetFromJsonAsync<string[]>("/api/admin/identity/security/blocked-users", Ct))!);

        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync($"/api/admin/identity/users/{id:N}/reset-failed-logins", null, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync($"/api/admin/identity/users/{id:N}/reset-mfa", null, Ct)).StatusCode);

        // A reset before the activation is refused; a new activation link is sent instead.
        var early = await client.PostAsJsonAsync($"/api/admin/identity/users/{id:N}/password-reset", new IssueLinkRequest(), Ct);
        Assert.Equal(HttpStatusCode.Conflict, early.StatusCode);
        Assert.Equal(IdentityErrors.AccountNotActivatedCode, await early.CodeOfAsync(Ct));
        var again = await client.PostAsJsonAsync($"/api/admin/identity/users/{id:N}/activation", new IssueLinkRequest(), Ct);
        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        Assert.Null((await again.Content.ReadFromJsonAsync<IssuedLink>(Ct))!.Link);
        var activationToken = app.Services.GetRequiredService<InMemoryIdentityMailer>().LastTo("jane@acme.test")!.Link!.Query["?token=".Length..];
        using (var scope = app.Services.CreateScope())
            Assert.True((await scope.ServiceProvider.GetRequiredService<ActivationService>().ActivateAsync(Uri.UnescapeDataString(activationToken), "Another-Horse-7", Ct)).IsSuccess);

        // Active, the account gets a reset link: the administrator never sets the password.
        var reset = await client.PostAsJsonAsync($"/api/admin/identity/users/{id:N}/password-reset", new IssueLinkRequest("email"), Ct);
        Assert.Equal(HttpStatusCode.OK, reset.StatusCode);
        Assert.Equal(InMemoryIdentityMailer.PasswordResetLink, app.Services.GetRequiredService<InMemoryIdentityMailer>().LastTo("jane@acme.test")!.Kind);
        var byHand = await client.PostAsJsonAsync($"/api/admin/identity/users/{id:N}/password-reset", new IssueLinkRequest("hand"), Ct);
        Assert.Equal(HttpStatusCode.Forbidden, byHand.StatusCode);   // the host did not declare it
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsync($"/api/admin/identity/users/{id:N}/change-password", null, Ct)).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync($"/api/admin/identity/users/{id:N}", Ct)).StatusCode);
        var gone = await client.GetAsync($"/api/admin/identity/users/{id:N}", Ct);
        Assert.Equal(HttpStatusCode.NotFound, gone.StatusCode);
        Assert.Equal(IdentityErrors.AccountNotFoundCode, await gone.CodeOfAsync(Ct));
        Assert.Contains(id.ToString("N"), (await client.GetFromJsonAsync<string[]>("/api/admin/identity/security/blocked-users", Ct))!);
    }

    [Fact]
    public async Task The_administrator_sets_the_email_of_an_account_whose_mailbox_is_lost_unproven()
    {
        await using var app = await StartAsync(MapPerOperation);
        var client = app.ClientAs("admin", Everything);
        var id = await app.CreateAccountAsync("jane@acme.test", ct: Ct);
        await app.CreateAccountAsync("john@acme.test", ct: Ct);

        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync($"/api/admin/identity/users/{id:N}/email", new ChangeEmailRequest("not an address"), Ct)).StatusCode);
        var taken = await client.PostAsJsonAsync($"/api/admin/identity/users/{id:N}/email", new ChangeEmailRequest("john@acme.test"), Ct);
        Assert.Equal(HttpStatusCode.Conflict, taken.StatusCode);
        Assert.Equal(IdentityErrors.EmailTakenCode, await taken.CodeOfAsync(Ct));
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsJsonAsync($"/api/admin/identity/users/{Guid.NewGuid():N}/email", new ChangeEmailRequest("x@acme.test"), Ct)).StatusCode);

        var moved = await client.PostAsJsonAsync($"/api/admin/identity/users/{id:N}/email", new ChangeEmailRequest("Jane.New@acme.test"), Ct);
        Assert.Equal(HttpStatusCode.NoContent, moved.StatusCode);
        var summary = (await client.GetFromJsonAsync<AccountSummary>($"/api/admin/identity/users/{id:N}", Ct))!;
        Assert.Equal("jane.new@acme.test", summary.Email);
        Assert.False(summary.EmailVerified);   // the person verifies it from their account page
    }

    [Fact]
    public async Task A_host_that_declares_the_hand_delivery_returns_the_link_once_under_its_public_address()
    {
        await using var app = await StartAsync(MapPerOperation, configure: builder => builder.Services.Configure<IdentityOptions>(options =>
        {
            options.Links.HandDelivery = true;
            options.Links.PublicBaseUrl = "https://id.acme.example/";
        }));
        var client = app.ClientAs("admin", Everything);

        var created = await client.PostAsJsonAsync("/api/admin/identity/users", new CreateAccountRequest("jane@acme.test", "Jane", "hand"), Ct);

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var link = (await created.Content.ReadFromJsonAsync<AccountCreated>(Ct))!.ActivationLink!;
        Assert.StartsWith("https://id.acme.example/activate?token=", link.ToString());
        Assert.Null(app.Services.GetRequiredService<InMemoryIdentityMailer>().LastTo("jane@acme.test"));   // nothing was mailed
        var token = Assert.Single(app.Services.GetRequiredService<InMemoryIdentityData>().AccountTokens.Values);
        Assert.Equal(TokenDelivery.Hand, token.Delivery);
        Assert.Equal(AccountTokens.Hash(Uri.UnescapeDataString(link.Query["?token=".Length..])), token.TokenHash);
    }

    [Fact]
    public async Task A_host_with_neither_a_mailer_nor_the_hand_delivery_refuses_to_map_the_routes()
    {
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => StartAsync(MapPerOperation, configure: builder => builder.Services.RemoveAll<IIdentityMailer>()));

        Assert.Contains("HandDelivery", exception.Message);
    }

    [Fact]
    public async Task A_caller_without_the_operation_is_refused_and_an_unauthenticated_one_challenged()
    {
        await using var app = await StartAsync(MapPerOperation);
        var reader = app.ClientAs("reader", "users.read");

        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync("/api/admin/identity/users", Ct)).StatusCode);
        var refused = await reader.PostAsJsonAsync("/api/admin/identity/users", new CreateAccountRequest("jane@acme.test", "Jane"), Ct);
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.GetAsync("/api/admin/identity/security/blocked-users", Ct)).StatusCode);

        var nobody = app.ClientAs(null);
        Assert.Equal(HttpStatusCode.Unauthorized, (await nobody.GetAsync("/api/admin/identity/users", Ct)).StatusCode);
    }

    [Fact]
    public async Task The_routes_map_in_an_application_with_compartments_without_reading_its_request_context()
    {
        await using var app = await StartAsync(MapPerOperation,
            frame: ApplicationFrame.SingleCompartment("acme"),
            configure: builder => builder.Services.AddStellaegisRequestContext());

        var page = await app.ClientAs("admin", Everything).GetFromJsonAsync<AccountPage>("/api/admin/identity/users", Ct);

        Assert.Equal(0, page!.TotalCount);
    }

    [Fact]
    public async Task Each_gesture_has_its_operation()
    {
        await using var app = await StartAsync(MapPerOperation);
        var jane = await app.CreateAccountAsync("jane@acme.test");
        var creator = app.ClientAs("creator", "users.create");
        var blocker = app.ClientAs("blocker", "users.block");

        Assert.Equal(HttpStatusCode.Forbidden, (await creator.PostAsync($"/api/admin/identity/users/{jane:N}/block", null, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await blocker.PostAsync($"/api/admin/identity/users/{jane:N}/reset-mfa", null, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await blocker.PostAsJsonAsync("/api/admin/identity/users", new CreateAccountRequest("john@acme.test", "John"), Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await blocker.PostAsync($"/api/admin/identity/users/{jane:N}/block", null, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await creator.PostAsJsonAsync("/api/admin/identity/users", new CreateAccountRequest("john@acme.test", "John"), Ct)).StatusCode);
    }

    [Fact]
    public async Task A_reset_link_in_hand_waits_for_a_second_person()
    {
        var approvals = new TestHandDeliveryApprovals();
        await using var app = await StartAsync(MapPerOperation, configure: builder =>
        {
            builder.Services.Configure<IdentityOptions>(options => options.Links.HandDelivery = true);
            builder.Services.AddSingleton<IHandDeliveryApprovals>(approvals);
        });
        var jane = await app.CreateAccountAsync("jane@acme.test");
        var admin = app.ClientAs("admin", Everything);

        var asked = await admin.PostAsJsonAsync($"/api/admin/identity/users/{jane:N}/password-reset", new IssueLinkRequest("hand"), Ct);
        Assert.Equal(HttpStatusCode.Accepted, asked.StatusCode);
        var approval = (await asked.Content.ReadFromJsonAsync<HandDeliveryPending>(Ct))!.Approval;

        var early = await admin.PostAsJsonAsync($"/api/admin/identity/users/{jane:N}/password-reset", new IssueLinkRequest("hand", approval), Ct);
        Assert.Equal(HttpStatusCode.Forbidden, early.StatusCode);
        Assert.Equal(IdentityErrors.HandDeliveryNotApprovedCode, await early.CodeOfAsync(Ct));

        approvals.Approve(approval, Actor.Parse("second"));
        var given = await admin.PostAsJsonAsync($"/api/admin/identity/users/{jane:N}/password-reset", new IssueLinkRequest("hand", approval), Ct);
        Assert.Equal(HttpStatusCode.OK, given.StatusCode);
        Assert.StartsWith("http://localhost/reset-password?token=", (await given.Content.ReadFromJsonAsync<IssuedLink>(Ct))!.Link!.ToString());
    }

    [Fact]
    public async Task Without_approvals_a_reset_link_is_never_handed_over()
    {
        await using var app = await StartAsync(MapPerOperation, configure: builder =>
            builder.Services.Configure<IdentityOptions>(options => options.Links.HandDelivery = true));
        var jane = await app.CreateAccountAsync("jane@acme.test");

        var refused = await app.ClientAs("admin", Everything).PostAsJsonAsync($"/api/admin/identity/users/{jane:N}/password-reset", new IssueLinkRequest("hand"), Ct);
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.Equal(IdentityErrors.HandDeliveryUnapprovableCode, await refused.CodeOfAsync(Ct));
    }

    [Fact]
    public async Task No_administration_route_acts_on_the_callers_own_account()
    {
        await using var app = await StartAsync(MapPerOperation);
        var jane = await app.CreateAccountAsync("jane@acme.test");
        var herself = app.ClientAs(jane.ToString("N"), Everything);

        foreach (var gesture in new[] { "block", "reset-mfa", "reset-failed-logins", "password-reset" })
        {
            var refused = await herself.PostAsync($"/api/admin/identity/users/{jane:N}/{gesture}", null, Ct);
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
            Assert.Equal(IdentityErrors.OwnAccountCode, await refused.CodeOfAsync(Ct));
        }
        Assert.Equal(HttpStatusCode.Forbidden, (await herself.DeleteAsync($"/api/admin/identity/users/{jane:N}", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await herself.GetAsync($"/api/admin/identity/users/{jane:N}", Ct)).StatusCode);   // reading takes nothing
        Assert.Equal(HttpStatusCode.NoContent, (await app.ClientAs("admin", Everything).PostAsync($"/api/admin/identity/users/{jane:N}/block", null, Ct)).StatusCode);
    }

    [Fact]
    public async Task A_gesture_on_an_account_is_decided_on_that_account()
    {
        await using var app = await StartAsync(MapDecidedOnTheAccount,
            configure: builder => builder.Services.AddSingleton<ProtectedAccounts>().AddSingleton<IAuthorizationHandler, ProtectedAccountsRule>());
        var jane = await app.CreateAccountAsync("jane@acme.test");
        var fred = await app.CreateAccountAsync("fred@acme.test");
        app.Services.GetRequiredService<ProtectedAccounts>().Subjects.Add(fred.ToString("N"));
        var manager = app.ClientAs("manager", Everything);

        foreach (var gesture in new[] { "block", "unblock", "reset-mfa", "reset-failed-logins", "password-reset", "activation" })
        {
            var refused = await manager.PostAsync($"/api/admin/identity/users/{fred:N}/{gesture}", null, Ct);
            Assert.Equal(HttpStatusCode.NotFound, refused.StatusCode);   // refused as an absence
            Assert.Equal(IdentityErrors.AccountNotFoundCode, await refused.CodeOfAsync(Ct));
        }
        Assert.Equal(HttpStatusCode.NotFound, (await manager.PostAsJsonAsync($"/api/admin/identity/users/{fred:N}/email", new ChangeEmailRequest("mine@acme.test"), Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await manager.DeleteAsync($"/api/admin/identity/users/{fred:N}", Ct)).StatusCode);
        Assert.True((await app.Services.GetRequiredService<IAuthUserStore>().GetByUniqueIdAsync(fred, Ct))!.IsEnabled);

        Assert.Equal(HttpStatusCode.NoContent, (await manager.PostAsync($"/api/admin/identity/users/{jane:N}/block", null, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await manager.GetAsync($"/api/admin/identity/users/{fred:N}", Ct)).StatusCode);   // reading is out of the hook
        Assert.Equal(HttpStatusCode.Created, (await manager.PostAsJsonAsync("/api/admin/identity/users", new CreateAccountRequest("john@acme.test", "John"), Ct)).StatusCode);
    }

    [Fact]
    public async Task Without_a_decider_nor_a_declared_opening_the_gestures_on_accounts_fail_the_startup()
    {
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => StartAsync(MapDecidedOnTheAccount));

        Assert.Contains("users.block", exception.Message);
        Assert.Contains("AllowAnyResource()", exception.Message);
        Assert.DoesNotContain("users.read", exception.Message);
    }

    [Fact]
    public async Task Routes_left_without_authorization_fail_the_startup()
    {
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            StartAsync(app => app.MapGroup("/api/admin").MapIdentityAdminEndpoints()));

        Assert.Contains("users.read", exception.Message);
        Assert.Contains("declare no authorization", exception.Message);
    }

    [Fact]
    public async Task The_routes_need_the_startup_check_their_registration_brings()
    {
        var builder = WebTestHost.Builder().WithHeaderAuthentication();
        var app = builder.Build();

        var exception = Assert.Throws<InvalidOperationException>(() => app.MapGroup("/api/admin").MapIdentityAdminEndpoints());

        Assert.Contains("AddStellaegisStartupCheck", exception.Message);
    }
}

/// <summary>The accounts a test's rights system protects from every administrator.</summary>
internal sealed class ProtectedAccounts
{
    public HashSet<string> Subjects { get; } = [];
}

/// <summary>A rights system that decides on the person: it lets every gesture through but on the protected accounts.</summary>
internal sealed class ProtectedAccountsRule(ProtectedAccounts accounts) : AuthorizationHandler<OperationRequirement, Subject>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, OperationRequirement requirement, Subject resource)
    {
        if (!accounts.Subjects.Contains(resource.Value))
            context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
