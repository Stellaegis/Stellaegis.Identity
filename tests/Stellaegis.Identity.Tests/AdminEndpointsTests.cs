using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Identity.AspNetCore;
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
        configure?.Invoke(builder);
        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        map(app);
        await app.StartAsync(Ct);
        return app;
    }

    private static void MapPerOperation(WebApplication app)
        => app.MapGroup("/api/admin").MapIdentityAdminEndpoints().RequireAuthorizationPerOperation(operation => operation.ToString());

    [Fact]
    public async Task An_administrator_holding_the_operations_runs_the_life_of_an_account()
    {
        await using var app = await StartAsync(MapPerOperation);
        var client = app.ClientAs("admin", Everything);

        var created = await client.PostAsJsonAsync("/api/admin/identity/users", new CreateAccountRequest("Jane@Acme.test", "Jane", "Correct-Horse-9"), Ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<AccountCreated>(Ct))!.UserUniqueId;
        Assert.NotEqual(Guid.Empty, id);
        var stored = await app.Services.GetRequiredService<IAuthUserStore>().GetByUniqueIdAsync(id, Ct);
        Assert.Equal(Actor.Parse("admin"), stored!.CreatedBy);

        var duplicate = await client.PostAsJsonAsync("/api/admin/identity/users", new CreateAccountRequest("jane@acme.test", "Jane", "Correct-Horse-9"), Ct);
        Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);
        Assert.Equal(IdentityErrors.EmailTakenCode, await duplicate.CodeOfAsync(Ct));

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
        var weak = await client.PostAsJsonAsync($"/api/admin/identity/users/{id:N}/change-password", new ChangePasswordRequest("short"), Ct);
        Assert.Equal(HttpStatusCode.BadRequest, weak.StatusCode);
        Assert.Equal(IdentityErrors.PasswordRejectedCode, await weak.CodeOfAsync(Ct));
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsJsonAsync($"/api/admin/identity/users/{id:N}/change-password", new ChangePasswordRequest("Another-Horse-7"), Ct)).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync($"/api/admin/identity/users/{id:N}", Ct)).StatusCode);
        var gone = await client.GetAsync($"/api/admin/identity/users/{id:N}", Ct);
        Assert.Equal(HttpStatusCode.NotFound, gone.StatusCode);
        Assert.Equal(IdentityErrors.AccountNotFoundCode, await gone.CodeOfAsync(Ct));
        Assert.Contains(id.ToString("N"), (await client.GetFromJsonAsync<string[]>("/api/admin/identity/security/blocked-users", Ct))!);
    }

    [Fact]
    public async Task A_caller_without_the_operation_is_refused_and_an_unauthenticated_one_challenged()
    {
        await using var app = await StartAsync(MapPerOperation);
        var reader = app.ClientAs("reader", "users.read");

        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync("/api/admin/identity/users", Ct)).StatusCode);
        var refused = await reader.PostAsJsonAsync("/api/admin/identity/users", new CreateAccountRequest("jane@acme.test", "Jane", "Correct-Horse-9"), Ct);
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
