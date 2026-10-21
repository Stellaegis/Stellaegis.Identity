using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;

namespace Stellaegis.Identity.AspNetCore;

/// <summary>
/// Maps the administration routes of the accounts module: what an administrator does to accounts, through
/// <see cref="AccountAdministrationService"/>, and the blocked accounts a resource server apart reads, through
/// <c>Stellaegis.Identity.Client</c>.
/// </summary>
/// <remarks>
/// <para>
/// The module has no compartments: its routes read no request context, and the actor of a write is read from the
/// principal the host authenticated. An account is nobody's resource — no compartment, no owner —, so the routes
/// declare they load none: the operation each is labelled with is the whole decision, and the host declares who
/// may call it, by operation or on the group. The startup check of <c>Stellaegis.Primitives.AspNetCore</c> refuses
/// a route left without authorization.
/// </para>
/// <list type="bullet">
///   <item><c>GET identity/users?skip=&amp;take=</c> — a page of the accounts, <c>users.read</c></item>
///   <item><c>POST identity/users/lookup</c> — the accounts with those ids, <c>users.read</c></item>
///   <item><c>GET identity/users/{id}</c> — one account, <c>users.read</c>; 404 with the code <c>Account.NotFound</c></item>
///   <item><c>POST identity/users</c> — create an account, <c>users.write</c>; 201 with its id</item>
///   <item><c>POST identity/users/{id}/block</c>, <c>/unblock</c>, <c>/reset-failed-logins</c>, <c>/reset-mfa</c>, <c>/change-password</c> — <c>users.write</c></item>
///   <item><c>DELETE identity/users/{id}</c> — delete an account, <c>users.delete</c></item>
///   <item><c>GET identity/security/blocked-users</c> — the subjects blocked at the door, <c>security.read</c></item>
/// </list>
/// <para>The routes carry no name, so the module can be mapped several times in one host.</para>
/// </remarks>
/// <example>
/// <code>
/// builder.Services.AddStellaegisIdentityPostgreSQL(builder.Configuration);
/// builder.Services.AddStellaegisIdentityAdministration();
///
/// var app = builder.Build();
/// app.UseAuthentication();
/// app.UseAuthorization();
/// app.MapGroup("/api/admin").MapIdentityAdminEndpoints().RequireAuthorizationPerOperation(op => op.ToString());
/// </code>
/// </example>
public static class IdentityAdminEndpoints
{
    /// <summary>
    /// Registers the startup check of the routes, which <see cref="MapIdentityAdminEndpoints"/> needs: a module
    /// without compartments registers it from its own registration, since no request context does. Harmless when
    /// something else registered it.
    /// </summary>
    public static IServiceCollection AddStellaegisIdentityAdministration(this IServiceCollection services)
    {
        Guard.NotNull(services);
        return services.AddStellaegisStartupCheck();
    }

    /// <summary>
    /// Maps the administration routes of the accounts, relative to <paramref name="endpoints"/>, under
    /// <c>identity</c>. The host declares who may call them on the returned group.
    /// </summary>
    /// <param name="endpoints">The builder to map the routes on — the application, or a route group.</param>
    /// <returns>The group holding the routes, for the host's authorization and further conventions.</returns>
    public static RouteGroupBuilder MapIdentityAdminEndpoints(this IEndpointRouteBuilder endpoints)
    {
        Guard.NotNull(endpoints);
        var group = endpoints.MapGroup("identity")
            .BelongsTo<IdentityModule>()
            .LoadsNoResource()
            .AddErrorTranslation();

        var users = group.MapGroup("/users");

        users.MapGet("/", async (IAuthUserStore store, IMfaStore mfa, CancellationToken ct, int skip = 0, int take = 50) =>
            {
                if (skip < 0 || take is < 1 or > 500)
                    return Result.Failure(Error.Validation("Page.Invalid", "skip is zero or more, take is 1 to 500.")).ToHttpResult();
                var page = await store.ListAsync(skip, take, cancellationToken: ct);
                var count = await store.CountAsync(cancellationToken: ct);
                return Results.Ok(new AccountPage(await SummariesAsync(page, mfa, ct), count));
            })
            .WithMetadata(IdentityOperations.UsersRead)
            .Produces<AccountPage>(StatusCodes.Status200OK);

        users.MapPost("/lookup", async (LookupAccountsRequest request, IAuthUserStore store, IMfaStore mfa, CancellationToken ct) =>
            {
                var ids = (request?.UserUniqueIds ?? []).Distinct().Take(100).ToList();
                var found = ids.Count == 0 ? [] : await store.ListByUniqueIdsAsync(ids, ct);
                return Results.Ok(new AccountList(await SummariesAsync(found, mfa, ct)));
            })
            .WithMetadata(IdentityOperations.UsersRead)
            .Produces<AccountList>(StatusCodes.Status200OK);

        users.MapGet("/{id:guid}", async (Guid id, IAuthUserStore store, IMfaStore mfa, CancellationToken ct) =>
            {
                var user = await store.GetByUniqueIdAsync(id, ct);
                return user is null
                    ? Result.Failure<AccountSummary>(IdentityErrors.AccountNotFound).ToHttpResult()
                    : Results.Ok(await SummaryAsync(user, mfa, ct));
            })
            .WithMetadata(IdentityOperations.UsersRead)
            .Produces<AccountSummary>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status404NotFound);

        users.MapPost("/", async (CreateAccountRequest request, HttpContext http, AccountAdministrationService accounts, CancellationToken ct) =>
            {
                if (request is null || string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.DisplayName) || string.IsNullOrWhiteSpace(request.Password))
                    return Result.Failure(Error.Validation("Account.Invalid", "An account has an e-mail, a display name and a password.")).ToHttpResult();
                var created = await accounts.CreateAsync(request.Email, request.DisplayName, request.Password, Callers.ActorOf(http), ct);
                return created.IsSuccess
                    ? Results.Created((string?)null, new AccountCreated(created.Value))
                    : created.ToHttpResult();
            })
            .WithMetadata(IdentityOperations.UsersWrite)
            .Produces<AccountCreated>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status409Conflict);

        users.MapPost("/{id:guid}/block", async (Guid id, HttpContext http, AccountAdministrationService accounts, CancellationToken ct) =>
                (await accounts.BlockAsync(id, Callers.ActorOf(http), ct)).ToHttpResult())
            .WithMetadata(IdentityOperations.UsersWrite)
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status404NotFound);

        users.MapPost("/{id:guid}/unblock", async (Guid id, HttpContext http, AccountAdministrationService accounts, CancellationToken ct) =>
                (await accounts.UnblockAsync(id, Callers.ActorOf(http), ct)).ToHttpResult())
            .WithMetadata(IdentityOperations.UsersWrite)
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status404NotFound);

        users.MapPost("/{id:guid}/reset-failed-logins", async (Guid id, HttpContext http, AccountAdministrationService accounts, CancellationToken ct) =>
                (await accounts.ResetFailedLoginsAsync(id, Callers.ActorOf(http), ct)).ToHttpResult())
            .WithMetadata(IdentityOperations.UsersWrite)
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status404NotFound);

        users.MapPost("/{id:guid}/reset-mfa", async (Guid id, HttpContext http, AccountAdministrationService accounts, CancellationToken ct) =>
                (await accounts.ResetMfaAsync(id, Callers.ActorOf(http), ct)).ToHttpResult())
            .WithMetadata(IdentityOperations.UsersWrite)
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status404NotFound);

        users.MapPost("/{id:guid}/change-password", async (Guid id, ChangePasswordRequest request, HttpContext http, AccountAdministrationService accounts, CancellationToken ct) =>
            {
                if (request is null || string.IsNullOrWhiteSpace(request.NewPassword))
                    return Result.Failure(Error.Validation("Password.Required", "A new password is required.")).ToHttpResult();
                return (await accounts.ChangePasswordAsync(id, request.NewPassword, Callers.ActorOf(http), ct)).ToHttpResult();
            })
            .WithMetadata(IdentityOperations.UsersWrite)
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status404NotFound);

        users.MapDelete("/{id:guid}", async (Guid id, HttpContext http, AccountAdministrationService accounts, CancellationToken ct) =>
                (await accounts.DeleteAsync(id, Callers.ActorOf(http), ct)).ToHttpResult())
            .WithMetadata(IdentityOperations.UsersDelete)
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapGet("/security/blocked-users", async (IBlockedUsersSource blocked, CancellationToken ct) =>
                Results.Ok(await blocked.GetBlockedSubjectsAsync(ct)))
            .WithMetadata(IdentityOperations.SecurityRead)
            .Produces<IReadOnlyCollection<string>>(StatusCodes.Status200OK);

        return group;
    }

    private static async Task<IReadOnlyList<AccountSummary>> SummariesAsync(IReadOnlyList<AuthUser> users, IMfaStore mfa, CancellationToken ct)
    {
        var enabled = users.Count == 0
            ? new HashSet<Guid>()
            : await mfa.GetEnabledUserIdsAsync(users.Select(user => user.UserUniqueId).ToList(), ct);
        return users.Select(user => AccountSummary.Of(user, enabled.Contains(user.UserUniqueId))).ToList();
    }

    private static async Task<AccountSummary> SummaryAsync(AuthUser user, IMfaStore mfa, CancellationToken ct)
        => AccountSummary.Of(user, (await mfa.GetAsync(user.UserUniqueId, ct))?.IsEnabled == true);
}

// The wire of the administration routes.

/// <summary>An account as the administration shows it: nothing secret, and whether a second factor is enabled, read from where the login reads it.</summary>
/// <param name="UserUniqueId">The identity of the account.</param>
/// <param name="Email">Its e-mail, normalized.</param>
/// <param name="DisplayName">Its display name.</param>
/// <param name="IsEnabled">Whether it is enabled; a disabled account is blocked at the door.</param>
/// <param name="MfaEnabled">Whether a second factor is required at login.</param>
/// <param name="BlockedUntil">Until when a lockout holds, or <see langword="null"/>.</param>
/// <param name="FailedLoginCount">How many logins failed since the last success.</param>
/// <param name="LastLogin">When the last login succeeded, or <see langword="null"/>.</param>
/// <param name="CreatedAt">When the account was created.</param>
/// <param name="ModifiedAt">When it was last modified.</param>
public sealed record AccountSummary(
    Guid UserUniqueId,
    string Email,
    string DisplayName,
    bool IsEnabled,
    bool MfaEnabled,
    DateTimeOffset? BlockedUntil,
    int FailedLoginCount,
    DateTimeOffset? LastLogin,
    DateTimeOffset CreatedAt,
    DateTimeOffset ModifiedAt)
{
    internal static AccountSummary Of(AuthUser user, bool mfaEnabled) => new(
        user.UserUniqueId, user.Email, user.DisplayName, user.IsEnabled, mfaEnabled,
        user.BlockedUntil, user.FailedLoginCount, user.LastLogin, user.CreatedAt, user.ModifiedAt);
}

/// <summary>A page of the accounts.</summary>
/// <param name="Items">The accounts of the page.</param>
/// <param name="TotalCount">How many accounts there are in all.</param>
public sealed record AccountPage(IReadOnlyList<AccountSummary> Items, int TotalCount);

/// <summary>The accounts found by a lookup.</summary>
/// <param name="Items">The accounts, those not found absent.</param>
public sealed record AccountList(IReadOnlyList<AccountSummary> Items);

/// <summary>Which accounts to look up, 100 at most.</summary>
/// <param name="UserUniqueIds">Their ids.</param>
public sealed record LookupAccountsRequest(Guid[]? UserUniqueIds);

/// <summary>An account to create, enabled.</summary>
/// <param name="Email">Its e-mail.</param>
/// <param name="DisplayName">Its display name.</param>
/// <param name="Password">Its password, which the policy of the host checks.</param>
public sealed record CreateAccountRequest(string? Email, string? DisplayName, string? Password);

/// <summary>The account just created.</summary>
/// <param name="UserUniqueId">Its id.</param>
public sealed record AccountCreated(Guid UserUniqueId);

/// <summary>A new password set by an administrator, without the current one.</summary>
/// <param name="NewPassword">The new password.</param>
public sealed record ChangePasswordRequest(string? NewPassword);
