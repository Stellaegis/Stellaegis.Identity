using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;

namespace Stellaegis.Identity.AspNetCore;

/// <summary>
/// Maps the routes a signed-in person calls on their own account, from a client of the host's — a rich page that
/// shows the name of the person and lets them change it. The person is the session's, read from the cookie of
/// <see cref="IdentityCookie"/>: these routes act on oneself, under no operation and no role, and nobody reaches
/// another account through them.
/// </summary>
/// <remarks>
/// <list type="bullet">
///   <item><c>GET identity/account/profile</c> — the profile, <see cref="AccountProfile"/></item>
///   <item><c>PUT identity/account/profile</c> — the name, the language and the time zone, replaced; the session is
///   signed in again, so that its <c>locale</c> and <c>zoneinfo</c> follow; 400 with the code of the refusal</item>
/// </list>
/// <para>
/// A write is a <c>PUT</c> with a JSON body: a browser sends neither cross-site without a preflight that the host's
/// CORS policy answers, and the cookie is sent on same-site requests only.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// builder.Services.AddStellaegisIdentityCookie();
/// builder.Services.AddStellaegisStartupCheck();   // the routes of a module are checked at startup
/// ...
/// app.MapIdentityAccountEndpoints();
/// </code>
/// </example>
public static class IdentityAccountEndpoints
{
    /// <summary>The change a person asks of their profile: every field replaced, an empty language or time zone being no choice.</summary>
    /// <param name="DisplayName">The name of the account.</param>
    /// <param name="Locale">The language, a culture name such as <c>fr</c>; empty or absent for none.</param>
    /// <param name="TimeZone">The time zone, an IANA name such as <c>Europe/Paris</c>; empty or absent for none.</param>
    public sealed record ProfileChange(string? DisplayName, string? Locale, string? TimeZone);

    /// <summary>
    /// Maps the routes of the signed-in person's own account, relative to <paramref name="endpoints"/>, under
    /// <c>identity/account</c>, open to whoever the cookie of <see cref="IdentityCookie"/> signed in.
    /// </summary>
    /// <returns>The group holding the routes, for further conventions.</returns>
    public static RouteGroupBuilder MapIdentityAccountEndpoints(this IEndpointRouteBuilder endpoints)
    {
        Guard.NotNull(endpoints);
        var group = endpoints.MapGroup("identity/account")
            .BelongsTo<IdentityModule>()
            .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = IdentityCookie.Scheme })
            .AddErrorTranslation();

        group.MapGet("/profile", async (HttpContext http, ProfileService profiles, CancellationToken ct)
                => SubjectOf(http) is { } id ? (await profiles.GetAsync(id, ct)).ToHttpResult() : Results.Forbid())
            .Produces<AccountProfile>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapPut("/profile", async (ProfileChange change, HttpContext http, ProfileService profiles, CookieSignIn signIn, CancellationToken ct) =>
            {
                if (SubjectOf(http) is not { } id)
                    return Results.Forbid();
                var changed = await profiles.UpdateAsync(id, change.DisplayName, change.Locale, change.TimeZone, ct);
                if (changed.IsSuccess)
                    await signIn.RefreshAsync(http, ct);
                return changed.ToHttpResult();
            })
            .Produces<AccountProfile>()
            .ProducesProblem(StatusCodes.Status400BadRequest);

        return group;
    }

    private static Guid? SubjectOf(HttpContext http)
        => Guid.TryParse(http.User.FindFirst("sub")?.Value, out var id) ? id : null;
}
