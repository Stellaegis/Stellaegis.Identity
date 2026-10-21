using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Identity.AspNetCore;

/// <summary>
/// Who calls a route of the accounts module. The module has no compartments, so its routes read no request
/// context — the startup check of Primitives refuses one on such a module — and the actor is read from the
/// principal the host authenticated, the way the request context reads it: the <c>NameIdentifier</c> claim,
/// then <c>sub</c>, then <c>client_id</c> for a service; the frame's anonymous actor when nobody is authenticated.
/// </summary>
internal static class Callers
{
    private static readonly string[] ActorClaims = [ClaimTypes.NameIdentifier, "sub", "client_id"];

    /// <summary>The actor of the request, never <see langword="null"/>.</summary>
    /// <exception cref="InvalidOperationException">An authenticated principal carries none of the claims, or a value that is not an actor.</exception>
    public static Actor ActorOf(HttpContext httpContext)
    {
        var user = httpContext.User;
        if (user.Identity?.IsAuthenticated != true)
            return httpContext.RequestServices.GetStellaegisFrame().AnonymousActor;

        foreach (var type in ActorClaims)
        {
            if (user.FindFirst(type)?.Value is not { } value)
                continue;
            if (Actor.TryParse(value, out var actor))
                return actor;
            throw new InvalidOperationException(
                $"The claim {type} of the authenticated user is not an actor: '{value}'. An actor is 1 to {Actor.MaxLength} "
                + "characters without control characters nor surrounding whitespace.");
        }
        throw new InvalidOperationException(
            "The authenticated user carries none of the claims an actor is read from: NameIdentifier, sub, client_id. "
            + "Recording the request as anonymous would attribute it to nobody: map the claim the token carries onto one of them.");
    }

    /// <summary>The subject of an authenticated principal — <c>sub</c>, then <c>NameIdentifier</c> —, or <see langword="null"/> when nobody is authenticated or no claim says.</summary>
    public static string? SubjectOf(ClaimsPrincipal user)
        => user.Identity?.IsAuthenticated == true
            ? user.FindFirst("sub")?.Value ?? user.FindFirst(ClaimTypes.NameIdentifier)?.Value
            : null;
}
