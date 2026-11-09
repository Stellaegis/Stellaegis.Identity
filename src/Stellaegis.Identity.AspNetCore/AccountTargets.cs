using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;

namespace Stellaegis.Identity.AspNetCore;

/// <summary>
/// The administration routes that act on an account that exists: the person they reach is part of the decision.
/// Before the route runs, the account of its <c>{id}</c> is loaded as a <see cref="Subject"/>: the caller's own is
/// refused, <see cref="IdentityErrors.OwnAccount"/>; any other is asked about — <c>AuthorizeResourceAsync</c>, the
/// route's operation as the requirement — and a refusal is answered as an absence, <see cref="IdentityErrors.AccountNotFound"/>.
/// </summary>
internal static class AccountTargets
{
    /// <summary>Declares that the route acts on the account of its <c>{id}</c>, decided on that account.</summary>
    public static RouteHandlerBuilder ActsOnAccount(this RouteHandlerBuilder route)
        => route
            .AddEndpointFilter(async (context, next) =>
            {
                var http = context.HttpContext;
                // The route's {id:guid} constraint answers anything else before the filter runs.
                if (http.Request.RouteValues["id"] is not string raw || !Guid.TryParse(raw, out var id))
                    return Result.Failure(IdentityErrors.AccountNotFound).ToHttpResult();
                var subject = Subject.Parse(id.ToString("N"));
                if (subject.Is(Callers.ActorOf(http)))
                    return Result.Failure(IdentityErrors.OwnAccount).ToHttpResult();
                if (!await http.AuthorizeResourceAsync(subject))
                    return Result.Failure(IdentityErrors.AccountNotFound).ToHttpResult();
                return await next(context);
            })
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);
}
