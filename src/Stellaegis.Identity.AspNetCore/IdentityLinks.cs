using Microsoft.AspNetCore.Http;
using Stellaegis.Primitives;

namespace Stellaegis.Identity.AspNetCore;

/// <summary>The links an account receives — a reset, an activation —, written the one way by the pages and the administration.</summary>
public static class IdentityLinks
{
    /// <summary>The path of the page that resets a password, <c>/reset-password</c>.</summary>
    public const string ResetPasswordPath = "/reset-password";

    /// <summary>The path of the page that activates an account, <c>/activate</c>.</summary>
    public const string ActivatePath = "/activate";

    /// <summary>The path of the page that restores the e-mail an account had before a change, <c>/revert-email</c>.</summary>
    public const string RevertEmailPath = "/revert-email";

    /// <summary>
    /// The absolute link to <paramref name="path"/> carrying <paramref name="token"/>: from
    /// <see cref="LinkOptions.PublicBaseUrl"/> when it is set, from <paramref name="request"/> otherwise — which
    /// supposes the pages are served by the host that issues the link.
    /// </summary>
    public static Uri Of(LinkOptions links, HttpRequest? request, string path, string token)
    {
        Guard.NotNull(links);
        Guard.NotWhiteSpace(path);
        Guard.NotWhiteSpace(token);
        var root = links.PublicBase?.ToString().TrimEnd('/')
            ?? (request is null
                ? throw new InvalidOperationException($"No request to take the address of the pages from: set {nameof(IdentityOptions.Links)}:{nameof(LinkOptions.PublicBaseUrl)}.")
                : $"{request.Scheme}://{request.Host}{request.PathBase}");
        return new Uri($"{root}{path}?token={Uri.EscapeDataString(token)}", UriKind.Absolute);
    }
}
