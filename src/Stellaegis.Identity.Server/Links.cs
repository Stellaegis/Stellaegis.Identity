using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Stellaegis.Identity.AspNetCore;

namespace Stellaegis.Identity.Server;

/// <summary>
/// The links between the pages, carrying the way back — the <c>return_url</c> the cookie's challenge set, or an
/// issuer's authorize request. The query string is appended by hand: a value generated from route values could be
/// lowercased by the host's routing, which corrupts the case-sensitive parts of an authorize URL.
/// </summary>
internal static class Links
{
    /// <summary>The query parameter carrying the way back, the cookie's.</summary>
    public const string ReturnUrlParameter = IdentityCookie.ReturnUrlParameter;

    /// <summary><paramref name="path"/> with <paramref name="returnUrl"/> appended, or <paramref name="path"/> alone when there is nothing to carry.</summary>
    public static string WithReturnUrl(string path, string? returnUrl)
        => string.IsNullOrEmpty(returnUrl) ? path : QueryHelpers.AddQueryString(path, ReturnUrlParameter, returnUrl);

    /// <summary><paramref name="returnUrl"/> when it is local to the host, <see langword="null"/> otherwise: a foreign one is dropped rather than followed.</summary>
    public static string? Local(IUrlHelper url, string? returnUrl)
        => !string.IsNullOrEmpty(returnUrl) && url.IsLocalUrl(returnUrl) ? returnUrl : null;
}
