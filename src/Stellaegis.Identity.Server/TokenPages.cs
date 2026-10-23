using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Stellaegis.Identity.Server;

/// <summary>What a page reached by a link carrying a token does to keep it.</summary>
internal static class TokenPages
{
    /// <summary>
    /// Sends no referrer from the page: the token is in its address, and a font, a script or a link to another site
    /// would otherwise carry it there.
    /// </summary>
    public static void KeepTokenFromReferrers(this PageModel page)
        => page.Response.Headers["Referrer-Policy"] = "no-referrer";
}
