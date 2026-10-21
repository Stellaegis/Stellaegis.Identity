using System.Security.Claims;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>What every page reads of the signed-in person and of the request.</summary>
internal static class PageModelExtensions
{
    /// <summary>The account of the signed-in person — the <c>sub</c> claim, then <c>NameIdentifier</c> —, or <see langword="null"/> when the claim is missing or not an id.</summary>
    public static Guid? UserId(this PageModel page)
    {
        var subject = page.User.FindFirstValue("sub") ?? page.User.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(subject, out var id) ? id : null;
    }

    /// <summary>The e-mail of the signed-in person, from the <c>email</c> claim; empty when none.</summary>
    public static string UserEmail(this PageModel page)
        => page.User.FindFirstValue("email") ?? page.User.FindFirstValue(ClaimTypes.Email) ?? "";

    /// <summary>The display name of the signed-in person, from the <c>name</c> claim; empty when none.</summary>
    public static string UserName(this PageModel page)
        => page.User.FindFirstValue("name") ?? page.User.FindFirstValue(ClaimTypes.Name) ?? "";

    /// <summary>The address the request came from, for the trace of logins.</summary>
    public static string? ClientAddress(this PageModel page) => page.HttpContext.Connection.RemoteIpAddress?.ToString();

    /// <summary>The user agent of the request, for the trace of logins.</summary>
    public static string? ClientAgent(this PageModel page)
    {
        var agent = page.HttpContext.Request.Headers.UserAgent.ToString();
        return agent.Length == 0 ? null : agent;
    }
}
