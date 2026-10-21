using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;

namespace Stellaegis.Identity.Server;

/// <summary>
/// What a flow keeps between two pages when the person is not signed in yet: the account whose password held and
/// awaits its second factor, the account that must set one up, the registration whose e-mail awaits its code.
/// Each lives in a cookie of its own, protected by the data protection of the host, out of scripts, for a few
/// minutes.
/// </summary>
internal sealed class PendingStates(IDataProtectionProvider protection, TimeProvider clock)
{
    private const char Separator = '\u001f';

    /// <summary>The login that awaits a second factor: the account, the way back, the method.</summary>
    public static readonly PendingState Mfa = new("stellaegis_identity.mfa", TimeSpan.FromMinutes(10));

    /// <summary>The login that awaits a second factor to be set up: the account, the way back, the e-mail.</summary>
    public static readonly PendingState MfaSetup = new("stellaegis_identity.mfa_setup", TimeSpan.FromMinutes(15));

    /// <summary>The registration that awaits its code: the e-mail, the display name, the password, the way back.</summary>
    public static readonly PendingState Registration = new("stellaegis_identity.registration", TimeSpan.FromMinutes(15));

    /// <summary>The change of e-mail that awaits its code: the new e-mail.</summary>
    public static readonly PendingState EmailChange = new("stellaegis_identity.email_change", TimeSpan.FromMinutes(15));

    /// <summary>Writes <paramref name="parts"/> as <paramref name="state"/> on the response, good for the state's lifetime.</summary>
    public void Write(HttpContext httpContext, PendingState state, params string[] parts)
    {
        var protector = protection.CreateProtector(Purpose(state)).ToTimeLimitedDataProtector();
        var payload = string.Join(Separator, parts.Select(part => part.Replace(Separator.ToString(), "", StringComparison.Ordinal)));
        httpContext.Response.Cookies.Append(state.CookieName, protector.Protect(payload, state.Lifetime), new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            IsEssential = true,
            Expires = clock.GetUtcNow().Add(state.Lifetime),
            Path = "/",
        });
    }

    /// <summary>The parts of <paramref name="state"/> on the request, or <see langword="null"/> when absent, altered or expired.</summary>
    public string[]? Read(HttpContext httpContext, PendingState state)
    {
        if (httpContext.Request.Cookies[state.CookieName] is not { Length: > 0 } cookie)
            return null;
        try
        {
            var protector = protection.CreateProtector(Purpose(state)).ToTimeLimitedDataProtector();
            return protector.Unprotect(cookie).Split(Separator);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return null;
        }
    }

    /// <summary>Removes <paramref name="state"/> from the browser.</summary>
    public void Clear(HttpContext httpContext, PendingState state)
        => httpContext.Response.Cookies.Delete(state.CookieName, new CookieOptions { Path = "/" });

    private static string Purpose(PendingState state) => "Stellaegis.Identity.Server:" + state.CookieName;
}

/// <summary>A pending state: the cookie that carries it, and how long it lives.</summary>
/// <param name="CookieName">The name of the cookie.</param>
/// <param name="Lifetime">How long the state is accepted.</param>
internal sealed record PendingState(string CookieName, TimeSpan Lifetime);
