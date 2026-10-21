using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Stellaegis.Primitives;

namespace Stellaegis.Identity.AspNetCore;

/// <summary>
/// The cookie a person is signed in with, once <see cref="LoginService"/> verified their credentials: the scheme
/// <see cref="Scheme"/>, the cookie <see cref="CookieName"/>, kept out of scripts, sent on same-site navigations,
/// over HTTPS only, and the login page at <see cref="LoginPath"/> for a challenge. The pages of
/// <c>Stellaegis.Identity.Server</c> sign in through <see cref="CookieSignIn"/>; a host writing its own page does
/// the same.
/// </summary>
public static class IdentityCookie
{
    /// <summary>The authentication scheme of the cookie: the cookie scheme of ASP.NET Core, which <see cref="LoginService.DefaultAuthenticationType"/> names too.</summary>
    public const string Scheme = CookieAuthenticationDefaults.AuthenticationScheme;

    /// <summary>The name of the cookie, <c>stellaegis_identity</c>.</summary>
    public const string CookieName = "stellaegis_identity";

    /// <summary>Where a challenge sends an unauthenticated person, <c>/login</c>.</summary>
    public const string LoginPath = "/login";

    /// <summary>The query parameter the login page reads the way back from, <c>return_url</c>.</summary>
    public const string ReturnUrlParameter = "return_url";
}

/// <summary>Registers the cookie a person signs in with.</summary>
public static class CookieServiceCollectionExtensions
{
    /// <summary>
    /// Registers the cookie scheme (<see cref="IdentityCookie"/>) as the default authentication of the host, and
    /// <see cref="CookieSignIn"/>, which the login page signs in and out with. <paramref name="configure"/> changes
    /// what the cookie does by default — its lifetime, its path, its domain. A host that authenticates its API
    /// otherwise — a bearer token — registers that scheme too, and chooses the default after this call.
    /// <code>
    /// builder.Services.AddStellaegisIdentityInMemory(builder.Configuration);
    /// builder.Services.AddStellaegisIdentityCookie();
    /// </code>
    /// </summary>
    public static AuthenticationBuilder AddStellaegisIdentityCookie(this IServiceCollection services, Action<CookieAuthenticationOptions>? configure = null)
    {
        Guard.NotNull(services);
        services.TryAddScoped<CookieSignIn>();
        return services.AddAuthentication(IdentityCookie.Scheme)
            .AddCookie(IdentityCookie.Scheme, options =>
            {
                options.LoginPath = IdentityCookie.LoginPath;
                options.ReturnUrlParameter = IdentityCookie.ReturnUrlParameter;
                options.Cookie.Name = IdentityCookie.CookieName;
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                configure?.Invoke(options);
            });
    }
}

/// <summary>
/// Signs a person in and out of the cookie: what a login page calls once <see cref="LoginService.AuthenticateAsync"/>
/// said the credentials hold, or once the one-time code of a second factor was checked.
/// </summary>
public sealed class CookieSignIn(LoginService login)
{
    /// <summary>
    /// Signs <paramref name="principal"/> in — the one a succeeded <see cref="LoginResult"/> carries —, for the
    /// session when <paramref name="persistent"/> is <see langword="false"/>, across sessions otherwise.
    /// </summary>
    public Task SignInAsync(HttpContext httpContext, ClaimsPrincipal principal, bool persistent = false)
    {
        Guard.NotNull(httpContext);
        Guard.NotNull(principal);
        return httpContext.SignInAsync(IdentityCookie.Scheme, principal, new AuthenticationProperties { IsPersistent = persistent });
    }

    /// <summary>
    /// Signs the account in, once something else than the password proved it — the one-time code of a second
    /// factor, for instance. Fails with <see cref="IdentityErrors.AccountBlocked"/> when the account is gone or
    /// blocked at the door since.
    /// </summary>
    public async Task<Result> SignInAsync(HttpContext httpContext, Guid userUniqueId, bool persistent = false, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(httpContext);
        var principal = await login.CreatePrincipalAsync(userUniqueId, IdentityCookie.Scheme, cancellationToken);
        if (principal is null)
            return Result.Failure(IdentityErrors.AccountBlocked);
        await SignInAsync(httpContext, principal, persistent);
        return Result.Success();
    }

    /// <summary>Signs the person out: the cookie is removed.</summary>
    public Task SignOutAsync(HttpContext httpContext)
    {
        Guard.NotNull(httpContext);
        return httpContext.SignOutAsync(IdentityCookie.Scheme);
    }
}
