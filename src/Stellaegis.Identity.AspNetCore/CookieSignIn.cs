using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
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
    /// <see cref="CookieSignIn"/>, which the login page signs in and out with. The cookie lasts
    /// <see cref="SessionPolicyOptions.Lifetime"/>, renewed by each request; <paramref name="configure"/> changes
    /// what it does by default — its path, its domain, its lifetime over the option. A host that authenticates its API
    /// otherwise — a bearer token — registers that scheme too, and chooses the default after this call.
    /// <para>
    /// The cookie is held against its account (<see cref="SessionPolicyOptions"/>): read again once its validation
    /// interval elapsed, it is closed when its account is gone, deleted or blocked. An <c>OnValidatePrincipal</c> the
    /// host sets in <paramref name="configure"/> runs after that reading, on the account as it is now; an
    /// <c>EventsType</c> replaces these events, the validation with them.
    /// </para>
    /// <code>
    /// builder.Services.AddStellaegisIdentityInMemory(builder.Configuration);
    /// builder.Services.AddStellaegisIdentityCookie();
    /// </code>
    /// </summary>
    public static AuthenticationBuilder AddStellaegisIdentityCookie(this IServiceCollection services, Action<CookieAuthenticationOptions>? configure = null)
    {
        Guard.NotNull(services);
        services.TryAddScoped<CookieSignIn>();
        // Registered before the cookie's own configuration, so that what the host sets in configure wins over the option.
        services.AddOptions<CookieAuthenticationOptions>(IdentityCookie.Scheme)
            .Configure<IOptions<IdentityOptions>>((options, identity) =>
            {
                options.ExpireTimeSpan = identity.Value.Session.Lifetime;
                options.SlidingExpiration = true;
            });
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
                var host = options.Events.OnValidatePrincipal;
                options.Events.OnValidatePrincipal = async context =>
                {
                    await SessionValidation.ValidateAsync(context);
                    if (context.Principal is not null)
                        await host(context);
                };
            });
    }
}

/// <summary>
/// Holds a session against its account, the mechanism of the security stamp validator of ASP.NET Core Identity: once
/// <see cref="SessionPolicyOptions.ValidationInterval"/> elapsed since its last reading, the account is read again.
/// A session whose account is gone — a database installed again under the same keys —, deleted or blocked is closed;
/// the others carry the account as it is now, with how and when the person proved who they are, and the cookie is
/// issued again with the time of the reading. A cookie without that time is dated by its issue.
/// </summary>
internal static class SessionValidation
{
    private const string ValidatedAtItem = ".stellaegis.validated";

    public static async Task ValidateAsync(CookieValidatePrincipalContext context)
    {
        var services = context.HttpContext.RequestServices;
        var interval = services.GetRequiredService<IOptions<IdentityOptions>>().Value.Session.ValidationInterval;
        var now = (context.Options.TimeProvider ?? TimeProvider.System).GetUtcNow();
        var validatedAt = DateTimeOffset.TryParse(context.Properties.GetString(ValidatedAtItem), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var at)
            ? at
            : context.Properties.IssuedUtc;
        if (interval > TimeSpan.Zero && validatedAt is { } last && now - last < interval)
            return;

        var principal = context.Principal is { } current
            ? await services.GetRequiredService<LoginService>().RenewPrincipalAsync(current, IdentityCookie.Scheme, context.HttpContext.RequestAborted)
            : null;
        if (principal is null)
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(context.Scheme.Name);
            return;
        }
        context.ReplacePrincipal(principal);
        context.Properties.SetString(ValidatedAtItem, now.ToString("O", CultureInfo.InvariantCulture));
        context.ShouldRenew = true;
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
    /// <param name="httpContext">The request.</param>
    /// <param name="userUniqueId">The account.</param>
    /// <param name="methods">How the person proved who they are, <see cref="AuthenticationMethods"/>: the session's <c>amr</c>.</param>
    /// <param name="persistent">Whether the cookie outlives the browser session.</param>
    /// <param name="cancellationToken">Cancels the sign-in.</param>
    public async Task<Result> SignInAsync(HttpContext httpContext, Guid userUniqueId, IReadOnlyCollection<string> methods, bool persistent = false, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(httpContext);
        var principal = await login.CreatePrincipalAsync(userUniqueId, methods, IdentityCookie.Scheme, cancellationToken);
        if (principal is null)
            return Result.Failure(IdentityErrors.AccountBlocked);
        await SignInAsync(httpContext, principal, persistent);
        return Result.Success();
    }

    /// <summary>
    /// Signs the signed-in person in again from their account, as it is now — a name or a language just changed —,
    /// keeping how and when they proved who they are and how long the cookie lasts. Fails with
    /// <see cref="IdentityErrors.AccountBlocked"/>, and signs the person out, when the account is gone or blocked at
    /// the door since.
    /// </summary>
    public async Task<Result> RefreshAsync(HttpContext httpContext, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(httpContext);
        var current = await httpContext.AuthenticateAsync(IdentityCookie.Scheme);
        if (!current.Succeeded)
            return Result.Failure(IdentityErrors.AccountBlocked);
        var principal = await login.RenewPrincipalAsync(current.Principal, IdentityCookie.Scheme, cancellationToken);
        if (principal is null)
        {
            await SignOutAsync(httpContext);
            return Result.Failure(IdentityErrors.AccountBlocked);
        }
        await httpContext.SignInAsync(IdentityCookie.Scheme, principal, current.Properties);
        return Result.Success();
    }

    /// <summary>Signs the person out: the cookie is removed.</summary>
    public Task SignOutAsync(HttpContext httpContext)
    {
        Guard.NotNull(httpContext);
        return httpContext.SignOutAsync(IdentityCookie.Scheme);
    }
}
