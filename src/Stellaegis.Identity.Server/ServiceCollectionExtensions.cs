using System.Globalization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Stellaegis.Identity.AspNetCore;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Identity.Server;

/// <summary>Registers the pages a person signs in and manages their account with.</summary>
public static class IdentityPagesServiceCollectionExtensions
{
    /// <summary>
    /// Registers the pages of the package — Razor Pages, the antiforgery that comes with them, the localization,
    /// the texts — with <see cref="IdentityPagesOptions"/> bound from <paramref name="sectionName"/> and validated
    /// when the host starts. The accounts and the cookie are registered apart:
    /// <code>
    /// builder.Services.AddStellaegisIdentityPostgreSQL(builder.Configuration);
    /// builder.Services.AddStellaegisIdentityCookie();
    /// builder.Services.AddStellaegisIdentityPages(builder.Configuration);
    /// builder.Services.AddSingleton&lt;IIdentityMailer, MyMailer&gt;();   // what the pages send
    /// ...
    /// app.MapStaticAssets();   // the stylesheet, the scripts and the logo of the pages
    /// app.UseAuthentication();
    /// app.UseAuthorization();
    /// app.MapStellaegisIdentityPages();
    /// </code>
    /// A host with Razor Pages of its own calls <c>AddRazorPages</c> as usual; this call adds the package's pages
    /// to them.
    /// </summary>
    public static IServiceCollection AddStellaegisIdentityPages(this IServiceCollection services, IConfiguration configuration, string sectionName = IdentityPagesOptions.SectionName)
    {
        Guard.NotNull(configuration);
        Guard.NotWhiteSpace(sectionName);
        services.AddStellaegisOptions<IdentityPagesOptions>(configuration, sectionName);
        return services.AddPages();
    }

    /// <summary>
    /// Registers the pages of the package with their options configured in code; otherwise as
    /// <see cref="AddStellaegisIdentityPages(IServiceCollection, IConfiguration, string)"/>.
    /// </summary>
    public static IServiceCollection AddStellaegisIdentityPages(this IServiceCollection services, Action<IdentityPagesOptions> configure)
    {
        Guard.NotNull(configure);
        services.AddStellaegisOptions(configure);
        return services.AddPages();
    }

    private static IServiceCollection AddPages(this IServiceCollection services)
    {
        Guard.NotNull(services);
        services.AddLocalization();
        services.AddAuthorization();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<CookieSignIn>();
        services.TryAddSingleton<IdentityTexts>();
        services.TryAddSingleton<PagesCulture>();
        services.TryAddSingleton<PendingStates>();
        services.TryAddSingleton<PasswordRules>();
        services.AddRazorPages()
            .AddApplicationPart(typeof(IdentityPagesOptions).Assembly);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<RazorPagesOptions>, IdentityPagesConventions>());
        return services;
    }
}

/// <summary>Maps the pages a person signs in and manages their account with.</summary>
public static class IdentityPagesEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps the Razor Pages of the host, the package's among them — <c>/login</c>, <c>/register</c>,
    /// <c>/forgot-password</c>, <c>/account/…</c> —, and <c>/</c> when <see cref="IdentityPagesOptions.RedirectRoot"/>
    /// says so. It is the host's <c>MapRazorPages</c>: a host does not call both. Refuses to start when the pages
    /// need an <see cref="IIdentityMailer"/> — a registration that is open, a password reset that is enabled — and
    /// the host registered none: better now than at the first person who registers.
    /// </summary>
    public static IEndpointConventionBuilder MapStellaegisIdentityPages(this IEndpointRouteBuilder endpoints)
    {
        Guard.NotNull(endpoints);
        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<IdentityPagesOptions>>().Value;
        var identity = endpoints.ServiceProvider.GetRequiredService<IOptions<IdentityOptions>>().Value;
        if (endpoints.ServiceProvider.GetService<IIdentityMailer>() is null)
        {
            var needs = new List<string>();
            if (identity.SelfRegistration == SelfRegistration.Open)
                needs.Add("the self-registration is open");
            if (options.PasswordResetEnabled)
                needs.Add("the password reset is enabled");
            if (needs.Count > 0)
                throw new InvalidOperationException(
                    $"The identity pages send e-mails — {string.Join(", ", needs)} — and no {nameof(IIdentityMailer)} is registered. "
                    + "Register the host's implementation, services.AddSingleton<IIdentityMailer, YourMailer>(); for development "
                    + "and tests, services.AddStellaegisInMemoryIdentityMailer().");
        }

        var pages = endpoints.MapRazorPages();
        if (options.RedirectRoot)
            endpoints.MapGet("/", (HttpContext http) => Results.LocalRedirect(http.User.Identity?.IsAuthenticated == true ? options.DefaultReturnUrl : IdentityCookie.LoginPath))
                .ExcludeFromDescription();
        return pages;
    }
}

/// <summary>
/// What the package asks of its own pages, and of no other page of the host: the rate limiting policy named in the
/// options, the culture they are read in (<see cref="PagesCulture"/>), and the refusal to be framed by another page.
/// </summary>
internal sealed class IdentityPagesConventions(IOptions<IdentityPagesOptions> options) : IConfigureOptions<RazorPagesOptions>
{
    public void Configure(RazorPagesOptions razorPages)
        => razorPages.Conventions.Add(new PagesConvention(options.Value));

    private sealed class PagesConvention(IdentityPagesOptions options) : IPageApplicationModelConvention
    {
        public void Apply(PageApplicationModel model)
        {
            if (model.PageType.Assembly != typeof(IdentityPagesOptions).Assembly)
                return;
            if (!string.IsNullOrWhiteSpace(options.RateLimitingPolicy))
                model.EndpointMetadata.Add(new EnableRateLimitingAttribute(options.RateLimitingPolicy));
            model.Filters.Add(new CultureFilter());
            model.Filters.Add(new FrameAncestorsFilter());
        }
    }

    /// <summary>
    /// Refuses the pages to any frame: a page of the host or of a third party could otherwise lay one over a decoy and
    /// have the person click, unknowing, "Continue", "Disable" or "Enable". <c>frame-ancestors</c> is appended as a
    /// policy of its own, so that one the host sets stays whole — several policies are all enforced —;
    /// <c>X-Frame-Options</c>, for the browsers that read only it, is set when the host set none.
    /// </summary>
    private sealed class FrameAncestorsFilter : IAsyncResourceFilter
    {
        public Task OnResourceExecutionAsync(ResourceExecutingContext context, ResourceExecutionDelegate next)
        {
            var headers = context.HttpContext.Response.Headers;
            headers.Append("Content-Security-Policy", "frame-ancestors 'none'");
            if (!headers.ContainsKey("X-Frame-Options"))
                headers.XFrameOptions = "DENY";
            return next();
        }
    }

    /// <summary>
    /// Reads the pages in the culture <see cref="PagesCulture"/> resolves: a resource filter, because it wraps the
    /// handler and the rendering of the page alike — a page filter would leave the rendering in the culture of the
    /// request.
    /// </summary>
    private sealed class CultureFilter : IAsyncResourceFilter
    {
        public Task OnResourceExecutionAsync(ResourceExecutingContext context, ResourceExecutionDelegate next)
        {
            if (context.HttpContext.RequestServices.GetRequiredService<PagesCulture>().Resolve(context.HttpContext) is { } culture)
            {
                CultureInfo.CurrentCulture = culture;
                CultureInfo.CurrentUICulture = culture;
            }
            return next();
        }
    }
}
