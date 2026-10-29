using System.Globalization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Stellaegis.Identity.Server;

/// <summary>
/// What a page gives the rate limiting of the package beyond the address of the client: the e-mail its form names,
/// when it names one — the one the person signs in as, registers with, asks a code or a link for.
/// </summary>
internal interface INamesAnEmail
{
    /// <summary>The e-mail the request is about, as typed, or <see langword="null"/> when the form names none.</summary>
    string? NamedEmail { get; }
}

/// <summary>Marks a page whose POSTs the rate limiting of the package leaves alone: choosing a language.</summary>
[AttributeUsage(AttributeTargets.Class)]
internal sealed class NotRateLimitedAttribute : Attribute;

/// <summary>
/// The rate limiting the package applies to its own pages, whatever the host set up. Every POST counts against the
/// address of the client, and against the e-mail the form names when it names one — a sliding window each, of
/// <see cref="PagesRateLimitingOptions"/>. Two windows, because each catches what the other cannot: behind a proxy
/// without <c>ForwardedHeaders</c> every client has the address of the proxy, and the e-mail still tells the targets
/// apart; and the address alone stops a client that tries many e-mails.
/// </summary>
internal sealed class PagesRateLimiter : IDisposable
{
    private readonly PartitionedRateLimiter<string> _byClient;
    private readonly PartitionedRateLimiter<string> _byEmail;
    private readonly TimeSpan _window;

    public PagesRateLimiter(IOptions<IdentityPagesOptions> options)
    {
        var settings = options.Value.RateLimiting;
        _window = settings.Window;
        _byClient = Create(settings.RequestsPerClient, settings.Window);
        _byEmail = Create(settings.RequestsPerEmail, settings.Window);
    }

    /// <summary>
    /// Takes one request of <paramref name="client"/>, and one for <paramref name="email"/> when the form names one:
    /// <see langword="false"/> when either is over its limit, with <paramref name="retryAfter"/> the time until a
    /// request is taken again.
    /// </summary>
    public bool TryAcquire(string client, string? email, out TimeSpan retryAfter)
    {
        using var byClient = _byClient.AttemptAcquire(client);
        if (!byClient.IsAcquired)
        {
            retryAfter = RetryAfter(byClient);
            return false;
        }
        if (email is null)
        {
            retryAfter = TimeSpan.Zero;
            return true;
        }
        using var byEmail = _byEmail.AttemptAcquire(email);
        if (!byEmail.IsAcquired)
        {
            retryAfter = RetryAfter(byEmail);
            return false;
        }
        retryAfter = TimeSpan.Zero;
        return true;
    }

    public void Dispose()
    {
        _byClient.Dispose();
        _byEmail.Dispose();
    }

    // A window of six segments: a permit frees ten seconds at a time on a window of a minute, rather than all at
    // once at its end. Nothing queues: a request over the limit is refused, not delayed.
    private static PartitionedRateLimiter<string> Create(int permits, TimeSpan window)
        => PartitionedRateLimiter.Create<string, string>(key => RateLimitPartition.GetSlidingWindowLimiter(key, _ => new SlidingWindowRateLimiterOptions
        {
            PermitLimit = permits,
            Window = window,
            SegmentsPerWindow = 6,
            QueueLimit = 0,
            AutoReplenishment = true,
        }));

    private TimeSpan RetryAfter(RateLimitLease lease)
        => lease.TryGetMetadata(MetadataName.RetryAfter, out var after) && after > TimeSpan.Zero ? after : _window;
}

/// <summary>
/// Counts the POSTs of a page of the package, and refuses the ones over the limit: the page again, with the seconds
/// to wait and nothing tried, status 429 and <c>Retry-After</c>. A GET costs nothing and is never counted.
/// </summary>
internal sealed class RateLimitFilter : IAsyncPageFilter
{
    public Task OnPageHandlerSelectionAsync(PageHandlerSelectedContext context) => Task.CompletedTask;

    public Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
    {
        var http = context.HttpContext;
        if (!HttpMethods.IsPost(http.Request.Method) || context.HandlerInstance?.GetType().IsDefined(typeof(NotRateLimitedAttribute), inherit: false) == true)
            return next();

        var client = http.Connection.RemoteIpAddress?.ToString() ?? "";
        var email = (context.HandlerInstance as INamesAnEmail)?.NamedEmail is { } named && !string.IsNullOrWhiteSpace(named)
            ? Emails.Normalize(named)
            : null;
        if (http.RequestServices.GetRequiredService<PagesRateLimiter>().TryAcquire(client, email, out var retryAfter))
            return next();

        var seconds = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds));
        http.Response.Headers.RetryAfter = seconds.ToString(CultureInfo.InvariantCulture);
        context.ModelState.AddModelError(string.Empty, http.RequestServices.GetRequiredService<IdentityTexts>().Format("Pages.TooManyRequests", seconds));
        context.Result = new PageResult { StatusCode = StatusCodes.Status429TooManyRequests };
        return Task.CompletedTask;
    }
}
