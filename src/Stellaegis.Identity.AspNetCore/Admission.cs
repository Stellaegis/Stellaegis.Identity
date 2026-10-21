using System.Collections.Concurrent;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Identity.AspNetCore;

/// <summary>
/// The options of the admission on a resource server, bound from <c>Stellaegis:Identity:Admission</c>: how often
/// the blocked accounts are read again from their source.
/// <code>
/// Stellaegis:Identity:Admission:ReconcileInterval = 00:02:00
/// </code>
/// </summary>
public sealed class IdentityAdmissionOptions : IValidatableOptions
{
    /// <summary>The configuration section of the options, <c>Stellaegis:Identity:Admission</c>.</summary>
    public const string SectionName = "Stellaegis:Identity:Admission";

    /// <summary>
    /// How often the blocked accounts are read again from <see cref="IBlockedUsersSource"/>, after the reading at
    /// startup: the safety net for an event lost between the host and the accounts. Two minutes unless set;
    /// <see cref="TimeSpan.Zero"/> reads once, at startup.
    /// </summary>
    public TimeSpan ReconcileInterval { get; set; } = TimeSpan.FromMinutes(2);

    /// <inheritdoc/>
    public string? FindError() => ReconcileInterval < TimeSpan.Zero ? $"{nameof(ReconcileInterval)} is zero or positive." : null;
}

/// <summary>
/// The accounts blocked at the door, as a resource server keeps them in memory to refuse their subjects on every
/// request without a round trip. Filled from <see cref="IBlockedUsersSource"/> when the host starts and then
/// periodically (<see cref="IdentityAdmissionOptions.ReconcileInterval"/>); kept current in between by the host,
/// which calls <see cref="Block(string)"/> and <see cref="Unblock(string)"/> from its subscriptions to
/// <see cref="UserBlockedEvent"/> and <see cref="UserUnblockedEvent"/> — the module subscribes to nothing, the
/// host connects its bus.
/// </summary>
public sealed class BlockedAccounts
{
    private volatile ConcurrentDictionary<string, byte> _blocked = new(StringComparer.Ordinal);

    /// <summary>Whether the subject — the <c>sub</c> claim, the id in the <c>N</c> format — is blocked at the door.</summary>
    public bool IsBlocked(string subject) => !string.IsNullOrWhiteSpace(subject) && _blocked.ContainsKey(subject);

    /// <summary>Refuses the subject from now on, until <see cref="Unblock(string)"/> or a reading that no longer lists it.</summary>
    public void Block(string subject) => _blocked.TryAdd(Guard.NotWhiteSpace(subject), 0);

    /// <summary>Refuses the account from now on, by its id.</summary>
    public void Block(Guid userUniqueId) => Block(userUniqueId.ToString("N"));

    /// <summary>Admits the subject again.</summary>
    public void Unblock(string subject) => _blocked.TryRemove(Guard.NotWhiteSpace(subject), out _);

    /// <summary>Admits the account again, by its id.</summary>
    public void Unblock(Guid userUniqueId) => Unblock(userUniqueId.ToString("N"));

    /// <summary>Replaces every subject by <paramref name="subjects"/>, in one move: what a reading of the source does.</summary>
    public void Replace(IEnumerable<string> subjects)
    {
        Guard.NotNull(subjects);
        var replacement = new ConcurrentDictionary<string, byte>(StringComparer.Ordinal);
        foreach (var subject in subjects)
        {
            if (!string.IsNullOrWhiteSpace(subject))
                replacement.TryAdd(subject, 0);
        }
        _blocked = replacement;
    }

    /// <summary>The subjects blocked, as a snapshot.</summary>
    public IReadOnlyCollection<string> Subjects => _blocked.Keys.ToList();
}

/// <summary>
/// Reads the blocked accounts from their source when the host starts — a restarted host would otherwise admit
/// everyone until the first event —, then every <see cref="IdentityAdmissionOptions.ReconcileInterval"/>. A source
/// out of reach is logged as critical and tried again at the next interval: the host keeps serving, with the
/// subjects it knows, rather than stopping for a dependency that is down.
/// </summary>
internal sealed class BlockedAccountsReconciliation(
    IServiceProvider services,
    BlockedAccounts accounts,
    IOptions<IdentityAdmissionOptions> options,
    ILogger<BlockedAccountsReconciliation> logger) : IHostedService, IAsyncDisposable
{
    private CancellationTokenSource? _loopCancellation;
    private Task? _loop;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using (var scope = services.CreateScope())
        {
            if (scope.ServiceProvider.GetService<IBlockedUsersSource>() is null)
            {
                throw new InvalidOperationException(
                    "The admission of actors is registered, and no source of the blocked accounts is: nothing would ever be refused. "
                    + "Register the local source on a host that holds the accounts, AddStellaegisLocalBlockedUsersSource(), "
                    + "or the HTTP source of Stellaegis.Identity.Client on a resource server apart, AddStellaegisIdentityClient(...).");
            }
        }

        await ReadAsync(atStartup: true, cancellationToken).ConfigureAwait(false);
        var interval = options.Value.ReconcileInterval;
        if (interval > TimeSpan.Zero)
        {
            _loopCancellation = new CancellationTokenSource();
            _loop = LoopAsync(interval, _loopCancellation.Token);
        }
    }

    private async Task LoopAsync(TimeSpan interval, CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(interval);
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
                await ReadAsync(atStartup: false, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // The host stops.
        }
    }

    internal async Task ReadAsync(bool atStartup, CancellationToken cancellationToken)
    {
        try
        {
            using var scope = services.CreateScope();
            var source = scope.ServiceProvider.GetRequiredService<IBlockedUsersSource>();
            var subjects = await source.GetBlockedSubjectsAsync(cancellationToken).ConfigureAwait(false);
            accounts.Replace(subjects);
            if (atStartup)
                logger.LogInformation("Blocked accounts read at startup: {Count}", subjects.Count);
            else
                logger.LogDebug("Blocked accounts read again: {Count}", subjects.Count);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The host stops.
        }
        catch (Exception exception)
        {
            logger.LogCritical(exception,
                "The blocked accounts could not be read: an account blocked since the last reading is admitted until the next one succeeds.");
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_loopCancellation is not null)
            await _loopCancellation.CancelAsync().ConfigureAwait(false);
        if (_loop is not null)
        {
            try
            {
                await _loop.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Best effort while stopping.
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_loopCancellation is not null)
        {
            await _loopCancellation.CancelAsync().ConfigureAwait(false);
            _loopCancellation.Dispose();
        }
    }
}

/// <summary>
/// Refuses, with 401 and the code <see cref="IdentityErrors.AccountBlockedCode"/>, a request whose authenticated
/// subject is blocked at the door — whatever its token or its cookie says. Runs after the authentication and
/// before the authorization.
/// </summary>
internal sealed class IdentityAdmissionMiddleware(RequestDelegate next, BlockedAccounts accounts, ILogger<IdentityAdmissionMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext httpContext)
    {
        if (Callers.SubjectOf(httpContext.User) is { } subject && accounts.IsBlocked(subject))
        {
            logger.LogWarning("Request of the blocked subject {Subject} refused on {Path}", subject, httpContext.Request.Path);
            httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await httpContext.Response.WriteAsJsonAsync(IdentityErrors.AccountBlocked.ToProblemDetails(), httpContext.RequestAborted).ConfigureAwait(false);
            return;
        }
        await next(httpContext).ConfigureAwait(false);
    }
}

/// <summary>Registers and enables the admission of actors on a resource server.</summary>
public static class AdmissionExtensions
{
    /// <summary>
    /// Registers the admission of actors: the blocked accounts kept in memory, read from
    /// <see cref="IBlockedUsersSource"/> at startup and then periodically, and its options bound from
    /// <paramref name="sectionName"/>. The host registers the source that fits it — local or HTTP —, enables the
    /// middleware with <see cref="UseStellaegisIdentityAdmission"/>, and connects its bus to
    /// <see cref="BlockedAccounts"/> so that a block applies without waiting for the next reading.
    /// </summary>
    public static IServiceCollection AddStellaegisIdentityAdmission(this IServiceCollection services, IConfiguration configuration, string sectionName = IdentityAdmissionOptions.SectionName)
    {
        Guard.NotNull(services);
        Guard.NotNull(configuration);
        services.AddStellaegisOptions<IdentityAdmissionOptions>(configuration, sectionName);
        return Admission(services);
    }

    /// <summary>
    /// Registers the admission of actors as <see cref="AddStellaegisIdentityAdmission(IServiceCollection, IConfiguration, string)"/>
    /// does, with its options configured in code — the defaults unless <paramref name="configure"/> changes them.
    /// </summary>
    public static IServiceCollection AddStellaegisIdentityAdmission(this IServiceCollection services, Action<IdentityAdmissionOptions>? configure = null)
    {
        Guard.NotNull(services);
        services.AddStellaegisOptions<IdentityAdmissionOptions>(configure ?? (_ => { }));
        return Admission(services);
    }

    private static IServiceCollection Admission(IServiceCollection services)
    {
        services.TryAddSingleton<BlockedAccounts>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, BlockedAccountsReconciliation>());
        return services;
    }

    /// <summary>
    /// Refuses the requests of the subjects blocked at the door. Call it after <c>UseAuthentication()</c>, so that
    /// the subject is known, and before <c>UseAuthorization()</c>.
    /// </summary>
    public static IApplicationBuilder UseStellaegisIdentityAdmission(this IApplicationBuilder app)
    {
        Guard.NotNull(app);
        if (app.ApplicationServices.GetService<BlockedAccounts>() is null)
        {
            throw new InvalidOperationException(
                "The admission of actors is enabled, and nothing registered it: call AddStellaegisIdentityAdmission(...) before building the host.");
        }
        return app.UseMiddleware<IdentityAdmissionMiddleware>();
    }
}
