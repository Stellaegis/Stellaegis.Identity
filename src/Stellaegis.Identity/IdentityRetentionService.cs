using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>What a purge removed: the attempts of the trace, the tokens, the verifications.</summary>
/// <param name="LoginEvents">The login attempts older than the retention.</param>
/// <param name="Tokens">The account tokens expired longer than the retention.</param>
/// <param name="Verifications">The e-mail verifications expired longer than the retention.</param>
public sealed record RetentionReport(int LoginEvents, int Tokens, int Verifications);

/// <summary>
/// Removes what identifies a person once it no longer serves, by the durations of
/// <see cref="IdentityOptions.Retention"/>: the trace of the logins — an address, a browser —, and the tokens and
/// verifications past their expiry. The module schedules nothing: the host runs it, every day, by its own scheduler —
/// a job of <c>Stellaegis.Operations</c>, for one — under an actor that names it, <c>job:identity_purge</c>. Run
/// again, it removes what came due since.
/// </summary>
public sealed class IdentityRetentionService(
    ILoginEventStore loginEvents,
    IAccountTokenStore tokens,
    IEmailVerificationStore verifications,
    IOptions<IdentityOptions> options,
    TimeProvider clock,
    ILogger<IdentityRetentionService> logger)
{
    /// <summary>The actor a scheduled purge runs under, <c>job:identity_purge</c>.</summary>
    public static Actor Job { get; } = Actor.Job("identity_purge");

    /// <summary>Removes what came due, and says how much, under <paramref name="actor"/>, which the log names.</summary>
    public async Task<RetentionReport> PurgeAsync(Actor actor, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(actor);
        var retention = options.Value.Retention;
        var now = clock.GetUtcNow();
        var report = new RetentionReport(
            await loginEvents.DeleteBeforeAsync(now - retention.LoginEvents, cancellationToken),
            await tokens.DeleteExpiredBeforeAsync(now - retention.Expired, cancellationToken),
            await verifications.DeleteExpiredBeforeAsync(now - retention.Expired, cancellationToken));
        logger.LogInformation(
            "Identity purge by {Actor}: {LoginEvents} login attempts, {Tokens} tokens, {Verifications} verifications",
            actor, report.LoginEvents, report.Tokens, report.Verifications);
        return report;
    }
}
