using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Stellaegis.Identity.AspNetCore;
using Stellaegis.Primitives;

namespace Stellaegis.Identity.Sample;

/// <summary>The frame of the example: one compartment, the company whose people the accounts are.</summary>
public static class SampleFrame
{
    public static readonly Compartment Company = Compartment.Parse("acme");

    public static readonly ApplicationFrame Value = ApplicationFrame.SingleCompartment(Company);
}

/// <summary>
/// The mailer of the example: what the pages ask to send goes to the log, where a developer reads the code or
/// the link. A real host implements <see cref="IIdentityMailer"/> on its messaging, with its own wording.
/// </summary>
public sealed class LoggingMailer(ILogger<LoggingMailer> logger) : IIdentityMailer
{
    public Task SendVerificationCodeAsync(string email, string code, TimeSpan lifetime, CancellationToken cancellationToken = default)
    {
        logger.LogWarning("MAIL to {Email}: your verification code is {Code}, valid for {Lifetime}", email, code, lifetime);
        return Task.CompletedTask;
    }

    public Task SendLoginCodeAsync(string email, string code, TimeSpan lifetime, CancellationToken cancellationToken = default)
    {
        logger.LogWarning("MAIL to {Email}: your login code is {Code}, valid for {Lifetime}", email, code, lifetime);
        return Task.CompletedTask;
    }

    public Task SendPasswordResetLinkAsync(string email, Uri link, TimeSpan lifetime, CancellationToken cancellationToken = default)
    {
        logger.LogWarning("MAIL to {Email}: reset your password at {Link}, valid for {Lifetime}", email, link, lifetime);
        return Task.CompletedTask;
    }

    public Task SendActivationLinkAsync(string email, Uri link, TimeSpan lifetime, CancellationToken cancellationToken = default)
    {
        logger.LogWarning("MAIL to {Email}: activate your account at {Link}, valid for {Lifetime}", email, link, lifetime);
        return Task.CompletedTask;
    }

    public Task SendAccountAlreadyExistsAsync(string email, CancellationToken cancellationToken = default)
    {
        logger.LogWarning("MAIL to {Email}: someone tried to register this address, which has an account already", email);
        return Task.CompletedTask;
    }

    public Task SendEmailChangedAsync(string previousEmail, string newEmail, Uri revertLink, TimeSpan lifetime, CancellationToken cancellationToken = default)
    {
        logger.LogWarning("MAIL to {Email}: the e-mail of your account is now {NewEmail}; if this was not you, restore it at {Link}, valid for {Lifetime}", previousEmail, newEmail, revertLink, lifetime);
        return Task.CompletedTask;
    }

    public Task SendAccountLockedAsync(string email, DateTimeOffset until, CancellationToken cancellationToken = default)
    {
        logger.LogWarning("MAIL to {Email}: your account is locked until {Until} after too many failed attempts", email, until);
        return Task.CompletedTask;
    }
}

/// <summary>
/// The bus of the example: a single process, so an event is handed to its one subscriber straight away — a block
/// or an unblock applies to the admission without waiting for its next reading. A host with several processes
/// registers the bus of <c>Stellaegis.Backplane</c> instead, and subscribes the same way.
/// </summary>
public sealed class AdmissionEventPublisher(BlockedAccounts accounts, ILogger<AdmissionEventPublisher> logger) : IEventPublisher
{
    public Task PublishAsync<TEvent>(TEvent @event, CancellationToken cancellationToken = default) where TEvent : IEvent
    {
        switch (@event)
        {
            case UserBlockedEvent blocked:
                accounts.Block(blocked.UserUniqueId);
                break;
            case UserUnblockedEvent unblocked:
                accounts.Unblock(unblocked.UserUniqueId);
                break;
        }
        logger.LogInformation("Event {Event}", @event);
        return Task.CompletedTask;
    }
}

/// <summary>
/// Who may administer the accounts, in the example: the people whose e-mail is listed in
/// <c>Sample:Administrators</c>, granted every operation of the module. A real host answers each policy from its
/// rights system — <c>Stellaegis.Access</c> —, by actor, space and operation.
/// </summary>
public static class SampleAdministrators
{
    public static IServiceCollection AddSampleAdministrators(this IServiceCollection services, IConfiguration configuration)
    {
        var administrators = configuration.GetSection("Sample:Administrators").Get<string[]>() ?? [];
        services.AddAuthorization(options =>
        {
            foreach (var operation in IdentityOperations.All)
            {
                options.AddPolicy(operation.ToString(), policy => policy
                    .RequireAuthenticatedUser()
                    .RequireAssertion(context => IsAdministrator(context.User, administrators)));
            }
        });
        return services;
    }

    private static bool IsAdministrator(ClaimsPrincipal user, string[] administrators)
    {
        var email = user.FindFirstValue("email") ?? user.FindFirstValue(ClaimTypes.Email);
        return email is not null && administrators.Contains(email, StringComparer.OrdinalIgnoreCase);
    }
}
