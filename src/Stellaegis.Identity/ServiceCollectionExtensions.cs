using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Stellaegis.Identity.InMemory;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Identity;

/// <summary>Registers the accounts module.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the services of the accounts — login, registration, account, password reset, e-mail verification,
    /// second factor, recovery codes, administration —, their options bound from <paramref name="sectionName"/>
    /// and validated when the host starts, and declares the module to the application. The stores come from an
    /// adapter: <see cref="AddStellaegisIdentityInMemory(IServiceCollection, IConfiguration, string)"/>, or
    /// <c>Stellaegis.Identity.PostgreSQL</c>, which call this. Events go to the registered
    /// <see cref="IEventPublisher"/>, or nowhere when the host registers none.
    /// </summary>
    public static IServiceCollection AddStellaegisIdentity(this IServiceCollection services, IConfiguration configuration, string sectionName = IdentityOptions.SectionName)
    {
        Guard.NotNull(configuration);
        Guard.NotWhiteSpace(sectionName);
        services.AddStellaegisOptions<IdentityOptions>(configuration, sectionName);
        return services.AddIdentityServices();
    }

    /// <summary>
    /// Registers the services of the accounts, their options configured in code; otherwise as
    /// <see cref="AddStellaegisIdentity(IServiceCollection, IConfiguration, string)"/>.
    /// </summary>
    public static IServiceCollection AddStellaegisIdentity(this IServiceCollection services, Action<IdentityOptions> configure)
    {
        Guard.NotNull(configure);
        services.AddStellaegisOptions(configure);
        return services.AddIdentityServices();
    }

    /// <summary>
    /// Registers the in-memory stores along with the services of the accounts, their options bound from
    /// <paramref name="sectionName"/>. For development and tests only: the accounts are lost with the process.
    /// </summary>
    public static IServiceCollection AddStellaegisIdentityInMemory(this IServiceCollection services, IConfiguration configuration, string sectionName = IdentityOptions.SectionName)
        => services.AddInMemoryStores().AddStellaegisIdentity(configuration, sectionName);

    /// <summary>
    /// Registers the in-memory stores along with the services of the accounts, their options configured in code.
    /// For development and tests only.
    /// </summary>
    public static IServiceCollection AddStellaegisIdentityInMemory(this IServiceCollection services, Action<IdentityOptions> configure)
        => services.AddInMemoryStores().AddStellaegisIdentity(configure);

    /// <summary>
    /// Registers the local source of blocked accounts, read from the <see cref="IAuthUserStore"/> of this host, for
    /// a resource server that holds the accounts. A resource server apart uses the HTTP source of
    /// <c>Stellaegis.Identity.Client</c> instead.
    /// </summary>
    public static IServiceCollection AddStellaegisLocalBlockedUsersSource(this IServiceCollection services)
    {
        Guard.NotNull(services);
        services.TryAddScoped<IBlockedUsersSource, LocalBlockedUsersSource>();
        return services;
    }

    /// <summary>
    /// Registers the mailer that keeps what it is asked to send, <see cref="InMemoryIdentityMailer"/>, for
    /// development and tests: nothing leaves the process. A host implements <see cref="IIdentityMailer"/> on its
    /// own messaging instead. Not registered by the in-memory stores, so that a host does not start on it by
    /// mistake.
    /// </summary>
    public static IServiceCollection AddStellaegisInMemoryIdentityMailer(this IServiceCollection services)
    {
        Guard.NotNull(services);
        services.TryAddSingleton<InMemoryIdentityMailer>();
        services.TryAddSingleton<IIdentityMailer>(provider => provider.GetRequiredService<InMemoryIdentityMailer>());
        return services;
    }

    private static IServiceCollection AddInMemoryStores(this IServiceCollection services)
    {
        Guard.NotNull(services);
        services.TryAddSingleton<InMemoryIdentityData>();
        services.TryAddSingleton<IAuthUserStore, InMemoryAuthUserStore>();
        services.TryAddSingleton<ILoginEventStore, InMemoryLoginEventStore>();
        services.TryAddSingleton<IAccountTokenStore, InMemoryAccountTokenStore>();
        services.TryAddSingleton<IEmailVerificationStore, InMemoryEmailVerificationStore>();
        services.TryAddSingleton<IMfaStore, InMemoryMfaStore>();
        services.TryAddSingleton<IAvatarStore, InMemoryAvatarStore>();
        services.TryAddSingleton<IRecoveryCodeStore, InMemoryRecoveryCodeStore>();
        return services;
    }

    private static IServiceCollection AddIdentityServices(this IServiceCollection services)
    {
        services.AddStellaegisIdentityModule();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IEventPublisher>(NullEventPublisher.Instance);
        services.TryAddSingleton<PasswordHasher>();
        services.TryAddSingleton<TotpSecretProtector>();
        services.TryAddSingleton<PasswordStrengthEvaluator>();
        services.TryAddSingleton<PasswordGenerator>();
        services.TryAddSingleton<LoginOtpService>();
        services.TryAddScoped<LoginService>();
        services.TryAddScoped<RegistrationService>();
        services.TryAddScoped<AccountService>();
        services.TryAddScoped<ProfileService>();
        services.TryAddScoped<AccountAdministrationService>();
        services.TryAddScoped<PasswordResetService>();
        services.TryAddScoped<ActivationService>();
        services.TryAddScoped<IdentityRetentionService>();
        services.TryAddScoped<EmailVerificationService>();
        services.TryAddScoped<MfaService>();
        services.TryAddScoped<RecoveryCodeService>();
        return services;
    }
}
