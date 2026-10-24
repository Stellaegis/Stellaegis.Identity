using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Data;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Identity.PostgreSQL;

/// <summary>Registers the PostgreSQL stores of the accounts.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the PostgreSQL stores of the accounts, their options bound from <paramref name="databaseSectionName"/>,
    /// along with the services of the module and its own options
    /// (<see cref="Identity.ServiceCollectionExtensions.AddStellaegisIdentity(IServiceCollection, IConfiguration, string)"/>,
    /// from <paramref name="identitySectionName"/>). The stores declare their database,
    /// <see cref="IdentityDatabase.Value"/>, which a host verifies at startup under the application's role with
    /// <c>AddStellaegisDatabaseVerification()</c>, and which an installer installs under an administration role.
    /// </summary>
    public static IServiceCollection AddStellaegisIdentityPostgreSQL(
        this IServiceCollection services,
        IConfiguration configuration,
        string databaseSectionName = IdentityDatabaseOptions.SectionName,
        string identitySectionName = IdentityOptions.SectionName)
    {
        Guard.NotNull(configuration);
        Guard.NotWhiteSpace(databaseSectionName);

        services.AddStellaegisOptions<IdentityDatabaseOptions>(configuration, databaseSectionName);
        services.AddStellaegisIdentity(configuration, identitySectionName);
        return services.AddPostgreSqlStores();
    }

    /// <summary>
    /// Registers the PostgreSQL stores of the accounts and the services of the module, their options configured in
    /// code; otherwise as <see cref="AddStellaegisIdentityPostgreSQL(IServiceCollection, IConfiguration, string, string)"/>.
    /// </summary>
    public static IServiceCollection AddStellaegisIdentityPostgreSQL(
        this IServiceCollection services,
        Action<IdentityDatabaseOptions> configureDatabase,
        Action<IdentityOptions> configure)
    {
        Guard.NotNull(configureDatabase);
        Guard.NotNull(configure);

        services.AddStellaegisOptions(configureDatabase);
        services.AddStellaegisIdentity(configure);
        return services.AddPostgreSqlStores();
    }

    private static IServiceCollection AddPostgreSqlStores(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<PostgreSqlIdentityStore>();
        services.TryAddSingleton<IAuthUserStore>(provider => provider.GetRequiredService<PostgreSqlIdentityStore>());
        services.TryAddSingleton<ILoginEventStore>(provider => provider.GetRequiredService<PostgreSqlIdentityStore>());
        services.TryAddSingleton<IAccountTokenStore>(provider => provider.GetRequiredService<PostgreSqlIdentityStore>());
        services.TryAddSingleton<IEmailVerificationStore>(provider => provider.GetRequiredService<PostgreSqlIdentityStore>());
        services.TryAddSingleton<IMfaStore>(provider => provider.GetRequiredService<PostgreSqlIdentityStore>());
        services.TryAddSingleton<IAvatarStore>(provider => provider.GetRequiredService<PostgreSqlIdentityStore>());
        services.TryAddSingleton<IRecoveryCodeStore>(provider => provider.GetRequiredService<PostgreSqlIdentityStore>());
        services.AddStellaegisModuleDatabase(IdentityDatabase.Value,
            (provider, cancellationToken) => provider.GetRequiredService<PostgreSqlIdentityStore>().OpenConnectionAsync(cancellationToken));
        return services;
    }
}
