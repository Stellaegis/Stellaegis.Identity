using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Data;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Identity.SqlServer;

/// <summary>Registers the SQL Server stores of the accounts.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the SQL Server stores of the accounts, their options bound from <paramref name="databaseSectionName"/>,
    /// along with the services of the module and its own options
    /// (<see cref="Identity.ServiceCollectionExtensions.AddStellaegisIdentity(IServiceCollection, IConfiguration, string)"/>,
    /// from <paramref name="identitySectionName"/>). The stores declare their database,
    /// <see cref="IdentityDatabase.Value"/>, which a host verifies at startup under the application's role with
    /// <c>AddStellaegisDatabaseVerification()</c>, and which an installer installs under an administration login.
    /// </summary>
    public static IServiceCollection AddStellaegisIdentitySqlServer(
        this IServiceCollection services,
        IConfiguration configuration,
        string databaseSectionName = IdentityDatabaseOptions.SectionName,
        string identitySectionName = IdentityOptions.SectionName)
    {
        Guard.NotNull(configuration);
        Guard.NotWhiteSpace(databaseSectionName);

        services.AddStellaegisOptions<IdentityDatabaseOptions>(configuration, databaseSectionName);
        services.AddStellaegisIdentity(configuration, identitySectionName);
        return services.AddSqlServerStores();
    }

    /// <summary>
    /// Registers the SQL Server stores of the accounts and the services of the module, their options configured in
    /// code; otherwise as <see cref="AddStellaegisIdentitySqlServer(IServiceCollection, IConfiguration, string, string)"/>.
    /// </summary>
    public static IServiceCollection AddStellaegisIdentitySqlServer(
        this IServiceCollection services,
        Action<IdentityDatabaseOptions> configureDatabase,
        Action<IdentityOptions> configure)
    {
        Guard.NotNull(configureDatabase);
        Guard.NotNull(configure);

        services.AddStellaegisOptions(configureDatabase);
        services.AddStellaegisIdentity(configure);
        return services.AddSqlServerStores();
    }

    private static IServiceCollection AddSqlServerStores(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<SqlServerIdentityStore>();
        services.TryAddSingleton<IAuthUserStore>(provider => provider.GetRequiredService<SqlServerIdentityStore>());
        services.TryAddSingleton<ILoginEventStore>(provider => provider.GetRequiredService<SqlServerIdentityStore>());
        services.TryAddSingleton<IAccountTokenStore>(provider => provider.GetRequiredService<SqlServerIdentityStore>());
        services.TryAddSingleton<IEmailVerificationStore>(provider => provider.GetRequiredService<SqlServerIdentityStore>());
        services.TryAddSingleton<IMfaStore>(provider => provider.GetRequiredService<SqlServerIdentityStore>());
        services.TryAddSingleton<IRecoveryCodeStore>(provider => provider.GetRequiredService<SqlServerIdentityStore>());
        services.AddStellaegisModuleDatabase(IdentityDatabase.Value,
            (provider, cancellationToken) => provider.GetRequiredService<SqlServerIdentityStore>().OpenConnectionAsync(cancellationToken));
        return services;
    }
}
