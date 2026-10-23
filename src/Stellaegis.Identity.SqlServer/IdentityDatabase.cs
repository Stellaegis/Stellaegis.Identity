using Stellaegis.Primitives.Data;

namespace Stellaegis.Identity.SqlServer;

/// <summary>
/// The database of the accounts module on SQL Server, as <c>Stellaegis.Primitives.Data</c> installs and verifies
/// it: the schema <c>ident</c> and its numbered scripts embedded in this package, the same tables as on PostgreSQL.
/// No row-level security: the module has no compartment, every row belongs to the application, and the
/// application's role reads them all. No table of an issuer either — the tokens are <c>Stellaegis.Issuer</c>'s, in a schema of its own.
/// </summary>
/// <remarks>
/// Registered by <see cref="ServiceCollectionExtensions.AddStellaegisIdentitySqlServer(Microsoft.Extensions.DependencyInjection.IServiceCollection, Microsoft.Extensions.Configuration.IConfiguration, string, string)"/>,
/// so that a host verifies it at startup under the application's role (<c>AddStellaegisDatabaseVerification</c>).
/// An installer installs it under an administration login: <c>DatabaseLifecycle.InstallAsync([IdentityDatabase.Value], frame, …)</c>.
/// Also the marker of the database for the units of work of the store.
/// </remarks>
public sealed class IdentityDatabase
{
    /// <summary>The schema holding the module's tables, <c>ident</c>.</summary>
    public const string Schema = "ident";

    private IdentityDatabase()
    {
    }

    /// <summary>The declaration of the database.</summary>
    public static ModuleDatabase Value { get; } = ModuleDatabase.SqlServer<IdentityModule>(Schema)
        .WithScripts(SqlScripts.FromResources(typeof(IdentityDatabase).Assembly, "Stellaegis.Identity.SqlServer.Sql.SqlServer"));
}
