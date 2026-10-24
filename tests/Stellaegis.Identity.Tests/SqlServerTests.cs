using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Identity.SqlServer;
using Stellaegis.Primitives.Data;

namespace Stellaegis.Identity.Tests;

/// <summary>
/// The seven stores on SQL Server (<see cref="IdentityStoreTests"/>), in a case-insensitive database, their
/// connections running as the application's user.
/// </summary>
[Collection(SqlServerCollection.Name)]
public sealed class SqlServerStoreTests(SqlServerFixture database) : IdentityStoreTests(database)
{
    /// <inheritdoc/>
    protected override ModuleDatabase Declaration => IdentityDatabase.Value;

    /// <inheritdoc/>
    protected override object CreateStore(TimeProvider clock)
        => new SqlServerIdentityStore(cancellationToken => database.OpenAsync(asApplication: true, cancellationToken), clock);

    /// <inheritdoc/>
    protected override async Task AssertRefusedAsync(Func<Task> write, Refusal refusal)
    {
        var exception = await Assert.ThrowsAsync<SqlException>(write);
        switch (refusal)
        {
            case Refusal.Duplicate:
                Assert.Contains(exception.Number, new[] { 2627, 2601 });   // a key, a unique index
                break;
            case Refusal.MissingAccount:
                Assert.Equal(547, exception.Number);
                Assert.Contains("\"fk_", exception.Message);   // the message speaks the language of the server; the name of the constraint is ours
                break;
            case Refusal.Check:
                Assert.Equal(547, exception.Number);
                Assert.Contains("\"ck_", exception.Message);
                break;
            default:
                Assert.Equal(229, exception.Number);   // the permission was denied
                break;
        }
    }

    [Fact]
    public void An_empty_connection_string_refuses_the_store()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => new SqlServerIdentityStore(
            Microsoft.Extensions.Options.Options.Create(new IdentityDatabaseOptions { ConnectionString = " " }), TimeProvider.System));

        Assert.Contains("ConnectionString is required", exception.Message);
    }

    [Fact]
    public void The_declaration_runs_on_SqlServer_with_its_own_script()
    {
        Assert.Equal(DatabaseEngine.SqlServer, IdentityDatabase.Value.Engine);
        Assert.Equal(["0001_ident.sql"], IdentityDatabase.Value.Scripts.Select(script => script.FileName));
        Assert.Contains("collate Latin1_General_100_BIN2", IdentityDatabase.Value.Scripts[0].Sql);
    }
}

/// <summary>
/// A host on the SQL Server stores (<see cref="IdentityHostTests"/>): configured with the login of the variable, its
/// store — and so the verification at startup — connecting as the application's user.
/// </summary>
[Collection(SqlServerCollection.Name)]
public sealed class SqlServerHostTests(SqlServerFixture database) : IdentityHostTests(database)
{
    /// <inheritdoc/>
    protected override ModuleDatabase Declaration => IdentityDatabase.Value;

    /// <inheritdoc/>
    protected override string ConnectionStringKey => "Stellaegis:Identity:SqlServer:ConnectionString";

    /// <inheritdoc/>
    protected override void AddIdentity(IServiceCollection services, IConfiguration configuration)
        => services.AddStellaegisIdentitySqlServer(configuration);

    /// <inheritdoc/>
    protected override void AddIdentity(IServiceCollection services, string connectionString, Action<IdentityOptions> configure)
        => services.AddStellaegisIdentitySqlServer(options => options.ConnectionString = connectionString, configure);

    /// <inheritdoc/>
    protected override void UnderApplicationRole(IServiceCollection services)
        => services.AddSingleton(provider => new SqlServerIdentityStore(
            cancellationToken => database.OpenAsync(asApplication: true, cancellationToken), provider.GetRequiredService<TimeProvider>()));

    /// <inheritdoc/>
    protected override string RenameRecordSql(bool back) => back
        ? $"exec sp_rename N'{IdentityDatabase.Schema}._schema_migrations_gone', N'_schema_migrations'"
        : $"exec sp_rename N'{IdentityDatabase.Value.MigrationsTable}', N'_schema_migrations_gone'";
}
