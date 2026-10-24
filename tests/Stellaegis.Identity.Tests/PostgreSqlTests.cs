using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Npgsql;
using Stellaegis.Identity.PostgreSQL;
using Stellaegis.Primitives.Data;

namespace Stellaegis.Identity.Tests;

/// <summary>The seven stores on PostgreSQL (<see cref="IdentityStoreTests"/>), connected under the application's role.</summary>
[Collection(PostgreSqlCollection.Name)]
public sealed class PostgreSqlStoreTests(PostgreSqlFixture database) : IdentityStoreTests(database)
{
    /// <inheritdoc/>
    protected override ModuleDatabase Declaration => IdentityDatabase.Value;

    /// <inheritdoc/>
    protected override object CreateStore(TimeProvider clock)
        => new PostgreSqlIdentityStore(Options.Create(new IdentityDatabaseOptions { ConnectionString = database.AppConnectionString }), clock);

    /// <inheritdoc/>
    protected override async Task AssertRefusedAsync(Func<Task> write, Refusal refusal)
    {
        var exception = await Assert.ThrowsAsync<PostgresException>(write);
        Assert.Equal(refusal switch
        {
            Refusal.Duplicate => "23505",
            Refusal.MissingAccount => "23503",
            Refusal.Check => "23514",
            _ => "42501",
        }, exception.SqlState);
    }

    [Fact]
    public void The_declaration_runs_on_PostgreSql_with_its_own_script()
    {
        Assert.Equal(DatabaseEngine.PostgreSql, IdentityDatabase.Value.Engine);
        Assert.Equal(["0001_ident.sql"], IdentityDatabase.Value.Scripts.Select(script => script.FileName));
    }
}

/// <summary>A host on the PostgreSQL stores (<see cref="IdentityHostTests"/>), its connection string under the application's role.</summary>
[Collection(PostgreSqlCollection.Name)]
public sealed class PostgreSqlHostTests(PostgreSqlFixture database) : IdentityHostTests(database)
{
    /// <inheritdoc/>
    protected override ModuleDatabase Declaration => IdentityDatabase.Value;

    /// <inheritdoc/>
    protected override string ConnectionStringKey => "Stellaegis:Identity:PostgreSQL:ConnectionString";

    /// <inheritdoc/>
    protected override void AddIdentity(IServiceCollection services, IConfiguration configuration)
        => services.AddStellaegisIdentityPostgreSQL(configuration);

    /// <inheritdoc/>
    protected override void AddIdentity(IServiceCollection services, string connectionString, Action<IdentityOptions> configure)
        => services.AddStellaegisIdentityPostgreSQL(options => options.ConnectionString = connectionString, configure);

    /// <inheritdoc/>
    protected override string RenameRecordSql(bool back) => back
        ? $"alter table {IdentityDatabase.Schema}._schema_migrations_gone rename to _schema_migrations"
        : $"alter table {IdentityDatabase.Value.MigrationsTable} rename to _schema_migrations_gone";
}
