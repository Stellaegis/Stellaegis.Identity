using System.Data.Common;
using Microsoft.Data.SqlClient;
using Stellaegis.Identity.SqlServer;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Data;

namespace Stellaegis.Identity.Tests;

/// <summary>The classes of the collection share one installed schema, and never run in parallel with one another.</summary>
[CollectionDefinition(SqlServerCollection.Name)]
public sealed class SqlServerCollection : ICollectionFixture<SqlServerFixture>
{
    /// <summary>The name of the collection.</summary>
    public const string Name = "SQL Server";
}

/// <summary>
/// A dedicated SQL Server database for the store tests, named by <c>STELLAEGIS_TEST_SQLSERVER</c> — the server the
/// family's tests use, under a login that may create databases — and skipped without it. The database
/// <c>stellaegis_identity_tests</c> is created at every run, with a case-insensitive collation as an installation
/// would choose, and dropped after: its <c>ident</c> schema is installed by the installation of the module, and the
/// application is the user <c>stellaegis_identity_probe</c>, without login, member of the role the installation
/// created. Its connections take that identity by <c>EXECUTE AS USER</c>, so that an instance accepting
/// integrated security only runs the tests.
/// </summary>
public sealed class SqlServerFixture : IIdentityDatabaseFixture
{
    private const string Variable = "STELLAEGIS_TEST_SQLSERVER";
    private const string Database = "stellaegis_identity_tests";
    private const string AppRole = "stellaegis_identity_app";
    private const string AppUser = "stellaegis_identity_probe";

    private string _server = string.Empty;

    /// <summary>The connection string of the installer, which owns the schema; empty without the variable.</summary>
    public string AdminConnectionString { get; private set; } = string.Empty;

    /// <inheritdoc/>
    /// <remarks>The login of the variable, without pooling: <see cref="OpenAsync"/> makes it the application.</remarks>
    public string AppConnectionString => AdminConnectionString;

    /// <inheritdoc/>
    public string? Unavailable { get; private set; }

    /// <inheritdoc/>
    public void SkipWhenUnavailable() => Assert.SkipWhen(Unavailable is not null, Unavailable ?? string.Empty);

    /// <inheritdoc/>
    public async ValueTask InitializeAsync()
    {
        var configured = Environment.GetEnvironmentVariable(Variable);
        if (string.IsNullOrWhiteSpace(configured))
        {
            Unavailable = $"{Variable} is not set.";
            return;
        }

        // No pooling: a connection that took the identity of the application must not serve the installer.
        _server = new SqlConnectionStringBuilder(configured) { InitialCatalog = "master", Pooling = false }.ConnectionString;
        AdminConnectionString = new SqlConnectionStringBuilder(_server) { InitialCatalog = Database }.ConnectionString;

        try
        {
            await DropAsync();
            await using (var connection = new SqlConnection(_server))
            {
                await connection.OpenAsync();
                await ExecuteAsync(connection, $"create database [{Database}] collate French_100_CI_AS");
            }
            await using (var connection = new SqlConnection(AdminConnectionString))
            {
                await connection.OpenAsync();
                await ExecuteAsync(connection, $"create user [{AppUser}] without login");
            }

            await DatabaseLifecycle.InstallAsync([IdentityDatabase.Value], IdentityStoreTests.Frame, (_, ct) => OpenAsync(asApplication: false, ct), AppRole, Actor.Job("tests"));
            await using (var connection = new SqlConnection(AdminConnectionString))
            {
                await connection.OpenAsync();
                await ExecuteAsync(connection, $"alter role [{AppRole}] add member [{AppUser}]");
            }
        }
        catch (SqlException e)
        {
            Unavailable = $"No SQL Server for the store tests ({Variable} = '{configured}'): {e.Message}";
        }
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (Unavailable is null && _server.Length > 0)
            await DropAsync();
    }

    /// <inheritdoc/>
    public async Task<DbConnection> OpenAsync(bool asApplication, CancellationToken cancellationToken)
    {
        var connection = new SqlConnection(AdminConnectionString);
        await connection.OpenAsync(cancellationToken);
        if (asApplication)
            await ExecuteAsync(connection, $"execute as user = N'{AppUser}'", cancellationToken);
        return connection;
    }

    private async Task DropAsync()
    {
        await using var connection = new SqlConnection(_server);
        await connection.OpenAsync();
        await ExecuteAsync(connection, $"""
            if db_id(N'{Database}') is not null
            begin
              alter database [{Database}] set single_user with rollback immediate;
              drop database [{Database}];
            end
            """);
    }

    private static async Task ExecuteAsync(DbConnection connection, string sql, CancellationToken cancellationToken = default)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
