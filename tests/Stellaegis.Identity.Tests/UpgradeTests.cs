using System.Data.Common;
using Microsoft.Data.SqlClient;
using Npgsql;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Data;
using PostgreSqlDatabase = Stellaegis.Identity.PostgreSQL.IdentityDatabase;
using SqlServerDatabase = Stellaegis.Identity.SqlServer.IdentityDatabase;

namespace Stellaegis.Identity.Tests;

/// <summary>
/// A database installed by Identity 7 — the script 0001 alone — takes the scripts 0002 and 0003 by running the
/// installation again, as an installer upgrading does, and refuses the application until it has. Each engine in a database of its
/// own, created and dropped by the test, so that the schema the store tests share is never touched.
/// </summary>
public abstract class UpgradeTests
{
    /// <summary>The variable naming the server; the test is skipped without it.</summary>
    protected abstract string Variable { get; }

    /// <summary>The full declaration of the engine, every script of the package.</summary>
    protected abstract ModuleDatabase Declaration { get; }

    /// <summary>The same declaration, as Identity 7 shipped it: the script 0001 alone.</summary>
    protected abstract ModuleDatabase Version7 { get; }

    /// <summary>The expression of the current time in the SQL of the engine.</summary>
    protected abstract string Now { get; }

    /// <summary>The literal of a boolean in the SQL of the engine.</summary>
    protected abstract string Boolean(bool value);

    /// <summary>Creates the database of the test on the server, dropping one left by an earlier run.</summary>
    protected abstract Task CreateDatabaseAsync(string server);

    /// <summary>Drops the database of the test.</summary>
    protected abstract Task DropDatabaseAsync(string server);

    /// <summary>Opens a connection to the database of the test under the installer.</summary>
    protected abstract Task<DbConnection> OpenAsync(string server, CancellationToken cancellationToken);

    /// <summary>
    /// Opens a connection to the database of the test as the application verifies it at startup. The installer by
    /// default; an engine whose verification refuses the installer — PostgreSQL refuses a superuser — connects under
    /// the role the installation grants.
    /// </summary>
    protected virtual Task<DbConnection> OpenApplicationAsync(string server, CancellationToken cancellationToken)
        => OpenAsync(server, cancellationToken);

    /// <summary>The role of the application the installation grants.</summary>
    protected const string AppRole = "stellaegis_identity_app";

    /// <summary>The database of the test.</summary>
    protected const string Database = "stellaegis_identity_upgrade_tests";

    [Fact]
    public async Task A_database_of_Identity_7_takes_the_scripts_0002_and_0003_by_installing_again()
    {
        var server = Environment.GetEnvironmentVariable(Variable);
        Assert.SkipWhen(string.IsNullOrWhiteSpace(server), $"{Variable} is not set.");
        var ct = TestContext.Current.CancellationToken;
        var frame = IdentityStoreTests.Frame;
        Task<DbConnection> Open(ModuleDatabase _, CancellationToken token) => OpenAsync(server!, token);
        Task<DbConnection> OpenApplication(ModuleDatabase _, CancellationToken token) => OpenApplicationAsync(server!, token);

        await CreateDatabaseAsync(server!);
        try
        {
            await DatabaseLifecycle.InstallAsync([Version7], frame, Open, AppRole, Actor.Job("tests"), ct);
            await ExecuteAsync(server!, $"insert into ident.email_verifications (email, purpose, code, created_at, expires_at) values ('jane@acme.test', 'registration', '123456', {Now}, {Now})", ct);
            foreach (var email in new[] { "jane@acme.test", "john@acme.test" })
                await ExecuteAsync(server!,
                    "insert into ident.users (user_unique_id, email, display_name, is_enabled, email_verified, created_at, created_by, modified_at, modified_by) "
                    + $"values ('{Guid.NewGuid()}', '{email}', 'Someone', {Boolean(true)}, {Boolean(false)}, {Now}, 'install', {Now}, 'install')", ct);

            // The application refuses a database the package is ahead of.
            var refused = await Assert.ThrowsAsync<InvalidOperationException>(() => DatabaseLifecycle.VerifyAsync([Declaration], frame, OpenApplication, ct));
            Assert.Contains("0002_ident.sql", refused.Message);

            var report = await DatabaseLifecycle.InstallAsync([Declaration], frame, Open, AppRole, Actor.Job("tests"), ct);
            Assert.Equal(["identity: 0002_ident.sql", "identity: 0003_ident.sql"], report.Applied);
            Assert.Equal(["identity: 0001_ident.sql"], report.Skipped);
            await DatabaseLifecycle.VerifyAsync([Declaration], frame, OpenApplication, ct);

            // The code in clear is gone with its verification; the hash and the login codes are there.
            Assert.Equal(0, await CountAsync(server!, "select count(*) from ident.email_verifications", ct));
            Assert.Equal(1, await CountAsync(server!, "select count(*) from information_schema.columns where table_schema = 'ident' and table_name = 'email_verifications' and column_name = 'code_hash'", ct));
            Assert.Equal(0, await CountAsync(server!, "select count(*) from information_schema.columns where table_schema = 'ident' and table_name = 'email_verifications' and column_name = 'code'", ct));
            Assert.Equal(4, await CountAsync(server!, "select count(*) from information_schema.columns where table_schema = 'ident' and table_name = 'login_codes'", ct));

            // Every account present has a stamp of its own.
            Assert.Equal(2, await CountAsync(server!, "select count(distinct security_stamp) from ident.users", ct));
        }
        finally
        {
            await DropDatabaseAsync(server!);
        }
    }

    private async Task ExecuteAsync(string server, string sql, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(server, cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task<int> CountAsync(string server, string sql, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(server, cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken));
    }

    /// <summary>Runs <paramref name="sql"/> on a connection that is closed after it.</summary>
    protected static async Task RunAsync(DbConnection connection, string sql)
    {
        await using (connection)
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            await command.ExecuteNonQueryAsync();
        }
    }
}

/// <summary>The upgrade on PostgreSQL (<see cref="UpgradeTests"/>).</summary>
public sealed class PostgreSqlUpgradeTests : UpgradeTests
{
    /// <inheritdoc/>
    protected override string Variable => "STELLAEGIS_TEST_POSTGRESQL";

    /// <inheritdoc/>
    protected override ModuleDatabase Declaration => PostgreSqlDatabase.Value;

    /// <inheritdoc/>
    protected override ModuleDatabase Version7 { get; } = ModuleDatabase.PostgreSql<IdentityModule>(PostgreSqlDatabase.Schema)
        .WithScripts(PostgreSqlDatabase.Value.Scripts.Take(1));

    /// <inheritdoc/>
    protected override string Now => "now()";

    /// <inheritdoc/>
    protected override string Boolean(bool value) => value ? "true" : "false";

    /// <inheritdoc/>
    protected override async Task CreateDatabaseAsync(string server)
    {
        await RunAsync(new NpgsqlConnection(server), $"drop database if exists \"{Database}\" with (force)");
        await RunAsync(new NpgsqlConnection(server), $"create database \"{Database}\"");
        await RunAsync(new NpgsqlConnection(server), $"""
            do $$ begin
              create role {AppRole} login password '{AppRole}';
            exception when duplicate_object or unique_violation then null;
            end $$;
            """);
    }

    /// <inheritdoc/>
    protected override Task DropDatabaseAsync(string server)
        => RunAsync(new NpgsqlConnection(server), $"drop database if exists \"{Database}\" with (force)");

    /// <inheritdoc/>
    protected override async Task<DbConnection> OpenAsync(string server, CancellationToken cancellationToken)
    {
        var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(server) { Database = Database, Pooling = false }.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    /// <inheritdoc/>
    protected override async Task<DbConnection> OpenApplicationAsync(string server, CancellationToken cancellationToken)
    {
        var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(server)
        {
            Database = Database,
            Username = AppRole,
            Password = AppRole,
            Pooling = false,
        }.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }
}

/// <summary>The upgrade on SQL Server (<see cref="UpgradeTests"/>).</summary>
public sealed class SqlServerUpgradeTests : UpgradeTests
{
    /// <inheritdoc/>
    protected override string Variable => "STELLAEGIS_TEST_SQLSERVER";

    /// <inheritdoc/>
    protected override ModuleDatabase Declaration => SqlServerDatabase.Value;

    /// <inheritdoc/>
    protected override ModuleDatabase Version7 { get; } = ModuleDatabase.SqlServer<IdentityModule>(SqlServerDatabase.Schema)
        .WithScripts(SqlServerDatabase.Value.Scripts.Take(1));

    /// <inheritdoc/>
    protected override string Now => "sysdatetimeoffset()";

    /// <inheritdoc/>
    protected override string Boolean(bool value) => value ? "1" : "0";

    /// <inheritdoc/>
    protected override async Task CreateDatabaseAsync(string server)
    {
        await DropDatabaseAsync(server);
        await RunAsync(Master(server), $"create database [{Database}] collate French_100_CI_AS");
    }

    /// <inheritdoc/>
    protected override Task DropDatabaseAsync(string server)
        => RunAsync(Master(server), $"""
            if db_id(N'{Database}') is not null
            begin
              alter database [{Database}] set single_user with rollback immediate;
              drop database [{Database}];
            end
            """);

    /// <inheritdoc/>
    protected override async Task<DbConnection> OpenAsync(string server, CancellationToken cancellationToken)
    {
        var connection = new SqlConnection(new SqlConnectionStringBuilder(server) { InitialCatalog = Database, Pooling = false }.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    private static SqlConnection Master(string server)
        => new(new SqlConnectionStringBuilder(server) { InitialCatalog = "master", Pooling = false }.ConnectionString);
}
