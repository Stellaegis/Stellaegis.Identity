using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Stellaegis.Identity.PostgreSQL;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Data;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Identity.Tests;

/// <summary>
/// A host assembled on the PostgreSQL stores, as an enterprise host is: the database installed by the fixture,
/// verified at startup under the application's role, and the services of the module running on it.
/// </summary>
[Collection(PostgreSqlCollection.Name)]
public sealed class PostgreSqlHostTests(PostgreSqlFixture database)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private IHost BuildHost()
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Stellaegis:Identity:PostgreSQL:ConnectionString"] = database.AppConnectionString,
            ["Stellaegis:Identity:PasswordHasher:Pepper"] = "test-pepper",
            ["Stellaegis:Identity:PasswordHasher:Iterations"] = "1000",
            ["Stellaegis:Identity:LoginPolicy:MinResponseTime"] = "00:00:00",
        });
        builder.Services
            .AddStellaegisFrame(PostgreSqlFixture.Frame)
            .AddStellaegisValidation()
            .AddStellaegisDatabaseVerification()
            .AddStellaegisIdentityPostgreSQL(builder.Configuration)
            .AddStellaegisLocalBlockedUsersSource();
        return builder.Build();
    }

    [Fact]
    public async Task The_host_verifies_the_installed_database_at_startup_under_the_application_role()
    {
        database.SkipWhenUnavailable();
        using var host = BuildHost();

        await host.StartAsync(Ct);
        await host.StopAsync(Ct);

        Assert.Equal([IdentityDatabase.Value], host.Services.GetStellaegisModuleDatabases());
        Assert.Contains(host.Services.GetStellaegisModules(), module => module.Module == typeof(IdentityModule));
    }

    [Fact]
    public async Task A_host_whose_database_is_not_installed_refuses_to_start()
    {
        database.SkipWhenUnavailable();
        var builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        builder.Services
            .AddStellaegisFrame(PostgreSqlFixture.Frame)
            .AddStellaegisDatabaseVerification()
            .AddStellaegisIdentityPostgreSQL(
                options => options.ConnectionString = database.AppConnectionString,
                options => options.PasswordHasher.Pepper = "test-pepper");
        using var host = builder.Build();
        await using (var connection = await database.OpenAsync(asApplication: false, Ct))
        await using (var command = connection.CreateCommand())
        {
            // The record of the installation is what the verification reads first: without it, nothing was installed.
            command.CommandText = $"alter table {IdentityDatabase.Value.MigrationsTable} rename to _schema_migrations_gone";
            await command.ExecuteNonQueryAsync(Ct);
        }

        try
        {
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => host.StartAsync(Ct));
            Assert.Contains("identity is not installed", exception.Message);
        }
        finally
        {
            await using var connection = await database.OpenAsync(asApplication: false, Ct);
            await using var command = connection.CreateCommand();
            command.CommandText = "alter table ident._schema_migrations_gone rename to _schema_migrations";
            await command.ExecuteNonQueryAsync(Ct);
        }
    }

    [Fact]
    public async Task An_account_created_by_the_administration_signs_in_and_is_refused_once_blocked()
    {
        database.SkipWhenUnavailable();
        using var host = BuildHost();
        await host.StartAsync(Ct);
        using var scope = host.Services.CreateScope();
        var email = $"{Guid.NewGuid():N}@acme.test";
        var created = await scope.ServiceProvider.GetRequiredService<AccountAdministrationService>().CreateAsync(email, "Jane", TokenDelivery.Hand, Actor.Parse("admin"), Ct);
        Assert.True(created.IsSuccess, created.Error?.ToString());
        var activated = await scope.ServiceProvider.GetRequiredService<ActivationService>().ActivateAsync(created.Value.ActivationToken, "Correct-Horse-9", Ct);
        Assert.True(activated.IsSuccess, activated.Error?.ToString());

        var login = scope.ServiceProvider.GetRequiredService<LoginService>();
        var result = await login.AuthenticateAsync(email, "Correct-Horse-9", cancellationToken: Ct);
        Assert.Equal(LoginStep.Succeeded, result.Step);
        Assert.Equal(created.Value.UserUniqueId.ToString("N"), result.Principal!.FindFirst("sub")!.Value);

        Assert.True((await scope.ServiceProvider.GetRequiredService<AccountAdministrationService>().BlockAsync(created.Value.UserUniqueId, Actor.Parse("admin"), Ct)).IsSuccess);
        Assert.Equal(LoginStep.Failed, (await login.AuthenticateAsync(email, "Correct-Horse-9", cancellationToken: Ct)).Step);
        Assert.Contains(created.Value.UserUniqueId.ToString("N"), await scope.ServiceProvider.GetRequiredService<IBlockedUsersSource>().GetBlockedSubjectsAsync(Ct));
        await host.StopAsync(Ct);
    }
}
