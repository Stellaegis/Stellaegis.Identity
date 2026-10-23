using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Data;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Identity.Tests;

/// <summary>
/// A host assembled on the stores of an engine, as an enterprise host is: the database installed by the fixture,
/// verified at startup under the application's role, and the services of the module running on it.
/// </summary>
public abstract class IdentityHostTests(IIdentityDatabaseFixture database)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>The declaration of the database of the engine.</summary>
    protected abstract ModuleDatabase Declaration { get; }

    /// <summary>The configuration key of the connection string of the adapter.</summary>
    protected abstract string ConnectionStringKey { get; }

    /// <summary>Registers the module on the adapter, its options bound from <paramref name="configuration"/>.</summary>
    protected abstract void AddIdentity(IServiceCollection services, IConfiguration configuration);

    /// <summary>Registers the module on the adapter, its options configured in code.</summary>
    protected abstract void AddIdentity(IServiceCollection services, string connectionString, Action<IdentityOptions> configure);

    /// <summary>Makes the stores, and the verification, connect under the application's role, when the connection string does not.</summary>
    protected virtual void UnderApplicationRole(IServiceCollection services)
    {
    }

    /// <summary>The statement that renames the record of the installation away, or back.</summary>
    protected abstract string RenameRecordSql(bool back);

    private IHost BuildHost()
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [ConnectionStringKey] = database.AppConnectionString,
            ["Stellaegis:Identity:PasswordHasher:Pepper"] = "test-pepper",
            ["Stellaegis:Identity:Mfa:SecretKeys:Keys:1"] = "test-totp-key",
            ["Stellaegis:Identity:PasswordHasher:Iterations"] = "1000",
            ["Stellaegis:Identity:LoginPolicy:MinResponseTime"] = "00:00:00",
        });
        builder.Services
            .AddStellaegisFrame(IdentityStoreTests.Frame)
            .AddStellaegisValidation()
            .AddStellaegisDatabaseVerification();
        AddIdentity(builder.Services, builder.Configuration);
        builder.Services.AddStellaegisLocalBlockedUsersSource();
        UnderApplicationRole(builder.Services);
        return builder.Build();
    }

    [Fact]
    public async Task The_host_verifies_the_installed_database_at_startup_under_the_application_role()
    {
        database.SkipWhenUnavailable();
        using var host = BuildHost();

        await host.StartAsync(Ct);
        await host.StopAsync(Ct);

        Assert.Equal([Declaration], host.Services.GetStellaegisModuleDatabases());
        Assert.Contains(host.Services.GetStellaegisModules(), module => module.Module == typeof(IdentityModule));
    }

    [Fact]
    public async Task A_host_whose_database_is_not_installed_refuses_to_start()
    {
        database.SkipWhenUnavailable();
        var builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        builder.Services
            .AddStellaegisFrame(IdentityStoreTests.Frame)
            .AddStellaegisDatabaseVerification();
        AddIdentity(builder.Services, database.AppConnectionString, options =>
        {
            options.PasswordHasher.Pepper = "test-pepper";
            options.Mfa.SecretKeys = new KeySlots { Keys = { [1] = "test-totp-key" } };
        });
        UnderApplicationRole(builder.Services);
        using var host = builder.Build();
        await using (var connection = await database.OpenAsync(asApplication: false, Ct))
        await using (var command = connection.CreateCommand())
        {
            // The record of the installation is what the verification reads first: without it, nothing was installed.
            command.CommandText = RenameRecordSql(back: false);
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
            command.CommandText = RenameRecordSql(back: true);
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
