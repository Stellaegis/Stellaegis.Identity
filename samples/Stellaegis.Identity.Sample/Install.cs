using System.Data.Common;
using Npgsql;
using Stellaegis.Identity.PostgreSQL;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Data;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Identity.Sample;

/// <summary>
/// The installation of the example, apart from the application and under another role: the database and the
/// application's role created if missing, the <c>ident</c> schema installed by the life cycle of Primitives under
/// the administration connection, and the first administrator created by the services of the module. Run again,
/// it changes nothing: the scripts are recorded, the administrator exists.
/// <code>
/// dotnet run -- install --admin-email admin@acme.test --admin-password 'Correct-Horse-9' [--display-name Admin]
/// </code>
/// </summary>
public static class Install
{
    public static async Task<int> RunAsync(string[] args)
    {
        var email = Argument(args, "--admin-email");
        var password = Argument(args, "--admin-password");
        var displayName = Argument(args, "--display-name") ?? "Administrator";
        if (email is null || password is null)
        {
            Console.Error.WriteLine("usage: install --admin-email <email> --admin-password <password> [--display-name <name>]");
            return 2;
        }

        var configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", optional: false)
            .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"}.json", optional: true)
            .AddUserSecrets<LoggingMailer>(optional: true)
            .AddEnvironmentVariables()
            .Build();

        // The application's connection string names the database and the role the application runs under; the
        // installer's connection string reaches the server under a role that may create both.
        var application = new NpgsqlConnectionStringBuilder(configuration["Stellaegis:Identity:PostgreSQL:ConnectionString"]
            ?? throw new InvalidOperationException("Stellaegis:Identity:PostgreSQL:ConnectionString is not configured."));
        var installer = new NpgsqlConnectionStringBuilder(configuration["Sample:Install:ConnectionString"]
            ?? throw new InvalidOperationException("Sample:Install:ConnectionString is not configured."));
        var role = application.Username ?? throw new InvalidOperationException("The application's connection string names no role.");
        var database = application.Database ?? throw new InvalidOperationException("The application's connection string names no database.");

        // 1. The database and the role, if missing.
        await using (var server = new NpgsqlConnection(installer.ConnectionString))
        {
            await server.OpenAsync();
            await using (var exists = new NpgsqlCommand("select 1 from pg_database where datname = @name", server))
            {
                exists.Parameters.AddWithValue("name", database);
                if (await exists.ExecuteScalarAsync() is null)
                {
                    await using var create = new NpgsqlCommand($"create database \"{database}\"", server);
                    await create.ExecuteNonQueryAsync();
                    Console.WriteLine($"Database {database} created.");
                }
            }
            await using (var createRole = new NpgsqlCommand(
                $"""
                do $$ begin
                  create role "{role}" login password '{application.Password?.Replace("'", "''")}';
                exception when duplicate_object or unique_violation then null;
                end $$;
                """, server))
            {
                await createRole.ExecuteNonQueryAsync();
            }
        }

        // 2. The schema, under the installer, which owns it; the application's role granted its rights.
        var adminOnDatabase = new NpgsqlConnectionStringBuilder(installer.ConnectionString) { Database = database }.ConnectionString;
        var report = await DatabaseLifecycle.InstallAsync(
            [IdentityDatabase.Value], SampleFrame.Value,
            async (_, ct) => { DbConnection c = new NpgsqlConnection(adminOnDatabase); await c.OpenAsync(ct); return c; },
            role);
        foreach (var applied in report.Applied)
            Console.WriteLine($"Applied: {applied}");
        foreach (var skipped in report.Skipped)
            Console.WriteLine($"Already applied: {skipped}");

        // 3. The first administrator, by the services of the module, under the application's role, as the
        // administration routes would: the installation is the one actor that creates an account by itself.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddStellaegisFrame(SampleFrame.Value);
        services.AddStellaegisIdentityPostgreSQL(configuration);
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var created = await scope.ServiceProvider.GetRequiredService<AccountAdministrationService>()
            .CreateAsync(email, displayName, password, Actor.Job("install"));
        if (created.IsSuccess)
            Console.WriteLine($"Administrator {email} created, {created.Value:N}.");
        else if (created.Error?.Code == IdentityErrors.EmailTakenCode)
            Console.WriteLine($"Administrator {email} exists already.");
        else
        {
            Console.Error.WriteLine($"The administrator was not created: {created.Error}");
            return 1;
        }
        return 0;
    }

    private static string? Argument(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }
}
