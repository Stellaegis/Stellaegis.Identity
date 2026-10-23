using System.Data.Common;
using Microsoft.Extensions.Options;
using Npgsql;
using Stellaegis.Identity.AspNetCore;
using Stellaegis.Identity.PostgreSQL;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Data;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Identity.Sample;

/// <summary>
/// The installation of the example, apart from the application and under another role: the database and the
/// application's role created if missing, the <c>ident</c> schema installed by the life cycle of Primitives under
/// the administration connection, and the first administrator created by the services of the module, without a
/// password: the installation prints its activation link, which the installer opens once the application runs, and
/// chooses the password there — no password goes through the command line, its history or the list of processes.
/// Run again, it changes nothing but a new link for an administrator still waiting for the activation.
/// <code>
/// dotnet run -- install --admin-email admin@acme.test [--display-name Admin]
/// </code>
/// </summary>
public static class Install
{
    public static async Task<int> RunAsync(string[] args)
    {
        var email = Argument(args, "--admin-email");
        var displayName = Argument(args, "--display-name") ?? "Administrator";
        if (email is null)
        {
            Console.Error.WriteLine("usage: install --admin-email <email> [--display-name <name>]");
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
        // administration routes would: the installation is the one actor that creates an account by itself. The
        // account has no password; its activation link is handed to the installer, here, this once.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddStellaegisFrame(SampleFrame.Value);
        services.AddStellaegisIdentityPostgreSQL(configuration);
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var links = provider.GetRequiredService<IOptions<IdentityOptions>>().Value.Links;
        var administration = scope.ServiceProvider.GetRequiredService<AccountAdministrationService>();
        var installedBy = Actor.Job("install");

        string? token = null;
        var created = await administration.CreateAsync(email, displayName, TokenDelivery.Hand, installedBy);
        if (created.IsSuccess)
        {
            Console.WriteLine($"Administrator {email} created, {created.Value.UserUniqueId:N}.");
            token = created.Value.ActivationToken;
        }
        else if (created.Error?.Code == IdentityErrors.EmailTakenCode)
        {
            var existing = await scope.ServiceProvider.GetRequiredService<IAuthUserStore>().GetByEmailAsync(Emails.Normalize(email));
            if (existing is { IsActivated: false })
                token = (await administration.IssueActivationAsync(existing.UserUniqueId, TokenDelivery.Hand, installedBy)).Value?.Token;
            else
                Console.WriteLine($"Administrator {email} exists already, and is active.");
        }
        else
        {
            Console.Error.WriteLine($"The administrator was not created: {created.Error}");
            return 1;
        }

        if (token is not null)
        {
            Console.WriteLine("Open this link once the application runs, and choose the administrator's password there:");
            Console.WriteLine(IdentityLinks.Of(links, null, IdentityLinks.ActivatePath, token));
        }
        return 0;
    }

    private static string? Argument(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }
}
