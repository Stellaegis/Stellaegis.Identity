using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Identity;

/// <summary>
/// The identity of the accounts module, <c>identity</c>: what its routes belong to, and what the application
/// declares it as. The module identifies a person and does nothing else: it holds the accounts, their passwords
/// and second factors, and answers whether an account is blocked. It has no compartments — one directory of
/// accounts serves the whole application — and it issues no token: that is <c>Stellaegis.Issuer</c>.
/// </summary>
public sealed class IdentityModule : IStellaegisModule
{
    /// <inheritdoc/>
    public static string Name => "identity";

    /// <summary>
    /// What the module declares to the application: no compartments, and the four operations of its
    /// administration. The routes of a person's own account — login, profile — carry no operation: they are the
    /// person's, not the application's to grant.
    /// </summary>
    public static ModuleDeclaration Declaration { get; } = ModuleDeclaration.WithoutCompartments<IdentityModule>()
        .WithOperations(IdentityOperations.UsersRead, IdentityOperations.UsersWrite, IdentityOperations.UsersDelete, IdentityOperations.SecurityRead);
}

/// <summary>The operations of the accounts module, which its administration routes are labelled with.</summary>
public static class IdentityOperations
{
    /// <summary>Listing and reading accounts, <c>users.read</c>.</summary>
    public static readonly Operation UsersRead = new("users", "read", OperationKind.Read);

    /// <summary>Creating an account, blocking or unblocking it, resetting its failed logins, its second factor or its password, <c>users.write</c>.</summary>
    public static readonly Operation UsersWrite = new("users", "write", OperationKind.Write);

    /// <summary>Deleting an account, <c>users.delete</c>.</summary>
    public static readonly Operation UsersDelete = new("users", "delete", OperationKind.Delete);

    /// <summary>Reading the blocked accounts, as a resource server does to admit actors, <c>security.read</c>.</summary>
    public static readonly Operation SecurityRead = new("security", "read", OperationKind.Read);

    /// <summary>Every operation of the module.</summary>
    public static IReadOnlyList<Operation> All { get; } = [UsersRead, UsersWrite, UsersDelete, SecurityRead];
}

/// <summary>Registers the accounts module itself, whatever stores hold the accounts.</summary>
public static class IdentityModuleServiceCollectionExtensions
{
    /// <summary>
    /// Declares the accounts module to the application (<see cref="IdentityModule.Declaration"/>). Every store's
    /// registration calls it; calling it again registers nothing more.
    /// </summary>
    public static IServiceCollection AddStellaegisIdentityModule(this IServiceCollection services)
    {
        Guard.NotNull(services);
        if (services.Any(descriptor => descriptor.ServiceType == typeof(IdentityModuleRegistered)))
            return services;
        services.AddSingleton(IdentityModuleRegistered.Instance);
        return services.AddStellaegisModule(IdentityModule.Declaration);
    }

    private sealed class IdentityModuleRegistered
    {
        public static readonly IdentityModuleRegistered Instance = new();
    }
}
