using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Identity.Client;

/// <summary>
/// The options of a resource server reaching the host that holds the accounts, bound from
/// <c>Stellaegis:Identity:Client</c>: the address of its administration routes, under which
/// <c>security/blocked-users</c> is read.
/// <code>
/// Stellaegis:Identity:Client:BaseUrl = https://identity.internal/api/admin/identity
/// </code>
/// </summary>
public sealed class IdentityClientOptions : StellaegisClientOptions
{
    /// <summary>The configuration section of the options, <c>Stellaegis:Identity:Client</c>.</summary>
    public const string SectionName = "Stellaegis:Identity:Client";
}

/// <summary>
/// Gives the client the bearer token it presents to the administration routes: the host implements it over its
/// own way of obtaining one — client credentials from the issuer, a static token. Without one registered, the
/// client presents no token, for a host that authenticates otherwise.
/// </summary>
public interface IIdentityClientTokenProvider
{
    /// <summary>The token to present, or <see langword="null"/> for none.</summary>
    ValueTask<string?> GetTokenAsync(CancellationToken cancellationToken = default);
}

/// <summary>The blocked accounts read over HTTP from <c>GET security/blocked-users</c> of the host that holds the accounts.</summary>
internal sealed class HttpBlockedUsersSource(HttpClient http, IServiceProvider services) : IBlockedUsersSource
{
    private readonly IIdentityClientTokenProvider? _tokens = Guard.NotNull(services).GetService<IIdentityClientTokenProvider>();

    public async Task<IReadOnlyCollection<string>> GetBlockedSubjectsAsync(CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "security/blocked-users");
        if (_tokens is not null && await _tokens.GetTokenAsync(cancellationToken).ConfigureAwait(false) is { } token)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (await response.ReadErrorAsync(cancellationToken).ConfigureAwait(false) is { } error)
            throw new HttpRequestException($"The accounts answered {error.Code}: {error.Message}", null, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<string[]>(cancellationToken).ConfigureAwait(false) ?? [];
    }
}

/// <summary>Registers the HTTP source of the blocked accounts.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="IBlockedUsersSource"/> over HTTP, its options bound from <paramref name="sectionName"/>
    /// and validated at startup, for the admission of actors on a resource server apart
    /// (<c>AddStellaegisIdentityAdmission</c> of <c>Stellaegis.Identity.AspNetCore</c>). Register an
    /// <see cref="IIdentityClientTokenProvider"/> before when the routes ask a token.
    /// </summary>
    /// <returns>The builder of the underlying HTTP client, to add handlers to.</returns>
    public static IHttpClientBuilder AddStellaegisIdentityClient(this IServiceCollection services, IConfiguration configuration, string sectionName = IdentityClientOptions.SectionName)
    {
        Guard.NotNull(services);
        Guard.NotNull(configuration);
        return services.AddStellaegisHttpClient<IBlockedUsersSource, HttpBlockedUsersSource, IdentityClientOptions>(configuration, sectionName);
    }

    /// <summary>
    /// Registers the HTTP source as <see cref="AddStellaegisIdentityClient(IServiceCollection, IConfiguration, string)"/>
    /// does, with its options configured in code.
    /// </summary>
    public static IHttpClientBuilder AddStellaegisIdentityClient(this IServiceCollection services, Action<IdentityClientOptions> configure)
    {
        Guard.NotNull(services);
        Guard.NotNull(configure);
        return services.AddStellaegisHttpClient<IBlockedUsersSource, HttpBlockedUsersSource, IdentityClientOptions>(configure);
    }
}
