using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Identity.PostgreSQL;

/// <summary>
/// The options of the PostgreSQL stores, bound from <see cref="SectionName"/> or configured in code, and validated
/// when the host starts.
/// <code>
/// Stellaegis:Identity:PostgreSQL:ConnectionString = Host=…;Database=…;Username=…
/// </code>
/// </summary>
public sealed class IdentityDatabaseOptions : IValidatableOptions
{
    /// <summary>The configuration section of the adapter, <c>Stellaegis:Identity:PostgreSQL</c>.</summary>
    public const string SectionName = "Stellaegis:Identity:PostgreSQL";

    /// <summary>
    /// The connection string to the database holding the <c>ident</c> schema, under the application's role — the
    /// one the installation granted its data rights, never the one that owns the schema.
    /// </summary>
    public string ConnectionString { get; set; } = string.Empty;

    /// <inheritdoc/>
    public string? FindError()
        => string.IsNullOrWhiteSpace(ConnectionString) ? $"{nameof(ConnectionString)} is required." : null;
}
