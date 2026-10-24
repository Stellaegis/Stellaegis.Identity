namespace Stellaegis.Identity.Server;

/// <summary>
/// The IANA names the pages suggest for a time zone: one per zone of the system — under Windows, the IANA name of each
/// Windows zone. A suggestion only: any IANA name the system knows is accepted (<see cref="ProfileService.IsTimeZone"/>),
/// <c>Europe/Brussels</c> included where the list only shows <c>Europe/Paris</c>.
/// </summary>
internal static class TimeZoneNames
{
    private static readonly Lazy<IReadOnlyList<string>> All = new(() =>
    [
        .. TimeZoneInfo.GetSystemTimeZones()
            .Select(zone => zone.HasIanaId ? zone.Id : TimeZoneInfo.TryConvertWindowsIdToIanaId(zone.Id, out var iana) ? iana : null)
            .OfType<string>()
            .Where(ProfileService.IsTimeZone)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal),
    ]);

    /// <summary>The names, in alphabetical order.</summary>
    public static IReadOnlyList<string> Suggested => All.Value;
}
