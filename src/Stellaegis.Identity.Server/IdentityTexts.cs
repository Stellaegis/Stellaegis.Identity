using System.Globalization;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity.Server;

/// <summary>The type the resource files of the pages are named after: <c>IdentityPagesResources.resx</c> in English, <c>IdentityPagesResources.fr.resx</c> in French.</summary>
public sealed class IdentityPagesResources
{
    private IdentityPagesResources()
    {
    }
}

/// <summary>
/// The texts of the pages, in the culture of the request: what <see cref="IdentityPagesOptions.Texts"/> replaced
/// first, the resources of the package otherwise. A page reads <c>Texts["Login.Title"]</c>; an error of the
/// module reads as <see cref="Describe"/>.
/// </summary>
internal sealed class IdentityTexts(IStringLocalizer<IdentityPagesResources> localizer, IOptions<IdentityPagesOptions> options)
{
    /// <summary>The text of <paramref name="key"/>, or the key itself when no resource has it.</summary>
    public string this[string key] => Find(key) ?? key;

    /// <summary>The text of <paramref name="key"/> with <paramref name="arguments"/> formatted in.</summary>
    public string Format(string key, params object[] arguments)
        => string.Format(CultureInfo.CurrentCulture, this[key], arguments);

    /// <summary>
    /// What a person reads of an error of the module: the text keyed <c>Error.{code}</c> when the resources have
    /// one, the error's own message otherwise.
    /// </summary>
    public string Describe(Error error)
        => Find("Error." + Guard.NotNull(error).Code) ?? error.Message;

    private string? Find(string key)
    {
        var overrides = options.Value.Texts;
        var culture = CultureInfo.CurrentUICulture;
        if (Overridden(overrides, culture.Name, key) is { } exact)
            return exact;
        if (culture.Name != culture.TwoLetterISOLanguageName && Overridden(overrides, culture.TwoLetterISOLanguageName, key) is { } language)
            return language;
        if (Overridden(overrides, "*", key) is { } any)
            return any;
        var localized = localizer[key];
        return localized.ResourceNotFound ? null : localized.Value;
    }

    private static string? Overridden(Dictionary<string, Dictionary<string, string>> overrides, string culture, string key)
        => overrides.TryGetValue(culture, out var texts) && texts.TryGetValue(key, out var text) ? text : null;
}
