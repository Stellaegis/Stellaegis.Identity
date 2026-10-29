using System.IO.Compression;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Identity;

/// <summary>
/// Where the passwords everyone chooses, or the breaches hold, are refused from: three layers, asked in this order
/// and each enough to refuse. The list the package ships, a hundred thousand of the most used passwords, brought up
/// to date with the package; a file of the installation, one password per line, which an administrator updates
/// whenever they want and which is read again when it changes; and, where the host opens it, the Pwned Passwords
/// service of Have I Been Pwned, asked by the first five characters of the SHA-1 of the password — the password
/// never leaves the host —, and silent when it does not answer: the two other layers stand. Nothing opens by
/// itself: the service is off unless set.
/// </summary>
public sealed class PasswordBlocklistOptions : IValidatableOptions
{
    /// <summary>Whether the list the package ships is consulted. Yes unless set.</summary>
    public bool UseEmbeddedList { get; set; } = true;

    /// <summary>
    /// The path of a file of the installation, one password per line, lines starting with <c>#</c> and blank ones
    /// ignored, compared without regard to case: read when it changes, so that an administrator adds to it without
    /// waiting for a version. None unless set; the host must exist when set.
    /// </summary>
    public string? Path { get; set; }

    /// <summary>The Pwned Passwords service of Have I Been Pwned, off unless set.</summary>
    public HibpOptions Hibp { get; set; } = new();

    /// <inheritdoc/>
    public string? FindError()
    {
        if (Path is not null && (string.IsNullOrWhiteSpace(Path) || !File.Exists(Path)))
            return $"{nameof(Path)} names a file that does not exist: {Path}.";
        return Hibp.FindError() is { } hibp ? $"{nameof(Hibp)}: {hibp}" : null;
    }
}

/// <summary>
/// The Pwned Passwords service of Have I Been Pwned, asked by range: the first five characters of the SHA-1 of the
/// password go, the service answers every suffix it knows under them, and the match is made here. A password never
/// leaves the host. The service not answering refuses nothing: the list and the file stand.
/// </summary>
public sealed class HibpOptions : IValidatableOptions
{
    /// <summary>Whether the service is asked. No unless set.</summary>
    public bool Enabled { get; set; }

    /// <summary>The address of the range endpoint. The service's own unless set.</summary>
    public string BaseUrl { get; set; } = "https://api.pwnedpasswords.com/range/";

    /// <summary>How long an answer is waited for. Two seconds unless set; past it, the service is held as silent.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(2);

    /// <inheritdoc/>
    public string? FindError()
    {
        if (!Enabled)
            return null;
        if (!Uri.TryCreate(BaseUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp)
            return $"{nameof(BaseUrl)} must be an absolute http(s) URL.";
        if (Timeout <= TimeSpan.Zero)
            return $"{nameof(Timeout)} must be positive.";
        return null;
    }
}

/// <summary>
/// The <see cref="IPasswordBlocklist"/> the package registers unless the host registers its own: the list the
/// package ships, the file of the installation, and Have I Been Pwned where opened
/// (<see cref="PasswordBlocklistOptions"/>). Passwords are compared without regard to case.
/// </summary>
public sealed class DefaultPasswordBlocklist(IOptions<IdentityOptions> options, IHttpClientFactory httpClients, ILogger<DefaultPasswordBlocklist> logger) : IPasswordBlocklist
{
    /// <summary>The name of the HTTP client that asks Have I Been Pwned.</summary>
    public const string HibpClientName = "Stellaegis.Identity.Hibp";

    private const string EmbeddedResource = "Stellaegis.Identity.common-passwords.txt.gz";

    // One copy for the process: the list is the package's, not the host's.
    private static readonly Lazy<HashSet<string>> Embedded = new(LoadEmbedded, LazyThreadSafetyMode.ExecutionAndPublication);

    private readonly Lock _file = new();
    private HashSet<string>? _fileEntries;
    private DateTime _fileWrittenAt;

    /// <summary>How many passwords the list the package ships holds.</summary>
    public static int EmbeddedCount => Embedded.Value.Count;

    /// <inheritdoc/>
    public async ValueTask<bool> IsBlockedAsync(string password, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(password);
        var settings = options.Value.PasswordBlocklist;
        var normalized = password.ToLowerInvariant();
        if (settings.UseEmbeddedList && Embedded.Value.Contains(normalized))
            return true;
        if (settings.Path is { } path && ReadFile(path).Contains(normalized))
            return true;
        return settings.Hibp.Enabled && await IsPwnedAsync(password, settings.Hibp, cancellationToken).ConfigureAwait(false);
    }

    private static HashSet<string> LoadEmbedded()
    {
        using var stream = typeof(DefaultPasswordBlocklist).Assembly.GetManifestResourceStream(EmbeddedResource)
            ?? throw new InvalidOperationException($"The resource {EmbeddedResource} is missing from the package.");
        using var unzipped = new GZipStream(stream, CompressionMode.Decompress);
        using var reader = new StreamReader(unzipped, Encoding.UTF8);
        var entries = new HashSet<string>(StringComparer.Ordinal);
        while (reader.ReadLine() is { } line)
        {
            if (line.Length > 0)
                entries.Add(line.ToLowerInvariant());
        }
        return entries;
    }

    // Read again when the file changed: a stat per check, a read per change. A file gone since the start refuses
    // nothing more than the empty file it has become, and says so once.
    private HashSet<string> ReadFile(string path)
    {
        var writtenAt = File.Exists(path) ? File.GetLastWriteTimeUtc(path) : DateTime.MinValue;
        lock (_file)
        {
            if (_fileEntries is not null && writtenAt == _fileWrittenAt)
                return _fileEntries;
            var entries = new HashSet<string>(StringComparer.Ordinal);
            if (writtenAt == DateTime.MinValue)
            {
                logger.LogWarning("The password blocklist file {Path} is missing: it refuses nothing until it is back", path);
            }
            else
            {
                foreach (var line in File.ReadLines(path))
                {
                    var trimmed = line.Trim();
                    if (trimmed.Length > 0 && !trimmed.StartsWith('#'))
                        entries.Add(trimmed.ToLowerInvariant());
                }
                logger.LogInformation("The password blocklist file {Path} is read: {Count} entries", path, entries.Count);
            }
            _fileEntries = entries;
            _fileWrittenAt = writtenAt;
            return entries;
        }
    }

    // The k-anonymity of Pwned Passwords: five characters of the hash go, the suffixes known under them come back,
    // "SUFFIX:COUNT" per line, padded with suffixes of count 0 so that the size of the answer says nothing either.
    private async Task<bool> IsPwnedAsync(string password, HibpOptions settings, CancellationToken cancellationToken)
    {
        var hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
        var prefix = hash[..5];
        var suffix = hash[5..];
        try
        {
            using var client = httpClients.CreateClient(HibpClientName);
            client.Timeout = settings.Timeout;
            using var request = new HttpRequestMessage(HttpMethod.Get, settings.BaseUrl + prefix);
            request.Headers.Add("Add-Padding", "true");
            request.Headers.UserAgent.ParseAdd("Stellaegis.Identity");
            using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("Have I Been Pwned answered {Status}: the password is not checked against it", (int)response.StatusCode);
                return false;
            }
            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            foreach (var line in body.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var separator = line.IndexOf(':');
                if (separator < 0)
                    continue;
                if (string.Equals(line[..separator], suffix, StringComparison.OrdinalIgnoreCase)
                    && long.TryParse(line[(separator + 1)..], out var count) && count > 0)
                    return true;
            }
            return false;
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning(exception, "Have I Been Pwned did not answer: the password is not checked against it");
            return false;
        }
    }
}
