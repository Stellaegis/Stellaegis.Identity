using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Stellaegis.Primitives;

namespace Stellaegis.Identity.Tests;

/// <summary>The passwords everyone chooses, refused from three layers: the list the package ships, a file of the installation, Have I Been Pwned.</summary>
public sealed class PasswordBlocklistTests
{
    [Fact]
    public async Task The_list_the_package_ships_refuses_the_common_passwords_whatever_their_case_wherever_a_password_is_accepted()
    {
        using var host = new TestHost();
        var blocklist = host.Get<IPasswordBlocklist>();

        Assert.IsType<DefaultPasswordBlocklist>(blocklist);
        Assert.True(DefaultPasswordBlocklist.EmbeddedCount > 90_000);
        Assert.True(await blocklist.IsBlockedAsync("123456"));
        Assert.True(await blocklist.IsBlockedAsync("Password"));
        Assert.True(await blocklist.IsBlockedAsync("QWERTY"));
        Assert.False(await blocklist.IsBlockedAsync("Correct-Horse-9"));

        // Eight characters, nothing else asked: the policy accepts it, the list refuses it.
        var id = await host.CreateUserAsync();
        Assert.Equal(IdentityErrors.PasswordBlocked, (await host.Get<AccountService>().ChangePasswordAsync(id, "Correct-Horse-9", "iloveyou")).Error);
        Assert.True((await host.Get<AccountService>().ChangePasswordAsync(id, "Correct-Horse-9", "Rare-Horse-2")).IsSuccess);

        using var without = new TestHost(o => o.PasswordBlocklist.UseEmbeddedList = false);
        Assert.False(await without.Get<IPasswordBlocklist>().IsBlockedAsync("123456"));
    }

    [Fact]
    public async Task The_file_of_the_installation_is_read_again_when_it_changes_and_must_exist_when_named()
    {
        var path = Path.Combine(Path.GetTempPath(), $"stellaegis-blocklist-{Guid.NewGuid():N}.txt");
        try
        {
            await File.WriteAllTextAsync(path, "# the names of the company\nAcme2026!\n\n  acme-corp \n");
            using var host = new TestHost(o => { o.PasswordBlocklist.UseEmbeddedList = false; o.PasswordBlocklist.Path = path; });
            var blocklist = host.Get<IPasswordBlocklist>();

            Assert.True(await blocklist.IsBlockedAsync("acme2026!"));
            Assert.True(await blocklist.IsBlockedAsync("ACME-CORP"));
            Assert.False(await blocklist.IsBlockedAsync("# the names of the company"));
            Assert.False(await blocklist.IsBlockedAsync("Winter-2026"));

            // The administrator adds a line: no restart, the next check reads the file again.
            await File.AppendAllTextAsync(path, "Winter-2026\n");
            File.SetLastWriteTimeUtc(path, File.GetLastWriteTimeUtc(path).AddMinutes(1));
            Assert.True(await blocklist.IsBlockedAsync("Winter-2026"));
        }
        finally
        {
            File.Delete(path);
        }

        var options = new IdentityOptions { PasswordHasher = { Pepper = "p" }, Mfa = { SecretKeys = new KeySlots { Keys = { [1] = "k" } } } };
        options.PasswordBlocklist.Path = path;
        Assert.StartsWith("PasswordBlocklist: Path names a file that does not exist", options.FindError());
    }

    [Fact]
    public async Task Have_I_Been_Pwned_is_asked_by_the_first_five_characters_of_the_hash_and_its_silence_refuses_nothing()
    {
        var handler = new Handler();
        using var host = new TestHost(
            o => { o.PasswordBlocklist.UseEmbeddedList = false; o.PasswordBlocklist.Hibp.Enabled = true; o.PasswordBlocklist.Hibp.BaseUrl = "https://hibp.test/range/"; },
            services => services.AddHttpClient(DefaultPasswordBlocklist.HibpClientName).ConfigurePrimaryHttpMessageHandler(() => handler));
        var blocklist = host.Get<IPasswordBlocklist>();
        var hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes("Correct-Horse-9")));

        // Known under its range: refused. The request carries five characters of the hash, never the rest.
        handler.Respond = request => Range($"00000000000000000000000000000000000:0\n{hash[5..]}:12\n");
        Assert.True(await blocklist.IsBlockedAsync("Correct-Horse-9"));
        Assert.Equal($"https://hibp.test/range/{hash[..5]}", handler.LastRequest!.RequestUri!.ToString());
        Assert.DoesNotContain(hash[5..], handler.LastRequest.RequestUri.ToString());
        Assert.Equal("true", handler.LastRequest.Headers.GetValues("Add-Padding").Single());

        // Padding only, or another suffix: not refused.
        handler.Respond = _ => Range($"{hash[5..]}:0\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:3\n");
        Assert.False(await blocklist.IsBlockedAsync("Correct-Horse-9"));

        // The service down, slow, or in error: nothing refused, nothing thrown.
        handler.Respond = _ => throw new HttpRequestException("down");
        Assert.False(await blocklist.IsBlockedAsync("Correct-Horse-9"));
        handler.Respond = _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        Assert.False(await blocklist.IsBlockedAsync("Correct-Horse-9"));

        using var off = new TestHost(o => o.PasswordBlocklist.UseEmbeddedList = false, services => services.AddHttpClient(DefaultPasswordBlocklist.HibpClientName).ConfigurePrimaryHttpMessageHandler(() => handler));
        handler.LastRequest = null;
        handler.Respond = _ => Range($"{hash[5..]}:12\n");
        Assert.False(await off.Get<IPasswordBlocklist>().IsBlockedAsync("Correct-Horse-9"));
        Assert.Null(handler.LastRequest);   // off unless set: never asked
    }

    private static HttpResponseMessage Range(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body) };

    private sealed class Handler : HttpMessageHandler
    {
        public Func<HttpRequestMessage, HttpResponseMessage> Respond { get; set; } = _ => new HttpResponseMessage(HttpStatusCode.NotFound);

        public HttpRequestMessage? LastRequest { get; set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(Respond(request));
        }
    }
}
