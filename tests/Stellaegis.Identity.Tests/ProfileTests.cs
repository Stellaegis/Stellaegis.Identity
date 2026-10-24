using System.Buffers.Binary;
using System.Text;
using Stellaegis.Primitives;

namespace Stellaegis.Identity.Tests;

/// <summary>What a person reads and changes of their own profile.</summary>
public sealed class ProfileTests
{
    [Fact]
    public async Task The_name_the_language_and_the_time_zone_are_changed_together_and_read_back()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var profiles = host.Get<ProfileService>();

        var changed = await profiles.UpdateAsync(id, "  Jane Doe ", "en-GB", "Europe/Paris");

        Assert.True(changed.IsSuccess);
        Assert.Equal("Jane Doe", changed.Value!.DisplayName);
        Assert.Equal("en-GB", changed.Value.Locale);
        Assert.Equal("Europe/Paris", changed.Value.TimeZone);
        Assert.Null(changed.Value.AvatarModifiedAt);
        var user = (await host.Get<IAuthUserStore>().GetByUniqueIdAsync(id))!;
        Assert.Equal(("Jane Doe", "en-GB", "Europe/Paris"), (user.DisplayName, user.Locale, user.TimeZone));
        Assert.Equal(user.AsActor(), user.ModifiedBy);
        Assert.Equal(changed.Value, (await profiles.GetAsync(id)).Value);

        var cleared = await profiles.UpdateAsync(id, "Jane Doe", "", " ");
        Assert.Null(cleared.Value!.Locale);
        Assert.Null(cleared.Value.TimeZone);
    }

    [Fact]
    public async Task What_others_see_is_published_when_the_name_changes_and_not_otherwise()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var profiles = host.Get<ProfileService>();

        await profiles.UpdateAsync(id, "Jane", "fr", null);
        Assert.Empty(host.Events.Events);

        await profiles.UpdateAsync(id, "Jane Doe", "fr", null);
        var changed = Assert.IsType<UserProfileChangedEvent>(Assert.Single(host.Events.Events));
        Assert.Equal((id, "Jane Doe"), (changed.UserUniqueId, changed.DisplayName));
        Assert.Null(changed.AvatarModifiedAt);
    }

    [Fact]
    public async Task A_name_a_language_or_a_time_zone_that_does_not_hold_is_refused()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var profiles = host.Get<ProfileService>();

        Assert.Equal(IdentityErrors.InvalidDisplayName, (await profiles.UpdateAsync(id, " ", null, null)).Error);
        Assert.Equal(IdentityErrors.InvalidDisplayName, (await profiles.UpdateAsync(id, new string('a', 201), null, null)).Error);
        Assert.Equal(IdentityErrors.InvalidLocale, (await profiles.UpdateAsync(id, "Jane", "en-gb", null)).Error);
        Assert.Equal(IdentityErrors.InvalidTimeZone, (await profiles.UpdateAsync(id, "Jane", null, "Romance Standard Time")).Error);
        Assert.Equal(IdentityErrors.AccountNotFound, (await profiles.UpdateAsync(Guid.NewGuid(), "Jane", null, null)).Error);
        Assert.Equal("Jane", (await host.Get<IAuthUserStore>().GetByUniqueIdAsync(id))!.DisplayName);
    }

    [Theory]
    [InlineData("fr", true)]
    [InlineData("en-GB", true)]
    [InlineData("zh-Hans-CN", true)]
    [InlineData("en-gb", false)]
    [InlineData("EN", false)]
    [InlineData("", false)]
    [InlineData("xx-YY", false)]
    [InlineData("fr_FR", false)]
    public void A_language_is_a_culture_name_in_its_canonical_form(string value, bool accepted)
        => Assert.Equal(accepted, ProfileService.IsLocale(value));

    [Theory]
    [InlineData("Europe/Paris", true)]
    [InlineData("America/Argentina/Buenos_Aires", true)]
    [InlineData("UTC", true)]
    [InlineData("europe/paris", false)]
    [InlineData("Romance Standard Time", false)]
    [InlineData("Mars/Olympus_Mons", false)]
    [InlineData("", false)]
    public void A_time_zone_is_an_iana_name_as_written(string value, bool accepted)
        => Assert.Equal(accepted, ProfileService.IsTimeZone(value));

    [Fact]
    public async Task The_session_carries_the_language_and_the_time_zone_the_person_chose()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var login = host.Get<LoginService>();

        var before = (await login.CreatePrincipalAsync(id, [AuthenticationMethods.Password]))!;
        Assert.Null(before.FindFirst(ProfileClaims.Locale));
        Assert.Null(before.FindFirst(ProfileClaims.TimeZone));

        await host.Get<ProfileService>().UpdateAsync(id, "Jane", "fr", "Europe/Paris");
        var after = (await login.CreatePrincipalAsync(id, [AuthenticationMethods.Password]))!;
        Assert.Equal("fr", after.FindFirst("locale")!.Value);
        Assert.Equal("Europe/Paris", after.FindFirst("zoneinfo")!.Value);
    }

    [Fact]
    public async Task An_avatar_is_kept_stripped_of_every_chunk_but_the_image_and_published()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var profiles = host.Get<ProfileService>();
        var plain = Png(256, 256);
        var withText = Png(256, 256, ("tEXt", Encoding.ASCII.GetBytes("GPS\0 47.21 N, 1.55 W")), ("tRNS", [0, 0]));

        var set = await profiles.SetAvatarAsync(id, withText);

        Assert.True(set.IsSuccess);
        Assert.Equal(host.Clock.Now, set.Value!.AvatarModifiedAt);
        var stored = (await host.Get<IAvatarStore>().GetAsync(id))!;
        Assert.Equal(Png(256, 256, ("tRNS", [0, 0])), stored.Image);
        Assert.Equal(user(host, id).AsActor(), stored.ModifiedBy);
        var changed = Assert.IsType<UserProfileChangedEvent>(Assert.Single(host.Events.Events));
        Assert.Equal(host.Clock.Now, changed.AvatarModifiedAt);

        Assert.True((await profiles.SetAvatarAsync(id, plain)).IsSuccess);
        Assert.Equal(plain, (await host.Get<IAvatarStore>().GetAsync(id))!.Image);

        static AuthUser user(TestHost host, Guid id) => host.Get<IAuthUserStore>().GetByUniqueIdAsync(id).Result!;
    }

    [Fact]
    public async Task An_image_that_is_not_a_sound_png_of_256_pixels_is_refused()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var profiles = host.Get<ProfileService>();
        var sound = Png(256, 256);
        var corrupted = (byte[])sound.Clone();
        corrupted[^20] ^= 0xff;

        foreach (var image in new[]
        {
            null,
            Array.Empty<byte>(),
            Encoding.UTF8.GetBytes("<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>"),
            Png(512, 512),
            Png(256, 128),
            corrupted,
            sound[..^12],
            [.. sound, 0],
            Png(256, 256, withoutImage: true),
            Png(256, 256, ("IDAT", new byte[AccountAvatar.MaxImageLength])),
        })
        {
            Assert.Equal(IdentityErrors.InvalidAvatar, (await profiles.SetAvatarAsync(id, image)).Error);
        }
        Assert.Null(await host.Get<IAvatarStore>().GetAsync(id));
        Assert.Empty(host.Events.Events);
    }

    [Fact]
    public async Task An_avatar_is_removed_by_the_person_and_with_the_account()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var profiles = host.Get<ProfileService>();
        await profiles.SetAvatarAsync(id, Png(256, 256));
        host.Events.Events.Clear();

        Assert.Null((await profiles.RemoveAvatarAsync(id)).Value!.AvatarModifiedAt);
        Assert.IsType<UserProfileChangedEvent>(Assert.Single(host.Events.Events));
        Assert.True((await profiles.RemoveAvatarAsync(id)).IsSuccess);
        Assert.Single(host.Events.Events);

        await profiles.SetAvatarAsync(id, Png(256, 256));
        Assert.True((await host.Get<AccountService>().DeleteAccountAsync(id, "Correct-Horse-9")).IsSuccess);
        Assert.Null(await host.Get<IAvatarStore>().GetAsync(id));
    }

    /// <summary>
    /// A PNG of that size, its structure and checksums sound: what the check reads, not an image a decoder would draw.
    /// </summary>
    internal static byte[] Png(int width, int height, params (string Type, byte[] Data)[] extra)
        => Png(width, height, withoutImage: false, extra);

    private static byte[] Png(int width, int height, bool withoutImage, params (string Type, byte[] Data)[] extra)
    {
        using var output = new MemoryStream();
        output.Write([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
        var header = new byte[13];
        BinaryPrimitives.WriteUInt32BigEndian(header, (uint)width);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), (uint)height);
        header[8] = 8;
        header[9] = 6;
        Chunk(output, "IHDR", header);
        foreach (var (type, data) in extra.Where(chunk => chunk.Type != "IDAT"))
            Chunk(output, type, data);
        if (!withoutImage)
            Chunk(output, "IDAT", [0x78, 0x9c, 0x63, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]);
        foreach (var (type, data) in extra.Where(chunk => chunk.Type == "IDAT"))
            Chunk(output, type, data);
        Chunk(output, "IEND", []);
        return output.ToArray();
    }

    private static void Chunk(Stream output, string type, byte[] data)
    {
        var chunk = new byte[12 + data.Length];
        BinaryPrimitives.WriteUInt32BigEndian(chunk, (uint)data.Length);
        Encoding.ASCII.GetBytes(type, chunk.AsSpan(4));
        data.CopyTo(chunk, 8);
        BinaryPrimitives.WriteUInt32BigEndian(chunk.AsSpan(8 + data.Length), AvatarImage.Crc(chunk.AsSpan(4, 4 + data.Length)));
        output.Write(chunk);
    }
}
