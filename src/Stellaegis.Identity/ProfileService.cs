using System.Globalization;
using Microsoft.Extensions.Logging;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// What a person reads and changes of their own profile: the name of the account, the language and the time zone
/// they chose, their avatar. What others see of the person — the name and the avatar — is published on change,
/// <see cref="UserProfileChangedEvent"/>.
/// </summary>
/// <remarks>
/// A session carries the language and the time zone of the login (<see cref="ProfileClaims"/>): a change reaches the
/// tokens of an issuer at the next login. A page that has just written the profile signs its session in again, from
/// <see cref="LoginService.CreatePrincipalAsync"/>, and shows it at once.
/// </remarks>
public sealed class ProfileService(
    IAuthUserStore users,
    IAvatarStore avatars,
    IEventPublisher events,
    TimeProvider clock,
    ILogger<ProfileService> logger)
{
    /// <summary>The longest name an account keeps.</summary>
    public const int MaxDisplayNameLength = 200;

    /// <summary>The profile of an enabled account, or <see cref="IdentityErrors.AccountNotFound"/>.</summary>
    public async Task<Result<AccountProfile>> GetAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
    {
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null || !user.IsEnabled)
            return Result.Failure<AccountProfile>(IdentityErrors.AccountNotFound);
        return Result.Success(await ProfileOfAsync(user, cancellationToken));
    }

    /// <summary>
    /// Replaces the name, the language and the time zone of the account. An empty language or time zone is no choice:
    /// the pages and the applications then follow the request.
    /// </summary>
    public async Task<Result<AccountProfile>> UpdateAsync(
        Guid userUniqueId, string? displayName, string? locale, string? timeZone, CancellationToken cancellationToken = default)
    {
        var name = displayName?.Trim() ?? "";
        if (name.Length is 0 or > MaxDisplayNameLength)
            return Result.Failure<AccountProfile>(IdentityErrors.InvalidDisplayName);
        locale = string.IsNullOrWhiteSpace(locale) ? null : locale;
        if (locale is not null && !IsLocale(locale))
            return Result.Failure<AccountProfile>(IdentityErrors.InvalidLocale);
        timeZone = string.IsNullOrWhiteSpace(timeZone) ? null : timeZone;
        if (timeZone is not null && !IsTimeZone(timeZone))
            return Result.Failure<AccountProfile>(IdentityErrors.InvalidTimeZone);

        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null || !user.IsEnabled)
            return Result.Failure<AccountProfile>(IdentityErrors.AccountNotFound);

        var renamed = !string.Equals(user.DisplayName, name, StringComparison.Ordinal);
        user.DisplayName = name;
        user.Locale = locale;
        user.TimeZone = timeZone;
        user.ModifiedAt = clock.GetUtcNow();
        user.ModifiedBy = user.AsActor();
        if (!await users.UpdateAsync(user, cancellationToken))
            return Result.Failure<AccountProfile>(IdentityErrors.AccountNotFound);

        var profile = await ProfileOfAsync(user, cancellationToken);
        if (renamed)
            await PublishAsync(profile, cancellationToken);
        logger.LogInformation("Profile of {UserUniqueId} changed", userUniqueId);
        return Result.Success(profile);
    }

    /// <summary>
    /// Sets the avatar of the account: a PNG of 256 by 256 pixels, kept stripped of every chunk but the image's own,
    /// or <see cref="IdentityErrors.InvalidAvatar"/>.
    /// </summary>
    public async Task<Result<AccountProfile>> SetAvatarAsync(Guid userUniqueId, byte[]? image, CancellationToken cancellationToken = default)
    {
        var normalized = AvatarImage.Normalize(image);
        if (normalized.IsFailure)
            return Result.Failure<AccountProfile>(normalized.Error!);
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null || !user.IsEnabled)
            return Result.Failure<AccountProfile>(IdentityErrors.AccountNotFound);

        await avatars.SetAsync(new AccountAvatar
        {
            UserUniqueId = userUniqueId,
            Image = normalized.Value!,
            ModifiedAt = clock.GetUtcNow(),
            ModifiedBy = user.AsActor(),
        }, cancellationToken);
        var profile = await ProfileOfAsync(user, cancellationToken);
        await PublishAsync(profile, cancellationToken);
        logger.LogInformation("Avatar of {UserUniqueId} set", userUniqueId);
        return Result.Success(profile);
    }

    /// <summary>Removes the avatar of the account; harmless when it has none.</summary>
    public async Task<Result<AccountProfile>> RemoveAvatarAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
    {
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null || !user.IsEnabled)
            return Result.Failure<AccountProfile>(IdentityErrors.AccountNotFound);

        var removed = await avatars.DeleteAsync(userUniqueId, cancellationToken);
        var profile = await ProfileOfAsync(user, cancellationToken);
        if (removed)
        {
            await PublishAsync(profile, cancellationToken);
            logger.LogInformation("Avatar of {UserUniqueId} removed", userUniqueId);
        }
        return Result.Success(profile);
    }

    /// <summary>
    /// Whether <paramref name="value"/> is a culture name .NET knows, in its canonical form: <c>en-GB</c>, never
    /// <c>en-gb</c> nor the invariant culture.
    /// </summary>
    public static bool IsLocale(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 35)
            return false;
        try
        {
            return string.Equals(CultureInfo.GetCultureInfo(value, predefinedOnly: true).Name, value, StringComparison.Ordinal);
        }
        catch (CultureNotFoundException)
        {
            return false;
        }
    }

    /// <summary>
    /// Whether <paramref name="value"/> is an IANA time zone name the system knows, as written: <c>Europe/Paris</c>,
    /// never a Windows name such as <c>Romance Standard Time</c>.
    /// </summary>
    public static bool IsTimeZone(string? value)
        => !string.IsNullOrEmpty(value) && value.Length <= 64
           && TimeZoneInfo.TryFindSystemTimeZoneById(value, out var zone)
           && zone.HasIanaId
           && string.Equals(zone.Id, value, StringComparison.Ordinal);

    private async Task<AccountProfile> ProfileOfAsync(AuthUser user, CancellationToken cancellationToken) => new()
    {
        UserUniqueId = user.UserUniqueId,
        Email = user.Email,
        DisplayName = user.DisplayName,
        Locale = user.Locale,
        TimeZone = user.TimeZone,
        AvatarModifiedAt = await avatars.GetModifiedAtAsync(user.UserUniqueId, cancellationToken),
    };

    private Task PublishAsync(AccountProfile profile, CancellationToken cancellationToken)
        => events.PublishAsync(new UserProfileChangedEvent
        {
            OccurredAt = clock.GetUtcNow(),
            UserUniqueId = profile.UserUniqueId,
            DisplayName = profile.DisplayName,
            AvatarModifiedAt = profile.AvatarModifiedAt,
        }, cancellationToken);
}
