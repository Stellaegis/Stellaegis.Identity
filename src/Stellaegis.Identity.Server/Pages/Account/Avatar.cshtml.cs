using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Stellaegis.Identity.AspNetCore;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>
/// The avatar of the signed-in person: served to their own session, set from the editor of the account page, removed.
/// The address <see cref="IdentityOptions.AvatarUrl"/> names.
/// </summary>
[Authorize]
internal sealed class AccountAvatarModel(IAvatarStore avatars, ProfileService profiles, CookieSignIn signIn, IdentityTexts texts) : PageModel
{
    private const string DataUrlPrefix = "data:image/png;base64,";

    /// <summary>The image the editor exported, as a data URL of a PNG.</summary>
    [BindProperty]
    public string? Image { get; set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        if (this.UserId() is not { } userId || await avatars.GetAsync(userId, cancellationToken) is not { } avatar)
            return NotFound();
        // The address is versioned by the session's picture claim; the image is the person's, for their browser only.
        Response.Headers.CacheControl = "private, max-age=86400";
        Response.Headers.XContentTypeOptions = "nosniff";
        Response.Headers.ContentSecurityPolicy = "default-src 'none'; sandbox";
        return new FileContentResult(avatar.Image, "image/png") { LastModified = avatar.ModifiedAt };
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (this.UserId() is not { } userId)
            return Forbid();
        var image = Decode(Image);
        var set = await profiles.SetAvatarAsync(userId, image, cancellationToken);
        if (set.IsFailure)
        {
            TempData["AvatarError"] = texts.Describe(set.Error!);
            return Redirect("/account");
        }
        await signIn.RefreshAsync(HttpContext, cancellationToken);
        TempData["Notice"] = "Account.Avatar.Saved";
        return Redirect("/account");
    }

    public async Task<IActionResult> OnPostRemoveAsync(CancellationToken cancellationToken)
    {
        if (this.UserId() is not { } userId)
            return Forbid();
        await profiles.RemoveAvatarAsync(userId, cancellationToken);
        await signIn.RefreshAsync(HttpContext, cancellationToken);
        TempData["Notice"] = "Account.Avatar.Removed";
        return Redirect("/account");
    }

    // A data URL longer than the largest file the module reads is refused before it is decoded.
    private static byte[]? Decode(string? dataUrl)
    {
        if (dataUrl is null || !dataUrl.StartsWith(DataUrlPrefix, StringComparison.Ordinal)
            || dataUrl.Length - DataUrlPrefix.Length > (AccountAvatar.MaxFileLength + 2) / 3 * 4)
            return null;
        try
        {
            return Convert.FromBase64String(dataUrl[DataUrlPrefix.Length..]);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
