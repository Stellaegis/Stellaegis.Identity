using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Stellaegis.Identity.Server.Pages;

/// <summary>The last attempts to sign in to the account, succeeded or not.</summary>
[Authorize]
internal sealed class AccountSecurityModel(ILoginEventStore loginEvents) : PageModel
{
    public IReadOnlyList<LoginEvent> Events { get; private set; } = [];

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        if (this.UserId() is not { } userId)
            return Forbid();
        Events = await loginEvents.GetRecentAsync(userId, 20, cancellationToken);
        return Page();
    }
}
