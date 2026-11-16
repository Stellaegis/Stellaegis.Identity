using OtpNet;
using Stellaegis.Primitives;

namespace Stellaegis.Identity.Tests;

/// <summary>
/// <see cref="UserSecurityStampRenewedEvent"/>: published at every renewal of the stamp, with its reason, and only
/// then — what a host revokes the access tokens of a person on, so that they do not live to their expiration.
/// </summary>
public sealed class SecurityStampEventTests
{
    private static readonly Actor Admin = Actor.Parse("admin");

    private static async Task<string?> StampOfAsync(TestHost host, Guid id)
        => (await host.Get<IAuthUserStore>().GetByUniqueIdAsync(id))!.SecurityStamp;

    /// <summary>The one event of a renewal the gesture made, its reason checked, and the stamp indeed renewed.</summary>
    private static async Task AssertRenewedAsync(TestHost host, Guid id, string before, string reason, int index = 0)
    {
        var renewed = host.Events.Events.OfType<UserSecurityStampRenewedEvent>().ToList();
        Assert.Equal(id, Assert.Single(renewed).UserUniqueId);
        Assert.Equal(reason, renewed[0].Reason);
        Assert.Equal(host.Clock.Now, renewed[0].OccurredAt);
        Assert.Same(renewed[0], host.Events.Events[index]);
        Assert.NotEqual(before, await StampOfAsync(host, id));
        host.Events.Events.Clear();
    }

    [Fact]
    public async Task A_password_changed_publishes_the_renewal_before_its_own_event()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var before = (await StampOfAsync(host, id))!;

        Assert.True((await host.Get<AccountService>().ChangePasswordAsync(id, "Correct-Horse-9", "New-Horse-10")).IsSuccess);

        Assert.IsType<UserPasswordChangedEvent>(host.Events.Events[1]);
        await AssertRenewedAsync(host, id, before, UserSecurityStampRenewedEvent.PasswordReason);
    }

    [Fact]
    public async Task An_email_changed_by_its_person_or_approved_by_the_previous_address_publishes_the_renewal()
    {
        using var host = new TestHost(o => o.EmailChange.RequireApprovalByPrevious = false);
        var id = await host.CreateUserAsync();
        var account = host.Get<AccountService>();
        var before = (await StampOfAsync(host, id))!;
        var code = await account.RequestEmailChangeAsync(id, "jane.doe@acme.test");
        Assert.True((await account.ConfirmEmailChangeAsync(id, "jane.doe@acme.test", code.Value)).IsSuccess);
        await AssertRenewedAsync(host, id, before, UserSecurityStampRenewedEvent.EmailReason);

        using var approving = new TestHost();   // the posture unless set: the previous address approves
        var other = await approving.CreateUserAsync();
        var asked = approving.Get<AccountService>();
        before = (await StampOfAsync(approving, other))!;
        var requested = await asked.RequestEmailChangeAsync(other, "jane.roe@acme.test");
        var pending = await asked.ConfirmEmailChangeAsync(other, "jane.roe@acme.test", requested.Value);
        Assert.True(pending.Value.IsPending);
        Assert.Empty(approving.Events.Events.OfType<UserSecurityStampRenewedEvent>());   // nothing applied yet
        Assert.True((await asked.ApproveEmailChangeAsync(pending.Value.ApprovalToken!)).IsSuccess);
        await AssertRenewedAsync(approving, other, before, UserSecurityStampRenewedEvent.EmailReason);
    }

    [Fact]
    public async Task An_email_set_a_block_and_a_second_factor_reset_by_an_administrator_publish_the_renewal()
    {
        using var host = new TestHost(o => o.Mfa.AllowedMethods = [MfaMethod.Totp, MfaMethod.Email]);
        var id = await host.CreateUserAsync();
        var administration = host.Get<AccountAdministrationService>();

        var before = (await StampOfAsync(host, id))!;
        Assert.True((await administration.ChangeEmailAsync(id, "jane.doe@acme.test", Admin)).IsSuccess);
        await AssertRenewedAsync(host, id, before, UserSecurityStampRenewedEvent.EmailReason);

        Assert.True((await host.Get<MfaService>().EnableEmailAsync(id)).IsSuccess);
        host.Events.Events.Clear();
        before = (await StampOfAsync(host, id))!;
        Assert.True((await administration.ResetMfaAsync(id, Admin)).IsSuccess);
        await AssertRenewedAsync(host, id, before, UserSecurityStampRenewedEvent.MfaReason);

        before = (await StampOfAsync(host, id))!;
        Assert.True((await administration.BlockAsync(id, Admin)).IsSuccess);
        Assert.IsType<UserBlockedEvent>(host.Events.Events[1]);
        await AssertRenewedAsync(host, id, before, UserSecurityStampRenewedEvent.BlockedReason);
    }

    [Fact]
    public async Task A_second_factor_enrolled_enabled_or_disabled_publishes_the_renewal()
    {
        using var host = new TestHost(o => o.Mfa.AllowedMethods = [MfaMethod.Totp, MfaMethod.Email]);
        var id = await host.CreateUserAsync();
        var mfa = host.Get<MfaService>();

        var before = (await StampOfAsync(host, id))!;
        var secret = await mfa.BeginSetupAsync(id);
        Assert.Empty(host.Events.Events);   // a setup begun changes nothing
        var code = new Totp(Base32Encoding.ToBytes(secret)).ComputeTotp(host.Clock.Now.UtcDateTime);
        Assert.True((await mfa.ConfirmSetupAsync(id, code)).IsSuccess);
        await AssertRenewedAsync(host, id, before, UserSecurityStampRenewedEvent.MfaReason);

        before = (await StampOfAsync(host, id))!;
        await mfa.DisableAsync(id);
        await AssertRenewedAsync(host, id, before, UserSecurityStampRenewedEvent.MfaReason);

        before = (await StampOfAsync(host, id))!;
        Assert.True((await mfa.EnableEmailAsync(id)).IsSuccess);
        await AssertRenewedAsync(host, id, before, UserSecurityStampRenewedEvent.MfaReason);
    }

    [Fact]
    public async Task Nothing_renewed_publishes_nothing()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var administration = host.Get<AccountAdministrationService>();

        Assert.True((await administration.BlockAsync(id, Admin)).IsSuccess);
        host.Events.Events.Clear();
        Assert.True((await administration.BlockAsync(id, Admin)).IsSuccess);   // already blocked
        Assert.True((await administration.UnblockAsync(id, Admin)).IsSuccess);
        Assert.Equal(IdentityErrors.AccountNotFound, (await administration.ChangeEmailAsync(Guid.NewGuid(), "x@acme.test", Admin)).Error);
        Assert.Equal(IdentityErrors.InvalidCurrentPassword, (await host.Get<AccountService>().ChangePasswordAsync(id, "wrong", "New-Horse-10")).Error);
        Assert.True((await administration.DeleteAsync(id, Admin)).IsSuccess);   // refused as deleted, no stamp renewed

        Assert.Empty(host.Events.Events.OfType<UserSecurityStampRenewedEvent>());
        Assert.Contains(host.Events.Events, e => e is UserBlockedEvent { Reason: AccountAdministrationService.DeletedReason });
    }
}
