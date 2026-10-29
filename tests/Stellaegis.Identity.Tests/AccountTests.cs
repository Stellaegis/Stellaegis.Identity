using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity.Tests;

/// <summary>What a person does to their own account.</summary>
public sealed class AccountTests
{
    [Fact]
    public async Task Changing_the_password_needs_the_current_one_and_a_good_new_one_and_forgets_the_failed_logins()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var account = host.Get<AccountService>();
        var user = (await host.Get<IAuthUserStore>().GetByUniqueIdAsync(id))!;
        user.FailedLoginCount = 3;

        Assert.Equal(IdentityErrors.InvalidCurrentPassword, (await account.ChangePasswordAsync(id, "nope", "New-Horse-10")).Error);
        Assert.Equal(IdentityErrors.PasswordRejectedCode, (await account.ChangePasswordAsync(id, "Correct-Horse-9", "weak")).Error!.Code);
        Assert.True((await account.ChangePasswordAsync(id, "Correct-Horse-9", "New-Horse-10")).IsSuccess);

        Assert.True((await account.VerifyCurrentPasswordAsync(id, "New-Horse-10")).IsSuccess);
        Assert.Equal(IdentityErrors.InvalidCurrentPassword, (await account.VerifyCurrentPasswordAsync(id, "Correct-Horse-9")).Error);
        Assert.Equal(1, user.FailedLoginCount);   // the wrong one just typed; the three before went with the change
        Assert.Null(user.BlockedUntil);
        Assert.Equal(user.AsActor(), user.ModifiedBy);
        var changed = Assert.IsType<UserPasswordChangedEvent>(Assert.Single(host.Events.Events));
        Assert.Equal(id, changed.UserUniqueId);
        Assert.Equal(UserPasswordChangedEvent.ChangedReason, changed.Reason);
    }

    [Fact]
    public async Task A_change_of_email_waits_for_the_approval_of_the_previous_address_and_an_administrator_is_the_way_out()
    {
        using var host = new TestHost();   // the posture unless set
        var id = await host.CreateUserAsync();
        await host.CreateUserAsync("john@acme.test");
        var account = host.Get<AccountService>();
        var users = host.Get<IAuthUserStore>();
        async Task<EmailChanged> AskAsync(string to)
        {
            var code = await account.RequestEmailChangeAsync(id, to);
            var changed = await account.ConfirmEmailChangeAsync(id, to, code.Value);
            Assert.True(changed.IsSuccess, changed.Error?.ToString());
            return changed.Value;
        }

        var first = await AskAsync("jane.doe@acme.test");
        Assert.True(first.IsPending);
        Assert.Null(first.RevertToken);
        Assert.Equal("jane@acme.test", (await users.GetByUniqueIdAsync(id))!.Email);   // nothing applied
        Assert.Equal(new EmailChangeApproved("jane@acme.test", "jane.doe@acme.test"), await account.ValidateApprovalTokenAsync(first.ApprovalToken!));

        // A newer request replaces the link; the one approved applies, once.
        var second = await AskAsync("jane.roe@acme.test");
        Assert.Null(await account.ValidateApprovalTokenAsync(first.ApprovalToken!));
        Assert.Equal(IdentityErrors.InvalidApprovalToken, (await account.ApproveEmailChangeAsync(first.ApprovalToken!)).Error);
        var approved = await account.ApproveEmailChangeAsync(second.ApprovalToken!);
        Assert.True(approved.IsSuccess, approved.Error?.ToString());
        Assert.Equal(new EmailChangeApproved("jane@acme.test", "jane.roe@acme.test"), approved.Value);
        var user = (await users.GetByUniqueIdAsync(id))!;
        Assert.Equal("jane.roe@acme.test", user.Email);
        Assert.True(user.EmailVerified);
        Assert.Equal(IdentityErrors.InvalidApprovalToken, (await account.ApproveEmailChangeAsync(second.ApprovalToken!)).Error);

        // The mailbox is lost: the administrator sets the address, unproven, and drops a change that waited.
        var third = await AskAsync("jane.poe@acme.test");
        var administration = host.Get<AccountAdministrationService>();
        Assert.Equal(IdentityErrors.SameEmail, (await administration.ChangeEmailAsync(id, "Jane.Roe@acme.test", Actor.Parse("admin"))).Error);
        Assert.Equal(IdentityErrors.EmailTaken, (await administration.ChangeEmailAsync(id, "john@acme.test", Actor.Parse("admin"))).Error);
        Assert.True((await administration.ChangeEmailAsync(id, "fresh@acme.test", Actor.Parse("admin"))).IsSuccess);
        user = (await users.GetByUniqueIdAsync(id))!;
        Assert.Equal("fresh@acme.test", user.Email);
        Assert.False(user.EmailVerified);
        Assert.Equal(Actor.Parse("admin"), user.ModifiedBy);
        Assert.Null(await account.ValidateApprovalTokenAsync(third.ApprovalToken!));
    }

    [Fact]
    public async Task A_password_the_host_blocklists_is_refused_wherever_a_password_is_accepted()
    {
        using var host = new TestHost(host: services => services.AddSingleton<IPasswordBlocklist>(new Blocklist("Common-Horse-1")));
        var id = await host.CreateUserAsync();
        var account = host.Get<AccountService>();

        Assert.Equal(IdentityErrors.PasswordBlocked, (await account.ChangePasswordAsync(id, "Correct-Horse-9", "Common-Horse-1")).Error);
        Assert.True((await account.ChangePasswordAsync(id, "Correct-Horse-9", "Rare-Horse-2")).IsSuccess);
        var reset = await host.Get<PasswordResetService>().RequestResetAsync("jane@acme.test");
        Assert.Equal(IdentityErrors.PasswordBlocked, (await host.Get<PasswordResetService>().ResetPasswordAsync(reset!, "Common-Horse-1")).Error);
        var created = await host.Get<AccountAdministrationService>().CreateAsync("john@acme.test", "John", TokenDelivery.Email, Actor.Parse("admin"));
        Assert.Equal(IdentityErrors.PasswordBlocked, (await host.Get<ActivationService>().ActivateAsync(created.Value.ActivationToken, "Common-Horse-1")).Error);
        await host.Get<EmailVerificationService>().RequestVerificationAsync("new@acme.test", EmailVerificationPurpose.Registration, null);
        Assert.Equal(IdentityErrors.PasswordBlocked, (await host.Get<RegistrationService>().CreateAccountAsync("new@acme.test", "New", "Common-Horse-1")).Error);

        using var without = new TestHost();
        var other = await without.CreateUserAsync();
        Assert.True((await without.Get<AccountService>().ChangePasswordAsync(other, "Correct-Horse-9", "Common-Horse-1")).IsSuccess);
    }

    private sealed class Blocklist(params string[] blocked) : IPasswordBlocklist
    {
        public ValueTask<bool> IsBlockedAsync(string password, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(blocked.Contains(password, StringComparer.Ordinal));
    }

    [Fact]
    public async Task The_address_of_a_deleted_account_is_free_again_and_a_return_is_a_new_account()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        Assert.True((await host.Get<AccountService>().DeleteAccountAsync(id, "Correct-Horse-9")).IsSuccess);

        var again = await host.CreateUserAsync();
        Assert.NotEqual(id, again);
        var users = host.Get<IAuthUserStore>();
        Assert.Equal(again, (await users.GetByEmailAsync("jane@acme.test"))!.UserUniqueId);
        Assert.Equal($"deleted:{id:N}", (await users.ListAsync(0, 10, includeDeleted: true)).Single(user => user.UserUniqueId == id).Email);
    }

    [Fact]
    public async Task A_password_typed_to_confirm_an_operation_is_a_login_attempt_counted_locked_out_and_traced()
    {
        using var host = new TestHost(o => { o.LoginPolicy.MaxFailedAttempts = 3; o.LoginPolicy.LockoutDuration = TimeSpan.FromMinutes(15); });
        var id = await host.CreateUserAsync();
        var account = host.Get<AccountService>();
        var users = host.Get<IAuthUserStore>();

        Assert.Equal(IdentityErrors.InvalidCurrentPassword, (await account.ChangePasswordAsync(id, "nope", "New-Horse-10", ipAddress: "10.0.0.7")).Error);
        var traced = (await host.Get<ILoginEventStore>().GetRecentAsync(id)).First();
        Assert.Equal(LoginFailureReasons.InvalidCurrentPassword, traced.FailReason);
        Assert.Equal("10.0.0.7", traced.IpAddress);
        Assert.Equal(IdentityErrors.InvalidCurrentPassword, (await account.VerifyCurrentPasswordAsync(id, "nope")).Error);
        Assert.Equal(IdentityErrors.LockedOut, (await account.DeleteAccountAsync(id, "nope")).Error);   // the third locks
        Assert.Equal(3, (await users.GetByUniqueIdAsync(id))!.FailedLoginCount);

        // Locked out, the right password opens nothing — neither here nor at the login —, and counts nothing more.
        Assert.Equal(IdentityErrors.LockedOut, (await account.ChangePasswordAsync(id, "Correct-Horse-9", "New-Horse-10")).Error);
        Assert.Equal(IdentityErrors.LockedOut, (await account.VerifyCurrentPasswordAsync(id, "Correct-Horse-9")).Error);
        Assert.Equal(IdentityErrors.LockedOut, (await account.DeleteAccountAsync(id, "Correct-Horse-9")).Error);
        Assert.Equal(LoginStep.LockedOut, (await host.Get<LoginService>().AuthenticateAsync("jane@acme.test", "Correct-Horse-9")).Step);
        Assert.Equal(3, (await users.GetByUniqueIdAsync(id))!.FailedLoginCount);
        Assert.NotNull(await users.GetByUniqueIdAsync(id));

        host.Clock.Advance(TimeSpan.FromMinutes(16));
        Assert.True((await account.ChangePasswordAsync(id, "Correct-Horse-9", "New-Horse-10")).IsSuccess);
        Assert.Equal(0, (await users.GetByUniqueIdAsync(id))!.FailedLoginCount);
        Assert.True((await account.DeleteAccountAsync(id, "New-Horse-10")).IsSuccess);
    }

    [Fact]
    public async Task Changing_the_email_goes_through_a_code_sent_to_the_new_one()
    {
        using var host = new TestHost(o => o.EmailChange.RequireApprovalByPrevious = false);
        var id = await host.CreateUserAsync();
        await host.CreateUserAsync("john@acme.test");
        var account = host.Get<AccountService>();

        Assert.Equal(IdentityErrors.SameEmail, (await account.RequestEmailChangeAsync(id, "Jane@acme.test")).Error);
        Assert.Equal(IdentityErrors.EmailTaken, (await account.RequestEmailChangeAsync(id, "john@acme.test")).Error);
        var code = await account.RequestEmailChangeAsync(id, "jane.doe@acme.test");
        Assert.True(code.IsSuccess);

        Assert.Equal(IdentityErrors.InvalidVerificationCode, (await account.ConfirmEmailChangeAsync(id, "jane.doe@acme.test", "000000")).Error);
        var changed = await account.ConfirmEmailChangeAsync(id, "jane.doe@acme.test", code.Value);
        Assert.True(changed.IsSuccess);
        Assert.Equal("jane@acme.test", changed.Value.PreviousEmail);
        Assert.Equal("jane.doe@acme.test", changed.Value.NewEmail);
        Assert.Equal("jane@acme.test", await account.ValidateRevertTokenAsync(changed.Value.RevertToken!));
        Assert.Equal("jane.doe@acme.test", (await host.Get<IAuthUserStore>().GetByUniqueIdAsync(id))!.Email);
        Assert.Null(await host.Get<IEmailVerificationStore>().GetAsync("jane.doe@acme.test", EmailVerificationPurpose.EmailChange));
    }

    [Fact]
    public async Task The_link_sent_to_the_previous_address_undoes_the_change_removes_the_password_and_what_came_after()
    {
        using var host = new TestHost(o => o.EmailChange.RequireApprovalByPrevious = false);
        var id = await host.CreateUserAsync();
        var account = host.Get<AccountService>();
        var reset = host.Get<PasswordResetService>();
        async Task<EmailChanged> ChangeAsync(string to)
        {
            var code = await account.RequestEmailChangeAsync(id, to);
            return (await account.ConfirmEmailChangeAsync(id, to, code.Value)).Value;
        }

        // Two changes in a row — what a thief does to shake off the first notice —: the first link survives the second.
        var first = await ChangeAsync("thief@evil.test");
        host.Clock.Advance(TimeSpan.FromMinutes(1));
        var second = await ChangeAsync("other@evil.test");
        host.Clock.Advance(TimeSpan.FromMinutes(1));
        // What the thief set up since: a second factor, a reset link to the new address.
        await host.Get<MfaService>().EnableEmailAsync(id);
        var thiefReset = await reset.RequestResetAsync("other@evil.test");
        Assert.NotNull(thiefReset);
        Assert.Equal("jane@acme.test", await account.ValidateRevertTokenAsync(first.RevertToken!));
        Assert.Equal("thief@evil.test", await account.ValidateRevertTokenAsync(second.RevertToken!));

        host.Events.Events.Clear();
        var reverted = await account.RevertEmailChangeAsync(first.RevertToken!);
        Assert.True(reverted.IsSuccess, reverted.Error?.ToString());
        Assert.Equal("jane@acme.test", reverted.Value.Email);
        Assert.Equal(UserPasswordChangedEvent.RemovedReason, Assert.IsType<UserPasswordChangedEvent>(Assert.Single(host.Events.Events)).Reason);
        var user = (await host.Get<IAuthUserStore>().GetByUniqueIdAsync(id))!;
        Assert.Equal("jane@acme.test", user.Email);
        Assert.True(user.EmailVerified);
        Assert.Null(user.PasswordHash);
        Assert.False(await host.Get<MfaService>().IsEnabledAsync(id));
        Assert.False(await reset.ValidateTokenAsync(thiefReset!));
        Assert.True(await reset.ValidateTokenAsync(reverted.Value.ResetToken));
        Assert.Null(await account.ValidateRevertTokenAsync(second.RevertToken!));   // revoked with the revert
        Assert.Equal(IdentityErrors.InvalidRevertToken, (await account.RevertEmailChangeAsync(first.RevertToken!)).Error);
        Assert.Equal(IdentityErrors.InvalidRevertToken, (await account.RevertEmailChangeAsync(second.RevertToken!)).Error);

        // The thief's password opens nothing; the person chooses a new one by the link, and signs in.
        var login = host.Get<LoginService>();
        Assert.Equal(LoginStep.Failed, (await login.AuthenticateAsync("jane@acme.test", "Correct-Horse-9")).Step);
        host.Events.Events.Clear();
        Assert.True((await reset.ResetPasswordAsync(reverted.Value.ResetToken, "Another-Horse-7")).IsSuccess);
        Assert.Equal(UserPasswordChangedEvent.ResetReason, Assert.IsType<UserPasswordChangedEvent>(Assert.Single(host.Events.Events)).Reason);
        Assert.True((await login.AuthenticateAsync("jane@acme.test", "Another-Horse-7")).Succeeded);

        // A second factor enrolled before the change stays through a revert.
        host.Clock.Advance(TimeSpan.FromMinutes(1));
        await host.Get<MfaService>().EnableEmailAsync(id);
        host.Clock.Advance(TimeSpan.FromMinutes(1));
        var third = await ChangeAsync("thief@evil.test");
        Assert.True((await account.RevertEmailChangeAsync(third.RevertToken!)).IsSuccess);
        Assert.True(await host.Get<MfaService>().IsEnabledAsync(id));
    }

    [Fact]
    public async Task Deleting_the_account_needs_the_password_blocks_it_at_the_door_and_says_so()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var account = host.Get<AccountService>();

        Assert.Equal(IdentityErrors.InvalidCurrentPassword, (await account.DeleteAccountAsync(id, "nope")).Error);
        Assert.True((await account.DeleteAccountAsync(id, "Correct-Horse-9")).IsSuccess);

        Assert.Null(await host.Get<IAuthUserStore>().GetByUniqueIdAsync(id));
        Assert.Equal(IdentityErrors.AccountNotFound, (await account.DeleteAccountAsync(id, "Correct-Horse-9")).Error);
        var blocked = Assert.IsType<UserBlockedEvent>(Assert.Single(host.Events.Events));
        Assert.Equal(AccountAdministrationService.DeletedReason, blocked.Reason);
        Assert.Equal([id.ToString("N")], await host.Get<IBlockedUsersSource>().GetBlockedSubjectsAsync());
    }
}

/// <summary>A person who forgot their password.</summary>
public sealed class PasswordResetTests
{
    [Fact]
    public async Task A_token_resets_the_password_once_and_an_unknown_email_gets_none()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var reset = host.Get<PasswordResetService>();

        Assert.Null(await reset.RequestResetAsync("nobody@acme.test"));
        var token = await reset.RequestResetAsync("JANE@acme.test");
        Assert.NotNull(token);
        Assert.True(await reset.ValidateTokenAsync(token));
        Assert.False(await reset.ValidateTokenAsync(AccountTokens.New().Token));
        Assert.False(await reset.ValidateTokenAsync(""));

        Assert.Equal(IdentityErrors.PasswordRejectedCode, (await reset.ResetPasswordAsync(token, "weak")).Error!.Code);
        Assert.True(await reset.ValidateTokenAsync(token));   // a rejected password spends nothing
        Assert.True((await reset.ResetPasswordAsync(token, "New-Horse-10")).IsSuccess);
        Assert.True((await host.Get<AccountService>().VerifyCurrentPasswordAsync(id, "New-Horse-10")).IsSuccess);
        Assert.False(await reset.ValidateTokenAsync(token));
        Assert.Equal(IdentityErrors.InvalidResetToken, (await reset.ResetPasswordAsync(token, "New-Horse-11")).Error);
    }

    [Fact]
    public async Task The_store_keeps_the_hash_of_a_token_never_the_token()
    {
        using var host = new TestHost();
        await host.CreateUserAsync();
        var reset = host.Get<PasswordResetService>();

        var token = (await reset.RequestResetAsync("jane@acme.test"))!;

        Assert.Equal(43, token.Length);   // 32 bytes, base64url
        var stored = Assert.Single(host.Get<Stellaegis.Identity.InMemory.InMemoryIdentityData>().AccountTokens.Values, t => t.Purpose == AccountTokenPurpose.PasswordReset);
        Assert.Equal(AccountTokens.Hash(token), stored.TokenHash);
        Assert.DoesNotContain(token, stored.TokenHash);
        Assert.Equal(TokenDelivery.Email, stored.Delivery);
        Assert.Equal(AccountTokenPurpose.PasswordReset, stored.Purpose);
    }

    [Fact]
    public async Task A_newer_token_revokes_the_previous_one()
    {
        using var host = new TestHost();
        await host.CreateUserAsync();
        var reset = host.Get<PasswordResetService>();

        var first = (await reset.RequestResetAsync("jane@acme.test"))!;
        var second = (await reset.RequestResetAsync("jane@acme.test"))!;

        Assert.False(await reset.ValidateTokenAsync(first));
        Assert.Equal(IdentityErrors.InvalidResetToken, (await reset.ResetPasswordAsync(first, "New-Horse-10")).Error);
        Assert.True((await reset.ResetPasswordAsync(second, "New-Horse-10")).IsSuccess);
    }

    [Fact]
    public async Task Two_uses_of_one_token_at_once_succeed_once()
    {
        using var host = new TestHost();
        await host.CreateUserAsync();
        var reset = host.Get<PasswordResetService>();
        var token = (await reset.RequestResetAsync("jane@acme.test"))!;

        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(i => reset.ResetPasswordAsync(token, $"New-Horse-{10 + i}")));

        Assert.Equal(1, results.Count(result => result.IsSuccess));
    }

    [Fact]
    public async Task A_token_dies_with_its_lifetime_and_with_the_account()
    {
        using var host = new TestHost(o => o.PasswordReset.TokenLifetime = TimeSpan.FromMinutes(30));
        var id = await host.CreateUserAsync();
        var reset = host.Get<PasswordResetService>();

        var expired = (await reset.RequestResetAsync("jane@acme.test"))!;
        host.Clock.Advance(TimeSpan.FromMinutes(31));
        Assert.False(await reset.ValidateTokenAsync(expired));
        Assert.Equal(IdentityErrors.ResetTokenExpired, (await reset.ResetPasswordAsync(expired, "New-Horse-10")).Error);

        var fresh = (await reset.RequestResetAsync("jane@acme.test"))!;
        await host.Get<AccountAdministrationService>().BlockAsync(id, Actor.Parse("admin"));
        Assert.Equal(IdentityErrors.InvalidResetToken, (await reset.ResetPasswordAsync(fresh, "New-Horse-10")).Error);
    }
}

/// <summary>Proving that a person owns an e-mail.</summary>
public sealed class EmailVerificationTests
{
    private const EmailVerificationPurpose Registration = EmailVerificationPurpose.Registration;

    [Fact]
    public async Task A_code_verifies_the_email_within_its_attempts_and_its_lifetime()
    {
        using var host = new TestHost(o => { o.EmailVerification.MaxAttempts = 2; o.EmailVerification.CodeLength = 8; });
        var verification = host.Get<EmailVerificationService>();

        Assert.Equal(IdentityErrors.NoPendingVerification, (await verification.VerifyCodeAsync("jane@acme.test", Registration, null, "1")).Error);
        var code = (await verification.RequestVerificationAsync("Jane@Acme.test", Registration, null, "10.0.0.1")).Value;
        Assert.Equal(8, code.Length);
        Assert.Equal(IdentityErrors.InvalidVerificationCode, (await verification.VerifyCodeAsync("jane@acme.test", Registration, null, "0")).Error);
        Assert.Equal(IdentityErrors.InvalidVerificationCode, (await verification.VerifyCodeAsync("jane@acme.test", Registration, null, "0")).Error);
        Assert.Equal(IdentityErrors.TooManyVerificationAttempts, (await verification.VerifyCodeAsync("jane@acme.test", Registration, null, code)).Error);

        code = (await verification.RequestVerificationAsync("jane@acme.test", Registration, null)).Value;
        Assert.True((await verification.VerifyCodeAsync("jane@acme.test", Registration, null, $"{code} ")).IsSuccess);
        Assert.True(await verification.IsEmailVerifiedAsync("JANE@acme.test", Registration, null));
        // Verified, the e-mail still answers to its code alone: what failed after the code is tried again with it, never without.
        Assert.Equal(IdentityErrors.InvalidVerificationCode, (await verification.VerifyCodeAsync("jane@acme.test", Registration, null, "whatever")).Error);
        Assert.True((await verification.VerifyCodeAsync("jane@acme.test", Registration, null, code)).IsSuccess);
        // A new request replaces a verified one: the person starts over.
        Assert.True((await verification.RequestVerificationAsync("jane@acme.test", Registration, null)).IsSuccess);
        Assert.False(await verification.IsEmailVerifiedAsync("jane@acme.test", Registration, null));

        await verification.CleanupAsync("jane@acme.test", Registration);
        Assert.Equal(IdentityErrors.NoPendingVerification, (await verification.VerifyCodeAsync("jane@acme.test", Registration, null, code)).Error);
        code = (await verification.RequestVerificationAsync("jane@acme.test", Registration, null)).Value;
        host.Clock.Advance(host.Options.EmailVerification.Lifetime + TimeSpan.FromSeconds(1));
        Assert.Equal(IdentityErrors.VerificationCodeExpired, (await verification.VerifyCodeAsync("jane@acme.test", Registration, null, code)).Error);
    }

    [Fact]
    public async Task A_verification_answers_to_its_purpose_and_its_requester_only()
    {
        using var host = new TestHost();
        var verification = host.Get<EmailVerificationService>();
        var jane = Guid.NewGuid();
        var john = Guid.NewGuid();

        // A stranger registers on the address while Jane asks to change hers to it: two verifications, two codes.
        var registering = (await verification.RequestVerificationAsync("new@acme.test", Registration, null)).Value;
        var changing = (await verification.RequestVerificationAsync("new@acme.test", EmailVerificationPurpose.EmailChange, jane)).Value;
        while (changing == registering)
            changing = (await verification.RequestVerificationAsync("new@acme.test", EmailVerificationPurpose.EmailChange, jane)).Value;
        Assert.NotNull(await host.Get<IEmailVerificationStore>().GetAsync("new@acme.test", Registration));

        // A code proves the e-mail for its own purpose, to its own requester.
        Assert.Equal(IdentityErrors.InvalidVerificationCode, (await verification.VerifyCodeAsync("new@acme.test", Registration, null, changing)).Error);
        Assert.Equal(IdentityErrors.NoPendingVerification, (await verification.VerifyCodeAsync("new@acme.test", EmailVerificationPurpose.EmailChange, john, changing)).Error);
        Assert.True((await verification.VerifyCodeAsync("new@acme.test", EmailVerificationPurpose.EmailChange, jane, changing)).IsSuccess);
        Assert.False(await verification.IsEmailVerifiedAsync("new@acme.test", EmailVerificationPurpose.EmailChange, john));
        Assert.False(await verification.IsEmailVerifiedAsync("new@acme.test", Registration, null));
        Assert.True((await verification.VerifyCodeAsync("new@acme.test", Registration, null, registering)).IsSuccess);

        // Jane's verification served and gone, the registration's is still there.
        await verification.CleanupAsync("new@acme.test", EmailVerificationPurpose.EmailChange);
        Assert.False(await verification.IsEmailVerifiedAsync("new@acme.test", EmailVerificationPurpose.EmailChange, jane));
        Assert.True(await verification.IsEmailVerifiedAsync("new@acme.test", Registration, null));

        // A purpose and its requester go together; a caller that gets it wrong is told so.
        await Assert.ThrowsAsync<ArgumentException>(() => verification.RequestVerificationAsync("new@acme.test", Registration, jane));
        await Assert.ThrowsAsync<ArgumentException>(() => verification.RequestVerificationAsync("new@acme.test", EmailVerificationPurpose.CurrentEmail, null));
    }
}

/// <summary>What an administrator does to accounts.</summary>
public sealed class AdministrationTests
{
    private static readonly Actor Admin = Actor.Parse("admin");

    [Fact]
    public async Task An_account_is_created_without_a_password_and_its_person_activates_it()
    {
        using var host = new TestHost(o => o.SelfRegistration = SelfRegistration.Closed);
        var administration = host.Get<AccountAdministrationService>();
        var activation = host.Get<ActivationService>();

        var created = await administration.CreateAsync("Jane@Acme.test", "Jane", TokenDelivery.Email, Admin);
        Assert.True(created.IsSuccess);
        Assert.Equal("jane@acme.test", created.Value.Email);
        Assert.Equal(IdentityErrors.EmailTaken, (await administration.CreateAsync("jane@acme.test", "Jane", TokenDelivery.Email, Admin)).Error);

        var user = (await host.Get<IAuthUserStore>().GetByUniqueIdAsync(created.Value.UserUniqueId))!;
        Assert.Null(user.PasswordHash);
        Assert.False(user.IsActivated);
        Assert.Equal(Admin, user.CreatedBy);
        Assert.Equal(created.Value.UserUniqueId, Assert.IsType<UserRegisteredEvent>(Assert.Single(host.Events.Events)).UserUniqueId);
        var token = Assert.Single(host.Get<Stellaegis.Identity.InMemory.InMemoryIdentityData>().AccountTokens.Values);
        Assert.Equal((AccountTokenPurpose.Activation, TokenDelivery.Email, Admin), (token.Purpose, token.Delivery, token.CreatedBy));

        // The account does not sign in until its person chose the password by the link.
        Assert.False((await host.Get<LoginService>().AuthenticateAsync("jane@acme.test", "Correct-Horse-9")).Succeeded);
        Assert.True(await activation.ValidateTokenAsync(created.Value.ActivationToken));
        Assert.Equal(IdentityErrors.PasswordRejectedCode, (await activation.ActivateAsync(created.Value.ActivationToken, "weak")).Error!.Code);
        Assert.True((await activation.ActivateAsync(created.Value.ActivationToken, "Correct-Horse-9")).IsSuccess);
        Assert.Equal(IdentityErrors.InvalidActivationToken, (await activation.ActivateAsync(created.Value.ActivationToken, "Correct-Horse-9")).Error);

        Assert.True((await host.Get<LoginService>().AuthenticateAsync("jane@acme.test", "Correct-Horse-9")).Succeeded);
        var activated = (await host.Get<IAuthUserStore>().GetByUniqueIdAsync(created.Value.UserUniqueId))!;
        Assert.Equal(activated.AsActor(), activated.ModifiedBy);   // the person chose it, nobody else
        Assert.True(activated.EmailVerified);   // the link reached the address the system mailed it to
    }

    [Fact]
    public async Task A_link_handed_over_proves_nothing_and_no_reset_is_mailed_to_an_address_never_proven()
    {
        using var host = new TestHost();
        var administration = host.Get<AccountAdministrationService>();
        var created = (await administration.CreateAsync("jane@acme.test", "Jane", TokenDelivery.Hand, Admin)).Value;
        Assert.True((await host.Get<ActivationService>().ActivateAsync(created.ActivationToken, "Correct-Horse-9")).IsSuccess);
        var users = host.Get<IAuthUserStore>();
        Assert.False((await users.GetByUniqueIdAsync(created.UserUniqueId))!.EmailVerified);

        // The address may be mistyped: whoever holds it would receive the reset link.
        Assert.Null(await host.Get<PasswordResetService>().RequestResetAsync("jane@acme.test"));
        Assert.Equal(IdentityErrors.EmailNotVerified, (await administration.IssuePasswordResetAsync(created.UserUniqueId, TokenDelivery.Email, Admin)).Error);

        // Handed over, the reset works, and proves the address no more.
        var byHand = await administration.IssuePasswordResetAsync(created.UserUniqueId, TokenDelivery.Hand, Admin);
        Assert.True((await host.Get<PasswordResetService>().ResetPasswordAsync(byHand.Value.Token, "New-Horse-10")).IsSuccess);
        Assert.False((await users.GetByUniqueIdAsync(created.UserUniqueId))!.EmailVerified);
    }

    [Fact]
    public async Task The_current_address_is_proven_by_a_code_and_then_receives_the_reset()
    {
        using var host = new TestHost();
        var created = (await host.Get<AccountAdministrationService>().CreateAsync("jane@acme.test", "Jane", TokenDelivery.Hand, Admin)).Value;
        await host.Get<ActivationService>().ActivateAsync(created.ActivationToken, "Correct-Horse-9");
        var account = host.Get<AccountService>();

        var code = await account.RequestEmailVerificationAsync(created.UserUniqueId);
        Assert.True(code.IsSuccess);
        Assert.Equal(IdentityErrors.InvalidVerificationCode, (await account.ConfirmEmailVerificationAsync(created.UserUniqueId, "000000" == code.Value ? "111111" : "000000")).Error);
        Assert.True((await account.ConfirmEmailVerificationAsync(created.UserUniqueId, code.Value)).IsSuccess);

        Assert.True((await host.Get<IAuthUserStore>().GetByUniqueIdAsync(created.UserUniqueId))!.EmailVerified);
        Assert.Equal(IdentityErrors.EmailAlreadyVerified, (await account.RequestEmailVerificationAsync(created.UserUniqueId)).Error);
        Assert.NotNull(await host.Get<PasswordResetService>().RequestResetAsync("jane@acme.test"));
    }

    [Fact]
    public async Task An_activation_link_expires_is_issued_again_and_a_reset_is_only_for_an_active_account()
    {
        using var host = new TestHost();
        var administration = host.Get<AccountAdministrationService>();
        var activation = host.Get<ActivationService>();
        var created = (await administration.CreateAsync("jane@acme.test", "Jane", TokenDelivery.Hand, Admin)).Value;

        host.Clock.Advance(TimeSpan.FromDays(8));
        Assert.Equal(IdentityErrors.ActivationTokenExpired, (await activation.ActivateAsync(created.ActivationToken, "Correct-Horse-9")).Error);
        Assert.Equal(IdentityErrors.AccountNotActivated, (await administration.IssuePasswordResetAsync(created.UserUniqueId, TokenDelivery.Hand, Admin)).Error);

        var again = await administration.IssueActivationAsync(created.UserUniqueId, TokenDelivery.Hand, Admin);
        Assert.True(again.IsSuccess);
        Assert.True((await activation.ActivateAsync(again.Value.Token, "Correct-Horse-9")).IsSuccess);
        Assert.Equal(IdentityErrors.AccountAlreadyActivated, (await administration.IssueActivationAsync(created.UserUniqueId, TokenDelivery.Hand, Admin)).Error);
        Assert.Equal(IdentityErrors.AccountNotFound, (await administration.IssueActivationAsync(Guid.NewGuid(), TokenDelivery.Hand, Admin)).Error);
    }

    [Fact]
    public async Task An_account_waiting_for_its_activation_is_refused_at_login_as_anyone_is_and_the_trace_says_why()
    {
        using var host = new TestHost();
        var created = (await host.Get<AccountAdministrationService>().CreateAsync("jane@acme.test", "Jane", TokenDelivery.Hand, Admin)).Value;

        var refused = await host.Get<LoginService>().AuthenticateAsync("jane@acme.test", "anything-at-all");

        Assert.Equal(IdentityErrors.InvalidCredentials, refused.Error);
        var trace = Assert.Single(await host.Get<ILoginEventStore>().GetRecentAsync(created.UserUniqueId));
        Assert.Equal(LoginFailureReasons.NotActivated, trace.FailReason);
        Assert.Equal(0, (await host.Get<IAuthUserStore>().GetByUniqueIdAsync(created.UserUniqueId))!.FailedLoginCount);
    }

    [Fact]
    public async Task Blocking_and_unblocking_say_so_and_feed_the_blocked_users_source()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var administration = host.Get<AccountAdministrationService>();
        var source = host.Get<IBlockedUsersSource>();

        Assert.Empty(await source.GetBlockedSubjectsAsync());
        Assert.True((await administration.BlockAsync(id, Admin)).IsSuccess);
        Assert.True((await administration.BlockAsync(id, Admin)).IsSuccess);
        Assert.Equal([id.ToString("N")], await source.GetBlockedSubjectsAsync());
        var blocked = Assert.IsType<UserBlockedEvent>(Assert.Single(host.Events.Events));
        Assert.Equal(AccountAdministrationService.DisabledReason, blocked.Reason);

        Assert.True((await administration.UnblockAsync(id, Admin)).IsSuccess);
        Assert.Empty(await source.GetBlockedSubjectsAsync());
        Assert.IsType<UserUnblockedEvent>(host.Events.Events[1]);
        Assert.Equal(IdentityErrors.AccountNotFound, (await administration.BlockAsync(Guid.NewGuid(), Admin)).Error);
    }

    [Fact]
    public async Task Deleting_keeps_the_account_blocked_at_the_door_under_its_identity()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var administration = host.Get<AccountAdministrationService>();

        Assert.True((await administration.DeleteAsync(id, Admin)).IsSuccess);
        Assert.Equal(IdentityErrors.AccountNotFound, (await administration.DeleteAsync(id, Admin)).Error);

        Assert.Null(await host.Get<IAuthUserStore>().GetByUniqueIdAsync(id));
        Assert.Equal(0, await host.Get<IAuthUserStore>().CountAsync());
        Assert.Equal(1, await host.Get<IAuthUserStore>().CountAsync(includeDeleted: true));
        var deleted = Assert.Single(await host.Get<IAuthUserStore>().ListAsync(0, 10, includeDeleted: true));
        Assert.Equal(Admin, deleted.DeletedBy);
        Assert.Equal([id.ToString("N")], await host.Get<IBlockedUsersSource>().GetBlockedSubjectsAsync());
    }

    [Fact]
    public async Task The_failed_logins_the_second_factor_and_the_password_are_reset_by_the_administrator()
    {
        using var host = new TestHost(o => o.LoginPolicy.MaxFailedAttempts = 1);
        var id = await host.CreateUserAsync();
        var administration = host.Get<AccountAdministrationService>();
        await host.Get<LoginService>().AuthenticateAsync("jane@acme.test", "nope");
        await host.Get<MfaService>().EnableEmailAsync(id);
        await host.Get<RecoveryCodeService>().GenerateAsync(id);

        Assert.True((await administration.ResetFailedLoginsAsync(id, Admin)).IsSuccess);
        Assert.True((await host.Get<LoginService>().AuthenticateAsync("jane@acme.test", "Correct-Horse-9")).Step == LoginStep.RequiresMfa);

        Assert.True((await administration.ResetMfaAsync(id, Admin)).IsSuccess);
        Assert.False(await host.Get<MfaService>().IsEnabledAsync(id));
        Assert.Equal(0, await host.Get<RecoveryCodeService>().CountRemainingAsync(id));

        // The administrator issues a reset link; the person chooses the new password.
        var reset = await administration.IssuePasswordResetAsync(id, TokenDelivery.Hand, Admin);
        Assert.True(reset.IsSuccess);
        Assert.True((await host.Get<PasswordResetService>().ResetPasswordAsync(reset.Value.Token, "New-Horse-10")).IsSuccess);
        Assert.True((await host.Get<LoginService>().AuthenticateAsync("jane@acme.test", "New-Horse-10")).Succeeded);
        var user = (await host.Get<IAuthUserStore>().GetByUniqueIdAsync(id))!;
        Assert.Equal(user.AsActor(), user.ModifiedBy);
    }
}

/// <summary>Hashing, checking and generating passwords.</summary>
public sealed class PasswordTests
{
    private static PasswordHasher Hasher(int iterations = 1000)
        => new(Options.Create(new IdentityOptions { PasswordHasher = { Pepper = "p", Iterations = iterations } }));

    [Fact]
    public void A_hash_carries_its_iterations_and_verifies_only_its_password()
    {
        var hasher = Hasher(1200);
        var hash = hasher.Hash("Correct-Horse-9");

        Assert.StartsWith("pbkdf2_sha256$1200$", hash);
        Assert.True(hasher.Verify("Correct-Horse-9", hash));
        Assert.True(Hasher(5000).Verify("Correct-Horse-9", hash));
        Assert.False(hasher.Verify("correct-horse-9", hash));
        Assert.False(hasher.Verify("Correct-Horse-9", "md5$x$y$z"));
        Assert.False(hasher.Verify("Correct-Horse-9", "pbkdf2_sha256$1200$not base64$!"));
        Assert.False(hasher.VerifyOrDummy("Correct-Horse-9", null));
        Assert.NotEqual(hash, hasher.Hash("Correct-Horse-9"));
        Assert.Throws<ArgumentException>(() => hasher.Hash(" "));
        Assert.Throws<ArgumentException>(() => new PasswordHasher(Options.Create(new IdentityOptions())));
    }

    [Fact]
    public void The_policy_is_checked_and_scored_and_the_generator_meets_it()
    {
        using var host = new TestHost(o => { o.PasswordPolicy.MinLength = 12; o.PasswordPolicy.RequireSpecialChar = false; });
        var evaluator = host.Get<PasswordStrengthEvaluator>();

        var weak = evaluator.Evaluate("abc");
        Assert.Equal(PasswordStrength.Weak, weak.Strength);
        Assert.False(weak.MeetsPolicy);
        Assert.Equal(["At least 12 characters are required.", "An uppercase letter is required.", "A digit is required."], weak.Violations);
        var strong = evaluator.Evaluate("Correct-Horse-Battery-9");
        Assert.True(strong.MeetsPolicy);
        Assert.Equal(PasswordStrength.VeryStrong, strong.Strength);
        Assert.Equal(100, strong.Score);
        Assert.Empty(evaluator.Violations("CorrectHorse9"));

        for (var i = 0; i < 20; i++)
        {
            var generated = host.Get<PasswordGenerator>().Generate();
            Assert.Equal(12, generated.Length);
            Assert.True(evaluator.Evaluate(generated).MeetsPolicy, generated);
        }
        Assert.Equal(20, host.Get<PasswordGenerator>().Generate(20).Length);
        Assert.Equal(host.Options.PasswordPolicy.MaxLength, host.Get<PasswordGenerator>().Generate(1000).Length);
    }
}

/// <summary>What identifies a person, removed once it no longer serves.</summary>
public sealed class RetentionTests
{
    [Fact]
    public async Task The_purge_removes_the_trace_and_the_tokens_past_their_retention_and_keeps_the_rest()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();   // its activation token, spent
        var login = host.Get<LoginService>();
        await login.AuthenticateAsync("jane@acme.test", "wrong", ipAddress: "10.0.0.1");
        await host.Get<EmailVerificationService>().RequestVerificationAsync("other@acme.test", EmailVerificationPurpose.Registration, null);
        var purge = host.Get<IdentityRetentionService>();

        // Nothing is due yet.
        Assert.Equal(new RetentionReport(0, 0, 0), await purge.PurgeAsync(IdentityRetentionService.Job));

        // Past the retention of the expired, the token and the verification go; the trace stays.
        host.Clock.Advance(TimeSpan.FromDays(40));
        var fresh = await host.Get<PasswordResetService>().RequestResetAsync("jane@acme.test");
        Assert.Equal(new RetentionReport(0, 1, 1), await purge.PurgeAsync(IdentityRetentionService.Job));
        Assert.True(await host.Get<PasswordResetService>().ValidateTokenAsync(fresh!));   // a token still usable stays

        // Past 180 days, the attempt goes; the recent one stays.
        host.Clock.Advance(TimeSpan.FromDays(145));
        await login.AuthenticateAsync("jane@acme.test", "Correct-Horse-9");
        var report = await purge.PurgeAsync(IdentityRetentionService.Job);
        Assert.Equal(1, report.LoginEvents);
        var left = Assert.Single(await host.Get<ILoginEventStore>().GetRecentAsync(id));
        Assert.True(left.Success);
    }

    [Fact]
    public void A_retention_may_be_raised_and_never_lowered_under_its_default()
    {
        Assert.Null(new RetentionOptions { LoginEvents = TimeSpan.FromDays(365), Expired = TimeSpan.FromDays(90) }.FindError());
        Assert.Equal("LoginEvents must be at least 180 days.", new RetentionOptions { LoginEvents = TimeSpan.FromDays(179) }.FindError());
        Assert.Equal("Expired must be at least 30 days.", new RetentionOptions { Expired = TimeSpan.FromDays(7) }.FindError());
    }
}
