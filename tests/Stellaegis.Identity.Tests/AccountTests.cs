using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity.Tests;

/// <summary>What a person does to their own account.</summary>
public sealed class AccountTests
{
    [Fact]
    public async Task Changing_the_password_needs_the_current_one_and_a_good_new_one_and_ends_a_lockout()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var account = host.Get<AccountService>();
        var user = (await host.Get<IAuthUserStore>().GetByUniqueIdAsync(id))!;
        user.FailedLoginCount = 3;
        user.BlockedUntil = host.Clock.Now.AddMinutes(10);

        Assert.Equal(IdentityErrors.InvalidCurrentPassword, (await account.ChangePasswordAsync(id, "nope", "New-Horse-10")).Error);
        Assert.Equal(IdentityErrors.PasswordRejectedCode, (await account.ChangePasswordAsync(id, "Correct-Horse-9", "weak")).Error!.Code);
        Assert.True((await account.ChangePasswordAsync(id, "Correct-Horse-9", "New-Horse-10")).IsSuccess);

        Assert.True(await account.VerifyCurrentPasswordAsync(id, "New-Horse-10"));
        Assert.False(await account.VerifyCurrentPasswordAsync(id, "Correct-Horse-9"));
        Assert.Equal(0, user.FailedLoginCount);
        Assert.Null(user.BlockedUntil);
        Assert.Equal(user.AsActor(), user.ModifiedBy);
    }

    [Fact]
    public async Task Changing_the_email_goes_through_a_code_sent_to_the_new_one()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        await host.CreateUserAsync("john@acme.test");
        var account = host.Get<AccountService>();

        Assert.Equal(IdentityErrors.SameEmail, (await account.RequestEmailChangeAsync(id, "Jane@acme.test")).Error);
        Assert.Equal(IdentityErrors.EmailTaken, (await account.RequestEmailChangeAsync(id, "john@acme.test")).Error);
        var code = await account.RequestEmailChangeAsync(id, "jane.doe@acme.test");
        Assert.True(code.IsSuccess);

        Assert.Equal(IdentityErrors.InvalidVerificationCode, (await account.ConfirmEmailChangeAsync(id, "jane.doe@acme.test", "000000")).Error);
        Assert.True((await account.ConfirmEmailChangeAsync(id, "jane.doe@acme.test", code.Value)).IsSuccess);
        Assert.Equal("jane.doe@acme.test", (await host.Get<IAuthUserStore>().GetByUniqueIdAsync(id))!.Email);
        Assert.Null(await host.Get<IEmailVerificationStore>().GetByEmailAsync("jane.doe@acme.test"));
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
        Assert.True(await host.Get<AccountService>().VerifyCurrentPasswordAsync(id, "New-Horse-10"));
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
        var stored = Assert.Single(host.Get<Stellaegis.Identity.InMemory.InMemoryIdentityData>().AccountTokens.Values);
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
    [Fact]
    public async Task A_code_verifies_the_email_within_its_attempts_and_its_lifetime()
    {
        using var host = new TestHost(o => { o.EmailVerification.MaxAttempts = 2; o.EmailVerification.CodeLength = 8; });
        var verification = host.Get<EmailVerificationService>();

        Assert.Equal(IdentityErrors.NoPendingVerification, (await verification.VerifyCodeAsync("jane@acme.test", "1")).Error);
        var code = (await verification.RequestVerificationAsync("Jane@Acme.test", "10.0.0.1")).Value;
        Assert.Equal(8, code.Length);
        Assert.Equal(IdentityErrors.InvalidVerificationCode, (await verification.VerifyCodeAsync("jane@acme.test", "0")).Error);
        Assert.Equal(IdentityErrors.InvalidVerificationCode, (await verification.VerifyCodeAsync("jane@acme.test", "0")).Error);
        Assert.Equal(IdentityErrors.TooManyVerificationAttempts, (await verification.VerifyCodeAsync("jane@acme.test", code)).Error);

        code = (await verification.RequestVerificationAsync("jane@acme.test")).Value;
        Assert.True((await verification.VerifyCodeAsync("jane@acme.test", $"{code} ")).IsSuccess);
        Assert.True(await verification.IsEmailVerifiedAsync("JANE@acme.test"));
        Assert.True((await verification.VerifyCodeAsync("jane@acme.test", "whatever")).IsSuccess);
        Assert.Equal(IdentityErrors.EmailAlreadyVerified, (await verification.RequestVerificationAsync("jane@acme.test")).Error);

        await verification.CleanupAsync("jane@acme.test");
        code = (await verification.RequestVerificationAsync("jane@acme.test")).Value;
        host.Clock.Advance(host.Options.EmailVerification.Lifetime + TimeSpan.FromSeconds(1));
        Assert.Equal(IdentityErrors.VerificationCodeExpired, (await verification.VerifyCodeAsync("jane@acme.test", code)).Error);
    }
}

/// <summary>What an administrator does to accounts.</summary>
public sealed class AdministrationTests
{
    private static readonly Actor Admin = Actor.Parse("admin");

    [Fact]
    public async Task Creating_an_account_needs_a_free_email_and_a_good_password_and_names_its_creator()
    {
        using var host = new TestHost(o => o.Registration.Posture = RegistrationPosture.Closed);
        var administration = host.Get<AccountAdministrationService>();

        Assert.Equal(IdentityErrors.PasswordRejectedCode, (await administration.CreateAsync("jane@acme.test", "Jane", "weak", Admin)).Error!.Code);
        var created = await administration.CreateAsync("Jane@Acme.test", "Jane", "Correct-Horse-9", Admin);
        Assert.True(created.IsSuccess);
        Assert.Equal(IdentityErrors.EmailTaken, (await administration.CreateAsync("jane@acme.test", "Jane", "Correct-Horse-9", Admin)).Error);

        var user = (await host.Get<IAuthUserStore>().GetByUniqueIdAsync(created.Value))!;
        Assert.Equal(Admin, user.CreatedBy);
        Assert.NotEqual(Guid.Empty, user.UserUniqueId);
        Assert.Equal(created.Value, Assert.IsType<UserRegisteredEvent>(Assert.Single(host.Events.Events)).UserUniqueId);
        Assert.Equal(1, await host.Get<IAuthUserStore>().CountAsync());
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

        Assert.True((await administration.ChangePasswordAsync(id, "New-Horse-10", Admin)).IsSuccess);
        Assert.True((await host.Get<LoginService>().AuthenticateAsync("jane@acme.test", "New-Horse-10")).Succeeded);
        Assert.Equal(Admin, (await host.Get<IAuthUserStore>().GetByUniqueIdAsync(id))!.ModifiedBy);
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
