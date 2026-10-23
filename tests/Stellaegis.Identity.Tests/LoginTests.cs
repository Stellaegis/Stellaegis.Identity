using OtpNet;
using Stellaegis.Primitives;

namespace Stellaegis.Identity.Tests;

/// <summary>A person signing in.</summary>
public sealed class LoginTests
{
    [Fact]
    public async Task The_right_password_signs_the_person_in_with_their_subject_and_records_the_login()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();

        var result = await host.Get<LoginService>().AuthenticateAsync("JANE@acme.test", "Correct-Horse-9", ipAddress: "10.0.0.1");

        Assert.Equal(LoginStep.Succeeded, result.Step);
        Assert.True(result.Succeeded);
        Assert.Equal(id.ToString("N"), result.Principal!.FindFirst("sub")!.Value);
        Assert.Equal("jane@acme.test", result.Principal.FindFirst("email")!.Value);
        Assert.Equal([AuthenticationMethods.Password], result.Principal.FindAll(AuthenticationMethods.ClaimType).Select(c => c.Value));
        Assert.Equal(LoginService.DefaultAuthenticationType, result.Principal.Identity!.AuthenticationType);
        var user = await host.Get<IAuthUserStore>().GetByUniqueIdAsync(id);
        Assert.Equal(host.Clock.Now, user!.LastLogin);
        var loginEvent = Assert.Single(await host.Get<ILoginEventStore>().GetRecentAsync(id));
        Assert.True(loginEvent.Success);
        Assert.Equal("10.0.0.1", loginEvent.IpAddress);
    }

    [Fact]
    public async Task A_wrong_password_an_unknown_email_and_a_disabled_account_get_the_same_answer()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var login = host.Get<LoginService>();

        var wrong = await login.AuthenticateAsync("jane@acme.test", "nope");
        var unknown = await login.AuthenticateAsync("nobody@acme.test", "Correct-Horse-9");
        await host.Get<AccountAdministrationService>().BlockAsync(id, Actor.Parse("admin"));
        var disabled = await login.AuthenticateAsync("jane@acme.test", "Correct-Horse-9");
        var blank = await login.AuthenticateAsync("", "");

        foreach (var result in new[] { wrong, unknown, disabled, blank })
        {
            Assert.Equal(LoginStep.Failed, result.Step);
            Assert.Equal(IdentityErrors.InvalidCredentials, result.Error);
            Assert.Null(result.Principal);
        }
        Assert.Equal(1, (await host.Get<IAuthUserStore>().GetByUniqueIdAsync(id))!.FailedLoginCount);
        Assert.Equal(LoginFailureReasons.InvalidCredentials, (await host.Get<ILoginEventStore>().GetRecentAsync(Guid.Empty)).Single().FailReason);
        Assert.Equal(2, (await host.Get<ILoginEventStore>().GetRecentAsync(id)).Count);
    }

    [Fact]
    public async Task Too_many_failed_logins_lock_the_account_until_the_lockout_ends()
    {
        using var host = new TestHost(o => { o.LoginPolicy.MaxFailedAttempts = 2; o.LoginPolicy.LockoutDuration = TimeSpan.FromMinutes(15); });
        var id = await host.CreateUserAsync();
        var login = host.Get<LoginService>();

        await login.AuthenticateAsync("jane@acme.test", "nope");
        host.Clock.Advance(TimeSpan.FromSeconds(1));
        await login.AuthenticateAsync("jane@acme.test", "nope");
        host.Clock.Advance(TimeSpan.FromSeconds(1));
        var locked = await login.AuthenticateAsync("jane@acme.test", "Correct-Horse-9");
        Assert.Equal(LoginStep.LockedOut, locked.Step);
        Assert.Equal(IdentityErrors.LockedOut, locked.Error);
        Assert.Equal(LoginFailureReasons.LockedOut, (await host.Get<ILoginEventStore>().GetRecentAsync(id)).First().FailReason);

        host.Clock.Advance(TimeSpan.FromMinutes(16));
        var again = await login.AuthenticateAsync("jane@acme.test", "Correct-Horse-9");
        Assert.True(again.Succeeded);
        Assert.Equal(0, (await host.Get<IAuthUserStore>().GetByUniqueIdAsync(id))!.FailedLoginCount);
    }

    [Fact]
    public async Task A_second_factor_is_asked_when_enabled_and_set_up_when_the_policy_requires_one()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var mfa = host.Get<MfaService>();
        var secret = await mfa.BeginSetupAsync(id);
        var code = new Totp(Base32Encoding.ToBytes(secret)).ComputeTotp(host.Clock.Now.UtcDateTime);
        Assert.True((await mfa.ConfirmSetupAsync(id, code)).IsSuccess);

        var result = await host.Get<LoginService>().AuthenticateAsync("jane@acme.test", "Correct-Horse-9");
        Assert.Equal(LoginStep.RequiresMfa, result.Step);
        Assert.Equal(id, result.UserUniqueId);
        Assert.Equal("jane@acme.test", result.Email);
        Assert.False(await mfa.ValidateCodeAsync(id, code));   // spent by the setup
        host.Clock.Advance(TimeSpan.FromSeconds(30));
        Assert.True(await mfa.ValidateCodeAsync(id, new Totp(Base32Encoding.ToBytes(secret)).ComputeTotp(host.Clock.Now.UtcDateTime)));
        Assert.False(await mfa.ValidateCodeAsync(id, "000000"));
        var principal = await host.Get<LoginService>().CreatePrincipalAsync(id, AuthenticationMethods.PasswordAndCode);
        Assert.Equal(id.ToString("N"), principal!.FindFirst("sub")!.Value);
        Assert.Equal(["pwd", "otp", "mfa"], principal.FindAll("amr").Select(c => c.Value));
        await Assert.ThrowsAsync<ArgumentException>(() => host.Get<LoginService>().CreatePrincipalAsync(id, []));

        using var required = new TestHost(o => o.Mfa.RequireForAllUsers = true);
        var other = await required.CreateUserAsync();
        var setup = await required.Get<LoginService>().AuthenticateAsync("jane@acme.test", "Correct-Horse-9");
        Assert.Equal(LoginStep.RequiresMfaSetup, setup.Step);
        Assert.Equal(other, setup.UserUniqueId);
    }

    [Fact]
    public async Task A_blocked_account_gets_no_principal_after_its_second_factor()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        await host.Get<AccountAdministrationService>().BlockAsync(id, Actor.Parse("admin"));

        Assert.Null(await host.Get<LoginService>().CreatePrincipalAsync(id, AuthenticationMethods.PasswordAndCode));
    }

    [Fact]
    public void The_email_one_time_code_is_spent_on_its_first_match_and_dies_after_ten_minutes()
    {
        var clock = new TestClock();
        var otp = new LoginOtpService(clock);
        var id = Guid.NewGuid();

        var code = otp.Generate(id);
        Assert.Equal(6, code.Length);
        Assert.False(otp.Validate(id, "000000"));
        Assert.True(otp.Validate(id, $" {code} "));
        Assert.False(otp.Validate(id, code));

        code = otp.Generate(id);
        clock.Advance(TimeSpan.FromMinutes(11));
        Assert.False(otp.Validate(id, code));
    }
}

/// <summary>The second factor and the recovery codes.</summary>
public sealed class MfaTests
{
    [Fact]
    public async Task Setting_up_an_authenticator_needs_a_first_code_and_can_be_disabled()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var mfa = host.Get<MfaService>();

        Assert.Equal(IdentityErrors.MfaNotPending, (await mfa.ConfirmSetupAsync(id, "123456")).Error);
        var secret = await mfa.BeginSetupAsync(id);
        Assert.Equal(IdentityErrors.InvalidMfaCode, (await mfa.ConfirmSetupAsync(id, "000000")).Error);
        Assert.False(await mfa.IsEnabledAsync(id));

        var code = new Totp(Base32Encoding.ToBytes(secret)).ComputeTotp(host.Clock.Now.UtcDateTime);
        Assert.True((await mfa.ConfirmSetupAsync(id, code)).IsSuccess);
        var status = await mfa.GetStatusAsync(id);
        Assert.True(status!.IsEnabled);
        Assert.Equal(MfaMethod.Totp, status.Method);
        Assert.Null(status.PendingSecret);
        Assert.Equal(host.Clock.Now, status.EnabledAt);
        Assert.Contains("otpauth://totp/Stellaegis:jane%40acme.test?secret=", MfaService.GetOtpAuthUri(secret, "jane@acme.test"));

        await mfa.DisableAsync(id);
        Assert.False(await mfa.IsEnabledAsync(id));
        Assert.False(await mfa.ValidateCodeAsync(id, code));
    }

    [Fact]
    public async Task A_code_is_accepted_once_and_never_one_of_an_earlier_step()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var mfa = host.Get<MfaService>();
        var secret = await mfa.BeginSetupAsync(id);
        string CodeAt(DateTimeOffset at) => new Totp(Base32Encoding.ToBytes(secret)).ComputeTotp(at.UtcDateTime);
        var enrolled = host.Clock.Now;
        Assert.True((await mfa.ConfirmSetupAsync(id, CodeAt(enrolled))).IsSuccess);

        host.Clock.Advance(TimeSpan.FromSeconds(30));
        var current = CodeAt(host.Clock.Now);
        var both = await Task.WhenAll(mfa.ValidateCodeAsync(id, current), mfa.ValidateCodeAsync(id, current));
        Assert.Equal(1, both.Count(accepted => accepted));       // two uses at once: one passes
        Assert.False(await mfa.ValidateCodeAsync(id, current));  // a replay
        Assert.False(await mfa.ValidateCodeAsync(id, CodeAt(enrolled)));   // still within the window, but earlier

        host.Clock.Advance(TimeSpan.FromSeconds(30));
        Assert.True(await mfa.ValidateCodeAsync(id, CodeAt(host.Clock.Now)));
    }

    [Fact]
    public async Task The_secret_is_kept_protected_bound_to_its_account_and_protected_again_under_a_new_key_at_its_use()
    {
        using var host = new TestHost(o => o.Mfa.SecretKeys = new KeySlots { ActiveKeySlot = 1, Keys = { [1] = "k1", [2] = "k2" } });
        var id = await host.CreateUserAsync();
        var mfa = host.Get<MfaService>();
        var secret = await mfa.BeginSetupAsync(id);
        Assert.True((await mfa.ConfirmSetupAsync(id, new Totp(Base32Encoding.ToBytes(secret)).ComputeTotp(host.Clock.Now.UtcDateTime))).IsSuccess);

        var stored = (await mfa.GetStatusAsync(id))!.TotpSecret!;
        Assert.StartsWith("1:", stored);
        Assert.DoesNotContain(secret, stored);
        var protector = host.Get<TotpSecretProtector>();
        Assert.Equal((secret, 1), protector.Unprotect(id, stored));
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() => protector.Unprotect(Guid.NewGuid(), stored));

        // The key rotates: the secret written under slot 1 still opens, and is protected again under slot 2 at its use.
        host.Get<Microsoft.Extensions.Options.IOptions<IdentityOptions>>().Value.Mfa.SecretKeys = new KeySlots { ActiveKeySlot = 2, Keys = { [1] = "k1", [2] = "k2" } };
        host.Clock.Advance(TimeSpan.FromSeconds(30));
        Assert.True(await mfa.ValidateCodeAsync(id, new Totp(Base32Encoding.ToBytes(secret)).ComputeTotp(host.Clock.Now.UtcDateTime)));
        var rotated = (await mfa.GetStatusAsync(id))!.TotpSecret!;
        Assert.StartsWith("2:", rotated);
        Assert.Equal((secret, 2), protector.Unprotect(id, rotated));
    }

    [Fact]
    public async Task The_email_method_needs_no_setup()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var mfa = host.Get<MfaService>();

        await mfa.EnableEmailAsync(id);

        Assert.True(await mfa.IsEnabledAsync(id));
        Assert.Equal(MfaMethod.Email, await mfa.GetMethodAsync(id));
        Assert.Equal([id], await host.Get<IMfaStore>().GetEnabledUserIdsAsync([id, Guid.NewGuid()]));
    }

    [Fact]
    public async Task Recovery_codes_are_issued_by_eight_formatted_unique_and_each_spent_once()
    {
        using var host = new TestHost();
        var id = await host.CreateUserAsync();
        var codes = host.Get<RecoveryCodeService>();

        var issued = await codes.GenerateAsync(id);
        Assert.Equal(RecoveryCodeService.CodeCount, issued.Count);
        Assert.All(issued, code => Assert.Matches("^[A-Z2-9]{5}-[A-Z2-9]{5}$", code));
        Assert.Equal(issued.Count, issued.Distinct().Count());

        Assert.True(await codes.TryConsumeAsync(id, issued[0]));
        Assert.False(await codes.TryConsumeAsync(id, issued[0]));
        Assert.True(await codes.TryConsumeAsync(id, issued[1].Replace("-", "").ToLowerInvariant()));
        Assert.False(await codes.TryConsumeAsync(id, "ZZZZZ-ZZZZZ"));
        Assert.False(await codes.TryConsumeAsync(id, ""));
        Assert.Equal(RecoveryCodeService.CodeCount - 2, await codes.CountRemainingAsync(id));

        var fresh = await codes.GenerateAsync(id);
        Assert.False(await codes.TryConsumeAsync(id, issued[2]));
        Assert.True(await codes.TryConsumeAsync(id, fresh[0]));
    }
}
