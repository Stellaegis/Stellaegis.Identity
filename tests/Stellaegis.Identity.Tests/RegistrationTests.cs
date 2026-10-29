using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Hosting;

namespace Stellaegis.Identity.Tests;

/// <summary>How the module is registered, and what its options refuse.</summary>
public sealed class ServiceRegistrationTests
{
    private static IConfiguration Configuration(params (string Key, string Value)[] values)
        => new ConfigurationBuilder().AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value))).Build();

    [Fact]
    public void The_options_are_bound_from_their_section_one_sub_section_per_concern()
    {
        var configuration = Configuration(
            ("Stellaegis:Identity:PasswordHasher:Pepper", "p"),
            ("Stellaegis:Identity:Mfa:SecretKeys:ActiveKeySlot", "2"),
            ("Stellaegis:Identity:Mfa:SecretKeys:Keys:2", "k2"),
            ("Stellaegis:Identity:PasswordHasher:Iterations", "2000"),
            ("Stellaegis:Identity:LoginPolicy:MaxFailedAttempts", "3"),
            ("Stellaegis:Identity:SelfRegistration", "Open"),
            ("Stellaegis:Identity:EmailVerification:CodeLength", "8"));
        using var provider = new ServiceCollection().AddStellaegisIdentityInMemory(configuration).BuildServiceProvider();

        var options = provider.GetRequiredService<IOptions<IdentityOptions>>().Value;
        Assert.Equal("p", options.PasswordHasher.Pepper);
        Assert.Equal(2000, options.PasswordHasher.Iterations);
        Assert.Equal(3, options.LoginPolicy.MaxFailedAttempts);
        Assert.Equal(SelfRegistration.Open, options.SelfRegistration);
        Assert.Equal(8, options.EmailVerification.CodeLength);
        Assert.Equal((2, "k2"), (options.Mfa.SecretKeys.ActiveKeySlot, options.Mfa.SecretKeys.ActiveKey));
        Assert.Equal(SelfRegistration.Closed, new IdentityOptions().SelfRegistration);
    }

    [Fact]
    public async Task A_host_without_a_pepper_refuses_to_start()
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Services.AddStellaegisFrame(ApplicationFrame.WithoutCompartments).AddStellaegisValidation();
        builder.Services.AddStellaegisIdentityInMemory(builder.Configuration);
        using var host = builder.Build();

        var exception = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(TestContext.Current.CancellationToken));
        Assert.Contains("PasswordHasher: Pepper is required", exception.Message);
    }

    [Theory]
    [InlineData("PasswordHasher", "Iterations must be at least 1000")]
    [InlineData("PasswordPolicy", "MaxLength must not be under MinLength")]
    [InlineData("LoginPolicy", "MaxFailedAttempts must be at least 1")]
    [InlineData("EmailVerification", "CodeLength must be between 4 and 10")]
    [InlineData("PasswordReset", "TokenLifetime must be positive")]
    [InlineData("Mfa", "SecretKeys: No key is configured for the active slot 1: set Keys:1")]
    [InlineData("Retention", "LoginEvents must be at least 180 days")]
    public void Each_concern_says_what_is_wrong_with_it(string concern, string error)
    {
        var options = Valid();
        switch (concern)
        {
            case "PasswordHasher": options.PasswordHasher.Iterations = 10; break;
            case "PasswordPolicy": options.PasswordPolicy.MaxLength = 4; break;
            case "LoginPolicy": options.LoginPolicy.MaxFailedAttempts = 0; break;
            case "EmailVerification": options.EmailVerification.CodeLength = 12; break;
            case "PasswordReset": options.PasswordReset.TokenLifetime = TimeSpan.Zero; break;
            case "Mfa": options.Mfa.SecretKeys = new KeySlots(); break;
            case "Retention": options.Retention.LoginEvents = TimeSpan.FromDays(30); break;
        }

        Assert.Equal($"{concern}: {error}.", options.FindError());
        Assert.Null(Valid().FindError());
    }

    private static IdentityOptions Valid()
        => new() { PasswordHasher = { Pepper = "p" }, Mfa = { SecretKeys = new KeySlots { Keys = { [1] = "k" } } } };

    [Fact]
    public void Every_registration_declares_the_module_once_and_resolves_every_service()
    {
        using var host = new TestHost();
        var services = new ServiceCollection()
            .AddStellaegisIdentityInMemory(o => { o.PasswordHasher.Pepper = "p"; o.Mfa.SecretKeys = new KeySlots { Keys = { [1] = "k" } }; })
            .AddStellaegisIdentity(o => { o.PasswordHasher.Pepper = "p"; o.Mfa.SecretKeys = new KeySlots { Keys = { [1] = "k" } }; });
        using var provider = services.BuildServiceProvider();

        var declared = Assert.Single(provider.GetStellaegisModules());
        Assert.Equal("identity", declared.Name);
        Assert.NotNull(host.Get<LoginService>());
        Assert.NotNull(host.Get<RegistrationService>());
        Assert.NotNull(host.Get<AccountService>());
        Assert.NotNull(host.Get<AccountAdministrationService>());
        Assert.NotNull(host.Get<PasswordResetService>());
        Assert.NotNull(host.Get<EmailVerificationService>());
        Assert.NotNull(host.Get<MfaService>());
        Assert.NotNull(host.Get<RecoveryCodeService>());
        Assert.NotNull(host.Get<LoginOtpService>());
        Assert.NotNull(host.Get<PasswordGenerator>());
        Assert.NotNull(host.Get<IBlockedUsersSource>());
    }
}

/// <summary>A person creating their own account.</summary>
public sealed class RegistrationTests
{
    private static async Task VerifyAsync(TestHost host, string email)
    {
        var code = await host.Get<EmailVerificationService>().RequestVerificationAsync(email, EmailVerificationPurpose.Registration, null);
        Assert.True((await host.Get<EmailVerificationService>().VerifyCodeAsync(email, EmailVerificationPurpose.Registration, null, code.Value)).IsSuccess);
    }

    [Fact]
    public async Task A_verified_email_and_a_good_password_make_an_account_that_is_its_own_creator()
    {
        using var host = new TestHost();
        await VerifyAsync(host, "Jane@Acme.test");

        var created = await host.Get<RegistrationService>().CreateAccountAsync("Jane@Acme.test", " Jane ", "Correct-Horse-9");

        Assert.True(created.IsSuccess, created.Error?.ToString());
        var user = await host.Get<IAuthUserStore>().GetByUniqueIdAsync(created.Value);
        Assert.NotNull(user);
        Assert.Equal("jane@acme.test", user.Email);
        Assert.Equal("Jane", user.DisplayName);
        Assert.True(user.IsEnabled);
        Assert.Equal(user.AsActor(), user.CreatedBy);
        Assert.Equal(host.Clock.Now, user.CreatedAt);
        Assert.False(await host.Get<EmailVerificationService>().IsEmailVerifiedAsync("jane@acme.test", EmailVerificationPurpose.Registration, null));
        var registered = Assert.IsType<UserRegisteredEvent>(Assert.Single(host.Events.Events));
        Assert.Equal(created.Value, registered.UserUniqueId);
        Assert.Equal("jane@acme.test", registered.Email);
    }

    [Fact]
    public async Task An_unverified_email_a_taken_email_and_a_weak_password_are_refused()
    {
        using var host = new TestHost();
        var registration = host.Get<RegistrationService>();

        Assert.Equal(IdentityErrors.EmailNotVerified, (await registration.CreateAccountAsync("jane@acme.test", "Jane", "Correct-Horse-9")).Error);

        await VerifyAsync(host, "jane@acme.test");
        Assert.Equal(IdentityErrors.PasswordRejectedCode, (await registration.CreateAccountAsync("jane@acme.test", "Jane", "short")).Error!.Code);

        await host.CreateUserAsync("jane@acme.test");
        Assert.Equal(IdentityErrors.EmailTaken, (await registration.CreateAccountAsync("jane@acme.test", "Jane", "Correct-Horse-9")).Error);
    }

    [Fact]
    public async Task A_closed_self_registration_creates_nothing_even_for_a_verified_email()
    {
        using var closed = new TestHost(o => o.SelfRegistration = SelfRegistration.Closed);
        await VerifyAsync(closed, "jane@acme.test");

        Assert.Equal(IdentityErrors.RegistrationClosed, (await closed.Get<RegistrationService>().CreateAccountAsync("jane@acme.test", "Jane", "Correct-Horse-9")).Error);
        Assert.Equal(0, await closed.Get<IAuthUserStore>().CountAsync());
    }
}
