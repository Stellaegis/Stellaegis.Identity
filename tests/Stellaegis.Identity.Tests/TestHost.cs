using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity.Tests;

/// <summary>A clock the tests move by hand.</summary>
internal sealed class TestClock : TimeProvider
{
    public DateTimeOffset Now { get; set; } = new(2026, 10, 21, 12, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow() => Now;

    public void Advance(TimeSpan by) => Now = Now.Add(by);
}

/// <summary>Keeps every event published, so that a test reads what the module said.</summary>
internal sealed class CapturingEventPublisher : IEventPublisher
{
    public List<IEvent> Events { get; } = [];

    public Task PublishAsync<TEvent>(TEvent @event, CancellationToken cancellationToken = default) where TEvent : IEvent
    {
        Events.Add(@event);
        return Task.CompletedTask;
    }
}

/// <summary>The module assembled in memory, with a hand-moved clock and captured events, as a test needs it.</summary>
internal sealed class TestHost : IDisposable
{
    public const string Pepper = "test-pepper";

    private readonly ServiceProvider _provider;
    private readonly IServiceScope _scope;

    public TestHost(Action<IdentityOptions>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(Clock);
        services.AddSingleton<IEventPublisher>(Events);
        services.AddStellaegisIdentityInMemory(options =>
        {
            options.PasswordHasher.Pepper = Pepper;
            options.PasswordHasher.Iterations = 1000;   // fast; the count does not change what is tested
            options.LoginPolicy.MinResponseTime = TimeSpan.Zero;
            options.Registration.Posture = RegistrationPosture.Open;
            configure?.Invoke(options);
        });
        services.AddStellaegisLocalBlockedUsersSource();
        _provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
        _scope = _provider.CreateScope();
    }

    public TestClock Clock { get; } = new();

    public CapturingEventPublisher Events { get; } = new();

    public IServiceProvider Services => _scope.ServiceProvider;

    public T Get<T>() where T : notnull => Services.GetRequiredService<T>();

    public IdentityOptions Options => Get<IOptions<IdentityOptions>>().Value;

    /// <summary>An enabled account, created by the administration, whose id is returned.</summary>
    public async Task<Guid> CreateUserAsync(string email = "jane@acme.test", string password = "Correct-Horse-9", string displayName = "Jane")
    {
        var result = await Get<AccountAdministrationService>().CreateAsync(email, displayName, TokenDelivery.Hand, Actor.Parse("admin"));
        Assert.True(result.IsSuccess, result.Error?.ToString());
        var activated = await Get<ActivationService>().ActivateAsync(result.Value.ActivationToken, password);
        Assert.True(activated.IsSuccess, activated.Error?.ToString());
        Events.Events.Clear();
        return result.Value.UserUniqueId;
    }

    public void Dispose()
    {
        _scope.Dispose();
        _provider.Dispose();
    }
}
