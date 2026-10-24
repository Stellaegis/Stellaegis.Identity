using System.Collections.Concurrent;
using Stellaegis.Primitives;

namespace Stellaegis.Identity.InMemory;

/// <summary>The accounts and everything attached, in memory: for development and tests, lost with the process.</summary>
public sealed class InMemoryIdentityData
{
    internal ConcurrentDictionary<Guid, AuthUser> Users { get; } = new();
    internal ConcurrentDictionary<string, EmailVerification> EmailVerifications { get; } = new(StringComparer.Ordinal);
    internal ConcurrentDictionary<string, AccountToken> AccountTokens { get; } = new(StringComparer.Ordinal);
    internal ConcurrentDictionary<Guid, ConcurrentQueue<LoginEvent>> LoginEvents { get; } = new();
    internal ConcurrentDictionary<Guid, MfaRecord> Mfa { get; } = new();
    internal ConcurrentDictionary<Guid, AccountAvatar> Avatars { get; } = new();
    internal ConcurrentDictionary<Guid, ConcurrentDictionary<string, bool>> RecoveryCodes { get; } = new();
}

internal sealed class InMemoryAuthUserStore(InMemoryIdentityData data) : IAuthUserStore
{
    public Task<AuthUser?> GetByUniqueIdAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
        => Task.FromResult(data.Users.TryGetValue(userUniqueId, out var user) && !user.IsDeleted ? user : null);

    public Task<AuthUser?> GetByEmailAsync(string email, CancellationToken cancellationToken = default)
        => Task.FromResult(data.Users.Values.FirstOrDefault(user => !user.IsDeleted && string.Equals(user.Email, email, StringComparison.Ordinal)));

    public Task<IReadOnlyList<AuthUser>> ListByUniqueIdsAsync(IReadOnlyCollection<Guid> userUniqueIds, CancellationToken cancellationToken = default)
    {
        var wanted = userUniqueIds as IReadOnlySet<Guid> ?? userUniqueIds.ToHashSet();
        return Task.FromResult<IReadOnlyList<AuthUser>>(data.Users.Values.Where(user => !user.IsDeleted && wanted.Contains(user.UserUniqueId)).ToList());
    }

    public Task<IReadOnlyList<AuthUser>> ListAsync(int skip, int take, bool includeDeleted = false, CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyList<AuthUser>>(data.Users.Values
            .Where(user => includeDeleted || !user.IsDeleted)
            .OrderBy(user => user.Email, StringComparer.Ordinal)
            .Skip(skip).Take(take)
            .ToList());

    public Task<IReadOnlyList<AuthUser>> ListBlockedAsync(CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyList<AuthUser>>(data.Users.Values.Where(user => user.IsBlockedAtDoor).ToList());

    public Task<int> CountAsync(bool includeDeleted = false, CancellationToken cancellationToken = default)
        => Task.FromResult(data.Users.Values.Count(user => includeDeleted || !user.IsDeleted));

    public Task CreateAsync(AuthUser user, CancellationToken cancellationToken = default)
    {
        Guard.NotEmpty(user.UserUniqueId);
        if (!data.Users.TryAdd(user.UserUniqueId, user))
            throw new InvalidOperationException($"An account with the id {user.UserUniqueId:N} exists already.");
        return Task.CompletedTask;
    }

    public Task<bool> UpdateAsync(AuthUser user, CancellationToken cancellationToken = default)
    {
        if (!data.Users.TryGetValue(user.UserUniqueId, out var existing) || existing.IsDeleted)
            return Task.FromResult(false);
        data.Users[user.UserUniqueId] = user;
        return Task.FromResult(true);
    }

    public Task<bool> SoftDeleteAsync(Guid userUniqueId, Actor deletedBy, CancellationToken cancellationToken = default)
    {
        if (!data.Users.TryGetValue(userUniqueId, out var user) || user.IsDeleted)
            return Task.FromResult(false);
        user.IsDeleted = true;
        user.DeletedAt = DateTimeOffset.UtcNow;
        user.DeletedBy = deletedBy;
        return Task.FromResult(true);
    }
}

internal sealed class InMemoryLoginEventStore(InMemoryIdentityData data) : ILoginEventStore
{
    private const int Kept = 100;

    public Task AddAsync(LoginEvent loginEvent, CancellationToken cancellationToken = default)
    {
        var queue = data.LoginEvents.GetOrAdd(loginEvent.UserUniqueId, _ => new ConcurrentQueue<LoginEvent>());
        queue.Enqueue(loginEvent);
        while (queue.Count > Kept)
            queue.TryDequeue(out _);
        return Task.CompletedTask;
    }

    public Task<int> DeleteBeforeAsync(DateTimeOffset before, CancellationToken cancellationToken = default)
    {
        var removed = 0;
        foreach (var (id, queue) in data.LoginEvents)
        {
            var kept = queue.Where(e => e.CreatedAt >= before).ToList();
            removed += queue.Count - kept.Count;
            data.LoginEvents[id] = new ConcurrentQueue<LoginEvent>(kept);
        }
        return Task.FromResult(removed);
    }

    public Task<IReadOnlyList<LoginEvent>> GetRecentAsync(Guid userUniqueId, int take = 20, CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyList<LoginEvent>>(data.LoginEvents.TryGetValue(userUniqueId, out var queue)
            ? queue.OrderByDescending(e => e.CreatedAt).Take(take).ToList()
            : []);
}

internal sealed class InMemoryAccountTokenStore(InMemoryIdentityData data) : IAccountTokenStore
{
    private readonly Lock _gate = new();

    public Task CreateAsync(AccountToken token, CancellationToken cancellationToken = default)
    {
        data.AccountTokens[token.TokenHash] = token;
        return Task.CompletedTask;
    }

    public Task<AccountToken?> GetAsync(string tokenHash, CancellationToken cancellationToken = default)
        => Task.FromResult(data.AccountTokens.TryGetValue(tokenHash, out var found) ? found : null);

    public Task<bool> TryConsumeAsync(string tokenHash, DateTimeOffset consumedAt, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (!data.AccountTokens.TryGetValue(tokenHash, out var token) || token.ConsumedAt is not null || token.RevokedAt is not null)
                return Task.FromResult(false);
            token.ConsumedAt = consumedAt;
            return Task.FromResult(true);
        }
    }

    public Task<int> DeleteExpiredBeforeAsync(DateTimeOffset before, CancellationToken cancellationToken = default)
    {
        var removed = 0;
        foreach (var (hash, token) in data.AccountTokens)
        {
            if (token.ExpiresAt < before && data.AccountTokens.TryRemove(hash, out _))
                removed++;
        }
        return Task.FromResult(removed);
    }

    public Task RevokeOutstandingAsync(Guid userUniqueId, AccountTokenPurpose purpose, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            foreach (var token in data.AccountTokens.Values.Where(t => t.UserUniqueId == userUniqueId && t.Purpose == purpose && t.ConsumedAt is null && t.RevokedAt is null))
                token.RevokedAt = revokedAt;
        }
        return Task.CompletedTask;
    }
}

internal sealed class InMemoryEmailVerificationStore(InMemoryIdentityData data) : IEmailVerificationStore
{
    public Task UpsertAsync(EmailVerification verification, CancellationToken cancellationToken = default)
    {
        data.EmailVerifications[verification.Email] = verification;
        return Task.CompletedTask;
    }

    public Task<int> DeleteExpiredBeforeAsync(DateTimeOffset before, CancellationToken cancellationToken = default)
    {
        var removed = 0;
        foreach (var (email, verification) in data.EmailVerifications)
        {
            if (verification.ExpiresAt < before && data.EmailVerifications.TryRemove(email, out _))
                removed++;
        }
        return Task.FromResult(removed);
    }

    public Task<EmailVerification?> GetByEmailAsync(string email, CancellationToken cancellationToken = default)
        => Task.FromResult(data.EmailVerifications.TryGetValue(email, out var found) ? found : null);

    public Task IncrementAttemptsAsync(string email, CancellationToken cancellationToken = default)
    {
        if (data.EmailVerifications.TryGetValue(email, out var found))
            found.Attempts++;
        return Task.CompletedTask;
    }

    public Task MarkVerifiedAsync(string email, CancellationToken cancellationToken = default)
    {
        if (data.EmailVerifications.TryGetValue(email, out var found))
            found.IsVerified = true;
        return Task.CompletedTask;
    }

    public Task DeleteByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        data.EmailVerifications.TryRemove(email, out _);
        return Task.CompletedTask;
    }
}

internal sealed class InMemoryAvatarStore(InMemoryIdentityData data) : IAvatarStore
{
    public Task<AccountAvatar?> GetAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
        => Task.FromResult(data.Avatars.TryGetValue(userUniqueId, out var avatar) ? avatar : null);

    public Task<DateTimeOffset?> GetModifiedAtAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
        => Task.FromResult(data.Avatars.TryGetValue(userUniqueId, out var avatar) ? avatar.ModifiedAt : (DateTimeOffset?)null);

    public Task SetAsync(AccountAvatar avatar, CancellationToken cancellationToken = default)
    {
        Guard.NotNull(avatar);
        if (!data.Users.ContainsKey(avatar.UserUniqueId))
            throw new InvalidOperationException($"No account has the id {avatar.UserUniqueId:N}.");
        data.Avatars[avatar.UserUniqueId] = avatar with { Image = [.. avatar.Image] };
        return Task.CompletedTask;
    }

    public Task<bool> DeleteAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
        => Task.FromResult(data.Avatars.TryRemove(userUniqueId, out _));
}

internal sealed class InMemoryMfaStore(InMemoryIdentityData data) : IMfaStore
{
    private readonly Lock _gate = new();

    public Task ReplaceTotpSecretAsync(Guid userUniqueId, string protectedSecret, CancellationToken cancellationToken = default)
    {
        data.Mfa.AddOrUpdate(userUniqueId, _ => new MfaRecord { UserUniqueId = userUniqueId }, (_, old) => old with { TotpSecret = protectedSecret });
        return Task.CompletedTask;
    }

    public Task<bool> TryUseStepAsync(Guid userUniqueId, long step, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (!data.Mfa.TryGetValue(userUniqueId, out var record) || record.LastUsedStep >= step)
                return Task.FromResult(false);
            data.Mfa[userUniqueId] = record with { LastUsedStep = step };
            return Task.FromResult(true);
        }
    }

    public Task<MfaRecord?> GetAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
        => Task.FromResult(data.Mfa.TryGetValue(userUniqueId, out var record) ? record : null);

    public Task<IReadOnlySet<Guid>> GetEnabledUserIdsAsync(IReadOnlyCollection<Guid> userUniqueIds, CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlySet<Guid>>(userUniqueIds.Where(id => data.Mfa.TryGetValue(id, out var record) && record.IsEnabled).ToHashSet());

    public Task SetPendingSecretAsync(Guid userUniqueId, string protectedSecret, CancellationToken cancellationToken = default)
    {
        data.Mfa.AddOrUpdate(userUniqueId,
            _ => new MfaRecord { UserUniqueId = userUniqueId, PendingSecret = protectedSecret },
            (_, old) => old with { PendingSecret = protectedSecret });
        return Task.CompletedTask;
    }

    public Task EnableAsync(Guid userUniqueId, DateTimeOffset enabledAt, CancellationToken cancellationToken = default)
    {
        data.Mfa.AddOrUpdate(userUniqueId,
            _ => new MfaRecord { UserUniqueId = userUniqueId, IsEnabled = true, EnabledAt = enabledAt, Method = MfaMethod.Totp },
            (_, old) => old with { TotpSecret = old.PendingSecret, PendingSecret = null, IsEnabled = true, EnabledAt = enabledAt, Method = MfaMethod.Totp });
        return Task.CompletedTask;
    }

    public Task EnableEmailAsync(Guid userUniqueId, DateTimeOffset enabledAt, CancellationToken cancellationToken = default)
    {
        data.Mfa[userUniqueId] = new MfaRecord { UserUniqueId = userUniqueId, IsEnabled = true, EnabledAt = enabledAt, Method = MfaMethod.Email };
        return Task.CompletedTask;
    }

    public Task DisableAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
    {
        data.Mfa.AddOrUpdate(userUniqueId,
            _ => new MfaRecord { UserUniqueId = userUniqueId },
            (_, old) => old with { TotpSecret = null, PendingSecret = null, IsEnabled = false, EnabledAt = null });
        return Task.CompletedTask;
    }
}

internal sealed class InMemoryRecoveryCodeStore(InMemoryIdentityData data) : IRecoveryCodeStore
{
    public Task ReplaceAllAsync(Guid userUniqueId, IReadOnlyList<string> codeHashes, CancellationToken cancellationToken = default)
    {
        var set = new ConcurrentDictionary<string, bool>(StringComparer.Ordinal);
        foreach (var hash in codeHashes)
            set[hash] = false;
        data.RecoveryCodes[userUniqueId] = set;
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<string>> GetUnusedHashesAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyList<string>>(data.RecoveryCodes.TryGetValue(userUniqueId, out var set)
            ? set.Where(pair => !pair.Value).Select(pair => pair.Key).ToList()
            : []);

    // Flipping false to true is one atomic step: a code spent by two attempts at once is spent by one of them.
    public Task<bool> MarkUsedAsync(Guid userUniqueId, string codeHash, CancellationToken cancellationToken = default)
        => Task.FromResult(data.RecoveryCodes.TryGetValue(userUniqueId, out var set) && set.TryUpdate(codeHash, true, false));

    public Task<int> CountUnusedAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
        => Task.FromResult(data.RecoveryCodes.TryGetValue(userUniqueId, out var set) ? set.Count(pair => !pair.Value) : 0);

    public Task DeleteAllAsync(Guid userUniqueId, CancellationToken cancellationToken = default)
    {
        data.RecoveryCodes.TryRemove(userUniqueId, out _);
        return Task.CompletedTask;
    }
}
