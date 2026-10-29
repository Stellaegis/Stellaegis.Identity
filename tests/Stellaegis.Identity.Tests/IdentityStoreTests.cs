using System.Data.Common;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Data;

namespace Stellaegis.Identity.Tests;

/// <summary>A database of an engine for the store tests, installed by the installation of its module.</summary>
public interface IIdentityDatabaseFixture : IAsyncLifetime
{
    /// <summary>The connection string a host is configured with.</summary>
    string AppConnectionString { get; }

    /// <summary>Why the database cannot be used, or <see langword="null"/> when it can.</summary>
    string? Unavailable { get; }

    /// <summary>Skips the calling test when the database cannot be used.</summary>
    void SkipWhenUnavailable();

    /// <summary>Opens a connection to the test database, under the application's role or the installer's.</summary>
    Task<DbConnection> OpenAsync(bool asApplication, CancellationToken cancellationToken);
}

/// <summary>What the schema refuses, whatever the engine says it with.</summary>
public enum Refusal
{
    /// <summary>A key or a unique value already taken.</summary>
    Duplicate,

    /// <summary>A row naming an account that does not exist.</summary>
    MissingAccount,

    /// <summary>A value its check refuses.</summary>
    Check,

    /// <summary>A right the role does not hold.</summary>
    PermissionDenied,
}

/// <summary>
/// The seven stores against a real engine, under the application's role: what the schema and the queries
/// guarantee, each port covered. Every engine runs the same scenarios; a derived class says only how its store is
/// built and how its engine refuses.
/// </summary>
public abstract class IdentityStoreTests(IIdentityDatabaseFixture database) : IDisposable
{
    /// <summary>The frame the database is installed for: the one of an enterprise host.</summary>
    public static readonly ApplicationFrame Frame = ApplicationFrame.SingleCompartment("acme");

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly TestClock _clock = new();
    private object? _store;

    /// <summary>The store of the engine on <paramref name="clock"/>, connected under the application's role.</summary>
    protected abstract object CreateStore(TimeProvider clock);

    /// <summary>Asserts that <paramref name="write"/> fails as the engine says <paramref name="refusal"/>.</summary>
    protected abstract Task AssertRefusedAsync(Func<Task> write, Refusal refusal);

    private object Store()
    {
        database.SkipWhenUnavailable();
        return _store ??= CreateStore(_clock);
    }

    private IAuthUserStore Users => (IAuthUserStore)Store();
    private ILoginEventStore Logins => (ILoginEventStore)Store();
    private IAccountTokenStore Tokens => (IAccountTokenStore)Store();
    private IEmailVerificationStore Verifications => (IEmailVerificationStore)Store();
    private IMfaStore Mfa => (IMfaStore)Store();
    private IAvatarStore Avatars => (IAvatarStore)Store();
    private IRecoveryCodeStore RecoveryCodes => (IRecoveryCodeStore)Store();

    /// <summary>The declaration of the database of the engine.</summary>
    protected abstract ModuleDatabase Declaration { get; }

    /// <summary>An account nobody else wrote: the tests share one table.</summary>
    private AuthUser NewUser(string? email = null, bool enabled = true) => new()
    {
        UserUniqueId = Guid.NewGuid(),
        Email = email ?? $"{Guid.NewGuid():N}@acme.test",
        DisplayName = "Jane",
        PasswordHash = "pbkdf2_sha256$1000$salt$hash",
        IsEnabled = enabled,
        CreatedAt = _clock.Now,
        CreatedBy = Actor.Parse("admin"),
        ModifiedAt = _clock.Now,
        ModifiedBy = Actor.Parse("admin"),
    };

    /// <inheritdoc/>
    public void Dispose()
    {
        (_store as IDisposable)?.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task An_account_is_created_read_back_by_id_and_by_email_updated_and_counted()
    {
        var user = NewUser();
        await Users.CreateAsync(user, Ct);

        var byId = await Users.GetByUniqueIdAsync(user.UserUniqueId, Ct);
        var byEmail = await Users.GetByEmailAsync(user.Email, Ct);
        Assert.NotNull(byId);
        Assert.Equal(user.Email, byId.Email);
        Assert.Equal(Actor.Parse("admin"), byId.CreatedBy);
        Assert.Equal(_clock.Now, byId.CreatedAt);
        Assert.Null(byId.DeletedBy);
        Assert.False(byId.EmailVerified);
        Assert.Null(byId.Locale);
        Assert.Null(byId.TimeZone);
        Assert.Equal(user.UserUniqueId, byEmail!.UserUniqueId);

        byId.DisplayName = "Jane Doe";
        byId.EmailVerified = true;
        byId.Locale = "en-GB";
        byId.TimeZone = "America/Argentina/ComodRivadavia";
        byId.FailedLoginCount = 2;
        byId.BlockedUntil = _clock.Now.AddMinutes(15);
        byId.LastLogin = _clock.Now;
        byId.ModifiedBy = byId.AsActor();
        Assert.True(await Users.UpdateAsync(byId, Ct));
        var updated = await Users.GetByUniqueIdAsync(user.UserUniqueId, Ct);
        Assert.Equal("Jane Doe", updated!.DisplayName);
        Assert.Equal(2, updated.FailedLoginCount);
        Assert.True(updated.EmailVerified);
        Assert.Equal("en-GB", updated.Locale);
        Assert.Equal("America/Argentina/ComodRivadavia", updated.TimeZone);
        Assert.Equal(_clock.Now.AddMinutes(15), updated.BlockedUntil);
        Assert.Equal(byId.AsActor(), updated.ModifiedBy);

        Assert.Contains(user.UserUniqueId, (await Users.ListByUniqueIdsAsync([user.UserUniqueId, Guid.NewGuid()], Ct)).Select(u => u.UserUniqueId));
        Assert.Empty(await Users.ListByUniqueIdsAsync([], Ct));
        Assert.True(await Users.CountAsync(cancellationToken: Ct) >= 1);
        Assert.Contains((await Users.ListAsync(0, 1000, cancellationToken: Ct)).Select(u => u.UserUniqueId), id => id == user.UserUniqueId);
    }

    [Fact]
    public async Task A_language_or_a_time_zone_out_of_its_bounds_is_refused_by_the_schema()
    {
        var user = NewUser();
        await Users.CreateAsync(user, Ct);

        user.Locale = "f";
        await AssertRefusedAsync(() => Users.UpdateAsync(user, Ct), Refusal.Check);
        user.Locale = null;
        user.TimeZone = "";
        await AssertRefusedAsync(() => Users.UpdateAsync(user, Ct), Refusal.Check);
    }

    [Fact]
    public async Task An_avatar_is_set_replaced_read_back_and_removed()
    {
        var user = NewUser();
        await Users.CreateAsync(user, Ct);
        Assert.Null(await Avatars.GetAsync(user.UserUniqueId, Ct));
        Assert.Null(await Avatars.GetModifiedAtAsync(user.UserUniqueId, Ct));

        byte[] first = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3];
        await Avatars.SetAsync(new AccountAvatar { UserUniqueId = user.UserUniqueId, Image = first, ModifiedAt = _clock.Now, ModifiedBy = user.AsActor() }, Ct);
        var stored = await Avatars.GetAsync(user.UserUniqueId, Ct);
        Assert.Equal(first, stored!.Image);
        Assert.Equal(_clock.Now, stored.ModifiedAt);
        Assert.Equal(user.AsActor(), stored.ModifiedBy);

        var replacedAt = _clock.Now.AddMinutes(5);
        var second = new byte[AccountAvatar.MaxImageLength];
        await Avatars.SetAsync(new AccountAvatar { UserUniqueId = user.UserUniqueId, Image = second, ModifiedAt = replacedAt, ModifiedBy = Actor.Parse("admin") }, Ct);
        Assert.Equal(second, (await Avatars.GetAsync(user.UserUniqueId, Ct))!.Image);
        Assert.Equal(replacedAt, await Avatars.GetModifiedAtAsync(user.UserUniqueId, Ct));

        Assert.True(await Avatars.DeleteAsync(user.UserUniqueId, Ct));
        Assert.False(await Avatars.DeleteAsync(user.UserUniqueId, Ct));
        Assert.Null(await Avatars.GetAsync(user.UserUniqueId, Ct));

        // The account stays when it is deleted; its avatar goes with it, in the same transaction.
        await Avatars.SetAsync(new AccountAvatar { UserUniqueId = user.UserUniqueId, Image = first, ModifiedAt = _clock.Now, ModifiedBy = user.AsActor() }, Ct);
        Assert.True(await Users.SoftDeleteAsync(user.UserUniqueId, user.AsActor(), Ct));
        Assert.Null(await Avatars.GetAsync(user.UserUniqueId, Ct));
    }

    [Fact]
    public async Task An_avatar_is_refused_by_the_schema_beyond_its_bounds_or_without_an_account()
    {
        var user = NewUser();
        await Users.CreateAsync(user, Ct);
        AccountAvatar Avatar(byte[] image, Guid? owner = null)
            => new() { UserUniqueId = owner ?? user.UserUniqueId, Image = image, ModifiedAt = _clock.Now, ModifiedBy = user.AsActor() };

        await AssertRefusedAsync(() => Avatars.SetAsync(Avatar(new byte[AccountAvatar.MaxImageLength + 1]), Ct), Refusal.Check);
        await AssertRefusedAsync(() => Avatars.SetAsync(Avatar([1, 2, 3]), Ct), Refusal.Check);
        await AssertRefusedAsync(() => Avatars.SetAsync(Avatar(new byte[16], Guid.NewGuid()), Ct), Refusal.MissingAccount);
    }

    [Fact]
    public async Task A_second_account_with_the_same_email_is_refused_by_the_schema()
    {
        var user = NewUser();
        await Users.CreateAsync(user, Ct);

        await AssertRefusedAsync(() => Users.CreateAsync(NewUser(user.Email), Ct), Refusal.Duplicate);
    }

    [Fact]
    public async Task Failed_logins_counted_at_once_all_count_and_the_lockout_falls_where_the_policy_says()
    {
        var user = NewUser();
        await Users.CreateAsync(user, Ct);
        var lockout = TimeSpan.FromMinutes(15);

        // Twenty attempts in flight together: a count read, raised and written back by each would lose most of them.
        var results = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => Users.RecordFailedLoginAsync(user.UserUniqueId, _clock.Now, 5, lockout, Ct)));

        Assert.All(results, result => Assert.NotNull(result));
        Assert.Equal(Enumerable.Range(1, 20), results.Select(result => result!.FailedLoginCount).Order());
        Assert.Equal(4, results.Count(result => result!.BlockedUntil is null));
        Assert.All(results.Where(result => result!.FailedLoginCount >= 5), result => Assert.Equal(_clock.Now.Add(lockout), result!.BlockedUntil));
        var stored = await Users.GetByUniqueIdAsync(user.UserUniqueId, Ct);
        Assert.Equal(20, stored!.FailedLoginCount);
        Assert.Equal(_clock.Now, stored.FailedLoginLast);
        Assert.Equal(_clock.Now.Add(lockout), stored.BlockedUntil);
        Assert.All(results, result => Assert.Equal(result!.FailedLoginCount >= 5, result.IsLockedOutAt(_clock.Now)));

        // A failure counted while the account is locked out starts the lockout again from that failure.
        _clock.Advance(TimeSpan.FromMinutes(1));
        var later = await Users.RecordFailedLoginAsync(user.UserUniqueId, _clock.Now, 5, lockout, Ct);
        Assert.Equal(21, later!.FailedLoginCount);
        Assert.Equal(_clock.Now.Add(lockout), later.BlockedUntil);

        Assert.Null(await Users.RecordFailedLoginAsync(Guid.NewGuid(), _clock.Now, 5, lockout, Ct));
    }

    [Fact]
    public async Task A_deleted_account_stays_hidden_and_keeps_its_id_and_a_disabled_one_is_blocked_at_the_door()
    {
        var deleted = NewUser();
        var address = deleted.Email;
        var disabled = NewUser(enabled: false);
        var fine = NewUser();
        await Users.CreateAsync(deleted, Ct);
        await Users.CreateAsync(disabled, Ct);
        await Users.CreateAsync(fine, Ct);

        Assert.True(await Users.SoftDeleteAsync(deleted.UserUniqueId, Actor.Parse("admin"), Ct));
        Assert.False(await Users.SoftDeleteAsync(deleted.UserUniqueId, Actor.Parse("admin"), Ct));
        Assert.False(await Users.UpdateAsync(deleted, Ct));

        Assert.Null(await Users.GetByUniqueIdAsync(deleted.UserUniqueId, Ct));
        Assert.Null(await Users.GetByEmailAsync(deleted.Email, Ct));
        Assert.DoesNotContain(deleted.UserUniqueId, (await Users.ListAsync(0, 1000, cancellationToken: Ct)).Select(u => u.UserUniqueId));
        var withDeleted = (await Users.ListAsync(0, 1000, includeDeleted: true, Ct)).Single(u => u.UserUniqueId == deleted.UserUniqueId);
        Assert.True(withDeleted.IsDeleted);
        Assert.Equal(Actor.Parse("admin"), withDeleted.DeletedBy);
        Assert.Equal(_clock.Now, withDeleted.DeletedAt);
        // The address went with the deletion: it is free for a new account, under a new identity.
        Assert.Equal($"deleted:{deleted.UserUniqueId:N}", withDeleted.Email);
        await Users.CreateAsync(NewUser(email: address), Ct);
        Assert.NotEqual(deleted.UserUniqueId, (await Users.GetByEmailAsync(address, Ct))!.UserUniqueId);
        Assert.True(await Users.CountAsync(includeDeleted: true, Ct) > await Users.CountAsync(cancellationToken: Ct));

        // The id of a deleted account is taken for good.
        var sameId = NewUser();
        sameId.UserUniqueId = deleted.UserUniqueId;
        await AssertRefusedAsync(() => Users.CreateAsync(sameId, Ct), Refusal.Duplicate);

        var blocked = (await Users.ListBlockedAsync(Ct)).Select(u => u.UserUniqueId).ToList();
        Assert.Contains(deleted.UserUniqueId, blocked);
        Assert.Contains(disabled.UserUniqueId, blocked);
        Assert.DoesNotContain(fine.UserUniqueId, blocked);
    }

    [Fact]
    public async Task Login_events_are_appended_and_read_newest_first()
    {
        var user = NewUser();
        await Users.CreateAsync(user, Ct);
        await Logins.AddAsync(new LoginEvent { UserUniqueId = user.UserUniqueId, Email = user.Email, Success = false, FailReason = LoginFailureReasons.InvalidCredentials, IpAddress = "10.0.0.1", CreatedAt = _clock.Now }, Ct);
        _clock.Advance(TimeSpan.FromMinutes(1));
        await Logins.AddAsync(new LoginEvent { UserUniqueId = user.UserUniqueId, Email = user.Email, Success = true, UserAgent = "wpf", CreatedAt = _clock.Now }, Ct);
        await Logins.AddAsync(new LoginEvent { UserUniqueId = Guid.Empty, Email = "nobody@acme.test", Success = false, FailReason = LoginFailureReasons.InvalidCredentials, CreatedAt = _clock.Now }, Ct);

        var recent = await Logins.GetRecentAsync(user.UserUniqueId, 20, Ct);

        Assert.Equal(2, recent.Count);
        Assert.True(recent[0].Success);
        Assert.Equal("wpf", recent[0].UserAgent);
        Assert.Equal(LoginFailureReasons.InvalidCredentials, recent[1].FailReason);
        Assert.Equal("10.0.0.1", recent[1].IpAddress);
        Assert.Single(await Logins.GetRecentAsync(user.UserUniqueId, 1, Ct));
    }

    [Fact]
    public async Task An_account_token_is_read_back_by_its_hash_consumed_once_and_revoked()
    {
        var user = NewUser();
        await Users.CreateAsync(user, Ct);
        AccountToken Issued(string hash, AccountTokenPurpose purpose = AccountTokenPurpose.PasswordReset, Guid? owner = null) => new()
        {
            TokenHash = hash, UserUniqueId = owner ?? user.UserUniqueId, Purpose = purpose, Delivery = TokenDelivery.Hand, Email = user.Email,
            CreatedAt = _clock.Now, CreatedBy = Actor.Parse("admin"), ExpiresAt = _clock.Now.AddHours(1), IpAddress = "10.0.0.2",
        };
        var token = Issued(AccountTokens.New().Hash);
        await Tokens.CreateAsync(token, Ct);

        var found = await Tokens.GetAsync(token.TokenHash, Ct);
        Assert.NotNull(found);
        Assert.True(found.IsValidAt(_clock.Now));
        Assert.Equal(user.UserUniqueId, found.UserUniqueId);
        Assert.Equal(TokenDelivery.Hand, found.Delivery);
        Assert.Equal(AccountTokenPurpose.PasswordReset, found.Purpose);
        Assert.Equal("admin", found.CreatedBy.Value);
        Assert.Equal("10.0.0.2", found.IpAddress);
        Assert.Null(await Tokens.GetAsync(AccountTokens.New().Hash, Ct));

        var consumedAt = _clock.Now.AddMinutes(5);
        Assert.True(await Tokens.TryConsumeAsync(token.TokenHash, consumedAt, Ct));
        Assert.False(await Tokens.TryConsumeAsync(token.TokenHash, consumedAt.AddHours(1), Ct));   // the first use holds
        var consumed = await Tokens.GetAsync(token.TokenHash, Ct);
        Assert.Equal(consumedAt, consumed!.ConsumedAt);
        Assert.False(consumed.IsValidAt(_clock.Now));

        // Revoking reaches the usable tokens of the purpose, and a revoked token is not consumed.
        var reset = Issued(AccountTokens.New().Hash);
        var activation = Issued(AccountTokens.New().Hash, AccountTokenPurpose.Activation);
        var revert = Issued(AccountTokens.New().Hash, AccountTokenPurpose.EmailRevert);
        var approval = Issued(AccountTokens.New().Hash, AccountTokenPurpose.EmailChangeApproval);
        await Tokens.CreateAsync(reset, Ct);
        await Tokens.CreateAsync(activation, Ct);
        await Tokens.CreateAsync(revert, Ct);
        await Tokens.CreateAsync(approval, Ct);
        Assert.Equal(AccountTokenPurpose.EmailChangeApproval, (await Tokens.GetAsync(approval.TokenHash, Ct))!.Purpose);
        await Tokens.RevokeOutstandingAsync(user.UserUniqueId, AccountTokenPurpose.PasswordReset, _clock.Now, Ct);
        Assert.NotNull((await Tokens.GetAsync(reset.TokenHash, Ct))!.RevokedAt);
        Assert.False(await Tokens.TryConsumeAsync(reset.TokenHash, _clock.Now, Ct));
        Assert.True((await Tokens.GetAsync(activation.TokenHash, Ct))!.IsValidAt(_clock.Now));
        Assert.Equal(AccountTokenPurpose.EmailRevert, (await Tokens.GetAsync(revert.TokenHash, Ct))!.Purpose);

        // A token of an account that does not exist, or a hash that is not one, is refused by the schema.
        await AssertRefusedAsync(() => Tokens.CreateAsync(Issued(AccountTokens.New().Hash, owner: Guid.NewGuid()), Ct), Refusal.MissingAccount);
        await AssertRefusedAsync(() => Tokens.CreateAsync(Issued(new string('Z', 64)), Ct), Refusal.Check);
        await AssertRefusedAsync(() => Tokens.CreateAsync(Issued(AccountTokens.New().Hash.ToUpperInvariant()), Ct), Refusal.Check);
    }

    [Fact]
    public async Task The_purge_deletes_what_came_due_by_its_date_and_says_how_much()
    {
        var user = NewUser();
        await Users.CreateAsync(user, Ct);
        var old = _clock.Now.AddDays(-400);
        await Logins.AddAsync(new LoginEvent { UserUniqueId = user.UserUniqueId, Email = user.Email, Success = false, CreatedAt = old }, Ct);
        await Logins.AddAsync(new LoginEvent { UserUniqueId = user.UserUniqueId, Email = user.Email, Success = true, CreatedAt = _clock.Now }, Ct);
        AccountToken Token(DateTimeOffset expiresAt) => new()
        {
            TokenHash = AccountTokens.New().Hash, UserUniqueId = user.UserUniqueId, Purpose = AccountTokenPurpose.PasswordReset,
            Delivery = TokenDelivery.Email, Email = user.Email, CreatedAt = expiresAt.AddHours(-1), CreatedBy = user.AsActor(), ExpiresAt = expiresAt,
        };
        await Tokens.CreateAsync(Token(old), Ct);
        var live = Token(_clock.Now.AddHours(1));
        await Tokens.CreateAsync(live, Ct);
        var email = $"{Guid.NewGuid():N}@acme.test";
        await Verifications.UpsertAsync(new EmailVerification { Email = email, Code = "1234", CreatedAt = old, ExpiresAt = old.AddMinutes(15) }, Ct);

        var cutoff = _clock.Now.AddDays(-180);
        Assert.True(await Logins.DeleteBeforeAsync(cutoff, Ct) >= 1);
        Assert.True(await Tokens.DeleteExpiredBeforeAsync(cutoff, Ct) >= 1);
        Assert.True(await Verifications.DeleteExpiredBeforeAsync(cutoff, Ct) >= 1);

        Assert.True(Assert.Single(await Logins.GetRecentAsync(user.UserUniqueId, 10, Ct)).Success);
        Assert.NotNull(await Tokens.GetAsync(live.TokenHash, Ct));
        Assert.Null(await Verifications.GetByEmailAsync(email, Ct));
    }

    [Fact]
    public async Task An_email_verification_is_one_per_email_replaced_by_a_new_request_counted_marked_and_deleted()
    {
        var email = $"{Guid.NewGuid():N}@acme.test";
        await Verifications.UpsertAsync(new EmailVerification { Email = email, Code = "1234", CreatedAt = _clock.Now, ExpiresAt = _clock.Now.AddMinutes(15) }, Ct);
        await Verifications.IncrementAttemptsAsync(email, Ct);
        await Verifications.IncrementAttemptsAsync(email, Ct);
        Assert.Equal(2, (await Verifications.GetByEmailAsync(email, Ct))!.Attempts);

        _clock.Advance(TimeSpan.FromMinutes(1));
        await Verifications.UpsertAsync(new EmailVerification { Email = email, Code = "9876543210", CreatedAt = _clock.Now, ExpiresAt = _clock.Now.AddMinutes(15), IpAddress = "10.0.0.3" }, Ct);
        var replaced = await Verifications.GetByEmailAsync(email, Ct);
        Assert.Equal("9876543210", replaced!.Code);
        Assert.Equal(0, replaced.Attempts);
        Assert.False(replaced.IsVerified);

        await Verifications.MarkVerifiedAsync(email, Ct);
        Assert.True((await Verifications.GetByEmailAsync(email, Ct))!.IsVerified);
        await Verifications.DeleteByEmailAsync(email, Ct);
        Assert.Null(await Verifications.GetByEmailAsync(email, Ct));

        // A code that is not 4 to 10 digits is refused by the schema.
        await AssertRefusedAsync(() => Verifications.UpsertAsync(new EmailVerification { Email = email, Code = "12a", CreatedAt = _clock.Now, ExpiresAt = _clock.Now.AddMinutes(15) }, Ct), Refusal.Check);
        await AssertRefusedAsync(() => Verifications.UpsertAsync(new EmailVerification { Email = email, Code = "123", CreatedAt = _clock.Now, ExpiresAt = _clock.Now.AddMinutes(15) }, Ct), Refusal.Check);
    }

    [Fact]
    public async Task Upserts_racing_on_the_same_key_leave_one_row()
    {
        var email = $"{Guid.NewGuid():N}@acme.test";
        var user = NewUser();
        await Users.CreateAsync(user, Ct);

        await Task.WhenAll(Enumerable.Range(0, 8).Select(i => Verifications.UpsertAsync(
            new EmailVerification { Email = email, Code = $"{1000 + i}", CreatedAt = _clock.Now, ExpiresAt = _clock.Now.AddMinutes(15) }, Ct)));
        await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Mfa.SetPendingSecretAsync(user.UserUniqueId, "JBSWY3DPEHPK3PXP", Ct)));

        Assert.NotNull(await Verifications.GetByEmailAsync(email, Ct));
        Assert.Equal("JBSWY3DPEHPK3PXP", (await Mfa.GetAsync(user.UserUniqueId, Ct))!.PendingSecret);
    }

    [Fact]
    public async Task The_second_factor_goes_from_pending_to_enabled_by_authenticator_or_by_email_and_back()
    {
        var user = NewUser();
        var other = NewUser();
        await Users.CreateAsync(user, Ct);
        await Users.CreateAsync(other, Ct);
        Assert.Null(await Mfa.GetAsync(user.UserUniqueId, Ct));

        await Mfa.SetPendingSecretAsync(user.UserUniqueId, "JBSWY3DPEHPK3PXP", Ct);
        var pending = await Mfa.GetAsync(user.UserUniqueId, Ct);
        Assert.Equal("JBSWY3DPEHPK3PXP", pending!.PendingSecret);
        Assert.False(pending.IsEnabled);

        var enabledAt = _clock.Now;
        await Mfa.EnableAsync(user.UserUniqueId, enabledAt, Ct);
        var enabled = await Mfa.GetAsync(user.UserUniqueId, Ct);
        Assert.True(enabled!.IsEnabled);
        Assert.Equal("JBSWY3DPEHPK3PXP", enabled.TotpSecret);
        Assert.Null(enabled.PendingSecret);
        Assert.Equal(enabledAt, enabled.EnabledAt);
        Assert.Equal(MfaMethod.Totp, enabled.Method);
        Assert.Equal(new HashSet<Guid> { user.UserUniqueId }, await Mfa.GetEnabledUserIdsAsync([user.UserUniqueId, other.UserUniqueId], Ct));
        Assert.Empty(await Mfa.GetEnabledUserIdsAsync([], Ct));

        // A code is accepted once: the step recorded only moves forward, atomically.
        Assert.Null(enabled.LastUsedStep);
        Assert.True(await Mfa.TryUseStepAsync(user.UserUniqueId, 100, Ct));
        Assert.False(await Mfa.TryUseStepAsync(user.UserUniqueId, 100, Ct));
        Assert.False(await Mfa.TryUseStepAsync(user.UserUniqueId, 99, Ct));
        Assert.True(await Mfa.TryUseStepAsync(user.UserUniqueId, 101, Ct));
        Assert.Equal(101, (await Mfa.GetAsync(user.UserUniqueId, Ct))!.LastUsedStep);

        // A protected secret — a slot, a nonce, a ciphertext and a tag — fits, and is replaced under another key.
        var protectedSecret = "2:" + Convert.ToBase64String(new byte[12 + 32 + 16]);
        await Mfa.ReplaceTotpSecretAsync(user.UserUniqueId, protectedSecret, Ct);
        Assert.Equal(protectedSecret, (await Mfa.GetAsync(user.UserUniqueId, Ct))!.TotpSecret);

        await Mfa.EnableEmailAsync(other.UserUniqueId, enabledAt, Ct);
        var byEmail = await Mfa.GetAsync(other.UserUniqueId, Ct);
        Assert.Equal(MfaMethod.Email, byEmail!.Method);
        Assert.True(byEmail.IsEnabled);
        Assert.Null(byEmail.TotpSecret);

        await Mfa.DisableAsync(user.UserUniqueId, Ct);
        var disabled = await Mfa.GetAsync(user.UserUniqueId, Ct);
        Assert.False(disabled!.IsEnabled);
        Assert.Null(disabled.TotpSecret);
        Assert.Null(disabled.EnabledAt);
    }

    [Fact]
    public async Task Recovery_codes_are_replaced_as_a_set_and_each_is_spent_once()
    {
        var user = NewUser();
        await Users.CreateAsync(user, Ct);

        await RecoveryCodes.ReplaceAllAsync(user.UserUniqueId, ["h1", "h2", "h3"], Ct);
        Assert.Equal(3, await RecoveryCodes.CountUnusedAsync(user.UserUniqueId, Ct));
        Assert.True(await RecoveryCodes.MarkUsedAsync(user.UserUniqueId, "h2", Ct));
        Assert.False(await RecoveryCodes.MarkUsedAsync(user.UserUniqueId, "h2", Ct));
        Assert.False(await RecoveryCodes.MarkUsedAsync(user.UserUniqueId, "nope", Ct));
        Assert.Equal(new[] { "h1", "h3" }, (await RecoveryCodes.GetUnusedHashesAsync(user.UserUniqueId, Ct)).Order());

        await RecoveryCodes.ReplaceAllAsync(user.UserUniqueId, ["n1"], Ct);
        Assert.Equal(["n1"], await RecoveryCodes.GetUnusedHashesAsync(user.UserUniqueId, Ct));

        await RecoveryCodes.DeleteAllAsync(user.UserUniqueId, Ct);
        Assert.Equal(0, await RecoveryCodes.CountUnusedAsync(user.UserUniqueId, Ct));
        Assert.Empty(await RecoveryCodes.GetUnusedHashesAsync(user.UserUniqueId, Ct));
    }

    [Fact]
    public async Task The_application_role_has_no_right_on_the_record_of_the_installation()
    {
        database.SkipWhenUnavailable();
        await using var connection = await database.OpenAsync(asApplication: true, Ct);
        await using var command = connection.CreateCommand();
        command.CommandText = $"insert into {Declaration.MigrationsTable} (version, script_name, checksum, applied_by) values (9, 'x', 'x', 'x')";

        await AssertRefusedAsync(() => command.ExecuteNonQueryAsync(Ct), Refusal.PermissionDenied);
    }
}
