using Microsoft.Extensions.Options;
using Npgsql;
using Stellaegis.Identity.PostgreSQL;
using Stellaegis.Primitives;

namespace Stellaegis.Identity.Tests;

/// <summary>
/// The six stores against a real PostgreSQL, under the application's role: what the schema and the queries
/// guarantee, each port covered.
/// </summary>
[Collection(PostgreSqlCollection.Name)]
public sealed class PostgreSqlStoreTests(PostgreSqlFixture database) : IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly TestClock _clock = new();
    private PostgreSqlIdentityStore? _store;

    private PostgreSqlIdentityStore Store()
    {
        database.SkipWhenUnavailable();
        return _store ??= new PostgreSqlIdentityStore(Options.Create(new IdentityDatabaseOptions { ConnectionString = database.AppConnectionString }), _clock);
    }

    private IAuthUserStore Users => Store();
    private ILoginEventStore Logins => Store();
    private IAccountTokenStore Tokens => Store();
    private IEmailVerificationStore Verifications => Store();
    private IMfaStore Mfa => Store();
    private IRecoveryCodeStore RecoveryCodes => Store();

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

    public void Dispose() => _store?.Dispose();

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
        Assert.Equal(user.UserUniqueId, byEmail!.UserUniqueId);

        byId.DisplayName = "Jane Doe";
        byId.EmailVerified = true;
        byId.FailedLoginCount = 2;
        byId.BlockedUntil = _clock.Now.AddMinutes(15);
        byId.LastLogin = _clock.Now;
        byId.ModifiedBy = byId.AsActor();
        Assert.True(await Users.UpdateAsync(byId, Ct));
        var updated = await Users.GetByUniqueIdAsync(user.UserUniqueId, Ct);
        Assert.Equal("Jane Doe", updated!.DisplayName);
        Assert.Equal(2, updated.FailedLoginCount);
        Assert.True(updated.EmailVerified);
        Assert.Equal(_clock.Now.AddMinutes(15), updated.BlockedUntil);
        Assert.Equal(byId.AsActor(), updated.ModifiedBy);

        Assert.Contains(user.UserUniqueId, (await Users.ListByUniqueIdsAsync([user.UserUniqueId, Guid.NewGuid()], Ct)).Select(u => u.UserUniqueId));
        Assert.Empty(await Users.ListByUniqueIdsAsync([], Ct));
        Assert.True(await Users.CountAsync(cancellationToken: Ct) >= 1);
        Assert.Contains((await Users.ListAsync(0, 1000, cancellationToken: Ct)).Select(u => u.UserUniqueId), id => id == user.UserUniqueId);
    }

    [Fact]
    public async Task A_second_account_with_the_same_email_is_refused_by_the_schema()
    {
        var user = NewUser();
        await Users.CreateAsync(user, Ct);

        var exception = await Assert.ThrowsAsync<PostgresException>(() => Users.CreateAsync(NewUser(user.Email), Ct));
        Assert.Equal("23505", exception.SqlState);
    }

    [Fact]
    public async Task A_deleted_account_stays_hidden_and_keeps_its_id_and_a_disabled_one_is_blocked_at_the_door()
    {
        var deleted = NewUser();
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
        Assert.True(await Users.CountAsync(includeDeleted: true, Ct) > await Users.CountAsync(cancellationToken: Ct));

        // The id of a deleted account is taken for good.
        var sameId = NewUser();
        sameId.UserUniqueId = deleted.UserUniqueId;
        var exception = await Assert.ThrowsAsync<PostgresException>(() => Users.CreateAsync(sameId, Ct));
        Assert.Equal("23505", exception.SqlState);

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
        await Tokens.CreateAsync(reset, Ct);
        await Tokens.CreateAsync(activation, Ct);
        await Tokens.RevokeOutstandingAsync(user.UserUniqueId, AccountTokenPurpose.PasswordReset, _clock.Now, Ct);
        Assert.NotNull((await Tokens.GetAsync(reset.TokenHash, Ct))!.RevokedAt);
        Assert.False(await Tokens.TryConsumeAsync(reset.TokenHash, _clock.Now, Ct));
        Assert.True((await Tokens.GetAsync(activation.TokenHash, Ct))!.IsValidAt(_clock.Now));

        // A token of an account that does not exist, or a hash that is not one, is refused by the schema.
        var orphan = await Assert.ThrowsAsync<PostgresException>(() => Tokens.CreateAsync(Issued(AccountTokens.New().Hash, owner: Guid.NewGuid()), Ct));
        Assert.Equal("23503", orphan.SqlState);
        var notAHash = await Assert.ThrowsAsync<PostgresException>(() => Tokens.CreateAsync(Issued(new string('Z', 64)), Ct));
        Assert.Equal("23514", notAHash.SqlState);
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
        var bad = await Assert.ThrowsAsync<PostgresException>(() => Verifications.UpsertAsync(new EmailVerification { Email = email, Code = "12a", CreatedAt = _clock.Now, ExpiresAt = _clock.Now.AddMinutes(15) }, Ct));
        Assert.Equal("23514", bad.SqlState);
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
        command.CommandText = $"insert into {IdentityDatabase.Value.MigrationsTable} (version, script_name, checksum, applied_by) values (9, 'x', 'x', 'x')";

        var exception = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Ct));

        Assert.Equal("42501", exception.SqlState);
    }
}
