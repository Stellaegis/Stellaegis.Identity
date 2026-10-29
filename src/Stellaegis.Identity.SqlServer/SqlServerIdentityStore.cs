using System.Data.Common;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Data;

namespace Stellaegis.Identity.SqlServer;

/// <summary>
/// The seven stores of the accounts on SQL Server, in the schema <c>ident</c>: one object, one connection string, the
/// repositories of <see cref="IdentityDatabase"/> handed out by a unit of work of <c>Stellaegis.Primitives.Data</c>.
/// Each operation opens its own unit of work and closes it: no connection outlives a call, and none is shared
/// between two. The two operations that write several rows at once — the replacement of the recovery codes, the
/// deletion of an account with its avatar — run in a transaction. The pool of the connections is <c>Microsoft.Data.SqlClient</c>'s, by connection string.
/// </summary>
internal sealed class SqlServerIdentityStore
    : IAuthUserStore, ILoginEventStore, IAccountTokenStore, IEmailVerificationStore, IMfaStore, IAvatarStore, IRecoveryCodeStore
{
    private readonly Func<CancellationToken, Task<DbConnection>> _open;
    private readonly AdoUnitOfWorkFactory<IdentityDatabase> _units;
    private readonly TimeProvider _clock;

    /// <summary>Creates the store from options the host validated at startup, or that a caller built by hand.</summary>
    /// <exception cref="InvalidOperationException">The options do not hold: <see cref="IdentityDatabaseOptions.FindError"/> says why.</exception>
    public SqlServerIdentityStore(IOptions<IdentityDatabaseOptions> options, TimeProvider clock)
        : this(OpenFrom(Guard.NotNull(options).Value), clock)
    {
    }

    /// <summary>Creates the store on connections <paramref name="open"/> opens — the tests take the application's identity on them.</summary>
    internal SqlServerIdentityStore(Func<CancellationToken, Task<DbConnection>> open, TimeProvider clock)
    {
        _open = Guard.NotNull(open);
        _clock = Guard.NotNull(clock);

        var registry = new RepositoryRegistry<IdentityDatabase>()
            .Add<UserRepository>((connection, transaction) => new UserRepository(connection, transaction))
            .Add<LoginEventRepository>((connection, transaction) => new LoginEventRepository(connection, transaction))
            .Add<AccountTokenRepository>((connection, transaction) => new AccountTokenRepository(connection, transaction))
            .Add<EmailVerificationRepository>((connection, transaction) => new EmailVerificationRepository(connection, transaction))
            .Add<MfaRepository>((connection, transaction) => new MfaRepository(connection, transaction))
            .Add<AvatarRepository>((connection, transaction) => new AvatarRepository(connection, transaction))
            .Add<RecoveryCodeRepository>((connection, transaction) => new RecoveryCodeRepository(connection, transaction));

        _units = new AdoUnitOfWorkFactory<IdentityDatabase>(_open, registry);
    }

    /// <summary>Opens a connection under the application's role, as the verification of the database needs one.</summary>
    public Task<DbConnection> OpenConnectionAsync(CancellationToken cancellationToken) => _open(cancellationToken);

    private static Func<CancellationToken, Task<DbConnection>> OpenFrom(IdentityDatabaseOptions options)
    {
        if (options.FindError() is { } error)
            throw new InvalidOperationException($"{nameof(IdentityDatabaseOptions)}: {error}");
        var connectionString = options.ConnectionString;
        return async cancellationToken =>
        {
            var connection = new SqlConnection(connectionString);
            try
            {
                await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
                return connection;
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        };
    }

    // ── Accounts ─────────────────────────────────────────────────────────────

    async Task<AuthUser?> IAuthUserStore.GetByUniqueIdAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<UserRepository>().FindAsync(userUniqueId, cancellationToken).ConfigureAwait(false);
    }

    async Task<AuthUser?> IAuthUserStore.GetByEmailAsync(string email, CancellationToken cancellationToken)
    {
        Guard.NotWhiteSpace(email);
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<UserRepository>().FindByEmailAsync(email, cancellationToken).ConfigureAwait(false);
    }

    async Task<IReadOnlyList<AuthUser>> IAuthUserStore.ListByUniqueIdsAsync(IReadOnlyCollection<Guid> userUniqueIds, CancellationToken cancellationToken)
    {
        Guard.NotNull(userUniqueIds);
        if (userUniqueIds.Count == 0)
            return [];
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<UserRepository>().ListByIdsAsync(userUniqueIds, cancellationToken).ConfigureAwait(false);
    }

    async Task<IReadOnlyList<AuthUser>> IAuthUserStore.ListAsync(int skip, int take, bool includeDeleted, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<UserRepository>().ListAsync(skip, take, includeDeleted, cancellationToken).ConfigureAwait(false);
    }

    async Task<IReadOnlyList<AuthUser>> IAuthUserStore.ListBlockedAsync(CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<UserRepository>().ListBlockedAsync(cancellationToken).ConfigureAwait(false);
    }

    async Task<int> IAuthUserStore.CountAsync(bool includeDeleted, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<UserRepository>().CountAsync(includeDeleted, cancellationToken).ConfigureAwait(false);
    }

    async Task IAuthUserStore.CreateAsync(AuthUser user, CancellationToken cancellationToken)
    {
        Guard.NotNull(user);
        Guard.NotEmpty(user.UserUniqueId);
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        await uow.Repo<UserRepository>().InsertAsync(user, cancellationToken).ConfigureAwait(false);
    }

    async Task<bool> IAuthUserStore.UpdateAsync(AuthUser user, CancellationToken cancellationToken)
    {
        Guard.NotNull(user);
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<UserRepository>().UpdateAsync(user, cancellationToken).ConfigureAwait(false);
    }

    async Task<FailedLogin?> IAuthUserStore.RecordFailedLoginAsync(Guid userUniqueId, DateTimeOffset now, int maxAttempts, TimeSpan lockoutDuration, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<UserRepository>().RecordFailedLoginAsync(userUniqueId, now, maxAttempts, now.Add(lockoutDuration), cancellationToken).ConfigureAwait(false);
    }

    async Task<bool> IAuthUserStore.SoftDeleteAsync(Guid userUniqueId, Actor deletedBy, CancellationToken cancellationToken)
    {
        Guard.NotNull(deletedBy);
        await using var uow = await _units.OpenAndBeginAsync(cancellationToken).ConfigureAwait(false);
        if (!await uow.Repo<UserRepository>().SoftDeleteAsync(userUniqueId, deletedBy, _clock.GetUtcNow(), cancellationToken).ConfigureAwait(false))
            return false;
        await uow.Repo<AvatarRepository>().DeleteAsync(userUniqueId, cancellationToken).ConfigureAwait(false);
        await uow.CommitAsync(cancellationToken).ConfigureAwait(false);
        return true;
    }

    // ── Login events ─────────────────────────────────────────────────────────

    async Task ILoginEventStore.AddAsync(LoginEvent loginEvent, CancellationToken cancellationToken)
    {
        Guard.NotNull(loginEvent);
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        await uow.Repo<LoginEventRepository>().InsertAsync(loginEvent, cancellationToken).ConfigureAwait(false);
    }

    async Task<int> ILoginEventStore.DeleteBeforeAsync(DateTimeOffset before, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<LoginEventRepository>().DeleteBeforeAsync(before, cancellationToken).ConfigureAwait(false);
    }

    async Task<IReadOnlyList<LoginEvent>> ILoginEventStore.GetRecentAsync(Guid userUniqueId, int take, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<LoginEventRepository>().ListRecentAsync(userUniqueId, take, cancellationToken).ConfigureAwait(false);
    }

    // ── Account tokens ───────────────────────────────────────────────────────

    async Task IAccountTokenStore.CreateAsync(AccountToken token, CancellationToken cancellationToken)
    {
        Guard.NotNull(token);
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        await uow.Repo<AccountTokenRepository>().InsertAsync(token, cancellationToken).ConfigureAwait(false);
    }

    async Task<AccountToken?> IAccountTokenStore.GetAsync(string tokenHash, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<AccountTokenRepository>().FindAsync(tokenHash, cancellationToken).ConfigureAwait(false);
    }

    async Task<bool> IAccountTokenStore.TryConsumeAsync(string tokenHash, DateTimeOffset consumedAt, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<AccountTokenRepository>().TryConsumeAsync(tokenHash, consumedAt, cancellationToken).ConfigureAwait(false);
    }

    async Task<int> IAccountTokenStore.DeleteExpiredBeforeAsync(DateTimeOffset before, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<AccountTokenRepository>().DeleteExpiredBeforeAsync(before, cancellationToken).ConfigureAwait(false);
    }

    async Task IAccountTokenStore.RevokeOutstandingAsync(Guid userUniqueId, AccountTokenPurpose purpose, DateTimeOffset revokedAt, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        await uow.Repo<AccountTokenRepository>().RevokeOutstandingAsync(userUniqueId, purpose, revokedAt, cancellationToken).ConfigureAwait(false);
    }

    // ── E-mail verifications ─────────────────────────────────────────────────

    async Task IEmailVerificationStore.UpsertAsync(EmailVerification verification, CancellationToken cancellationToken)
    {
        Guard.NotNull(verification);
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        await uow.Repo<EmailVerificationRepository>().UpsertAsync(verification, cancellationToken).ConfigureAwait(false);
    }

    async Task<int> IEmailVerificationStore.DeleteExpiredBeforeAsync(DateTimeOffset before, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<EmailVerificationRepository>().DeleteExpiredBeforeAsync(before, cancellationToken).ConfigureAwait(false);
    }

    async Task<EmailVerification?> IEmailVerificationStore.GetAsync(string email, EmailVerificationPurpose purpose, CancellationToken cancellationToken)
    {
        Guard.NotWhiteSpace(email);
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<EmailVerificationRepository>().FindAsync(email, purpose, cancellationToken).ConfigureAwait(false);
    }

    async Task IEmailVerificationStore.IncrementAttemptsAsync(string email, EmailVerificationPurpose purpose, CancellationToken cancellationToken)
    {
        Guard.NotWhiteSpace(email);
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        await uow.Repo<EmailVerificationRepository>().IncrementAttemptsAsync(email, purpose, cancellationToken).ConfigureAwait(false);
    }

    async Task IEmailVerificationStore.MarkVerifiedAsync(string email, EmailVerificationPurpose purpose, CancellationToken cancellationToken)
    {
        Guard.NotWhiteSpace(email);
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        await uow.Repo<EmailVerificationRepository>().MarkVerifiedAsync(email, purpose, cancellationToken).ConfigureAwait(false);
    }

    async Task IEmailVerificationStore.DeleteAsync(string email, EmailVerificationPurpose purpose, CancellationToken cancellationToken)
    {
        Guard.NotWhiteSpace(email);
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        await uow.Repo<EmailVerificationRepository>().DeleteAsync(email, purpose, cancellationToken).ConfigureAwait(false);
    }

    // ── Second factor ────────────────────────────────────────────────────────

    async Task<MfaRecord?> IMfaStore.GetAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<MfaRepository>().FindAsync(userUniqueId, cancellationToken).ConfigureAwait(false);
    }

    async Task<IReadOnlySet<Guid>> IMfaStore.GetEnabledUserIdsAsync(IReadOnlyCollection<Guid> userUniqueIds, CancellationToken cancellationToken)
    {
        Guard.NotNull(userUniqueIds);
        if (userUniqueIds.Count == 0)
            return new HashSet<Guid>();
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<MfaRepository>().ListEnabledAsync(userUniqueIds, cancellationToken).ConfigureAwait(false);
    }

    async Task IMfaStore.SetPendingSecretAsync(Guid userUniqueId, string protectedSecret, CancellationToken cancellationToken)
    {
        Guard.NotWhiteSpace(protectedSecret);
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        await uow.Repo<MfaRepository>().SetPendingSecretAsync(userUniqueId, protectedSecret, cancellationToken).ConfigureAwait(false);
    }

    async Task IMfaStore.ReplaceTotpSecretAsync(Guid userUniqueId, string protectedSecret, CancellationToken cancellationToken)
    {
        Guard.NotWhiteSpace(protectedSecret);
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        await uow.Repo<MfaRepository>().ReplaceTotpSecretAsync(userUniqueId, protectedSecret, cancellationToken).ConfigureAwait(false);
    }

    async Task<bool> IMfaStore.TryUseStepAsync(Guid userUniqueId, long step, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<MfaRepository>().TryUseStepAsync(userUniqueId, step, cancellationToken).ConfigureAwait(false);
    }

    async Task IMfaStore.EnableAsync(Guid userUniqueId, DateTimeOffset enabledAt, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        await uow.Repo<MfaRepository>().EnableAsync(userUniqueId, enabledAt, cancellationToken).ConfigureAwait(false);
    }

    async Task IMfaStore.EnableEmailAsync(Guid userUniqueId, DateTimeOffset enabledAt, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        await uow.Repo<MfaRepository>().EnableEmailAsync(userUniqueId, enabledAt, cancellationToken).ConfigureAwait(false);
    }

    async Task IMfaStore.DisableAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        await uow.Repo<MfaRepository>().DisableAsync(userUniqueId, cancellationToken).ConfigureAwait(false);
    }

    // ── Avatars ──────────────────────────────────────────────────────────────

    async Task<AccountAvatar?> IAvatarStore.GetAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<AvatarRepository>().FindAsync(userUniqueId, cancellationToken).ConfigureAwait(false);
    }

    async Task<DateTimeOffset?> IAvatarStore.GetModifiedAtAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<AvatarRepository>().FindModifiedAtAsync(userUniqueId, cancellationToken).ConfigureAwait(false);
    }

    async Task IAvatarStore.SetAsync(AccountAvatar avatar, CancellationToken cancellationToken)
    {
        Guard.NotNull(avatar);
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        await uow.Repo<AvatarRepository>().UpsertAsync(avatar, cancellationToken).ConfigureAwait(false);
    }

    async Task<bool> IAvatarStore.DeleteAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<AvatarRepository>().DeleteAsync(userUniqueId, cancellationToken).ConfigureAwait(false);
    }

    // ── Recovery codes ───────────────────────────────────────────────────────

    async Task IRecoveryCodeStore.ReplaceAllAsync(Guid userUniqueId, IReadOnlyList<string> codeHashes, CancellationToken cancellationToken)
    {
        Guard.NotNull(codeHashes);
        await using var uow = await _units.OpenAndBeginAsync(cancellationToken).ConfigureAwait(false);
        var codes = uow.Repo<RecoveryCodeRepository>();
        await codes.DeleteAllAsync(userUniqueId, cancellationToken).ConfigureAwait(false);
        if (codeHashes.Count > 0)
            await codes.InsertAllAsync(userUniqueId, codeHashes, cancellationToken).ConfigureAwait(false);
        await uow.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    async Task<IReadOnlyList<string>> IRecoveryCodeStore.GetUnusedHashesAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<RecoveryCodeRepository>().ListUnusedHashesAsync(userUniqueId, cancellationToken).ConfigureAwait(false);
    }

    async Task<bool> IRecoveryCodeStore.MarkUsedAsync(Guid userUniqueId, string codeHash, CancellationToken cancellationToken)
    {
        Guard.NotWhiteSpace(codeHash);
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<RecoveryCodeRepository>().MarkUsedAsync(userUniqueId, codeHash, _clock.GetUtcNow(), cancellationToken).ConfigureAwait(false);
    }

    async Task<int> IRecoveryCodeStore.CountUnusedAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await uow.Repo<RecoveryCodeRepository>().CountUnusedAsync(userUniqueId, cancellationToken).ConfigureAwait(false);
    }

    async Task IRecoveryCodeStore.DeleteAllAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        await using var uow = await _units.OpenAsync(cancellationToken).ConfigureAwait(false);
        await uow.Repo<RecoveryCodeRepository>().DeleteAllAsync(userUniqueId, cancellationToken).ConfigureAwait(false);
    }
}
