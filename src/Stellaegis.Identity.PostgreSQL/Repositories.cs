using System.Data.Common;
using Dapper;
using Stellaegis.Primitives;
using Stellaegis.Primitives.Data;

namespace Stellaegis.Identity.PostgreSQL;

/// <summary>The rows of <c>ident.users</c>, read and written on the connection of a unit of work.</summary>
internal sealed class UserRepository(DbConnection connection, Func<DbTransaction?> transaction)
{
    private const string Columns =
        "user_unique_id, email, display_name, password_hash, is_enabled, email_verified, failed_login_count, failed_login_last, " +
        "blocked_until, created_at, created_by, modified_at, modified_by, last_login, is_deleted, deleted_at, deleted_by";

    static UserRepository()
    {
        PrimitiveTypeHandlers.Register();
        SnakeCaseTypeMap<UserRow>.Register();
    }

    public async Task<AuthUser?> FindAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        var row = await connection.QuerySingleOrDefaultAsync<UserRow>(new CommandDefinition(
            $"select {Columns} from ident.users where user_unique_id = @userUniqueId and is_deleted = false",
            new { userUniqueId }, transaction(), cancellationToken: cancellationToken)).ConfigureAwait(false);
        return row?.ToUser();
    }

    public async Task<AuthUser?> FindByEmailAsync(string email, CancellationToken cancellationToken)
    {
        var row = await connection.QuerySingleOrDefaultAsync<UserRow>(new CommandDefinition(
            $"select {Columns} from ident.users where email = @email and is_deleted = false",
            new { email }, transaction(), cancellationToken: cancellationToken)).ConfigureAwait(false);
        return row?.ToUser();
    }

    public async Task<IReadOnlyList<AuthUser>> ListByIdsAsync(IReadOnlyCollection<Guid> userUniqueIds, CancellationToken cancellationToken)
    {
        var rows = await connection.QueryAsync<UserRow>(new CommandDefinition(
            $"select {Columns} from ident.users where user_unique_id = any(@ids) and is_deleted = false",
            new { ids = userUniqueIds.ToArray() }, transaction(), cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(row => row.ToUser()).ToList();
    }

    public async Task<IReadOnlyList<AuthUser>> ListAsync(int skip, int take, bool includeDeleted, CancellationToken cancellationToken)
    {
        var rows = await connection.QueryAsync<UserRow>(new CommandDefinition(
            $"""
            select {Columns} from ident.users
            where @includeDeleted or is_deleted = false
            order by email
            offset @skip limit @take
            """,
            new { includeDeleted, skip, take }, transaction(), cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(row => row.ToUser()).ToList();
    }

    public async Task<IReadOnlyList<AuthUser>> ListBlockedAsync(CancellationToken cancellationToken)
    {
        var rows = await connection.QueryAsync<UserRow>(new CommandDefinition(
            $"select {Columns} from ident.users where is_enabled = false or is_deleted = true",
            transaction: transaction(), cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(row => row.ToUser()).ToList();
    }

    public Task<int> CountAsync(bool includeDeleted, CancellationToken cancellationToken)
        => connection.ExecuteScalarAsync<int>(new CommandDefinition(
            "select count(*) from ident.users where @includeDeleted or is_deleted = false",
            new { includeDeleted }, transaction(), cancellationToken: cancellationToken));

    public Task InsertAsync(AuthUser user, CancellationToken cancellationToken)
        => connection.ExecuteAsync(new CommandDefinition(
            """
            insert into ident.users (
                user_unique_id, email, display_name, password_hash, is_enabled, email_verified,
                failed_login_count, failed_login_last, blocked_until,
                created_at, created_by, modified_at, modified_by, last_login,
                is_deleted, deleted_at, deleted_by)
            values (
                @UserUniqueId, @Email, @DisplayName, @PasswordHash, @IsEnabled, @EmailVerified,
                @FailedLoginCount, @FailedLoginLast, @BlockedUntil,
                @CreatedAt, @CreatedBy, @ModifiedAt, @ModifiedBy, @LastLogin,
                @IsDeleted, @DeletedAt, @DeletedBy)
            """,
            UserRow.From(user), transaction(), cancellationToken: cancellationToken));

    public async Task<bool> UpdateAsync(AuthUser user, CancellationToken cancellationToken)
    {
        var rows = await connection.ExecuteAsync(new CommandDefinition(
            """
            update ident.users
            set email = @Email,
                display_name = @DisplayName,
                password_hash = @PasswordHash,
                is_enabled = @IsEnabled,
                email_verified = @EmailVerified,
                failed_login_count = @FailedLoginCount,
                failed_login_last = @FailedLoginLast,
                blocked_until = @BlockedUntil,
                modified_at = @ModifiedAt,
                modified_by = @ModifiedBy,
                last_login = @LastLogin
            where user_unique_id = @UserUniqueId and is_deleted = false
            """,
            UserRow.From(user), transaction(), cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows > 0;
    }

    public async Task<bool> SoftDeleteAsync(Guid userUniqueId, Actor deletedBy, DateTimeOffset deletedAt, CancellationToken cancellationToken)
    {
        var rows = await connection.ExecuteAsync(new CommandDefinition(
            """
            update ident.users
            set is_deleted = true, deleted_at = @deletedAt, deleted_by = @deletedBy,
                modified_at = @deletedAt, modified_by = @deletedBy
            where user_unique_id = @userUniqueId and is_deleted = false
            """,
            new { userUniqueId, deletedBy, deletedAt }, transaction(), cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows > 0;
    }

    private sealed class UserRow
    {
        public Guid UserUniqueId { get; set; }
        public string Email { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string? PasswordHash { get; set; }
        public bool IsEnabled { get; set; }
        public bool EmailVerified { get; set; }
        public int FailedLoginCount { get; set; }
        public DateTimeOffset? FailedLoginLast { get; set; }
        public DateTimeOffset? BlockedUntil { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public Actor CreatedBy { get; set; } = null!;
        public DateTimeOffset ModifiedAt { get; set; }
        public Actor ModifiedBy { get; set; } = null!;
        public DateTimeOffset? LastLogin { get; set; }
        public bool IsDeleted { get; set; }
        public DateTimeOffset? DeletedAt { get; set; }
        public Actor? DeletedBy { get; set; }

        public static UserRow From(AuthUser user) => new()
        {
            UserUniqueId = user.UserUniqueId,
            Email = user.Email,
            DisplayName = user.DisplayName,
            PasswordHash = user.PasswordHash,
            IsEnabled = user.IsEnabled,
            EmailVerified = user.EmailVerified,
            FailedLoginCount = user.FailedLoginCount,
            FailedLoginLast = user.FailedLoginLast,
            BlockedUntil = user.BlockedUntil,
            CreatedAt = user.CreatedAt,
            CreatedBy = user.CreatedBy,
            ModifiedAt = user.ModifiedAt,
            ModifiedBy = user.ModifiedBy,
            LastLogin = user.LastLogin,
            IsDeleted = user.IsDeleted,
            DeletedAt = user.DeletedAt,
            DeletedBy = user.DeletedBy,
        };

        public AuthUser ToUser() => new()
        {
            UserUniqueId = UserUniqueId,
            Email = Email,
            DisplayName = DisplayName,
            PasswordHash = PasswordHash,
            IsEnabled = IsEnabled,
            EmailVerified = EmailVerified,
            FailedLoginCount = FailedLoginCount,
            FailedLoginLast = FailedLoginLast,
            BlockedUntil = BlockedUntil,
            CreatedAt = CreatedAt,
            CreatedBy = CreatedBy,
            ModifiedAt = ModifiedAt,
            ModifiedBy = ModifiedBy,
            LastLogin = LastLogin,
            IsDeleted = IsDeleted,
            DeletedAt = DeletedAt,
            DeletedBy = DeletedBy,
        };
    }
}

/// <summary>The rows of <c>ident.login_events</c>, append only.</summary>
internal sealed class LoginEventRepository(DbConnection connection, Func<DbTransaction?> transaction)
{
    static LoginEventRepository() => SnakeCaseTypeMap<LoginEventRow>.Register();

    public Task InsertAsync(LoginEvent loginEvent, CancellationToken cancellationToken)
        => connection.ExecuteAsync(new CommandDefinition(
            """
            insert into ident.login_events (user_unique_id, email, success, fail_reason, ip_address, user_agent, created_at)
            values (@UserUniqueId, @Email, @Success, @FailReason, @IpAddress, @UserAgent, @CreatedAt)
            """,
            new { loginEvent.UserUniqueId, loginEvent.Email, loginEvent.Success, loginEvent.FailReason, loginEvent.IpAddress, loginEvent.UserAgent, loginEvent.CreatedAt },
            transaction(), cancellationToken: cancellationToken));

    public async Task<IReadOnlyList<LoginEvent>> ListRecentAsync(Guid userUniqueId, int take, CancellationToken cancellationToken)
    {
        var rows = await connection.QueryAsync<LoginEventRow>(new CommandDefinition(
            """
            select user_unique_id, email, success, fail_reason, ip_address, user_agent, created_at
            from ident.login_events
            where user_unique_id = @userUniqueId
            order by created_at desc, login_event_id desc
            limit @take
            """,
            new { userUniqueId, take }, transaction(), cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(row => row.ToEvent()).ToList();
    }

    private sealed class LoginEventRow
    {
        public Guid UserUniqueId { get; set; }
        public string Email { get; set; } = "";
        public bool Success { get; set; }
        public string? FailReason { get; set; }
        public string? IpAddress { get; set; }
        public string? UserAgent { get; set; }
        public DateTimeOffset CreatedAt { get; set; }

        public LoginEvent ToEvent() => new()
        {
            UserUniqueId = UserUniqueId,
            Email = Email,
            Success = Success,
            FailReason = FailReason,
            IpAddress = IpAddress,
            UserAgent = UserAgent,
            CreatedAt = CreatedAt,
        };
    }
}

/// <summary>The rows of <c>ident.account_tokens</c>, keyed by the hash of the token.</summary>
internal sealed class AccountTokenRepository(DbConnection connection, Func<DbTransaction?> transaction)
{
    static AccountTokenRepository() => SnakeCaseTypeMap<AccountTokenRow>.Register();

    private const string Columns =
        "token_hash, user_unique_id, purpose, delivery, email, created_at, created_by, expires_at, consumed_at, revoked_at, ip_address";

    public Task InsertAsync(AccountToken token, CancellationToken cancellationToken)
        => connection.ExecuteAsync(new CommandDefinition(
            $"""
            insert into ident.account_tokens ({Columns})
            values (@TokenHash, @UserUniqueId, @Purpose, @Delivery, @Email, @CreatedAt, @CreatedBy, @ExpiresAt, @ConsumedAt, @RevokedAt, @IpAddress)
            """,
            AccountTokenRow.From(token), transaction(), cancellationToken: cancellationToken));

    public async Task<AccountToken?> FindAsync(string tokenHash, CancellationToken cancellationToken)
    {
        var row = await connection.QuerySingleOrDefaultAsync<AccountTokenRow>(new CommandDefinition(
            $"select {Columns} from ident.account_tokens where token_hash = @tokenHash",
            new { tokenHash }, transaction(), cancellationToken: cancellationToken)).ConfigureAwait(false);
        return row?.ToToken();
    }

    public async Task<bool> TryConsumeAsync(string tokenHash, DateTimeOffset consumedAt, CancellationToken cancellationToken)
        => await connection.ExecuteAsync(new CommandDefinition(
            "update ident.account_tokens set consumed_at = @consumedAt where token_hash = @tokenHash and consumed_at is null and revoked_at is null",
            new { tokenHash, consumedAt }, transaction(), cancellationToken: cancellationToken)).ConfigureAwait(false) == 1;

    public Task RevokeOutstandingAsync(Guid userUniqueId, AccountTokenPurpose purpose, DateTimeOffset revokedAt, CancellationToken cancellationToken)
        => connection.ExecuteAsync(new CommandDefinition(
            """
            update ident.account_tokens set revoked_at = @revokedAt
            where user_unique_id = @userUniqueId and purpose = @purpose and consumed_at is null and revoked_at is null
            """,
            new { userUniqueId, purpose = AccountTokenRow.PurposeOf(purpose), revokedAt }, transaction(), cancellationToken: cancellationToken));

    private sealed class AccountTokenRow
    {
        public string TokenHash { get; set; } = "";
        public Guid UserUniqueId { get; set; }
        public string Purpose { get; set; } = "";
        public string Delivery { get; set; } = "";
        public string Email { get; set; } = "";
        public DateTimeOffset CreatedAt { get; set; }
        public Actor CreatedBy { get; set; } = null!;
        public DateTimeOffset ExpiresAt { get; set; }
        public DateTimeOffset? ConsumedAt { get; set; }
        public DateTimeOffset? RevokedAt { get; set; }
        public string? IpAddress { get; set; }

        public static string PurposeOf(AccountTokenPurpose purpose) => purpose switch
        {
            AccountTokenPurpose.PasswordReset => "password_reset",
            AccountTokenPurpose.Activation => "activation",
            _ => throw new ArgumentOutOfRangeException(nameof(purpose), purpose, null),
        };

        public static AccountTokenRow From(AccountToken token) => new()
        {
            TokenHash = token.TokenHash,
            UserUniqueId = token.UserUniqueId,
            Purpose = PurposeOf(token.Purpose),
            Delivery = token.Delivery == TokenDelivery.Email ? "email" : "hand",
            Email = token.Email,
            CreatedAt = token.CreatedAt,
            CreatedBy = token.CreatedBy,
            ExpiresAt = token.ExpiresAt,
            ConsumedAt = token.ConsumedAt,
            RevokedAt = token.RevokedAt,
            IpAddress = token.IpAddress,
        };

        public AccountToken ToToken() => new()
        {
            TokenHash = TokenHash,
            UserUniqueId = UserUniqueId,
            Purpose = Purpose == "activation" ? AccountTokenPurpose.Activation : AccountTokenPurpose.PasswordReset,
            Delivery = Delivery == "hand" ? TokenDelivery.Hand : TokenDelivery.Email,
            Email = Email,
            CreatedAt = CreatedAt,
            CreatedBy = CreatedBy,
            ExpiresAt = ExpiresAt,
            ConsumedAt = ConsumedAt,
            RevokedAt = RevokedAt,
            IpAddress = IpAddress,
        };
    }
}

/// <summary>The rows of <c>ident.email_verifications</c>, one per e-mail.</summary>
internal sealed class EmailVerificationRepository(DbConnection connection, Func<DbTransaction?> transaction)
{
    static EmailVerificationRepository() => SnakeCaseTypeMap<VerificationRow>.Register();

    public Task UpsertAsync(EmailVerification verification, CancellationToken cancellationToken)
        => connection.ExecuteAsync(new CommandDefinition(
            """
            insert into ident.email_verifications (email, code, created_at, expires_at, attempts, is_verified, ip_address)
            values (@Email, @Code, @CreatedAt, @ExpiresAt, @Attempts, @IsVerified, @IpAddress)
            on conflict (email) do update set
                code = excluded.code,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at,
                attempts = excluded.attempts,
                is_verified = excluded.is_verified,
                ip_address = excluded.ip_address
            """,
            new { verification.Email, verification.Code, verification.CreatedAt, verification.ExpiresAt, verification.Attempts, verification.IsVerified, verification.IpAddress },
            transaction(), cancellationToken: cancellationToken));

    public async Task<EmailVerification?> FindAsync(string email, CancellationToken cancellationToken)
    {
        var row = await connection.QuerySingleOrDefaultAsync<VerificationRow>(new CommandDefinition(
            "select email, code, created_at, expires_at, attempts, is_verified, ip_address from ident.email_verifications where email = @email",
            new { email }, transaction(), cancellationToken: cancellationToken)).ConfigureAwait(false);
        return row?.ToVerification();
    }

    public Task IncrementAttemptsAsync(string email, CancellationToken cancellationToken)
        => connection.ExecuteAsync(new CommandDefinition(
            "update ident.email_verifications set attempts = attempts + 1 where email = @email",
            new { email }, transaction(), cancellationToken: cancellationToken));

    public Task MarkVerifiedAsync(string email, CancellationToken cancellationToken)
        => connection.ExecuteAsync(new CommandDefinition(
            "update ident.email_verifications set is_verified = true where email = @email",
            new { email }, transaction(), cancellationToken: cancellationToken));

    public Task DeleteAsync(string email, CancellationToken cancellationToken)
        => connection.ExecuteAsync(new CommandDefinition(
            "delete from ident.email_verifications where email = @email",
            new { email }, transaction(), cancellationToken: cancellationToken));

    private sealed class VerificationRow
    {
        public string Email { get; set; } = "";
        public string Code { get; set; } = "";
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset ExpiresAt { get; set; }
        public int Attempts { get; set; }
        public bool IsVerified { get; set; }
        public string? IpAddress { get; set; }

        public EmailVerification ToVerification() => new()
        {
            Email = Email,
            Code = Code,
            CreatedAt = CreatedAt,
            ExpiresAt = ExpiresAt,
            Attempts = Attempts,
            IsVerified = IsVerified,
            IpAddress = IpAddress,
        };
    }
}

/// <summary>The rows of <c>ident.user_mfa</c>, one per account that ever set a second factor up.</summary>
internal sealed class MfaRepository(DbConnection connection, Func<DbTransaction?> transaction)
{
    static MfaRepository() => SnakeCaseTypeMap<MfaRow>.Register();

    public async Task<MfaRecord?> FindAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        var row = await connection.QuerySingleOrDefaultAsync<MfaRow>(new CommandDefinition(
            "select user_unique_id, pending_secret, totp_secret, is_enabled, enabled_at, method, last_used_step from ident.user_mfa where user_unique_id = @userUniqueId",
            new { userUniqueId }, transaction(), cancellationToken: cancellationToken)).ConfigureAwait(false);
        return row?.ToRecord();
    }

    public async Task<IReadOnlySet<Guid>> ListEnabledAsync(IReadOnlyCollection<Guid> userUniqueIds, CancellationToken cancellationToken)
    {
        var ids = await connection.QueryAsync<Guid>(new CommandDefinition(
            "select user_unique_id from ident.user_mfa where is_enabled = true and user_unique_id = any(@ids)",
            new { ids = userUniqueIds.ToArray() }, transaction(), cancellationToken: cancellationToken)).ConfigureAwait(false);
        return ids.ToHashSet();
    }

    public Task SetPendingSecretAsync(Guid userUniqueId, string protectedSecret, CancellationToken cancellationToken)
        => connection.ExecuteAsync(new CommandDefinition(
            """
            insert into ident.user_mfa (user_unique_id, pending_secret)
            values (@userUniqueId, @protectedSecret)
            on conflict (user_unique_id) do update set pending_secret = excluded.pending_secret
            """,
            new { userUniqueId, protectedSecret }, transaction(), cancellationToken: cancellationToken));

    public Task ReplaceTotpSecretAsync(Guid userUniqueId, string protectedSecret, CancellationToken cancellationToken)
        => connection.ExecuteAsync(new CommandDefinition(
            "update ident.user_mfa set totp_secret = @protectedSecret where user_unique_id = @userUniqueId and totp_secret is not null",
            new { userUniqueId, protectedSecret }, transaction(), cancellationToken: cancellationToken));

    public async Task<bool> TryUseStepAsync(Guid userUniqueId, long step, CancellationToken cancellationToken)
        => await connection.ExecuteAsync(new CommandDefinition(
            "update ident.user_mfa set last_used_step = @step where user_unique_id = @userUniqueId and (last_used_step is null or last_used_step < @step)",
            new { userUniqueId, step }, transaction(), cancellationToken: cancellationToken)).ConfigureAwait(false) == 1;

    public Task EnableAsync(Guid userUniqueId, DateTimeOffset enabledAt, CancellationToken cancellationToken)
        => connection.ExecuteAsync(new CommandDefinition(
            """
            update ident.user_mfa
            set totp_secret = pending_secret, pending_secret = null, is_enabled = true, enabled_at = @enabledAt, method = 'totp'
            where user_unique_id = @userUniqueId
            """,
            new { userUniqueId, enabledAt }, transaction(), cancellationToken: cancellationToken));

    public Task EnableEmailAsync(Guid userUniqueId, DateTimeOffset enabledAt, CancellationToken cancellationToken)
        => connection.ExecuteAsync(new CommandDefinition(
            """
            insert into ident.user_mfa (user_unique_id, is_enabled, enabled_at, method)
            values (@userUniqueId, true, @enabledAt, 'email')
            on conflict (user_unique_id) do update set
                totp_secret = null, pending_secret = null, is_enabled = true, enabled_at = excluded.enabled_at, method = 'email'
            """,
            new { userUniqueId, enabledAt }, transaction(), cancellationToken: cancellationToken));

    public Task DisableAsync(Guid userUniqueId, CancellationToken cancellationToken)
        => connection.ExecuteAsync(new CommandDefinition(
            """
            update ident.user_mfa
            set totp_secret = null, pending_secret = null, is_enabled = false, enabled_at = null
            where user_unique_id = @userUniqueId
            """,
            new { userUniqueId }, transaction(), cancellationToken: cancellationToken));

    private sealed class MfaRow
    {
        public Guid UserUniqueId { get; set; }
        public string? PendingSecret { get; set; }
        public string? TotpSecret { get; set; }
        public bool IsEnabled { get; set; }
        public DateTimeOffset? EnabledAt { get; set; }
        public string Method { get; set; } = MfaMethod.Totp;
        public long? LastUsedStep { get; set; }

        public MfaRecord ToRecord() => new()
        {
            UserUniqueId = UserUniqueId,
            PendingSecret = PendingSecret,
            TotpSecret = TotpSecret,
            IsEnabled = IsEnabled,
            EnabledAt = EnabledAt,
            Method = Method,
            LastUsedStep = LastUsedStep,
        };
    }
}

/// <summary>The rows of <c>ident.recovery_codes</c>: hashes only, each used once.</summary>
internal sealed class RecoveryCodeRepository(DbConnection connection, Func<DbTransaction?> transaction)
{
    public Task DeleteAllAsync(Guid userUniqueId, CancellationToken cancellationToken)
        => connection.ExecuteAsync(new CommandDefinition(
            "delete from ident.recovery_codes where user_unique_id = @userUniqueId",
            new { userUniqueId }, transaction(), cancellationToken: cancellationToken));

    public Task InsertAllAsync(Guid userUniqueId, IReadOnlyList<string> codeHashes, CancellationToken cancellationToken)
        => connection.ExecuteAsync(new CommandDefinition(
            """
            insert into ident.recovery_codes (user_unique_id, code_hash)
            select @userUniqueId, unnest(@codeHashes)
            """,
            new { userUniqueId, codeHashes = codeHashes.ToArray() }, transaction(), cancellationToken: cancellationToken));

    public async Task<IReadOnlyList<string>> ListUnusedHashesAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        var hashes = await connection.QueryAsync<string>(new CommandDefinition(
            "select code_hash from ident.recovery_codes where user_unique_id = @userUniqueId and used_at is null",
            new { userUniqueId }, transaction(), cancellationToken: cancellationToken)).ConfigureAwait(false);
        return hashes.ToList();
    }

    // The used_at is null guard makes the transition single-use: a second attempt at once updates no row.
    public async Task<bool> MarkUsedAsync(Guid userUniqueId, string codeHash, DateTimeOffset usedAt, CancellationToken cancellationToken)
    {
        var rows = await connection.ExecuteAsync(new CommandDefinition(
            "update ident.recovery_codes set used_at = @usedAt where user_unique_id = @userUniqueId and code_hash = @codeHash and used_at is null",
            new { userUniqueId, codeHash, usedAt }, transaction(), cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows > 0;
    }

    public Task<int> CountUnusedAsync(Guid userUniqueId, CancellationToken cancellationToken)
        => connection.ExecuteScalarAsync<int>(new CommandDefinition(
            "select count(*) from ident.recovery_codes where user_unique_id = @userUniqueId and used_at is null",
            new { userUniqueId }, transaction(), cancellationToken: cancellationToken));
}
