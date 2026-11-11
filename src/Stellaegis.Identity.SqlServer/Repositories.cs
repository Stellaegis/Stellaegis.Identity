using System.Data;
using Microsoft.Data.SqlClient;
using Stellaegis.Primitives;

namespace Stellaegis.Identity.SqlServer;

/// <summary>The sizes the parameters of the statements are declared with.</summary>
internal static class Sizes
{
    /// <summary>
    /// The size of a string parameter for a column <c>nvarchar(n)</c> or <c>nchar(n)</c>: the largest n there is. A
    /// size taken from the column would cut a longer value without an error, and the statement would then compare
    /// or store what is left of it; a size taken from each value gives SQL Server one plan per length.
    /// </summary>
    public const int Text = 4000;

    /// <summary>
    /// The size of a parameter that may hold more than <see cref="Text"/> allows: an image, a list of identifiers.
    /// Under <see cref="Text"/>, the driver would cut it.
    /// </summary>
    public const int Max = -1;
}

/// <summary>The rows of <c>ident.users</c>, read and written on the connection of a unit of work.</summary>
internal sealed class UserRepository(SqlConnection connection, Func<SqlTransaction?> transaction)
{
    private const string Columns =
        "user_unique_id, email, display_name, password_hash, is_enabled, email_verified, locale, time_zone, failed_login_count, " +
        "failed_login_last, blocked_until, created_at, created_by, modified_at, modified_by, last_login, is_deleted, deleted_at, deleted_by, " +
        "security_stamp";

    public async Task<AuthUser?> FindAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            $"select {Columns} from ident.users where user_unique_id = @userUniqueId and is_deleted = 0",
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? Read(reader) : null;
    }

    public async Task<AuthUser?> FindByEmailAsync(string email, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            $"select {Columns} from ident.users where email = @email and is_deleted = 0",
            connection, transaction());
        command.Parameters.Add("@email", SqlDbType.NVarChar, Sizes.Text).Value = email;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? Read(reader) : null;
    }

    public async Task<IReadOnlyList<AuthUser>> ListByIdsAsync(IReadOnlyCollection<Guid> userUniqueIds, CancellationToken cancellationToken)
    {
        // string_split gives one empty value for an empty list, which is no identifier.
        if (userUniqueIds.Count == 0)
            return [];

        await using var command = new SqlCommand(
            $"select {Columns} from ident.users where user_unique_id in (select cast(value as uniqueidentifier) from string_split(@ids, N',')) and is_deleted = 0",
            connection, transaction());
        command.Parameters.Add("@ids", SqlDbType.NVarChar, Sizes.Max).Value = string.Join(',', userUniqueIds);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var users = new List<AuthUser>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            users.Add(Read(reader));
        return users;
    }

    public async Task<IReadOnlyList<AuthUser>> ListAsync(int skip, int take, bool includeDeleted, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            $"""
            select {Columns} from ident.users
            where @includeDeleted = 1 or is_deleted = 0
            order by email
            offset @skip rows fetch next @take rows only
            """,
            connection, transaction());
        command.Parameters.Add("@includeDeleted", SqlDbType.Bit).Value = includeDeleted;
        command.Parameters.Add("@skip", SqlDbType.Int).Value = skip;
        command.Parameters.Add("@take", SqlDbType.Int).Value = take;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var users = new List<AuthUser>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            users.Add(Read(reader));
        return users;
    }

    public async Task<IReadOnlyList<AuthUser>> ListBlockedAsync(CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            $"select {Columns} from ident.users where is_enabled = 0 or is_deleted = 1",
            connection, transaction());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var users = new List<AuthUser>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            users.Add(Read(reader));
        return users;
    }

    public async Task<int> CountAsync(bool includeDeleted, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            "select count(*) from ident.users where @includeDeleted = 1 or is_deleted = 0",
            connection, transaction());
        command.Parameters.Add("@includeDeleted", SqlDbType.Bit).Value = includeDeleted;
        return (int)(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false))!;
    }

    public async Task InsertAsync(AuthUser user, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            """
            insert into ident.users (
                user_unique_id, email, display_name, password_hash, is_enabled, email_verified, locale, time_zone,
                failed_login_count, failed_login_last, blocked_until,
                created_at, created_by, modified_at, modified_by, last_login,
                is_deleted, deleted_at, deleted_by, security_stamp)
            values (
                @UserUniqueId, @Email, @DisplayName, @PasswordHash, @IsEnabled, @EmailVerified, @Locale, @TimeZone,
                @FailedLoginCount, @FailedLoginLast, @BlockedUntil,
                @CreatedAt, @CreatedBy, @ModifiedAt, @ModifiedBy, @LastLogin,
                @IsDeleted, @DeletedAt, @DeletedBy, @SecurityStamp)
            """,
            connection, transaction());
        command.Parameters.Add("@UserUniqueId", SqlDbType.UniqueIdentifier).Value = user.UserUniqueId;
        command.Parameters.Add("@Email", SqlDbType.NVarChar, Sizes.Text).Value = user.Email;
        command.Parameters.Add("@DisplayName", SqlDbType.NVarChar, Sizes.Text).Value = user.DisplayName;
        command.Parameters.Add("@PasswordHash", SqlDbType.NVarChar, Sizes.Text).Value = (object?)user.PasswordHash ?? DBNull.Value;
        command.Parameters.Add("@IsEnabled", SqlDbType.Bit).Value = user.IsEnabled;
        command.Parameters.Add("@EmailVerified", SqlDbType.Bit).Value = user.EmailVerified;
        command.Parameters.Add("@Locale", SqlDbType.NVarChar, Sizes.Text).Value = (object?)user.Locale ?? DBNull.Value;
        command.Parameters.Add("@TimeZone", SqlDbType.NVarChar, Sizes.Text).Value = (object?)user.TimeZone ?? DBNull.Value;
        command.Parameters.Add("@FailedLoginCount", SqlDbType.Int).Value = user.FailedLoginCount;
        command.Parameters.Add("@FailedLoginLast", SqlDbType.DateTimeOffset).Value = (object?)user.FailedLoginLast ?? DBNull.Value;
        command.Parameters.Add("@BlockedUntil", SqlDbType.DateTimeOffset).Value = (object?)user.BlockedUntil ?? DBNull.Value;
        command.Parameters.Add("@CreatedAt", SqlDbType.DateTimeOffset).Value = user.CreatedAt;
        command.Parameters.Add("@CreatedBy", SqlDbType.NVarChar, Sizes.Text).Value = user.CreatedBy.Value;
        command.Parameters.Add("@ModifiedAt", SqlDbType.DateTimeOffset).Value = user.ModifiedAt;
        command.Parameters.Add("@ModifiedBy", SqlDbType.NVarChar, Sizes.Text).Value = user.ModifiedBy.Value;
        command.Parameters.Add("@LastLogin", SqlDbType.DateTimeOffset).Value = (object?)user.LastLogin ?? DBNull.Value;
        command.Parameters.Add("@IsDeleted", SqlDbType.Bit).Value = user.IsDeleted;
        command.Parameters.Add("@DeletedAt", SqlDbType.DateTimeOffset).Value = (object?)user.DeletedAt ?? DBNull.Value;
        command.Parameters.Add("@DeletedBy", SqlDbType.NVarChar, Sizes.Text).Value = (object?)user.DeletedBy?.Value ?? DBNull.Value;
        command.Parameters.Add("@SecurityStamp", SqlDbType.NVarChar, Sizes.Text).Value = user.SecurityStamp;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    // The stamp alone, which the update of the account never writes.
    public async Task<bool> RenewSecurityStampAsync(Guid userUniqueId, string securityStamp, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            "update ident.users set security_stamp = @securityStamp where user_unique_id = @userUniqueId and is_deleted = 0",
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        command.Parameters.Add("@securityStamp", SqlDbType.NVarChar, Sizes.Text).Value = securityStamp;
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) > 0;
    }

    public async Task<bool> UpdateAsync(AuthUser user, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            """
            update ident.users
            set email = @Email,
                display_name = @DisplayName,
                password_hash = @PasswordHash,
                is_enabled = @IsEnabled,
                email_verified = @EmailVerified,
                locale = @Locale,
                time_zone = @TimeZone,
                failed_login_count = @FailedLoginCount,
                failed_login_last = @FailedLoginLast,
                blocked_until = @BlockedUntil,
                modified_at = @ModifiedAt,
                modified_by = @ModifiedBy,
                last_login = @LastLogin
            where user_unique_id = @UserUniqueId and is_deleted = 0
            """,
            connection, transaction());
        command.Parameters.Add("@UserUniqueId", SqlDbType.UniqueIdentifier).Value = user.UserUniqueId;
        command.Parameters.Add("@Email", SqlDbType.NVarChar, Sizes.Text).Value = user.Email;
        command.Parameters.Add("@DisplayName", SqlDbType.NVarChar, Sizes.Text).Value = user.DisplayName;
        command.Parameters.Add("@PasswordHash", SqlDbType.NVarChar, Sizes.Text).Value = (object?)user.PasswordHash ?? DBNull.Value;
        command.Parameters.Add("@IsEnabled", SqlDbType.Bit).Value = user.IsEnabled;
        command.Parameters.Add("@EmailVerified", SqlDbType.Bit).Value = user.EmailVerified;
        command.Parameters.Add("@Locale", SqlDbType.NVarChar, Sizes.Text).Value = (object?)user.Locale ?? DBNull.Value;
        command.Parameters.Add("@TimeZone", SqlDbType.NVarChar, Sizes.Text).Value = (object?)user.TimeZone ?? DBNull.Value;
        command.Parameters.Add("@FailedLoginCount", SqlDbType.Int).Value = user.FailedLoginCount;
        command.Parameters.Add("@FailedLoginLast", SqlDbType.DateTimeOffset).Value = (object?)user.FailedLoginLast ?? DBNull.Value;
        command.Parameters.Add("@BlockedUntil", SqlDbType.DateTimeOffset).Value = (object?)user.BlockedUntil ?? DBNull.Value;
        command.Parameters.Add("@ModifiedAt", SqlDbType.DateTimeOffset).Value = user.ModifiedAt;
        command.Parameters.Add("@ModifiedBy", SqlDbType.NVarChar, Sizes.Text).Value = user.ModifiedBy.Value;
        command.Parameters.Add("@LastLogin", SqlDbType.DateTimeOffset).Value = (object?)user.LastLogin ?? DBNull.Value;
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) > 0;
    }

    // One statement, on the stored count: two attempts at once both add one. The case reads the count before the
    // update, as every expression of a set clause does.
    public async Task<FailedLogin?> RecordFailedLoginAsync(Guid userUniqueId, DateTimeOffset now, int maxAttempts, DateTimeOffset lockedUntil, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            """
            update ident.users
            set failed_login_count = failed_login_count + 1,
                failed_login_last = @now,
                blocked_until = case when failed_login_count + 1 >= @maxAttempts then @lockedUntil else blocked_until end
            output inserted.failed_login_count, inserted.blocked_until
            where user_unique_id = @userUniqueId and is_deleted = 0
            """,
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        command.Parameters.Add("@now", SqlDbType.DateTimeOffset).Value = now;
        command.Parameters.Add("@maxAttempts", SqlDbType.Int).Value = maxAttempts;
        command.Parameters.Add("@lockedUntil", SqlDbType.DateTimeOffset).Value = lockedUntil;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            return null;
        return new FailedLogin(
            reader.GetInt32("failed_login_count"),
            reader.IsDBNull("blocked_until") ? null : reader.GetFieldValue<DateTimeOffset>("blocked_until"));
    }

    // The address goes with the deletion, replaced by a mark that names the account: the address is free for a new
    // account, and the row keeps the identity, which is never reused.
    public async Task<bool> SoftDeleteAsync(Guid userUniqueId, Actor deletedBy, DateTimeOffset deletedAt, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            """
            update ident.users
            set is_deleted = 1, deleted_at = @deletedAt, deleted_by = @deletedBy,
                email = N'deleted:' + lower(replace(convert(nvarchar(36), user_unique_id), '-', '')),
                modified_at = @deletedAt, modified_by = @deletedBy
            where user_unique_id = @userUniqueId and is_deleted = 0
            """,
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        command.Parameters.Add("@deletedBy", SqlDbType.NVarChar, Sizes.Text).Value = deletedBy.Value;
        command.Parameters.Add("@deletedAt", SqlDbType.DateTimeOffset).Value = deletedAt;
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) > 0;
    }

    private static AuthUser Read(SqlDataReader row) => new()
    {
        UserUniqueId = row.GetGuid("user_unique_id"),
        Email = row.GetString("email"),
        DisplayName = row.GetString("display_name"),
        PasswordHash = row.IsDBNull("password_hash") ? null : row.GetString("password_hash"),
        IsEnabled = row.GetBoolean("is_enabled"),
        EmailVerified = row.GetBoolean("email_verified"),
        Locale = row.IsDBNull("locale") ? null : row.GetString("locale"),
        TimeZone = row.IsDBNull("time_zone") ? null : row.GetString("time_zone"),
        FailedLoginCount = row.GetInt32("failed_login_count"),
        FailedLoginLast = row.IsDBNull("failed_login_last") ? null : row.GetFieldValue<DateTimeOffset>("failed_login_last"),
        BlockedUntil = row.IsDBNull("blocked_until") ? null : row.GetFieldValue<DateTimeOffset>("blocked_until"),
        CreatedAt = row.GetFieldValue<DateTimeOffset>("created_at"),
        CreatedBy = Actor.Parse(row.GetString("created_by")),
        ModifiedAt = row.GetFieldValue<DateTimeOffset>("modified_at"),
        ModifiedBy = Actor.Parse(row.GetString("modified_by")),
        LastLogin = row.IsDBNull("last_login") ? null : row.GetFieldValue<DateTimeOffset>("last_login"),
        IsDeleted = row.GetBoolean("is_deleted"),
        DeletedAt = row.IsDBNull("deleted_at") ? null : row.GetFieldValue<DateTimeOffset>("deleted_at"),
        DeletedBy = row.IsDBNull("deleted_by") ? null : Actor.Parse(row.GetString("deleted_by")),
        SecurityStamp = row.GetString("security_stamp"),
    };
}

/// <summary>The rows of <c>ident.login_events</c>, append only.</summary>
internal sealed class LoginEventRepository(SqlConnection connection, Func<SqlTransaction?> transaction)
{
    public async Task<int> DeleteBeforeAsync(DateTimeOffset before, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand("delete from ident.login_events where created_at < @before", connection, transaction());
        command.Parameters.Add("@before", SqlDbType.DateTimeOffset).Value = before;
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task InsertAsync(LoginEvent loginEvent, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            """
            insert into ident.login_events (user_unique_id, email, success, fail_reason, ip_address, user_agent, created_at)
            values (@UserUniqueId, @Email, @Success, @FailReason, @IpAddress, @UserAgent, @CreatedAt)
            """,
            connection, transaction());
        command.Parameters.Add("@UserUniqueId", SqlDbType.UniqueIdentifier).Value = loginEvent.UserUniqueId;
        command.Parameters.Add("@Email", SqlDbType.NVarChar, Sizes.Text).Value = loginEvent.Email;
        command.Parameters.Add("@Success", SqlDbType.Bit).Value = loginEvent.Success;
        command.Parameters.Add("@FailReason", SqlDbType.NVarChar, Sizes.Text).Value = (object?)loginEvent.FailReason ?? DBNull.Value;
        command.Parameters.Add("@IpAddress", SqlDbType.NVarChar, Sizes.Text).Value = (object?)loginEvent.IpAddress ?? DBNull.Value;
        command.Parameters.Add("@UserAgent", SqlDbType.NVarChar, Sizes.Text).Value = (object?)loginEvent.UserAgent ?? DBNull.Value;
        command.Parameters.Add("@CreatedAt", SqlDbType.DateTimeOffset).Value = loginEvent.CreatedAt;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<LoginEvent>> ListRecentAsync(Guid userUniqueId, int take, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            """
            select top (@take) user_unique_id, email, success, fail_reason, ip_address, user_agent, created_at
            from ident.login_events
            where user_unique_id = @userUniqueId
            order by created_at desc, login_event_id desc
            """,
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        command.Parameters.Add("@take", SqlDbType.Int).Value = take;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var events = new List<LoginEvent>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            events.Add(Read(reader));
        return events;
    }

    private static LoginEvent Read(SqlDataReader row) => new()
    {
        UserUniqueId = row.GetGuid("user_unique_id"),
        Email = row.GetString("email"),
        Success = row.GetBoolean("success"),
        FailReason = row.IsDBNull("fail_reason") ? null : row.GetString("fail_reason"),
        IpAddress = row.IsDBNull("ip_address") ? null : row.GetString("ip_address"),
        UserAgent = row.IsDBNull("user_agent") ? null : row.GetString("user_agent"),
        CreatedAt = row.GetFieldValue<DateTimeOffset>("created_at"),
    };
}

/// <summary>The rows of <c>ident.account_tokens</c>, keyed by the hash of the token.</summary>
internal sealed class AccountTokenRepository(SqlConnection connection, Func<SqlTransaction?> transaction)
{
    private const string Columns =
        "token_hash, user_unique_id, purpose, delivery, email, created_at, created_by, expires_at, consumed_at, revoked_at, ip_address";

    public async Task InsertAsync(AccountToken token, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            $"""
            insert into ident.account_tokens ({Columns})
            values (@TokenHash, @UserUniqueId, @Purpose, @Delivery, @Email, @CreatedAt, @CreatedBy, @ExpiresAt, @ConsumedAt, @RevokedAt, @IpAddress)
            """,
            connection, transaction());
        command.Parameters.Add("@TokenHash", SqlDbType.NVarChar, Sizes.Text).Value = token.TokenHash;
        command.Parameters.Add("@UserUniqueId", SqlDbType.UniqueIdentifier).Value = token.UserUniqueId;
        command.Parameters.Add("@Purpose", SqlDbType.NVarChar, Sizes.Text).Value = PurposeOf(token.Purpose);
        command.Parameters.Add("@Delivery", SqlDbType.NVarChar, Sizes.Text).Value = token.Delivery == TokenDelivery.Email ? "email" : "hand";
        command.Parameters.Add("@Email", SqlDbType.NVarChar, Sizes.Text).Value = token.Email;
        command.Parameters.Add("@CreatedAt", SqlDbType.DateTimeOffset).Value = token.CreatedAt;
        command.Parameters.Add("@CreatedBy", SqlDbType.NVarChar, Sizes.Text).Value = token.CreatedBy.Value;
        command.Parameters.Add("@ExpiresAt", SqlDbType.DateTimeOffset).Value = token.ExpiresAt;
        command.Parameters.Add("@ConsumedAt", SqlDbType.DateTimeOffset).Value = (object?)token.ConsumedAt ?? DBNull.Value;
        command.Parameters.Add("@RevokedAt", SqlDbType.DateTimeOffset).Value = (object?)token.RevokedAt ?? DBNull.Value;
        command.Parameters.Add("@IpAddress", SqlDbType.NVarChar, Sizes.Text).Value = (object?)token.IpAddress ?? DBNull.Value;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<AccountToken?> FindAsync(string tokenHash, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            $"select {Columns} from ident.account_tokens where token_hash = @tokenHash",
            connection, transaction());
        command.Parameters.Add("@tokenHash", SqlDbType.NVarChar, Sizes.Text).Value = tokenHash;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? Read(reader) : null;
    }

    public async Task<bool> TryConsumeAsync(string tokenHash, DateTimeOffset consumedAt, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            "update ident.account_tokens set consumed_at = @consumedAt where token_hash = @tokenHash and consumed_at is null and revoked_at is null",
            connection, transaction());
        command.Parameters.Add("@tokenHash", SqlDbType.NVarChar, Sizes.Text).Value = tokenHash;
        command.Parameters.Add("@consumedAt", SqlDbType.DateTimeOffset).Value = consumedAt;
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) == 1;
    }

    public async Task RevokeOutstandingAsync(Guid userUniqueId, AccountTokenPurpose purpose, DateTimeOffset revokedAt, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            """
            update ident.account_tokens set revoked_at = @revokedAt
            where user_unique_id = @userUniqueId and purpose = @purpose and consumed_at is null and revoked_at is null
            """,
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        command.Parameters.Add("@purpose", SqlDbType.NVarChar, Sizes.Text).Value = PurposeOf(purpose);
        command.Parameters.Add("@revokedAt", SqlDbType.DateTimeOffset).Value = revokedAt;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<int> DeleteExpiredBeforeAsync(DateTimeOffset before, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand("delete from ident.account_tokens where expires_at < @before", connection, transaction());
        command.Parameters.Add("@before", SqlDbType.DateTimeOffset).Value = before;
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<DateTimeOffset?> LastIssuedAtAsync(Guid userUniqueId, AccountTokenPurpose purpose, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            "select max(created_at) as created_at from ident.account_tokens where user_unique_id = @userUniqueId and purpose = @purpose",
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        command.Parameters.Add("@purpose", SqlDbType.NVarChar, Sizes.Text).Value = PurposeOf(purpose);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        return reader.IsDBNull("created_at") ? null : reader.GetFieldValue<DateTimeOffset>("created_at");
    }

    private static string PurposeOf(AccountTokenPurpose purpose) => purpose switch
    {
        AccountTokenPurpose.PasswordReset => "password_reset",
        AccountTokenPurpose.Activation => "activation",
        AccountTokenPurpose.EmailRevert => "email_revert",
        AccountTokenPurpose.EmailChangeApproval => "email_change_approval",
        _ => throw new ArgumentOutOfRangeException(nameof(purpose), purpose, null),
    };

    private static AccountTokenPurpose PurposeOf(string purpose) => purpose switch
    {
        "activation" => AccountTokenPurpose.Activation,
        "email_revert" => AccountTokenPurpose.EmailRevert,
        "email_change_approval" => AccountTokenPurpose.EmailChangeApproval,
        _ => AccountTokenPurpose.PasswordReset,
    };

    private static AccountToken Read(SqlDataReader row) => new()
    {
        TokenHash = row.GetString("token_hash"),
        UserUniqueId = row.GetGuid("user_unique_id"),
        Purpose = PurposeOf(row.GetString("purpose")),
        Delivery = row.GetString("delivery") == "hand" ? TokenDelivery.Hand : TokenDelivery.Email,
        Email = row.GetString("email"),
        CreatedAt = row.GetFieldValue<DateTimeOffset>("created_at"),
        CreatedBy = Actor.Parse(row.GetString("created_by")),
        ExpiresAt = row.GetFieldValue<DateTimeOffset>("expires_at"),
        ConsumedAt = row.IsDBNull("consumed_at") ? null : row.GetFieldValue<DateTimeOffset>("consumed_at"),
        RevokedAt = row.IsDBNull("revoked_at") ? null : row.GetFieldValue<DateTimeOffset>("revoked_at"),
        IpAddress = row.IsDBNull("ip_address") ? null : row.GetString("ip_address"),
    };
}

/// <summary>The rows of <c>ident.email_verifications</c>, one per e-mail and purpose.</summary>
internal sealed class EmailVerificationRepository(SqlConnection connection, Func<SqlTransaction?> transaction)
{
    public async Task<int> DeleteExpiredBeforeAsync(DateTimeOffset before, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand("delete from ident.email_verifications where expires_at < @before", connection, transaction());
        command.Parameters.Add("@before", SqlDbType.DateTimeOffset).Value = before;
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    // The upserts of SQL Server: an update, an insert when it found no row, and the update again when a request at
    // the same moment inserted first. It holds no range lock, so two requests at once cannot deadlock on it; a merge
    // under holdlock did, on a table then without a clustered index. The last request written wins, as on PostgreSQL.
    public async Task UpsertAsync(EmailVerification verification, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            """
            begin try
                update ident.email_verifications set requested_by = @RequestedBy, code_hash = @CodeHash, created_at = @CreatedAt, expires_at = @ExpiresAt, attempts = @Attempts, is_verified = @IsVerified, ip_address = @IpAddress where email = @Email and purpose = @Purpose;
                if @@rowcount = 0
                    insert into ident.email_verifications (email, purpose, requested_by, code_hash, created_at, expires_at, attempts, is_verified, ip_address) values (@Email, @Purpose, @RequestedBy, @CodeHash, @CreatedAt, @ExpiresAt, @Attempts, @IsVerified, @IpAddress);
            end try
            begin catch
                if error_number() not in (2601, 2627) throw;
                update ident.email_verifications set requested_by = @RequestedBy, code_hash = @CodeHash, created_at = @CreatedAt, expires_at = @ExpiresAt, attempts = @Attempts, is_verified = @IsVerified, ip_address = @IpAddress where email = @Email and purpose = @Purpose;
            end catch
            """,
            connection, transaction());
        command.Parameters.Add("@Email", SqlDbType.NVarChar, Sizes.Text).Value = verification.Email;
        command.Parameters.Add("@Purpose", SqlDbType.NVarChar, Sizes.Text).Value = PurposeOf(verification.Purpose);
        command.Parameters.Add("@RequestedBy", SqlDbType.UniqueIdentifier).Value = (object?)verification.RequestedBy ?? DBNull.Value;
        command.Parameters.Add("@CodeHash", SqlDbType.NVarChar, Sizes.Text).Value = verification.CodeHash;
        command.Parameters.Add("@CreatedAt", SqlDbType.DateTimeOffset).Value = verification.CreatedAt;
        command.Parameters.Add("@ExpiresAt", SqlDbType.DateTimeOffset).Value = verification.ExpiresAt;
        command.Parameters.Add("@Attempts", SqlDbType.Int).Value = verification.Attempts;
        command.Parameters.Add("@IsVerified", SqlDbType.Bit).Value = verification.IsVerified;
        command.Parameters.Add("@IpAddress", SqlDbType.NVarChar, Sizes.Text).Value = (object?)verification.IpAddress ?? DBNull.Value;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<EmailVerification?> FindAsync(string email, EmailVerificationPurpose purpose, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            "select email, purpose, requested_by, code_hash, created_at, expires_at, attempts, is_verified, ip_address from ident.email_verifications where email = @email and purpose = @purpose",
            connection, transaction());
        command.Parameters.Add("@email", SqlDbType.NVarChar, Sizes.Text).Value = email;
        command.Parameters.Add("@purpose", SqlDbType.NVarChar, Sizes.Text).Value = PurposeOf(purpose);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? Read(reader) : null;
    }

    public async Task IncrementAttemptsAsync(string email, EmailVerificationPurpose purpose, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            "update ident.email_verifications set attempts = attempts + 1 where email = @email and purpose = @purpose",
            connection, transaction());
        command.Parameters.Add("@email", SqlDbType.NVarChar, Sizes.Text).Value = email;
        command.Parameters.Add("@purpose", SqlDbType.NVarChar, Sizes.Text).Value = PurposeOf(purpose);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task MarkVerifiedAsync(string email, EmailVerificationPurpose purpose, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            "update ident.email_verifications set is_verified = 1 where email = @email and purpose = @purpose",
            connection, transaction());
        command.Parameters.Add("@email", SqlDbType.NVarChar, Sizes.Text).Value = email;
        command.Parameters.Add("@purpose", SqlDbType.NVarChar, Sizes.Text).Value = PurposeOf(purpose);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteAsync(string email, EmailVerificationPurpose purpose, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            "delete from ident.email_verifications where email = @email and purpose = @purpose",
            connection, transaction());
        command.Parameters.Add("@email", SqlDbType.NVarChar, Sizes.Text).Value = email;
        command.Parameters.Add("@purpose", SqlDbType.NVarChar, Sizes.Text).Value = PurposeOf(purpose);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static string PurposeOf(EmailVerificationPurpose purpose) => purpose switch
    {
        EmailVerificationPurpose.Registration => "registration",
        EmailVerificationPurpose.EmailChange => "email_change",
        EmailVerificationPurpose.CurrentEmail => "current_email",
        _ => throw new ArgumentOutOfRangeException(nameof(purpose), purpose, null),
    };

    private static EmailVerificationPurpose PurposeOf(string purpose) => purpose switch
    {
        "email_change" => EmailVerificationPurpose.EmailChange,
        "current_email" => EmailVerificationPurpose.CurrentEmail,
        _ => EmailVerificationPurpose.Registration,
    };

    private static EmailVerification Read(SqlDataReader row) => new()
    {
        Email = row.GetString("email"),
        Purpose = PurposeOf(row.GetString("purpose")),
        RequestedBy = row.IsDBNull("requested_by") ? null : row.GetGuid("requested_by"),
        CodeHash = row.GetString("code_hash"),
        CreatedAt = row.GetFieldValue<DateTimeOffset>("created_at"),
        ExpiresAt = row.GetFieldValue<DateTimeOffset>("expires_at"),
        Attempts = row.GetInt32("attempts"),
        IsVerified = row.GetBoolean("is_verified"),
        IpAddress = row.IsDBNull("ip_address") ? null : row.GetString("ip_address"),
    };
}

/// <summary>The rows of <c>ident.user_avatars</c>, one per account that has an avatar.</summary>
internal sealed class AvatarRepository(SqlConnection connection, Func<SqlTransaction?> transaction)
{
    public async Task<AccountAvatar?> FindAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            "select user_unique_id, image, modified_at, modified_by from ident.user_avatars where user_unique_id = @userUniqueId",
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            return null;
        return new AccountAvatar
        {
            UserUniqueId = reader.GetGuid("user_unique_id"),
            Image = reader.GetFieldValue<byte[]>("image"),
            ModifiedAt = reader.GetFieldValue<DateTimeOffset>("modified_at"),
            ModifiedBy = Actor.Parse(reader.GetString("modified_by")),
        };
    }

    public async Task<DateTimeOffset?> FindModifiedAtAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            "select modified_at from ident.user_avatars where user_unique_id = @userUniqueId",
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? reader.GetFieldValue<DateTimeOffset>("modified_at") : null;
    }

    public async Task UpsertAsync(AccountAvatar avatar, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            """
            begin try
                update ident.user_avatars set image = @Image, modified_at = @ModifiedAt, modified_by = @ModifiedBy
                where user_unique_id = @UserUniqueId;
                if @@rowcount = 0
                    insert into ident.user_avatars (user_unique_id, image, modified_at, modified_by)
                    values (@UserUniqueId, @Image, @ModifiedAt, @ModifiedBy);
            end try
            begin catch
                if error_number() not in (2601, 2627) throw;
                update ident.user_avatars set image = @Image, modified_at = @ModifiedAt, modified_by = @ModifiedBy
                where user_unique_id = @UserUniqueId;
            end catch
            """,
            connection, transaction());
        command.Parameters.Add("@UserUniqueId", SqlDbType.UniqueIdentifier).Value = avatar.UserUniqueId;
        command.Parameters.Add("@Image", SqlDbType.VarBinary, Sizes.Max).Value = avatar.Image;
        command.Parameters.Add("@ModifiedAt", SqlDbType.DateTimeOffset).Value = avatar.ModifiedAt;
        command.Parameters.Add("@ModifiedBy", SqlDbType.NVarChar, Sizes.Text).Value = avatar.ModifiedBy.Value;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> DeleteAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand("delete from ident.user_avatars where user_unique_id = @userUniqueId", connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) > 0;
    }
}

/// <summary>The rows of <c>ident.user_mfa</c>, one per account that ever set a second factor up.</summary>
internal sealed class MfaRepository(SqlConnection connection, Func<SqlTransaction?> transaction)
{
    public async Task<MfaRecord?> FindAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            "select user_unique_id, pending_secret, totp_secret, is_enabled, enabled_at, method, last_used_step from ident.user_mfa where user_unique_id = @userUniqueId",
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            return null;
        return new MfaRecord
        {
            UserUniqueId = reader.GetGuid("user_unique_id"),
            PendingSecret = reader.IsDBNull("pending_secret") ? null : reader.GetString("pending_secret"),
            TotpSecret = reader.IsDBNull("totp_secret") ? null : reader.GetString("totp_secret"),
            IsEnabled = reader.GetBoolean("is_enabled"),
            EnabledAt = reader.IsDBNull("enabled_at") ? null : reader.GetFieldValue<DateTimeOffset>("enabled_at"),
            Method = reader.GetString("method"),
            LastUsedStep = reader.IsDBNull("last_used_step") ? null : reader.GetInt64("last_used_step"),
        };
    }

    public async Task<IReadOnlySet<Guid>> ListEnabledAsync(IReadOnlyCollection<Guid> userUniqueIds, CancellationToken cancellationToken)
    {
        // string_split gives one empty value for an empty list, which is no identifier.
        if (userUniqueIds.Count == 0)
            return new HashSet<Guid>();

        await using var command = new SqlCommand(
            "select user_unique_id from ident.user_mfa where is_enabled = 1 and user_unique_id in (select cast(value as uniqueidentifier) from string_split(@ids, N','))",
            connection, transaction());
        command.Parameters.Add("@ids", SqlDbType.NVarChar, Sizes.Max).Value = string.Join(',', userUniqueIds);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var enabled = new HashSet<Guid>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            enabled.Add(reader.GetGuid("user_unique_id"));
        return enabled;
    }

    public async Task SetPendingSecretAsync(Guid userUniqueId, string protectedSecret, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            """
            begin try
                update ident.user_mfa set pending_secret = @protectedSecret where user_unique_id = @userUniqueId;
                if @@rowcount = 0
                    insert into ident.user_mfa (user_unique_id, pending_secret) values (@userUniqueId, @protectedSecret);
            end try
            begin catch
                if error_number() not in (2601, 2627) throw;
                update ident.user_mfa set pending_secret = @protectedSecret where user_unique_id = @userUniqueId;
            end catch
            """,
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        command.Parameters.Add("@protectedSecret", SqlDbType.NVarChar, Sizes.Text).Value = protectedSecret;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task ReplaceTotpSecretAsync(Guid userUniqueId, string protectedSecret, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            "update ident.user_mfa set totp_secret = @protectedSecret where user_unique_id = @userUniqueId and totp_secret is not null",
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        command.Parameters.Add("@protectedSecret", SqlDbType.NVarChar, Sizes.Text).Value = protectedSecret;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> TryUseStepAsync(Guid userUniqueId, long step, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            "update ident.user_mfa set last_used_step = @step where user_unique_id = @userUniqueId and (last_used_step is null or last_used_step < @step)",
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        command.Parameters.Add("@step", SqlDbType.BigInt).Value = step;
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) == 1;
    }

    public async Task EnableAsync(Guid userUniqueId, DateTimeOffset enabledAt, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            """
            update ident.user_mfa
            set totp_secret = pending_secret, pending_secret = null, is_enabled = 1, enabled_at = @enabledAt, method = N'totp'
            where user_unique_id = @userUniqueId
            """,
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        command.Parameters.Add("@enabledAt", SqlDbType.DateTimeOffset).Value = enabledAt;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task EnableEmailAsync(Guid userUniqueId, DateTimeOffset enabledAt, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            """
            begin try
                update ident.user_mfa set totp_secret = null, pending_secret = null, is_enabled = 1, enabled_at = @enabledAt, method = N'email' where user_unique_id = @userUniqueId;
                if @@rowcount = 0
                    insert into ident.user_mfa (user_unique_id, is_enabled, enabled_at, method) values (@userUniqueId, 1, @enabledAt, N'email');
            end try
            begin catch
                if error_number() not in (2601, 2627) throw;
                update ident.user_mfa set totp_secret = null, pending_secret = null, is_enabled = 1, enabled_at = @enabledAt, method = N'email' where user_unique_id = @userUniqueId;
            end catch
            """,
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        command.Parameters.Add("@enabledAt", SqlDbType.DateTimeOffset).Value = enabledAt;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task DisableAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            """
            update ident.user_mfa
            set totp_secret = null, pending_secret = null, is_enabled = 0, enabled_at = null
            where user_unique_id = @userUniqueId
            """,
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>The rows of <c>ident.recovery_codes</c>: hashes only, each used once.</summary>
internal sealed class RecoveryCodeRepository(SqlConnection connection, Func<SqlTransaction?> transaction)
{
    public async Task DeleteAllAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand("delete from ident.recovery_codes where user_unique_id = @userUniqueId", connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    // One statement per hash, on one command, in the transaction of the replacement.
    public async Task InsertAllAsync(Guid userUniqueId, IReadOnlyList<string> codeHashes, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            "insert into ident.recovery_codes (user_unique_id, code_hash) values (@userUniqueId, @codeHash)",
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        var codeHash = command.Parameters.Add("@codeHash", SqlDbType.NVarChar, Sizes.Text);
        foreach (var value in codeHashes)
        {
            codeHash.Value = value;
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task<IReadOnlyList<string>> ListUnusedHashesAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            "select code_hash from ident.recovery_codes where user_unique_id = @userUniqueId and used_at is null",
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var hashes = new List<string>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            hashes.Add(reader.GetString("code_hash"));
        return hashes;
    }

    // The used_at is null guard makes the transition single-use: a second attempt at once updates no row.
    public async Task<bool> MarkUsedAsync(Guid userUniqueId, string codeHash, DateTimeOffset usedAt, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            "update ident.recovery_codes set used_at = @usedAt where user_unique_id = @userUniqueId and code_hash = @codeHash and used_at is null",
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        command.Parameters.Add("@codeHash", SqlDbType.NVarChar, Sizes.Text).Value = codeHash;
        command.Parameters.Add("@usedAt", SqlDbType.DateTimeOffset).Value = usedAt;
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) > 0;
    }

    public async Task<int> CountUnusedAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            "select count(*) from ident.recovery_codes where user_unique_id = @userUniqueId and used_at is null",
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        return (int)(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false))!;
    }
}

/// <summary>The rows of <c>ident.login_codes</c>: one per account, a hash only, removed when spent.</summary>
internal sealed class LoginCodeRepository(SqlConnection connection, Func<SqlTransaction?> transaction)
{
    // The upsert of SQL Server, as for the verifications: an update, an insert, the update again after a race.
    public async Task UpsertAsync(LoginCode code, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            """
            begin try
                update ident.login_codes set code_hash = @CodeHash, created_at = @CreatedAt, expires_at = @ExpiresAt where user_unique_id = @UserUniqueId;
                if @@rowcount = 0
                    insert into ident.login_codes (user_unique_id, code_hash, created_at, expires_at) values (@UserUniqueId, @CodeHash, @CreatedAt, @ExpiresAt);
            end try
            begin catch
                if error_number() not in (2601, 2627) throw;
                update ident.login_codes set code_hash = @CodeHash, created_at = @CreatedAt, expires_at = @ExpiresAt where user_unique_id = @UserUniqueId;
            end catch
            """,
            connection, transaction());
        command.Parameters.Add("@UserUniqueId", SqlDbType.UniqueIdentifier).Value = code.UserUniqueId;
        command.Parameters.Add("@CodeHash", SqlDbType.NVarChar, Sizes.Text).Value = code.CodeHash;
        command.Parameters.Add("@CreatedAt", SqlDbType.DateTimeOffset).Value = code.CreatedAt;
        command.Parameters.Add("@ExpiresAt", SqlDbType.DateTimeOffset).Value = code.ExpiresAt;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    // One statement checks the hash and the expiry and removes the row: two tries at once remove it once.
    public async Task<bool> DeleteMatchingAsync(Guid userUniqueId, string codeHash, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            "delete from ident.login_codes where user_unique_id = @userUniqueId and code_hash = @codeHash and expires_at > @now",
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        command.Parameters.Add("@codeHash", SqlDbType.NVarChar, Sizes.Text).Value = codeHash;
        command.Parameters.Add("@now", SqlDbType.DateTimeOffset).Value = now;
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) > 0;
    }

    public async Task<DateTimeOffset?> FindCreatedAtAsync(Guid userUniqueId, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand(
            "select created_at from ident.login_codes where user_unique_id = @userUniqueId",
            connection, transaction());
        command.Parameters.Add("@userUniqueId", SqlDbType.UniqueIdentifier).Value = userUniqueId;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? reader.GetFieldValue<DateTimeOffset>("created_at") : null;
    }

    public async Task<int> DeleteExpiredBeforeAsync(DateTimeOffset before, CancellationToken cancellationToken)
    {
        await using var command = new SqlCommand("delete from ident.login_codes where expires_at < @before", connection, transaction());
        command.Parameters.Add("@before", SqlDbType.DateTimeOffset).Value = before;
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }
}
