namespace Stellaegis.Identity;

/// <summary>Where the accounts are kept. Each method is one atomic write; the store normalizes nothing: it gets e-mails already lowercase and trimmed.</summary>
public interface IAuthUserStore
{
    /// <summary>The account with that id, deleted ones excluded, or <see langword="null"/>.</summary>
    Task<AuthUser?> GetByUniqueIdAsync(Guid userUniqueId, CancellationToken cancellationToken = default);

    /// <summary>The account with that e-mail, deleted ones excluded, or <see langword="null"/>.</summary>
    Task<AuthUser?> GetByEmailAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>The accounts with any of those ids, deleted ones excluded, in one round trip.</summary>
    Task<IReadOnlyList<AuthUser>> ListByUniqueIdsAsync(IReadOnlyCollection<Guid> userUniqueIds, CancellationToken cancellationToken = default);

    /// <summary>A page of the accounts, by e-mail, deleted ones included when asked.</summary>
    Task<IReadOnlyList<AuthUser>> ListAsync(int skip, int take, bool includeDeleted = false, CancellationToken cancellationToken = default);

    /// <summary>The accounts blocked at the door, disabled or deleted: what a resource server refuses.</summary>
    Task<IReadOnlyList<AuthUser>> ListBlockedAsync(CancellationToken cancellationToken = default);

    /// <summary>How many accounts there are, deleted ones included when asked.</summary>
    Task<int> CountAsync(bool includeDeleted = false, CancellationToken cancellationToken = default);

    /// <summary>Creates the account, whose id the caller has set.</summary>
    Task CreateAsync(AuthUser user, CancellationToken cancellationToken = default);

    /// <summary>Writes the account back. <see langword="false"/> when no account with that id exists, or it is deleted.</summary>
    Task<bool> UpdateAsync(AuthUser user, CancellationToken cancellationToken = default);

    /// <summary>
    /// Counts one more failed login against the account — a wrong password, a wrong second factor —, at
    /// <paramref name="now"/>, and locks the account out until <paramref name="now"/> plus
    /// <paramref name="lockoutDuration"/> once the count reaches <paramref name="maxAttempts"/>. The count and the
    /// lock are one write on the row as it is, never on the row as it was read: attempts made at once all count, so
    /// that a lockout cannot be outrun by sending them together. <see langword="null"/> when no account with that
    /// id exists, or it is deleted.
    /// </summary>
    Task<FailedLogin?> RecordFailedLoginAsync(Guid userUniqueId, DateTimeOffset now, int maxAttempts, TimeSpan lockoutDuration, CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks the account deleted, by <paramref name="deletedBy"/>, replaces its e-mail by <c>deleted:{id}</c> and
    /// removes its avatar in the same gesture: the account stays so that its id is never reused, the address is free
    /// for a new account — a person who returns is a new account —, the image goes since it identifies the person.
    /// <see langword="false"/> when no account with that id exists, or it is deleted already.
    /// </summary>
    Task<bool> SoftDeleteAsync(Guid userUniqueId, Primitives.Actor deletedBy, CancellationToken cancellationToken = default);
}

/// <summary>Where the login attempts are kept, append only.</summary>
public interface ILoginEventStore
{
    /// <summary>Records an attempt.</summary>
    Task AddAsync(LoginEvent loginEvent, CancellationToken cancellationToken = default);

    /// <summary>Deletes the attempts made before <paramref name="before"/>, and returns how many.</summary>
    Task<int> DeleteBeforeAsync(DateTimeOffset before, CancellationToken cancellationToken = default);

    /// <summary>The most recent attempts of an account, newest first.</summary>
    Task<IReadOnlyList<LoginEvent>> GetRecentAsync(Guid userUniqueId, int take = 20, CancellationToken cancellationToken = default);
}

/// <summary>The account tokens, kept by their hash: issued, found, spent once, revoked.</summary>
public interface IAccountTokenStore
{
    /// <summary>Records a token issued.</summary>
    Task CreateAsync(AccountToken token, CancellationToken cancellationToken = default);

    /// <summary>The token whose hash is <paramref name="tokenHash"/>, or <see langword="null"/>.</summary>
    Task<AccountToken?> GetAsync(string tokenHash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Spends the token whose hash is <paramref name="tokenHash"/>, at <paramref name="consumedAt"/>, if neither spent
    /// nor revoked: <see langword="false"/> when another use came first.
    /// </summary>
    Task<bool> TryConsumeAsync(string tokenHash, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    /// <summary>Deletes the tokens that expired before <paramref name="before"/>, used or not, and returns how many.</summary>
    Task<int> DeleteExpiredBeforeAsync(DateTimeOffset before, CancellationToken cancellationToken = default);

    /// <summary>Revokes the tokens of the account for <paramref name="purpose"/> still usable: a newer one replaces them.</summary>
    Task RevokeOutstandingAsync(Guid userUniqueId, AccountTokenPurpose purpose, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);

    /// <summary>When the latest token of the account for <paramref name="purpose"/> was issued, used or not, or <see langword="null"/> when none was.</summary>
    Task<DateTimeOffset?> LastIssuedAtAsync(Guid userUniqueId, AccountTokenPurpose purpose, CancellationToken cancellationToken = default);
}

/// <summary>Where the e-mail verifications are kept, one per e-mail and purpose.</summary>
public interface IEmailVerificationStore
{
    /// <summary>Creates or replaces the verification of its e-mail and purpose.</summary>
    Task UpsertAsync(EmailVerification verification, CancellationToken cancellationToken = default);

    /// <summary>Deletes the verifications that expired before <paramref name="before"/>, and returns how many.</summary>
    Task<int> DeleteExpiredBeforeAsync(DateTimeOffset before, CancellationToken cancellationToken = default);

    /// <summary>The verification of that e-mail for that purpose, or <see langword="null"/>.</summary>
    Task<EmailVerification?> GetAsync(string email, EmailVerificationPurpose purpose, CancellationToken cancellationToken = default);

    /// <summary>Counts one more attempt against the verification of that e-mail for that purpose.</summary>
    Task IncrementAttemptsAsync(string email, EmailVerificationPurpose purpose, CancellationToken cancellationToken = default);

    /// <summary>Marks the e-mail verified for that purpose.</summary>
    Task MarkVerifiedAsync(string email, EmailVerificationPurpose purpose, CancellationToken cancellationToken = default);

    /// <summary>Removes the verification of that e-mail for that purpose, once the account exists or the change is done.</summary>
    Task DeleteAsync(string email, EmailVerificationPurpose purpose, CancellationToken cancellationToken = default);
}

/// <summary>Where the second factors are kept.</summary>
public interface IMfaStore
{
    /// <summary>The second factor of an account, or <see langword="null"/> when none was ever set up.</summary>
    Task<MfaRecord?> GetAsync(Guid userUniqueId, CancellationToken cancellationToken = default);

    /// <summary>Among those accounts, the ones whose second factor is enabled, in one round trip.</summary>
    Task<IReadOnlySet<Guid>> GetEnabledUserIdsAsync(IReadOnlyCollection<Guid> userUniqueIds, CancellationToken cancellationToken = default);

    /// <summary>Keeps a TOTP secret just generated, until a first code confirms it.</summary>
    Task SetPendingSecretAsync(Guid userUniqueId, string protectedSecret, CancellationToken cancellationToken = default);

    /// <summary>Replaces the active TOTP secret by the same one protected again, under another key.</summary>
    Task ReplaceTotpSecretAsync(Guid userUniqueId, string protectedSecret, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records <paramref name="step"/> as the time step of the last code accepted, if it comes after the one recorded:
    /// <see langword="false"/> when a code of that step or a later one was accepted already — a replay. The check
    /// and the set are one, so that one code is never accepted twice.
    /// </summary>
    Task<bool> TryUseStepAsync(Guid userUniqueId, long step, CancellationToken cancellationToken = default);

    /// <summary>Makes the pending secret the active one, and enables the second factor by authenticator, at <paramref name="enabledAt"/>.</summary>
    Task EnableAsync(Guid userUniqueId, DateTimeOffset enabledAt, CancellationToken cancellationToken = default);

    /// <summary>Enables the second factor by e-mail, clearing any TOTP secret, at <paramref name="enabledAt"/>.</summary>
    Task EnableEmailAsync(Guid userUniqueId, DateTimeOffset enabledAt, CancellationToken cancellationToken = default);

    /// <summary>Disables the second factor and clears the secrets.</summary>
    Task DisableAsync(Guid userUniqueId, CancellationToken cancellationToken = default);
}

/// <summary>Where the avatars are kept, one per account that has one.</summary>
public interface IAvatarStore
{
    /// <summary>The avatar of an account, or <see langword="null"/> when it has none.</summary>
    Task<AccountAvatar?> GetAsync(Guid userUniqueId, CancellationToken cancellationToken = default);

    /// <summary>When the avatar of an account was set, without reading the image, or <see langword="null"/> when it has none.</summary>
    Task<DateTimeOffset?> GetModifiedAtAsync(Guid userUniqueId, CancellationToken cancellationToken = default);

    /// <summary>Sets the avatar of an account, replacing the one it had.</summary>
    Task SetAsync(AccountAvatar avatar, CancellationToken cancellationToken = default);

    /// <summary>Removes the avatar of an account. <see langword="false"/> when it had none.</summary>
    Task<bool> DeleteAsync(Guid userUniqueId, CancellationToken cancellationToken = default);
}

/// <summary>Where the recovery codes are kept, as hashes only, like passwords.</summary>
public interface IRecoveryCodeStore
{
    /// <summary>Replaces every code of the account by those hashes: a fresh set, the previous one gone, used or not.</summary>
    Task ReplaceAllAsync(Guid userUniqueId, IReadOnlyList<string> codeHashes, CancellationToken cancellationToken = default);

    /// <summary>The hashes of the codes not used yet.</summary>
    Task<IReadOnlyList<string>> GetUnusedHashesAsync(Guid userUniqueId, CancellationToken cancellationToken = default);

    /// <summary>Marks the code with that hash used. <see langword="true"/> only when it was unused: the check and the set are one, so a code is never spent twice.</summary>
    Task<bool> MarkUsedAsync(Guid userUniqueId, string codeHash, CancellationToken cancellationToken = default);

    /// <summary>How many codes are left unused.</summary>
    Task<int> CountUnusedAsync(Guid userUniqueId, CancellationToken cancellationToken = default);

    /// <summary>Removes every code of the account, when an administrator resets its second factor.</summary>
    Task DeleteAllAsync(Guid userUniqueId, CancellationToken cancellationToken = default);
}

/// <summary>
/// The one question the accounts answer any resource server: which subjects are blocked at the door, disabled or
/// deleted, and must be refused whatever their token says. A resource server reads it when it starts and then
/// periodically, and keeps the answer in memory; the events <see cref="UserBlockedEvent"/> and
/// <see cref="UserUnblockedEvent"/> shorten the wait between two readings.
/// </summary>
/// <remarks>
/// Two sources exist: the local one, on <see cref="IAuthUserStore"/>, for a host that holds the accounts; and the
/// HTTP one of <c>Stellaegis.Identity.Client</c>, for a resource server apart. Subjects are the ids in the
/// <c>N</c> format, as the <c>sub</c> claim carries them.
/// </remarks>
public interface IBlockedUsersSource
{
    /// <summary>The subjects blocked at the door; empty when none is.</summary>
    Task<IReadOnlyCollection<string>> GetBlockedSubjectsAsync(CancellationToken cancellationToken = default);
}
