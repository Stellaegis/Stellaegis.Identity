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

    /// <summary>Marks the account deleted, by <paramref name="deletedBy"/>. <see langword="false"/> when no account with that id exists, or it is deleted already.</summary>
    Task<bool> SoftDeleteAsync(Guid userUniqueId, Primitives.Actor deletedBy, CancellationToken cancellationToken = default);
}

/// <summary>Where the login attempts are kept, append only.</summary>
public interface ILoginEventStore
{
    /// <summary>Records an attempt.</summary>
    Task AddAsync(LoginEvent loginEvent, CancellationToken cancellationToken = default);

    /// <summary>The most recent attempts of an account, newest first.</summary>
    Task<IReadOnlyList<LoginEvent>> GetRecentAsync(Guid userUniqueId, int take = 20, CancellationToken cancellationToken = default);
}

/// <summary>Where the password reset tokens are kept.</summary>
public interface IPasswordResetStore
{
    /// <summary>Stores a token just issued.</summary>
    Task CreateAsync(PasswordResetToken token, CancellationToken cancellationToken = default);

    /// <summary>The token with that value, or <see langword="null"/>.</summary>
    Task<PasswordResetToken?> GetByTokenAsync(Guid token, CancellationToken cancellationToken = default);

    /// <summary>Marks the token used, at <paramref name="consumedAt"/>.</summary>
    Task ConsumeAsync(Guid token, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);
}

/// <summary>Where the e-mail verifications are kept, one per e-mail.</summary>
public interface IEmailVerificationStore
{
    /// <summary>Creates or replaces the verification of its e-mail.</summary>
    Task UpsertAsync(EmailVerification verification, CancellationToken cancellationToken = default);

    /// <summary>The verification of that e-mail, or <see langword="null"/>.</summary>
    Task<EmailVerification?> GetByEmailAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>Counts one more attempt against the verification of that e-mail.</summary>
    Task IncrementAttemptsAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>Marks the e-mail verified.</summary>
    Task MarkVerifiedAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>Removes the verification of that e-mail, once the account exists or the change is done.</summary>
    Task DeleteByEmailAsync(string email, CancellationToken cancellationToken = default);
}

/// <summary>Where the second factors are kept.</summary>
public interface IMfaStore
{
    /// <summary>The second factor of an account, or <see langword="null"/> when none was ever set up.</summary>
    Task<MfaRecord?> GetAsync(Guid userUniqueId, CancellationToken cancellationToken = default);

    /// <summary>Among those accounts, the ones whose second factor is enabled, in one round trip.</summary>
    Task<IReadOnlySet<Guid>> GetEnabledUserIdsAsync(IReadOnlyCollection<Guid> userUniqueIds, CancellationToken cancellationToken = default);

    /// <summary>Keeps a TOTP secret just generated, until a first code confirms it.</summary>
    Task SetPendingSecretAsync(Guid userUniqueId, string secretBase32, CancellationToken cancellationToken = default);

    /// <summary>Makes the pending secret the active one, and enables the second factor by authenticator, at <paramref name="enabledAt"/>.</summary>
    Task EnableAsync(Guid userUniqueId, DateTimeOffset enabledAt, CancellationToken cancellationToken = default);

    /// <summary>Enables the second factor by e-mail, clearing any TOTP secret, at <paramref name="enabledAt"/>.</summary>
    Task EnableEmailAsync(Guid userUniqueId, DateTimeOffset enabledAt, CancellationToken cancellationToken = default);

    /// <summary>Disables the second factor and clears the secrets.</summary>
    Task DisableAsync(Guid userUniqueId, CancellationToken cancellationToken = default);
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
