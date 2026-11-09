using Microsoft.Extensions.Logging;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// What Identity asks of the invitations, which live in the host's rights system — <c>Stellaegis.Registry</c>, the
/// host bridging the two in a few lines. Identity creates an account on an invitation only by asking this port: no
/// caller tells it an invitation was checked. Without it, no invitation opens anything.
/// </summary>
public interface IInvitationAcceptance
{
    /// <summary>
    /// What <paramref name="token"/> opens, when it can still be accepted, without spending it — or
    /// <see langword="null"/>. A page shows nothing of it before the person submits.
    /// </summary>
    Task<InvitationOffer?> FindAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Accepts the invitation for the account of <paramref name="subject"/>, whose address is the one invited:
    /// everything is checked again, the token is spent once, and what the invitation carries is applied.
    /// <paramref name="emailVerified"/> says whether that address is proven.
    /// </summary>
    Task<Result> AcceptAsync(string token, Subject subject, bool emailVerified, CancellationToken cancellationToken = default);
}

/// <summary>What an invitation opens, as Identity needs it: the address invited, and whether its link proves it.</summary>
/// <param name="Email">The address invited: the account that accepts carries it.</param>
/// <param name="SentByEmail">Whether the link was sent by e-mail by the system to that address — which receiving it proves —, rather than handed over.</param>
public sealed record InvitationOffer(string Email, bool SentByEmail);

/// <summary>
/// A person accepting an invitation: under the account they are signed in to, whose address is the one invited, or
/// under an account created from the invitation, at that address, whatever <see cref="IdentityOptions.SelfRegistration"/>
/// says. The invitation itself — who invited, to what, with which roles — is the host's, through
/// <see cref="IInvitationAcceptance"/>, without which nothing here opens.
/// </summary>
public sealed class InvitationService(
    IAuthUserStore users,
    PasswordHasher hasher,
    PasswordStrengthEvaluator passwords,
    IEventPublisher events,
    TimeProvider clock,
    ILogger<InvitationService> logger,
    IInvitationAcceptance? acceptance = null)
{
    /// <summary>Whether the host takes invitations: it registered an <see cref="IInvitationAcceptance"/>.</summary>
    public bool IsOpen => acceptance is not null;

    /// <summary>What <paramref name="token"/> opens, its address normalized, without spending it; <see langword="null"/> when nothing.</summary>
    public async Task<InvitationOffer?> FindAsync(string? token, CancellationToken cancellationToken = default)
    {
        if (acceptance is null || string.IsNullOrWhiteSpace(token))
            return null;
        return await acceptance.FindAsync(token, cancellationToken) is { } offer
            ? offer with { Email = Emails.Normalize(offer.Email) }
            : null;
    }

    /// <summary>Whether an account holds the address <paramref name="email"/>: the person then signs in to it before accepting.</summary>
    public async Task<bool> HasAccountAsync(string email, CancellationToken cancellationToken = default)
        => await users.GetByEmailAsync(Emails.Normalize(email), cancellationToken) is not null;

    /// <summary>
    /// Accepts the invitation for the account <paramref name="userUniqueId"/>, which must carry the address invited
    /// (<see cref="IdentityErrors.InvitationOtherAddress"/> otherwise): an invitation is bound to its address, never to
    /// whoever holds the link. The address must be proven — by the account, or by this link if it came by e-mail, which
    /// then proves it on the account too.
    /// </summary>
    public async Task<Result> AcceptAsync(string? token, Guid userUniqueId, CancellationToken cancellationToken = default)
    {
        if (await FindAsync(token, cancellationToken) is not { } offer)
            return Result.Failure(IdentityErrors.InvitationInvalid);
        var user = await users.GetByUniqueIdAsync(userUniqueId, cancellationToken);
        if (user is null)
            return Result.Failure(IdentityErrors.AccountNotFound);
        if (!string.Equals(user.Email, offer.Email, StringComparison.Ordinal))
            return Result.Failure(IdentityErrors.InvitationOtherAddress);
        var verified = user.EmailVerified || offer.SentByEmail;
        if (!verified)
            return Result.Failure(IdentityErrors.EmailNotVerified);

        var accepted = await acceptance!.AcceptAsync(token!, Subject.Parse(user.Subject), verified, cancellationToken);
        if (accepted.IsFailure)
            return accepted;
        if (!user.EmailVerified)
        {
            user.EmailVerified = true;   // the link reached the address: the account's address is proven
            user.ModifiedAt = clock.GetUtcNow();
            user.ModifiedBy = user.AsActor();
            await users.UpdateAsync(user, cancellationToken);
        }
        logger.LogInformation("Invitation accepted by {UserUniqueId}", userUniqueId);
        return Result.Success();
    }

    /// <summary>
    /// Creates the account of the address invited, with the name and password its person chooses, and returns its id;
    /// the person is its creator. The address is proven when the link came by e-mail. An address that has an account
    /// already is <see cref="IdentityErrors.EmailTaken"/>: its person signs in, then accepts. The invitation is not
    /// accepted yet: <see cref="AcceptAsync"/> does, and if it no longer holds meanwhile, the account stays, granted
    /// nothing.
    /// </summary>
    public async Task<Result<Guid>> CreateAccountAsync(string? token, string? displayName, string password, CancellationToken cancellationToken = default)
    {
        if (await FindAsync(token, cancellationToken) is not { } offer)
            return Result.Failure<Guid>(IdentityErrors.InvitationInvalid);
        var name = displayName?.Trim() ?? "";
        if (name.Length is 0 or > ProfileService.MaxDisplayNameLength)
            return Result.Failure<Guid>(IdentityErrors.InvalidDisplayName);
        if (await passwords.RefuseAsync(password, cancellationToken) is { } refused)
            return Result.Failure<Guid>(refused);
        if (await HasAccountAsync(offer.Email, cancellationToken))
            return Result.Failure<Guid>(IdentityErrors.EmailTaken);

        var id = Guid.NewGuid();
        var self = Actor.Parse(id.ToString("N"));
        var now = clock.GetUtcNow();
        await users.CreateAsync(new AuthUser
        {
            UserUniqueId = id,
            Email = offer.Email,
            DisplayName = name,
            PasswordHash = hasher.Hash(password),
            IsEnabled = true,
            EmailVerified = offer.SentByEmail,
            CreatedAt = now,
            CreatedBy = self,
            ModifiedAt = now,
            ModifiedBy = self,
        }, cancellationToken);
        await events.PublishAsync(new UserRegisteredEvent { OccurredAt = now, UserUniqueId = id, Email = offer.Email, DisplayName = name }, cancellationToken);
        logger.LogInformation("Account {UserUniqueId} created from an invitation", id);
        return Result.Success(id);
    }
}
