using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// Verifies that a person owns an e-mail, by a code the host sends there: the service issues and checks the code,
/// and never sends anything itself. A verification is one per e-mail and purpose, and its code answers to who
/// asked for it only: a registration pending on an address is not touched by an account asking for the same
/// address, and a code issued to one account proves nothing to another.
/// </summary>
public sealed class EmailVerificationService(IEmailVerificationStore store, IOptions<IdentityOptions> options, TimeProvider clock)
{
    /// <summary>
    /// Issues a code for <paramref name="email"/> and <paramref name="purpose"/>, replacing the one pending for the
    /// same — verified or not: the person starts over —, and returns it for the host to send. A registration has
    /// no <paramref name="requestedBy"/>; every other purpose names the account that asks. Asked again within
    /// <see cref="EmailVerificationOptions.MinimumInterval"/> of the last code to that e-mail for that purpose,
    /// whoever asked it, nothing is issued: <see cref="IdentityErrors.VerificationThrottled"/>, which a page keeps to
    /// itself.
    /// </summary>
    public async Task<Result<string>> RequestVerificationAsync(string email, EmailVerificationPurpose purpose, Guid? requestedBy, string? ipAddress = null, CancellationToken cancellationToken = default)
    {
        CheckRequester(purpose, requestedBy);
        var settings = options.Value.EmailVerification;
        var now = clock.GetUtcNow();
        var normalized = Emails.Normalize(email);
        if (settings.MinimumInterval > TimeSpan.Zero
            && await store.GetAsync(normalized, purpose, cancellationToken) is { } last
            && last.CreatedAt + settings.MinimumInterval > now)
            return Result.Failure<string>(IdentityErrors.VerificationThrottled);

        var code = GenerateCode(settings.CodeLength);
        await store.UpsertAsync(new EmailVerification
        {
            Email = normalized,
            Purpose = purpose,
            RequestedBy = requestedBy,
            Code = code,
            CreatedAt = now,
            ExpiresAt = now.Add(settings.Lifetime),
            Attempts = 0,
            IsVerified = false,
            IpAddress = ipAddress,
        }, cancellationToken);
        return Result.Success(code);
    }

    /// <summary>
    /// Checks <paramref name="code"/> against the verification of <paramref name="email"/> for
    /// <paramref name="purpose"/> asked by <paramref name="requestedBy"/>, and marks the e-mail verified when it
    /// holds. A verification asked by someone else is as if there were none. A verified e-mail still answers to its
    /// code, and to nothing else: what failed after the code — the creation of the account — is tried again with it.
    /// </summary>
    public async Task<Result> VerifyCodeAsync(string email, EmailVerificationPurpose purpose, Guid? requestedBy, string? code, CancellationToken cancellationToken = default)
    {
        CheckRequester(purpose, requestedBy);
        var normalized = Emails.Normalize(email);
        var verification = await store.GetAsync(normalized, purpose, cancellationToken);
        if (verification is null || verification.RequestedBy != requestedBy)
            return Result.Failure(IdentityErrors.NoPendingVerification);
        if (verification.ExpiresAt < clock.GetUtcNow())
            return Result.Failure(IdentityErrors.VerificationCodeExpired);
        if (verification.Attempts >= options.Value.EmailVerification.MaxAttempts)
            return Result.Failure(IdentityErrors.TooManyVerificationAttempts);
        if (!string.Equals(verification.Code, code?.Trim(), StringComparison.Ordinal))
        {
            await store.IncrementAttemptsAsync(normalized, purpose, cancellationToken);
            return Result.Failure(IdentityErrors.InvalidVerificationCode);
        }
        if (!verification.IsVerified)
            await store.MarkVerifiedAsync(normalized, purpose, cancellationToken);
        return Result.Success();
    }

    /// <summary>Whether <paramref name="email"/> was verified for <paramref name="purpose"/>, by <paramref name="requestedBy"/>.</summary>
    public async Task<bool> IsEmailVerifiedAsync(string email, EmailVerificationPurpose purpose, Guid? requestedBy, CancellationToken cancellationToken = default)
    {
        CheckRequester(purpose, requestedBy);
        return await store.GetAsync(Emails.Normalize(email), purpose, cancellationToken) is { IsVerified: true } verification
            && verification.RequestedBy == requestedBy;
    }

    /// <summary>Forgets the verification of <paramref name="email"/> for <paramref name="purpose"/>, once it has served.</summary>
    public Task CleanupAsync(string email, EmailVerificationPurpose purpose, CancellationToken cancellationToken = default)
        => store.DeleteAsync(Emails.Normalize(email), purpose, cancellationToken);

    // A registration has no account to ask; every other purpose is asked by one. A caller that gets it wrong is a
    // programming error, not a case to answer.
    private static void CheckRequester(EmailVerificationPurpose purpose, Guid? requestedBy)
    {
        if (purpose == EmailVerificationPurpose.Registration ? requestedBy is not null : requestedBy is null)
            throw new ArgumentException($"A {purpose} verification {(requestedBy is null ? "names the account that asks for it" : "is asked by nobody")}.", nameof(requestedBy));
    }

    private static string GenerateCode(int length)
        => RandomNumberGenerator.GetInt32(0, (int)Math.Pow(10, length)).ToString().PadLeft(length, '0');
}
