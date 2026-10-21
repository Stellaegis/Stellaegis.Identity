using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// Verifies that a person owns an e-mail, by a code the host sends there: the service issues and checks the code,
/// and never sends anything itself.
/// </summary>
public sealed class EmailVerificationService(IEmailVerificationStore store, IOptions<IdentityOptions> options, TimeProvider clock)
{
    /// <summary>Issues a code for <paramref name="email"/>, replacing any pending one, and returns it for the host to send.</summary>
    public async Task<Result<string>> RequestVerificationAsync(string email, string? ipAddress = null, CancellationToken cancellationToken = default)
    {
        var normalized = Emails.Normalize(email);
        var existing = await store.GetByEmailAsync(normalized, cancellationToken);
        if (existing is { IsVerified: true })
            return Result.Failure<string>(IdentityErrors.EmailAlreadyVerified);

        var settings = options.Value.EmailVerification;
        var now = clock.GetUtcNow();
        var code = GenerateCode(settings.CodeLength);
        await store.UpsertAsync(new EmailVerification
        {
            Email = normalized,
            Code = code,
            CreatedAt = now,
            ExpiresAt = now.Add(settings.Lifetime),
            Attempts = 0,
            IsVerified = false,
            IpAddress = ipAddress,
        }, cancellationToken);
        return Result.Success(code);
    }

    /// <summary>Checks <paramref name="code"/> for <paramref name="email"/>, and marks the e-mail verified when it holds.</summary>
    public async Task<Result> VerifyCodeAsync(string email, string? code, CancellationToken cancellationToken = default)
    {
        var normalized = Emails.Normalize(email);
        var verification = await store.GetByEmailAsync(normalized, cancellationToken);
        if (verification is null)
            return Result.Failure(IdentityErrors.NoPendingVerification);
        if (verification.IsVerified)
            return Result.Success();
        if (verification.ExpiresAt < clock.GetUtcNow())
            return Result.Failure(IdentityErrors.VerificationCodeExpired);
        if (verification.Attempts >= options.Value.EmailVerification.MaxAttempts)
            return Result.Failure(IdentityErrors.TooManyVerificationAttempts);
        if (!string.Equals(verification.Code, code?.Trim(), StringComparison.Ordinal))
        {
            await store.IncrementAttemptsAsync(normalized, cancellationToken);
            return Result.Failure(IdentityErrors.InvalidVerificationCode);
        }
        await store.MarkVerifiedAsync(normalized, cancellationToken);
        return Result.Success();
    }

    /// <summary>Whether <paramref name="email"/> was verified.</summary>
    public async Task<bool> IsEmailVerifiedAsync(string email, CancellationToken cancellationToken = default)
        => await store.GetByEmailAsync(Emails.Normalize(email), cancellationToken) is { IsVerified: true };

    /// <summary>Forgets the verification of <paramref name="email"/>, once it has served.</summary>
    public Task CleanupAsync(string email, CancellationToken cancellationToken = default)
        => store.DeleteByEmailAsync(Emails.Normalize(email), cancellationToken);

    private static string GenerateCode(int length)
        => RandomNumberGenerator.GetInt32(0, (int)Math.Pow(10, length)).ToString().PadLeft(length, '0');
}
