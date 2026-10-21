using System.Collections.Concurrent;

namespace Stellaegis.Identity.InMemory;

/// <summary>What the in-memory mailer was asked to send: the kind of message, to whom, with which code or link.</summary>
/// <param name="Kind">One of <see cref="InMemoryIdentityMailer.VerificationCode"/>, <see cref="InMemoryIdentityMailer.LoginCode"/>, <see cref="InMemoryIdentityMailer.PasswordResetLink"/>, <see cref="InMemoryIdentityMailer.AccountAlreadyExists"/>.</param>
/// <param name="Email">The recipient.</param>
/// <param name="Code">The code, for the two kinds that carry one.</param>
/// <param name="Link">The link, for a password reset.</param>
public sealed record IdentityMail(string Kind, string Email, string? Code, Uri? Link);

/// <summary>
/// A mailer that keeps what it was asked to send, for development and tests: nothing leaves the process, and a
/// test reads the code it needs from <see cref="Sent"/>.
/// </summary>
public sealed class InMemoryIdentityMailer : IIdentityMailer
{
    /// <summary>The kind of a verification code.</summary>
    public const string VerificationCode = "verification_code";

    /// <summary>The kind of a login code.</summary>
    public const string LoginCode = "login_code";

    /// <summary>The kind of a password reset link.</summary>
    public const string PasswordResetLink = "password_reset_link";

    /// <summary>The kind of the notice that an e-mail has an account already.</summary>
    public const string AccountAlreadyExists = "account_already_exists";

    private readonly ConcurrentQueue<IdentityMail> _sent = new();

    /// <summary>Every message asked so far, in order.</summary>
    public IReadOnlyCollection<IdentityMail> Sent => _sent;

    /// <summary>The last message asked for <paramref name="email"/>, or <see langword="null"/>.</summary>
    public IdentityMail? LastTo(string email) => _sent.LastOrDefault(mail => string.Equals(mail.Email, email, StringComparison.OrdinalIgnoreCase));

    /// <inheritdoc/>
    public Task SendVerificationCodeAsync(string email, string code, TimeSpan lifetime, CancellationToken cancellationToken = default)
    {
        _sent.Enqueue(new IdentityMail(VerificationCode, email, code, null));
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task SendLoginCodeAsync(string email, string code, TimeSpan lifetime, CancellationToken cancellationToken = default)
    {
        _sent.Enqueue(new IdentityMail(LoginCode, email, code, null));
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task SendPasswordResetLinkAsync(string email, Uri link, TimeSpan lifetime, CancellationToken cancellationToken = default)
    {
        _sent.Enqueue(new IdentityMail(PasswordResetLink, email, null, link));
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task SendAccountAlreadyExistsAsync(string email, CancellationToken cancellationToken = default)
    {
        _sent.Enqueue(new IdentityMail(AccountAlreadyExists, email, null, null));
        return Task.CompletedTask;
    }
}
