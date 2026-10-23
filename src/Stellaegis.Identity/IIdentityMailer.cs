namespace Stellaegis.Identity;

/// <summary>
/// What the accounts send by e-mail, and nothing of how: a code to verify an e-mail, a code to finish a login, a
/// link to reset a password, a notice that an e-mail already has an account. The host implements it on its own
/// messaging — <c>Stellaegis.Messaging</c>, an SMTP relay, anything —, with its own templates and wording; the
/// module never sends anything itself. Without an implementation, the pages that need one refuse to start rather
/// than fail at the first registration.
/// </summary>
public interface IIdentityMailer
{
    /// <summary>Sends <paramref name="code"/> to <paramref name="email"/>, to prove the person reads it; the code works for <paramref name="lifetime"/>.</summary>
    Task SendVerificationCodeAsync(string email, string code, TimeSpan lifetime, CancellationToken cancellationToken = default);

    /// <summary>Sends the one-time <paramref name="code"/> a login by e-mail second factor asks for; the code works for <paramref name="lifetime"/>.</summary>
    Task SendLoginCodeAsync(string email, string code, TimeSpan lifetime, CancellationToken cancellationToken = default);

    /// <summary>Sends the <paramref name="link"/> that resets the password of the account of <paramref name="email"/>; the link works for <paramref name="lifetime"/>.</summary>
    Task SendPasswordResetLinkAsync(string email, Uri link, TimeSpan lifetime, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sends the <paramref name="link"/> by which the person of <paramref name="email"/> chooses the first password
    /// of the account an administrator created; the link works for <paramref name="lifetime"/>.
    /// </summary>
    Task SendActivationLinkAsync(string email, Uri link, TimeSpan lifetime, CancellationToken cancellationToken = default);

    /// <summary>
    /// Tells <paramref name="email"/> that someone tried to register it while it has an account already. Sent so
    /// that a registration answers the same way whether the e-mail is known or not; the owner learns of the
    /// attempt, the stranger learns nothing.
    /// </summary>
    Task SendAccountAlreadyExistsAsync(string email, CancellationToken cancellationToken = default);
}
