namespace Stellaegis.Identity;

/// <summary>
/// How a person proved who they are, as the session says it in its <c>amr</c> claims — the values of RFC 8176, which
/// an issuer carries into its tokens. What decides on them is the session's proof, not the account's settings: an
/// operation that requires a second factor asks whether it was used, not whether one exists.
/// </summary>
public static class AuthenticationMethods
{
    /// <summary>The claim type, <c>amr</c>: one claim per method.</summary>
    public const string ClaimType = "amr";

    /// <summary>A password, <c>pwd</c>.</summary>
    public const string Password = "pwd";

    /// <summary>A one-time code generated for this login — an authenticator's, or one sent by e-mail —, <c>otp</c>.</summary>
    public const string OneTimePassword = "otp";

    /// <summary>More than one factor, <c>mfa</c>.</summary>
    public const string MultipleFactors = "mfa";

    /// <summary>A password alone.</summary>
    public static IReadOnlyList<string> PasswordOnly { get; } = [Password];

    /// <summary>A password and a one-time code of an authenticator: two factors.</summary>
    public static IReadOnlyList<string> PasswordAndCode { get; } = [Password, OneTimePassword, MultipleFactors];

    /// <summary>
    /// A password and a one-time code sent by e-mail: a code was typed, <c>otp</c>, but the mailbox is the channel of
    /// a reset link, so whoever holds it holds the password too — one factor proven twice, never <c>mfa</c>. An
    /// operation that requires a second factor refuses such a session.
    /// </summary>
    public static IReadOnlyList<string> PasswordAndEmailCode { get; } = [Password, OneTimePassword];

    /// <summary>
    /// A password and a recovery code: a second factor, but no code generated for this login — an application that
    /// wants a living second factor tells them apart.
    /// </summary>
    public static IReadOnlyList<string> PasswordAndRecoveryCode { get; } = [Password, MultipleFactors];
}
