using Stellaegis.Primitives;

namespace Stellaegis.Identity;

/// <summary>
/// The errors the module answers its caller, each with the code that lets the caller recognize it: in process
/// through a failed <see cref="Result"/> or a <see cref="UserFacingException"/>, over HTTP through the <c>code</c>
/// of the problem details. The messages are written for the person in front of the screen, and say nothing that
/// would let a caller tell an unknown account from a wrong password.
/// </summary>
public static class IdentityErrors
{
    /// <summary>The code of <see cref="InvalidCredentials"/>: the e-mail or the password is wrong, or the account is disabled or unknown.</summary>
    public const string InvalidCredentialsCode = "Credentials.Invalid";

    /// <summary>The code of <see cref="LockedOut"/>: too many failed logins, the account is locked for a while.</summary>
    public const string LockedOutCode = "Account.LockedOut";

    /// <summary>The code of <see cref="AccountNotFound"/>: no enabled account with that id.</summary>
    public const string AccountNotFoundCode = "Account.NotFound";

    /// <summary>The code of <see cref="AccountBlocked"/>: the account is disabled or deleted.</summary>
    public const string AccountBlockedCode = "Account.Blocked";

    /// <summary>The code of <see cref="InvalidCurrentPassword"/>: the password given to confirm the operation is wrong.</summary>
    public const string InvalidCurrentPasswordCode = "Password.InvalidCurrent";

    /// <summary>The code of <see cref="PasswordRejected"/>: the new password does not meet the policy.</summary>
    public const string PasswordRejectedCode = "Password.Rejected";

    /// <summary>The code of <see cref="EmailTaken"/>: another account has that e-mail.</summary>
    public const string EmailTakenCode = "Email.Taken";

    /// <summary>The code of <see cref="SameEmail"/>: the new e-mail is the current one.</summary>
    public const string SameEmailCode = "Email.Same";

    /// <summary>The code of <see cref="EmailNotVerified"/>: the e-mail must be verified first.</summary>
    public const string EmailNotVerifiedCode = "Email.NotVerified";

    /// <summary>The code of <see cref="EmailAlreadyVerified"/>: the e-mail was verified already.</summary>
    public const string EmailAlreadyVerifiedCode = "Email.AlreadyVerified";

    /// <summary>The code of <see cref="NoPendingVerification"/>: no code was requested for that e-mail.</summary>
    public const string NoPendingVerificationCode = "Verification.NotPending";

    /// <summary>The code of <see cref="VerificationCodeExpired"/>: the code is too old.</summary>
    public const string VerificationCodeExpiredCode = "Verification.Expired";

    /// <summary>The code of <see cref="TooManyVerificationAttempts"/>: the code was tried too many times.</summary>
    public const string TooManyVerificationAttemptsCode = "Verification.TooManyAttempts";

    /// <summary>The code of <see cref="InvalidVerificationCode"/>: the code is wrong.</summary>
    public const string InvalidVerificationCodeCode = "Verification.Invalid";

    /// <summary>The code of <see cref="InvalidResetToken"/>: the reset link is unknown, consumed, or for a disabled account.</summary>
    public const string InvalidResetTokenCode = "PasswordReset.Invalid";

    /// <summary>The code of <see cref="ResetTokenExpired"/>: the reset link is too old.</summary>
    public const string ResetTokenExpiredCode = "PasswordReset.Expired";

    /// <summary>The code of <see cref="RegistrationClosed"/>: the application does not take registrations.</summary>
    public const string RegistrationClosedCode = "Registration.Closed";

    /// <summary>The code of <see cref="RegistrationByInvitation"/>: the application takes registrations on invitation only.</summary>
    public const string RegistrationByInvitationCode = "Registration.ByInvitation";

    /// <summary>The code of <see cref="MfaNotPending"/>: no second factor is being set up.</summary>
    public const string MfaNotPendingCode = "Mfa.NotPending";

    /// <summary>The code of <see cref="InvalidMfaCode"/>: the one-time code is wrong.</summary>
    public const string InvalidMfaCodeCode = "Mfa.Invalid";

    /// <summary>The e-mail or the password is wrong, or the account is disabled or unknown: one message for all.</summary>
    public static Error InvalidCredentials { get; } =
        Error.Unauthorized(InvalidCredentialsCode, "The e-mail or the password is incorrect.");

    /// <summary>Too many failed logins: the account is locked for a while.</summary>
    public static Error LockedOut { get; } =
        Error.Unauthorized(LockedOutCode, "The account is temporarily locked. Try again later.");

    /// <summary>No enabled account with that id.</summary>
    public static Error AccountNotFound { get; } =
        Error.NotFound(AccountNotFoundCode, "The account was not found.");

    /// <summary>The account is disabled or deleted.</summary>
    public static Error AccountBlocked { get; } =
        Error.Forbidden(AccountBlockedCode, "The account is blocked.");

    /// <summary>The password given to confirm the operation is wrong.</summary>
    public static Error InvalidCurrentPassword { get; } =
        Error.Unauthorized(InvalidCurrentPasswordCode, "The current password is incorrect.");

    /// <summary>The new password does not meet the policy; <paramref name="violations"/> say what is missing.</summary>
    public static Error PasswordRejected(IReadOnlyList<string> violations)
        => Error.Validation(PasswordRejectedCode, string.Join(' ', Guard.NotNull(violations)));

    /// <summary>Another account has that e-mail.</summary>
    public static Error EmailTaken { get; } =
        Error.Conflict(EmailTakenCode, "This e-mail address is already used by another account.");

    /// <summary>The new e-mail is the current one.</summary>
    public static Error SameEmail { get; } =
        Error.Validation(SameEmailCode, "This is already the e-mail address of the account.");

    /// <summary>The e-mail must be verified before the account is created.</summary>
    public static Error EmailNotVerified { get; } =
        Error.PreconditionFailed(EmailNotVerifiedCode, "The e-mail address must be verified first.");

    /// <summary>The e-mail was verified already.</summary>
    public static Error EmailAlreadyVerified { get; } =
        Error.Conflict(EmailAlreadyVerifiedCode, "This e-mail address has already been verified.");

    /// <summary>No code was requested for that e-mail.</summary>
    public static Error NoPendingVerification { get; } =
        Error.NotFound(NoPendingVerificationCode, "No verification is pending for this e-mail address.");

    /// <summary>The verification code is too old.</summary>
    public static Error VerificationCodeExpired { get; } =
        Error.PreconditionFailed(VerificationCodeExpiredCode, "The verification code has expired. Request a new one.");

    /// <summary>The verification code was tried too many times.</summary>
    public static Error TooManyVerificationAttempts { get; } =
        Error.PreconditionFailed(TooManyVerificationAttemptsCode, "Too many failed attempts. Request a new code.");

    /// <summary>The verification code is wrong.</summary>
    public static Error InvalidVerificationCode { get; } =
        Error.Validation(InvalidVerificationCodeCode, "The verification code is incorrect.");

    /// <summary>The reset link is unknown, consumed, or for a disabled account.</summary>
    public static Error InvalidResetToken { get; } =
        Error.NotFound(InvalidResetTokenCode, "This password reset link is invalid or has already been used.");

    /// <summary>The reset link is too old.</summary>
    public static Error ResetTokenExpired { get; } =
        Error.PreconditionFailed(ResetTokenExpiredCode, "This password reset link has expired. Request a new one.");

    /// <summary>The application does not take registrations.</summary>
    public static Error RegistrationClosed { get; } =
        Error.Forbidden(RegistrationClosedCode, "This application does not take registrations.");

    /// <summary>The application takes registrations on invitation only.</summary>
    public static Error RegistrationByInvitation { get; } =
        Error.Forbidden(RegistrationByInvitationCode, "This application takes registrations on invitation only.");

    /// <summary>No second factor is being set up.</summary>
    public static Error MfaNotPending { get; } =
        Error.PreconditionFailed(MfaNotPendingCode, "No second factor is being set up.");

    /// <summary>The one-time code is wrong.</summary>
    public static Error InvalidMfaCode { get; } =
        Error.Unauthorized(InvalidMfaCodeCode, "The code is incorrect.");
}
