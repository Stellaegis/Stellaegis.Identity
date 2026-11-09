# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [9.0.1] — 2026-11-09

On `Stellaegis.Primitives` 5.6.0, whose startup refuses a host it used to let through badly assembled; and an
invitation handed over no longer reads as lapsed.

### Fixed

- **An invitation handed over waits for the address, it does not lapse.** A person who created the account from an
  invitation whose link was handed over was told the invitation no longer held: the acceptance refuses an address
  not proven, and the page read every refusal as a lapse. The invitation still holds; the page now tells to verify
  the address from the account, then open the same link again — which, opened before that, says the same. New texts
  `Invitation.CreatedAddressUnproven` and `Invitation.ProveAddressFirst`.

### Changed

- **`Stellaegis.Primitives` 5.6.0 and Microsoft.Extensions 10.0.14.** Nothing changes in this package's code; a host
  meets what the startup of Primitives 5.6.0 now refuses — on PostgreSQL, the application connecting as a
  superuser, a `BYPASSRLS` role or the owner of the schema; a route of a module that declares no authorization;
  admissions registered without `UseStellaegisActorAdmission()` — listed with their way out in the CHANGELOG of
  Primitives, § *Updating from 5.5.0*.

### Updating from 9.0.0

Take the version. A host that starts on Primitives 5.6.0 needs nothing more from this package; one that does not
meets the list above, each item with its way out.

## [9.0.0] — 2026-11-09

Who may administer the accounts no longer reaches every account. The administration routes were decided on their
operation alone, `users.write`: holding it was holding every account, the administrator's included — blocking it,
removing its second factor, taking it by a reset link handed over. A gesture on an account is now decided on that
account, by the host's rights system; no administration route acts on the caller's own account; a reset link of an
active account is handed over only once a second person approved it; a session closes when what proves its person
changes; and the operations name their gestures. Invitations come with it, through a port the host bridges.

### Added

- **Invitations, through the port `IInvitationAcceptance`** that the host bridges to its rights system —
  `Stellaegis.Registry`: the page `/invitation` and `InvitationService`. Signed in under the address invited, the
  person accepts; with no account at that address, the person creates it there, its own creator whatever
  `SelfRegistration` says, then accepts. The page names nothing the invitation carries and sends no referrer; a link
  that came by e-mail proves the address. Without the port, the page is not there. New texts `Invitation.*`, errors
  `Invitation.Invalid` and `Invitation.OtherAddress`.

### Changed

- **The operations name the gestures, and `users.write` is gone.** `users.create` creates an account and sends its
  activation again; `users.block` blocks and unblocks; `users.recover` lifts the lockout, removes the second factor,
  issues a reset link, sets the e-mail of a lost mailbox. `users.write` said nothing of what it granted — taking the
  account of an administrator among it. `users.read`, `users.delete` and `security.read` stay.
- **A gesture on an account is decided on that account.** The routes that act on an account that exists load the
  person as a `Subject` of `Stellaegis.Primitives` 5.5.0 and ask the resource-based authorization about it: the host
  answers with a handler on `OperationRequirement` and `Subject`, or declares `AllowAnyResource()` on the group. With
  neither, the host does not start; a refusal answers 404 `Account.NotFound`.
- **No administration route acts on the caller's own account**: 403 `Account.OwnAccount`.
- **A reset link of an active account is handed over only once a second person approved it.** Handed over, the link
  gives its holder the account: one administrator alone could take any. The new port `IHandDeliveryApprovals`, which
  the host's rights system implements: `AccountAdministrationService.RequestHandDeliveryAsync` asks, a second person
  grants, `IssuePasswordResetAsync(…, approval)` spends it. The route answers 202 with `HandDeliveryPending` first, then
  the link when called again with `IssueLinkRequest.Approval`. Without the port, a reset link is never handed over,
  403 `Delivery.NoApprover`; an activation link still is.
- **A session is held against the security stamp of its account.** `ident.users.security_stamp`, by the script
  `0003`, changes with whatever must close the other sessions — the password changed, reset or removed, the account
  blocked, the second factor enrolled, changed, disabled or reset, the e-mail changed —, and a session whose stamp is
  not the account's is closed at its next reading, `Session:ValidationInterval`. A session signed in before Identity 9
  carries none and is closed: every person signs in once more after the upgrade. `CookieSignIn.RefreshAsync` holds
  the session against the stamp; `RefreshAfterOwnChangeAsync` lets the session that made the change go on, and the
  account pages call it. `IAuthUserStore.RenewSecurityStampAsync` writes the stamp alone, `UpdateAsync` never does;
  `AuthUser.SecurityStamp`; `MfaService` takes `IAuthUserStore`; `LoginService.RenewPrincipalAfterOwnChangeAsync`.

### Updating from 8.0.0

1. **Run the installation again**: the schema `ident` takes its script `0003`, the security stamp, without being
   dropped, and a host refuses to start until it has. **Every person signs in once more** after the upgrade: the
   sessions opened before carry no stamp, and close at their next reading.
2. **The operations changed**: `users.write` is gone, for `users.create`, `users.block` and `users.recover`. A host
   that grants by operation grants the new ones; the catalogue of a rights system that records the declarations —
   `Stellaegis.Registry` 7 — retires the old one.
3. **Decide the gestures on an account**, or the host does not start: register a handler on `OperationRequirement`
   and `Subject` — `AddStellaegisRegistryAdministration()` of `Stellaegis.Registry` 7 does —, or declare
   `AllowAnyResource()` on the group of `MapIdentityAdminEndpoints()` when the administrators reach every account.
4. **A reset link handed over for an active account** needs an `IHandDeliveryApprovals`: without it, such a link is
   refused and the reset goes by e-mail. The route answers 202 with an approval first.
5. **Invitations** open when the host registers an `IInvitationAcceptance`, bridged to its rights system.
6. **A caller of the code**: `MfaService` takes `IAuthUserStore`; `AccountAdministrationService.IssuePasswordResetAsync`
   takes the approval; a store written outside the package implements `IAuthUserStore.RenewSecurityStampAsync`, and writes
   `AuthUser.SecurityStamp` at the creation only. A page of the host's that changes the password, the second factor or
   the e-mail of the person signed in calls `CookieSignIn.RefreshAfterOwnChangeAsync` after it.

## [8.0.0] — 2026-11-09

The short codes are kept as hashes, and the codes of a login by e-mail in the database. A code sent to verify an
e-mail was stored in clear; a code sent at a login lived in the memory of the process, refused by every other
instance of the host and lost at a restart; a recovery code cost a PBKDF2 for every code left at each try. Each is
now an HMAC-SHA256 under the pepper, bound to what it serves, looked up in the database. And a verification code of
ten digits never started with 3 or more.

### Added

- **`ILoginCodeStore`, the codes sent by e-mail during a login, in the database**: one per account, as a hash, spent by
  one write that checks the hash and the expiry, purged once expired. The table `ident.login_codes` comes with the
  script `0002`, on both engines, and the in-memory stores have their own.

### Changed

- **The codes sent by e-mail at a login are kept by `ILoginCodeStore`, not in the memory of the process**: a code
  issued by one instance of the host is checked by another, and a restart loses none. `LoginOtpService` is renamed
  `LoginCodeService`, scoped, its methods `GenerateAsync` and `ValidateAsync`; a code is an HMAC-SHA256 under the
  pepper, the account in the input. New options `LoginCode:Lifetime`, ten minutes as before, and
  `LoginCode:MinimumInterval`, a minute: a login asked again sooner sends no code — `LoginCode.Throttled` —, and the
  page goes on, the code sent still working. `RetentionReport` counts the login codes purged, `LoginCodes`. The
  method stays closed unless the installation opens it, `Mfa:AllowedMethods`: NIST SP 800-63B rev. 4 refuses e-mail as
  an out-of-band authenticator, and the session says `pwd, otp`, without `mfa`.
- **A verification code is kept as its hash, never in clear**: an HMAC-SHA256 under the pepper, its e-mail and purpose
  in the input, compared in constant time. `EmailVerification.Code` is renamed `CodeHash`, and the column
  `ident.email_verifications.code` `code_hash`, 64 lowercase hexadecimal digits under a check, on both engines. A host
  that implements `IEmailVerificationStore` stores `CodeHash` as it is given.
- **A recovery code is kept as an HMAC-SHA256 under the pepper, bound to its account**, and looked up: a try costs one
  hash, where it cost a PBKDF2 for every code left, up to eight. A recovery code has about 50 bits: a plain SHA-256
  would be found by trying them all, once for every account, while a keyed hash read from `ident` is worth nothing
  without the pepper. ⚠ **The codes issued before are no longer recognized**: a person who holds some generates a new
  set from the account pages. The store contract is unchanged; `IRecoveryCodeStore.GetUnusedHashesAsync` is no longer
  called by the package.

### Fixed

- **A verification code of ten digits draws every digit in every place.** Its bound, 10¹⁰, was cast to an `int`,
  which saturates at 2 147 483 647 since .NET 9: no code of `EmailVerification:CodeLength = 10` started with 3 or
  more, about 31 bits instead of 33. Codes are now drawn digit by digit, as the login codes by e-mail and the recovery
  codes are.

### Updating from 7.0.1

1. **Run the installation again**: the schema `ident` takes its script `0002`, without being dropped — the codes of
   the verifications become their hashes, and `ident.login_codes` appears —, and a host refuses to start until it
   has. The verifications pending are removed by it, their codes being in clear: the person asks a new code.
2. **The recovery codes issued before are no longer recognized**: whoever holds some generates a new set.
3. **A caller of `LoginOtpService`** calls `LoginCodeService`, `GenerateAsync` and `ValidateAsync`, and treats
   `LoginCode.Throttled` as a code sent. **A store written outside the package** implements `ILoginCodeStore`, and
   `EmailVerification.CodeHash` in place of `Code`; the three of the package do. **A reader of `RetentionReport`**
   finds `LoginCodes` beside the others.

## [7.0.1] — 2026-11-04

### Fixed

- **The account navigation folds behind a "Menu" button under 720 px.** On a phone the whole menu — three groups,
  seven entries, the language picker, "Sign out" — came before the page, which started below the fold. The navigation
  is now a native `<details>`, rendered closed, whose summary names the page the person is on; no script. Above 720 px
  nothing changes: the stylesheet hides the summary and keeps the content open through `::details-content`, and a
  browser without that pseudo-element shows the button at every width instead. A host that replaced
  `_AccountLayout.cshtml` keeps its own layout. New text `Account.Nav.Menu`.

## [7.0.0] — 2026-10-29

A wrong second factor is a failed login. For the ten minutes of a pending login, codes could be tried without
limit — three valid authenticator codes in a million per try, one in a million by e-mail —, and every try also
hashed each recovery code left. And the failed logins were counted by the service on the row it had read: attempts
sent together each wrote "one more" over the same value, and a lockout of five could be outrun. And a session taken
from its person could change the e-mail of the account — then reset its password by that e-mail —, replace an
authenticator by the e-mail method, or enroll an authenticator that locks the person out, all without the password.

### Changed

- **Changing the e-mail, enabling the second factor by e-mail and enrolling an authenticator ask the password**, as
  disabling the second factor and deleting the account did. A wrong or missing password shows the form again.
- **A locked account is told what anyone is told at the login**, `Credentials.Invalid`: five wrong passwords on an
  address, and the sixth answer said whether it had an account. The lockout stays in `LoginStep.LockedOut`, for the
  host; the person is told by e-mail when it starts, `IIdentityMailer.SendAccountLockedAsync`, once per lockout. After a
  password that held, or from a session, `Account.LockedOut` is still said: there is nothing left to hide.
- **The e-mail of a deleted account is replaced by `deleted:{id}`** at the deletion, by the store: the address is free
  for a new account, under a new identity. It stayed, unique, and a registration or `POST identity/users` on it hit the
  constraint — a failure that said an account had existed there.
- **The registration keeps the hash of the password, not the password**, in its protected cookie, between the form and
  the code: `RegistrationService.CreateAccountFromHashAsync` takes it, `CreateAccountAsync` still takes a password.
- **A hash made with a former iteration count is remade at the login that verified it**, `PasswordHasher.NeedsRehash`:
  raising `PasswordHasher:Iterations` now reaches the accounts, one login each. And the stand-in hash of an unknown
  account is made with the configured count: a fixed one cost a different time, and told an unknown account from a
  wrong password when the count was not the default.
- **`Session:Lifetime`**, fourteen days unless set, is the expiry of the cookie, renewed by each request: the default of
  ASP.NET Core, written as an option so that it is a decision. The culture cookie is sent over HTTPS only, as the others.
- **`POST identity/users` checks the shape of the e-mail**, as the pages do: what it took reached the mailer as given.
- **`Pages:DefaultReturnUrl` refuses `//` and `/\`**: both passed as local and failed at the first redirection.
- **The pages refuse to be framed**: `Content-Security-Policy: frame-ancestors 'none'`, appended beside any policy the
  host sets, and `X-Frame-Options: DENY` when the host sets none. A page laid under a decoy could have the person click
  "Continue", "Disable" or "Enable" unknowing.
- **A password typed from a session to confirm an operation is a login attempt**: `AccountService` refuses it while the
  account is locked out, counts a wrong one toward the lockout, traces it as `LoginFailureReasons.InvalidCurrentPassword`,
  and answers in `LoginPolicy:MinResponseTime` at least. Six places let a taken session guess the password without limit.
  `VerifyCurrentPasswordAsync` answers a `Result` — `Password.InvalidCurrent` or `Account.LockedOut` — and takes the
  address of the request, as `ChangePasswordAsync` and `DeleteAccountAsync` do; a change of password no longer ends a
  lockout, it is refused during one.
- **A change of e-mail waits for the approval of the previous address**, `EmailChange:RequireApprovalByPrevious`, the
  posture unless set: once the new address proved itself by its code, a link goes to the previous one,
  `IIdentityMailer.SendEmailChangeApprovalAsync`, good for `EmailChange:ApprovalLifetime`, seven days unless set, and
  nothing applies until it is opened there, `/approve-email`; a newer request replaces it. A lost mailbox goes through
  an administrator, `POST identity/users/{id}/email`, `AccountAdministrationService.ChangeEmailAsync`, which sets the
  address unproven. `AccountService.ApproveEmailChangeAsync` and `ValidateApprovalTokenAsync` carry the link;
  `AccountTokenPurpose.EmailChangeApproval` is its purpose. A host that lets the change apply at once sets the option
  to false, and gets the notice below.
- **The previous address is told of a change of e-mail**, `IIdentityMailer.SendEmailChangedAsync`, once the new one
  is confirmed and when the installation asks no approval, with the link that undoes it — good for
  `EmailChange:RevertLifetime`, seven days unless set. The link,
  `/revert-email`, restores the address, removes the password, revokes the reset links and a second factor enrolled
  since the change, and sends a reset link to the restored address; the sessions close at their next reading, an
  account without a password keeping none. A second change does not kill the link of the first.
  `AccountService.ConfirmEmailChangeAsync` answers the token with the change; `RevertEmailChangeAsync` and
  `ValidateRevertTokenAsync` carry the link; `AccountTokenPurpose.EmailRevert` is its purpose.
- **A verification of an e-mail is one per e-mail and purpose, and answers to its requester only.**
  `ident.email_verifications` had the address for its whole key, and the service answered success without the code on
  a row already verified: a registration whose account failed after the code could be completed by anyone; and an
  account asking for an address erased the verification a stranger had pending on it. The row carries its purpose,
  `EmailVerificationPurpose` — `Registration`, `EmailChange`, `CurrentEmail` —, keyed with the address, and
  `RequestedBy`, the account that asked, none for a registration; `EmailVerificationService` takes both on every
  call, answers `Verification.NotPending` to another requester, and a verified e-mail still answers to its code and to
  nothing else. `IEmailVerificationStore` reads, counts, marks and deletes by e-mail and purpose.

- **A password is at least eight characters long, and nothing else unless the host asks for it**: `PasswordPolicy`
  requires no kind of character unless set — `RequireUppercase`, `RequireLowercase`, `RequireDigit`,
  `RequireSpecialChar`, each false now —, the posture of NIST SP 800-63B, revision 4, which forbids such rules: they
  yield `Password1!`, which every list of the common ones holds. The strength is scored on the length first, six
  points per character past the sixth up to seventy, then on what the password mixes; the meter of the pages too.

### Added

- **The passwords everyone chooses are refused, in three layers**, by the `IPasswordBlocklist` the package registers
  unless the host registers its own, `DefaultPasswordBlocklist`: the hundred thousand most used passwords, shipped
  with the package, `PasswordBlocklist:UseEmbeddedList`; a file of the installation, `PasswordBlocklist:Path`, one
  password per line, read again when it changes, so that an administrator adds to it without waiting for a version;
  and Have I Been Pwned, `PasswordBlocklist:Hibp:Enabled`, off unless set, asked by the first five characters of the
  SHA-1 — the password never leaves the host — and silent when it does not answer. Compared without regard to case.
  Until then the port was empty: nothing was refused without a list of the host's.
- **The strength meter on every page that takes a new password**: `/activate`, `/reset-password` and
  `/account/password` show it as `/register` did; an account created by its administration never saw it.
- **The methods of the second factor are the installation's to allow**, `Mfa:AllowedMethods`: the authenticator alone
  unless set, the code by e-mail where the host opens it. The pages offer the allowed ones only;
  `MfaService.EnableEmailAsync`, which answers a `Result` now, and `ConfirmSetupAsync` refuse the others,
  `Mfa.MethodNotAllowed`; an account whose method is no longer allowed keeps it; `MfaService.Allows` says. Until then
  every account could take the code by e-mail, and a host had no say.
- **A code sent by e-mail is no longer a second factor**: the session says `pwd` and `otp`, without `mfa`. The mailbox
  is the channel of a reset link, so whoever holds it holds the password too — one factor proven twice —, and an
  operation that requires a second factor was satisfied by it. `AuthenticationMethods.PasswordAndEmailCode` names it.
- **The pages limit what comes too fast, whatever the host set up.** Every POST of the pages — a GET is never
  counted — is counted against the address of the client, `Pages:RateLimiting:RequestsPerClient`, sixty a minute
  unless set, and against the e-mail the form names when it names one — the one the person signs in as, registers
  with, asks a code or a link for —, `Pages:RateLimiting:RequestsPerEmail`, ten a minute unless set, over a sliding
  `Pages:RateLimiting:Window`. Over either limit the page comes back with the seconds to wait, status 429 and
  `Retry-After`, and nothing is tried; the pages of the language choice are never counted. Until then, the pages were
  limited only by a policy of the host named in `Pages:RateLimitingPolicy`, and a host that named none had no limit at
  all: a password could be tried on every address, a mailbox flooded with codes. `Pages:RateLimitingPolicy` stays, in
  addition; a host that limits the pages by its own policy turns the package's off, `Pages:RateLimiting:Enabled`.
  `PagesRateLimitingOptions` holds the settings.
- **A code or a link asked again too soon for one address is not sent**, whoever asks: `EmailVerification:MinimumInterval`
  between two codes to one e-mail for one purpose, `PasswordReset:MinimumInterval` between two reset links to one
  account, a minute each unless set, zero for none. `EmailVerificationService.RequestVerificationAsync` answers
  `Verification.Throttled`, which the pages keep to themselves, and `PasswordResetService.RequestResetAsync` answers
  `null` as for an unknown address: the page says what it always says, and the code or the link sent still works. A
  stranger could flood a mailbox with codes and links, and each one replaced the one the person was waiting for.
  `IAccountTokenStore.LastIssuedAtAsync` says when the latest token of an account for a purpose was issued.
- **`IPasswordBlocklist`**, the port a host registers to refuse the passwords everyone chooses or the breaches hold,
  asked wherever a password is accepted — `PasswordStrengthEvaluator.RefuseAsync`, which the registration, the
  activation, the reset, the change and the registration page go through —, answered `Password.Blocked`. The module
  ships no list: without one registered, nothing is refused for this.
- **`UserPasswordChangedEvent`**, published when the password is changed by its person, reset by a link, or removed by
  the link that undoes a change of e-mail, with its reason: an issuer revokes the refresh tokens and the authorizations
  of the subject on it — what was issued on the former password is no longer the person's. Until then, a stolen
  password that had served to obtain tokens went on serving after the reset.
- **`LoginService.CompleteWithSecondFactorAsync`**: the second step of a login, in the service. A locked account is
  refused before the code is read; a recovery code is recognized by its shape — ten letters or digits — and tried
  alone, `RecoveryCodeService.LooksLikeCode`; a wrong code counts as a failed login and locks the account out like a
  wrong password, traced as `LoginFailureReasons.InvalidSecondFactor`; the answer takes `LoginPolicy:MinResponseTime`
  at least. `/login/mfa` signs in on its answer, and leaves the pending login on a lockout.
- **`IAuthUserStore.RecordFailedLoginAsync`**: one more failed login counted and the lockout set in one write on the
  stored row, answering `FailedLogin` — the count, and until when the account is locked out. Both engines write it
  in one statement; the in-memory store under a lock.

### Updating from 6.3.0

1. **The schema `ident` is installed again**: `0001` is corrected in place — `ck_account_tokens_purpose` takes
   `email_revert` and `email_change_approval`, `email_verifications` is keyed by e-mail and purpose and carries
   `requested_by` —, so the installation and the verification refuse the schema of a 6.x. Drop it, then `install`.
2. **A store written outside the package implements `RecordFailedLoginAsync`**, `LastIssuedAtAsync`, and the e-mail
   verifications by e-mail and purpose; the three of the package do. **A caller of `EmailVerificationService`** passes
   the purpose and the requester, and treats `Verification.Throttled` as a code sent.
3. **A host that wants kinds of characters in a password** asks for them now, `PasswordPolicy:RequireUppercase` and
   the three others, false unless set: the passwords accepted so far stay as they are. **The common passwords are
   refused from now on** by the list the package ships, unless the host registered an `IPasswordBlocklist` of its
   own, which it keeps; `PasswordBlocklist:UseEmbeddedList` turns the list off.
4. **A host whose people take the code by e-mail as second factor** names it, `Mfa:AllowedMethods:1 = email`: the
   pages offer the authenticator alone otherwise. And a decision that required `mfa` is no longer satisfied by a
   code by e-mail: such people enroll an authenticator, or the host reconsiders what it requires. A caller of
   `MfaService.EnableEmailAsync` reads a `Result`.
5. **A host that limits the pages by a policy of its own** keeps `Pages:RateLimitingPolicy` and sets
   `Pages:RateLimiting:Enabled` to false, or lets both apply. A host that set up nothing has the package's limits now,
   and enables `ForwardedHeaders` behind a proxy so that the count is the client's rather than the proxy's.
   **An `IIdentityMailer` implements `SendEmailChangeApprovalAsync`**, the approval link to the previous address,
   **`SendEmailChangedAsync`**, the notice to the previous address with its link, and **`SendAccountLockedAsync`**,
   the notice that the account is locked out.
   **A caller of `AccountService.ConfirmEmailChangeAsync`** reads a `Result<EmailChanged>`, and sends the notice.
6. **A page that checked the second factor itself** — on `MfaService`, `LoginOtpService` or `RecoveryCodeService` —
   calls `LoginService.CompleteWithSecondFactorAsync` instead, so that a wrong code counts.

## [6.3.0] — 2026-10-28

When the person proved who they are. The session said how, not when: an issuer had nothing to answer `max_age`
with, nor a decision asking for a recent authentication.

### Added

- **`auth_time`** in the principal of a session, seconds since the epoch, set at the login and kept for the whole
  session; `AuthenticationTime` names the claim and reads it.
- **`LoginService.RenewPrincipalAsync`**: the principal of a session that goes on, its account read again, how and
  when the person proved who they are kept. The validation of the cookie and `CookieSignIn.RefreshAsync` go through it.

### Updating from 6.2.0

1. **Nothing to install**: the schema is unchanged.
2. **A session signed in before the update carries no `auth_time`** until its next login.

## [6.2.0] — 2026-10-28

A session confronted with its account. The cookie was trusted for its whole lifetime: a session whose account had
been deleted, disabled, or lost with a database installed again under the same keys kept opening the pages, and a
token issuer composed on them gave it tokens. And the login page followed any open session, whichever account it
named.

### Added

- **The session is read against its account**, once `Stellaegis:Identity:Session:ValidationInterval` elapsed — five
  minutes unless set, zero for every request —, the mechanism of the security stamp validator of ASP.NET Core
  Identity: an account gone, deleted or disabled signs the session out; the others are issued again with the
  account as it is now. `SessionPolicyOptions`, `IdentityOptions.Session`.
- **`/login` shows an open session**, its avatar, name and address, with "Continue" and "Switch account".

### Changed

- **The default logo is the Stellaegis mark** on its own tile, which reads in light and dark alike.
- **The languages are a list** with a button that applies the choice, for a large number of them. The classes
  `language-select` and `language-apply` replace `language-option`.
- **The footer of the card wraps**, its blocks centered vertically.
- **The French texts carry their no-break spaces**: U+202F before ? ! ;, U+00A0 before : and inside « ».

### Fixed

- **The account page** answered a session whose account was gone or disabled with a 500; it signs it out.

### Updating from 6.1.0

1. **Nothing to install**: the schema is unchanged.
2. **A session older than five minutes is read again at its first request** after the update, and one whose
   account is no more is signed out.
3. **A host that linked to `/login` for a signed-in person** to send them on now shows them the open session; a
   link to the way back itself goes there directly.
4. **A stylesheet of the host that styled `language-option`** styles `language-select` and `language-apply`.

## [6.1.0] — 2026-10-24

What a person chooses of their own account: the language of the pages, a time zone, the name, an avatar. The pages
follow the person rather than the browser alone, and the session carries what an application needs to show dates
and names as the person wants them.

### Added

- **`ProfileService`**: the name, the language — a culture name in its canonical form —, the time zone — an IANA
  name —, read and changed by the person; the avatar, a PNG of 256 by 256 pixels, checked and rebuilt from the chunks
  that draw it, without an image library. `AccountProfile`, `IAvatarStore` and `AccountAvatar`, kept apart from the
  account in `ident.user_avatars`, removed with it. `UserProfileChangedEvent` when the name or the avatar changes.
- **The claims of the profile**, `ProfileClaims`: `locale` and `zoneinfo` when the person chose them, `picture` when
  the host declares `Stellaegis:Identity:AvatarUrl`.
- **The language of the pages** follows, unless `Pages:Culture` imposes one: the account, the `ui_locales` of the
  authorization request, the choice made on the pages — kept in `.AspNetCore.Culture` and the account —, the host's
  request localization or the browser, then `Pages:DefaultCulture`. A row of buttons offers the languages with texts.
- **The account page** changes the profile in place, the time zone of the browser suggested, and carries the avatar
  editor: a file, or a Gravatar asked by the browser behind `Pages:GravatarImport`, off unless set.
  `/account/avatar` serves the avatar to its person. `Pages:AvatarCornerRadius` rounds it, a circle unless set.
- **The registration** keeps the time zone of the browser.
- **`MapIdentityAccountEndpoints()`**: `GET` and `PUT identity/account/profile`, on oneself, under the cookie.
- **`CookieSignIn.RefreshAsync`** signs the session in again from the account, keeping its `amr` and its lifetime.

### Fixed

- The danger button reads in the dark theme: `--si-danger-text`.

### Updating from 6.0.0

1. **Reinstall the schema.** `0001_ident.sql` is corrected in place, with the language, the time zone and the
   avatars: drop the schema `ident` and run the installation again. The verification at startup refuses the 6.0.0
   schema, and says so.
2. **Without `Pages:Culture`, the pages no longer follow the host's request localization first**: the account, the
   `ui_locales` and the choice made on the pages come before it. A host that wants a single language sets `Culture`.
3. **A registration in progress during the update** restarts: what waits between its two pages changed.
4. **`MapIdentityAccountEndpoints()`** needs the startup check of Primitives registered, as the administration routes do.

## [6.0.0] — 2026-10-23

The creation of the accounts reviewed for its security, and the stores on SQL Server. An administrator no
longer chooses the password of anyone: the account is created without one, and its person chooses it by a link.
The links carry tokens of which only the hash is kept, the address of an account is proven before a reset link
goes there, the secrets of the second factor are protected at rest, the session says how the person proved who
they are, and what identifies a person is removed once it no longer serves.

### Migrating from 5.x

1. **Reinstall the schema.** `0001_ident.sql` is corrected in place — no database held real data yet: drop the
   schema `ident` (`drop schema ident cascade`) and run the installation again. The verification at startup
   refuses a schema installed from the 5.x script, and says so.
2. **Configure `Stellaegis:Identity:Mfa:SecretKeys`**, required like the pepper: `ActiveKeySlot` and
   `Keys:<slot>`, secrets of the deployment. The startup refuses a host without it.
3. **`Registration:Posture` becomes `SelfRegistration`**, `Closed` or `Open`, `Closed` unless set.
   `RegistrationPosture`, `ByInvitation` and the `invited` flag of the registration are gone: an invitation will be
   a port of its own, in a later version.
4. **`AccountAdministrationService.CreateAsync(email, displayName, delivery, actor)`** creates the account without
   a password and answers a `PendingAccount` carrying its activation token. `ChangePasswordAsync` and the route
   `POST identity/users/{id}/change-password` are gone: `IssuePasswordResetAsync` and
   `POST identity/users/{id}/password-reset` issue a reset link instead. `POST identity/users` takes
   `{ "email", "displayName", "delivery" }`.
5. **Implement `IIdentityMailer.SendActivationLinkAsync`**, or declare `Links:HandDelivery`:
   `MapIdentityAdminEndpoints()` refuses a host that can do neither. Set `Links:PublicBaseUrl` when the pages are
   served behind a proxy or by another host, and wherever a link is issued outside a request.
6. **`IAccountTokenStore` replaces `IPasswordResetStore`**; `PasswordResetService` takes and returns the token as
   a string.
7. **`LoginService.CreatePrincipalAsync` and `CookieSignIn.SignInAsync` by id take the authentication methods**,
   `AuthenticationMethods.PasswordOnly` and its siblings: a principal says how its person proved who they are.
8. **Schedule the purge**: call `IdentityRetentionService.PurgeAsync(IdentityRetentionService.Job)` every day from
   the host's scheduler.

### Added

- `Stellaegis.Identity.SqlServer`: the six stores and the schema `ident` on SQL Server, the same tables and rules
  as on PostgreSQL, registered by `AddStellaegisIdentitySqlServer` from `Stellaegis:Identity:SqlServer`.
- The activation: `ActivationService`, the page `/activate`, `Activation:TokenLifetime` (7 days),
  `AccountAdministrationService.IssueActivationAsync` and the route `POST identity/users/{id}/activation`. An
  account waiting for its activation is refused at login, recorded as `NOT_ACTIVATED`, and its person is answered
  what anyone is.
- `Links:PublicBaseUrl` and `Links:HandDelivery`: how the links are written, and whether an administrator may
  receive one to hand over.
- `AuthUser.EmailVerified`: the address proven by a code, or by a link the system mailed — never by a link handed
  over. While it is not, no reset link is mailed there, and an administrator asking for one is refused with
  `Email.NotVerified`. The account page verifies the current address.
- The `amr` claim in the principal, with the values of RFC 8176: `pwd`; `pwd`, `otp`, `mfa`; `pwd`, `mfa` after a
  recovery code. `AuthenticationMethods` names them.
- `IdentityRetentionService` and `Retention:LoginEvents` (180 days) and `Retention:Expired` (30 days), each may be
  raised and never lowered under its default.

### Changed

- The tokens of the links are 32 random bytes, of which only the SHA-256 is kept, in `ident.account_tokens`; a
  token is spent once, atomically, and a newer one of the same purpose revokes the previous ones.
- The TOTP secrets are protected at rest — AES-256-GCM under a key of `Mfa:SecretKeys` derived by HKDF, the account
  bound as associated data —, protected again under the active key at their use; a code is accepted once, and a
  code of an earlier step is refused.
- The French texts of the pages address nobody: the infinitive or an impersonal turn, never « vous ».
- The packages take `Stellaegis.Primitives` 5.2.0.

### Removed

- `AccountAdministrationService.ChangePasswordAsync`, the route `change-password`, `IPasswordResetStore`,
  `RegistrationPosture`, `Registration:Posture`, the error `Registration.ByInvitation`.

## [5.1.0] — 2026-10-21

### Added

- `BlockedAccounts` implements `IActorAdmission` of `Stellaegis.Primitives.AspNetCore` 5.1.0, registered by
  `AddStellaegisIdentityAdmission(...)` beside the admissions of the other modules: `UseStellaegisActorAdmission()`
  of Primitives refuses a blocked account at the door with `Account.Blocked`, and a token issuer asks the same
  question through `IActorAdmissions`.

### Deprecated

- `UseStellaegisIdentityAdmission()`: call `UseStellaegisActorAdmission()` of Primitives. The former enables the
  same middleware, once, whichever of the two is called.

### Changed

- The packages take `Stellaegis.Primitives` 5.1.0.

## [5.0.0] — 2026-10-21

First release of the packages: the accounts of the Stellaegis framework, extracted and rewritten on
`Stellaegis.Primitives` 5.0. They start at the major version of the family. Identity identifies a person and does
nothing else: the OpenID Connect issuer of the framework is extracted apart, as `Stellaegis.Issuer`, and takes the
person this package signed in without reading its accounts.

### What it keeps from the framework

The services of `Stellaegis.Identity` — login with its lockout and its constant response time, registration,
account, password reset, e-mail verification, second factor by authenticator app or by e-mail, recovery codes —,
PBKDF2 with a pepper and 310 000 iterations, the six stores on PostgreSQL, the pages of the `Platform.Identity` host
and their behaviour, the administration of accounts of `Admin.Identity`, the blocking of accounts of
`Stellaegis.Security`.

### What changes for a host coming from the framework

1. **No OpenIddict, no token.** `Identity.OpenIddict`, the routes of clients and scopes, the `oidc_*` tables are not
   here; `ident` holds no `oidc_*` table. The `Sessions` page of the account, which listed refresh tokens, is the
   issuer's.
2. **No seeder.** `IdentityBootstrapSeeder`, `BootstrapOptions` and the variables `STELLAEGIS_ADMIN_*` are gone: the
   first administrator is created by the installation, through `AccountAdministrationService`, as the example's
   `install` verb does. The schema is installed by `DatabaseLifecycle.InstallAsync([IdentityDatabase.Value], …)`
   under an administration role, and verified at every startup under the application's role, rather than applied
   by hand from `docs/sql`.
3. **One section, `Stellaegis:Identity`**, one sub-section per concern — `PasswordHasher`, `PasswordPolicy`,
   `LoginPolicy`, `Mfa`, `EmailVerification`, `PasswordReset`, `Registration` —, bound by `AddStellaegisIdentity`
   and validated at startup. `Stellaegis:Security:PasswordPolicy` and `HistoryCount`, which no code read, are gone;
   `Stellaegis:Identity:Database:ConnectionStringName` becomes `Stellaegis:Identity:PostgreSQL:ConnectionString`.
4. **The registration has a posture**, `Closed` by default: a host that let anyone register sets `Open`.
5. **The actors of a write are `Actor`s, without a default**: `created_by`, `modified_by`, `deleted_by` carry who
   did it, never `'system'`; the installation writes `job:install`. The person is the actor of what they do to
   their own account.
6. **`ident.users` has no surrogate key**: `user_unique_id` is the primary key, nothing joined on `user_id`.
   `password_history` and `v_users`, which no code read, are not created.
7. **The administration routes carry their operation** — `users.read`, `users.write`, `users.delete`,
   `security.read`, declared on `IdentityModule` — and no policy by name: the host translates with
   `RequireAuthorizationPerOperation`. `POST identity/users` sets the id of the account, which the framework's route
   left empty; `POST …/block` takes no end date, blocking is disabling; the routes `/oidc-*`, `/oidc/apis` and
   `/security/revoked-tokens` are the issuer's.
8. **The pages are a Razor class library**, `Stellaegis.Identity.Server`, mounted by `AddStellaegisIdentityPages`
   and `MapStellaegisIdentityPages`, their texts in English and in French, replaceable page by page by the host.
   What they send goes through `IIdentityMailer`, a port the host implements: the module no longer references
   `Stellaegis.Messaging`.
9. **The blocking of accounts is the admission of actors**: `AddStellaegisIdentityAdmission` and
   `UseStellaegisIdentityAdmission` replace `AddUserSecurity` and `UseUserSecurity` for the accounts;
   `IBlockedUsersSource` is a port of the core, local or HTTP (`Stellaegis.Identity.Client`). The revoked tokens are
   the issuer's.
10. **The events are `IEvent`s** — `UserRegisteredEvent`, `UserBlockedEvent`, `UserUnblockedEvent` — published
    through `IEventPublisher`, and the module subscribes to nothing: the host connects its bus.

### Fixed, against the framework

- `ILoginEventStore` was a singleton holding one connection, shared by concurrent requests; every store now opens
  its own unit of work, and no store opens a connection synchronously.
- `POST /users` of the administration never set `UserUniqueId`, so the second account created violated the unique
  index.
- The e-mail verification code is checked against its configured length, where the schema fixed six digits.
