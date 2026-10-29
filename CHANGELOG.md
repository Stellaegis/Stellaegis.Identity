# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- **A password typed from a session to confirm an operation is a login attempt**: `AccountService` refuses it while the
  account is locked out, counts a wrong one toward the lockout, traces it as `LoginFailureReasons.InvalidCurrentPassword`,
  and answers in `LoginPolicy:MinResponseTime` at least. Six places let a taken session guess the password without limit.
  `VerifyCurrentPasswordAsync` answers a `Result` — `Password.InvalidCurrent` or `Account.LockedOut` — and takes the
  address of the request, as `ChangePasswordAsync` and `DeleteAccountAsync` do; a change of password no longer ends a
  lockout, it is refused during one.
- **The previous address is told of a change of e-mail**, `IIdentityMailer.SendEmailChangedAsync`, once the new one
  is confirmed, with the link that undoes it — good for `EmailChange:RevertLifetime`, seven days unless set. The link,
  `/revert-email`, restores the address, removes the password, revokes the reset links and a second factor enrolled
  since the change, and sends a reset link to the restored address; the sessions close at their next reading, an
  account without a password keeping none. A second change does not kill the link of the first.
  `AccountService.ConfirmEmailChangeAsync` answers the token with the change; `RevertEmailChangeAsync` and
  `ValidateRevertTokenAsync` carry the link; `AccountTokenPurpose.EmailRevert` is its purpose.

### Added

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
   `email_revert` —, so the installation and the verification refuse the schema of a 6.x. Drop it, then `install`.
2. **A store written outside the package implements `RecordFailedLoginAsync`**; the three of the package do.
   **An `IIdentityMailer` implements `SendEmailChangedAsync`**, the notice to the previous address with its link, and
   **`SendAccountLockedAsync`**, the notice that the account is locked out.
   **A caller of `AccountService.ConfirmEmailChangeAsync`** reads a `Result<EmailChanged>`, and sends the notice.
3. **A page that checked the second factor itself** — on `MfaService`, `LoginOtpService` or `RecoveryCodeService` —
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
