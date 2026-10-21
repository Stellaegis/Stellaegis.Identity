# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
