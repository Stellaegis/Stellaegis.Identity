# Stellaegis.Identity

Stellaegis.Identity holds the accounts of a .NET application assembled on
[Stellaegis.Primitives](https://github.com/Stellaegis/Stellaegis.Primitives): who a person is, and that they are
who they say. Accounts created by an administrator and activated by their person, or registered by the person
alone; login with a lockout, a second factor by authenticator app or by e-mail, recovery codes, e-mail
verification, password reset, the trace of logins and its purge, the administration of accounts — and, for any
resource server, the one question it asks of the accounts: is this one blocked?

It issues no token. Turning a signed-in person into tokens is the work of `Stellaegis.Issuer`, which takes the
person the host authenticated — by the cookie of this package, or otherwise — and never reads the accounts.
And it decides no right: that is `Stellaegis.Access`. Identity identifies a person, and does nothing else.

The library targets .NET 10 and is released under the MIT license.

## Packages

| Package | Contents | Depends on |
| --- | --- | --- |
| `Stellaegis.Identity` | The services — login, registration, account, password reset, e-mail verification, second factor, recovery codes, administration —, the ports of the stores, the in-memory stores, the module and its operations, the events, the passwords, the mailer port | `Stellaegis.Primitives`, `Stellaegis.Primitives.Hosting`, Otp.NET |
| `Stellaegis.Identity.PostgreSQL` | The stores on PostgreSQL, and the `ident` schema declared as a module database for the installation and the verification | `Stellaegis.Primitives.Data`, Npgsql, Dapper |
| `Stellaegis.Identity.SqlServer` | The same stores and the same schema on SQL Server | `Stellaegis.Primitives.Data`, Microsoft.Data.SqlClient, Dapper |
| `Stellaegis.Identity.AspNetCore` | The cookie a person signs in with, the administration routes of the accounts under their operations, and the admission of actors on a resource server | `Stellaegis.Primitives.AspNetCore`, ASP.NET Core |
| `Stellaegis.Identity.Client` | The HTTP source of the blocked accounts, for a resource server apart from the host that holds the accounts | `Stellaegis.Primitives.Hosting` |
| `Stellaegis.Identity.Server` | The pages a person signs in and manages their account with, as a Razor class library the host mounts | `Stellaegis.Identity.AspNetCore`, ASP.NET Core |

The six packages share one version. They started at the major version of Stellaegis.Primitives, 5; 6.0.0 runs
on Primitives 5.2.0.

## A host, in full

An enterprise application — one compartment, the company itself — holding the accounts of its own people. This
is `samples/Stellaegis.Identity.Sample`, which runs as is on a PostgreSQL server; on SQL Server, the host calls
`AddStellaegisIdentitySqlServer` instead, from `Stellaegis:Identity:SqlServer`.

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddStellaegisFrame(ApplicationFrame.SingleCompartment("acme"));
builder.Services.AddStellaegisRequestContext();

builder.Services.AddStellaegisIdentityPostgreSQL(builder.Configuration);   // Stellaegis:Identity:PostgreSQL, Stellaegis:Identity
builder.Services.AddStellaegisIdentityCookie();
builder.Services.AddStellaegisIdentityPages(builder.Configuration);        // Stellaegis:Identity:Pages
builder.Services.AddStellaegisIdentityAdministration();
builder.Services.AddStellaegisLocalBlockedUsersSource();
builder.Services.AddStellaegisIdentityAdmission(builder.Configuration);    // Stellaegis:Identity:Admission

builder.Services.AddSingleton<IIdentityMailer, MyMailer>();                 // what the pages send, on the host's messaging
builder.Services.AddAuthorization(options => { /* one policy per operation of IdentityOperations.All */ });

var app = builder.Build();
await app.Services.VerifyStellaegisDatabasesAsync();   // the installation ran before, under another role: prove it

app.MapStaticAssets();
app.UseAuthentication();
app.UseStellaegisActorAdmission();                                    // of Primitives: the blocked accounts, and any other admission
app.UseAuthorization();

app.MapStellaegisIdentityPages();                                           // /login, /register, /account/…
app.MapGroup("/api/admin").MapIdentityAdminEndpoints()
   .RequireAuthorizationPerOperation(operation => operation.ToString());   // "users.read", "users.write", …

app.Run();
```

What the host brings is its own: its API and its modules, its rights system answering the policies named after
the operations, its messaging behind `IIdentityMailer`, its bus behind `IEventPublisher`.

## Installing, then verifying

The accounts live in the schema `ident` of a PostgreSQL or SQL Server database — the same tables, the same rules.
Two executants, two roles, as everywhere in the family: an installer installs, under a role that owns the schema;
the application verifies at every startup, under its own role, which was granted its data rights and never a DDL
right. On SQL Server, the application's role is a database role, which the login of the application joins.

```csharp
await DatabaseLifecycle.InstallAsync([IdentityDatabase.Value], frame, openAsAdministrator, applicationRole: "myapp_app");
```

The installation creates the schema, applies its scripts once and records each with its checksum, and grants the
application's role what it needs. It is replayable. The application then verifies — `AddStellaegisDatabaseVerification()`
in a generic host, `app.Services.VerifyStellaegisDatabasesAsync()` in an ASP.NET Core host — and refuses to start
when the schema is not installed, or not as the package declares it.

No account is seeded. The first administrator is a gesture of the installation, through the services of the
module, as the example does:

```sh
dotnet run -- install --admin-email admin@acme.test
```

The example's `install` verb creates the database and the application's role if missing, installs the schema
under the administration connection, then calls `AccountAdministrationService.CreateAsync` as the actor
`job:install`. The account has no password: the installation prints its activation link, which the installer
opens once the application runs, and chooses the password there — no password goes through the command line, its
history or the list of processes. Run again, it changes nothing but a new link for an administrator still waiting.

## The accounts

An account is an `AuthUser`: its identity `UserUniqueId`, a random GUID that its `sub` claim carries and that is
never reused; its e-mail, normalized and unique among the accounts, and whether that address was proven; its
display name; the language and the time zone its person chose, absent while they chose none; the hash of its
password, absent while the account waits for its activation; whether it is enabled; its failed logins and its
lockout; who created, modified and deleted it, as `Actor`s, never a default. A deleted account stays, marked, so
that its identity is never given to someone else. Its avatar is kept apart, and goes with it.

The services do what a person or an administrator does to accounts, and answer a `Result` whose `Error` carries
a code the caller recognizes — `Credentials.Invalid`, `Account.LockedOut`, `Account.Blocked`, `Email.Taken`,
`Password.Rejected`, `Registration.Closed`, `Account.NotActivated`, and so on, in `IdentityErrors`:

| Service | What it does |
| --- | --- |
| `LoginService` | Verifies an e-mail and a password, counts the failed attempts and locks the account out after too many, answers in the same time whether the account exists or not, says whether a second factor is due, and builds the principal — `sub`, `email`, `name`, and `locale`, `zoneinfo`, `picture` when the person chose them — a host signs in |
| `RegistrationService` | Creates an account when the self-registration is open, after the e-mail was proved by a code |
| `ActivationService` | Lets the person of an account an administrator created choose its first password, by the link of its activation |
| `AccountService` | Changes the password, the e-mail, verifies the current address by a code, deletes the account, verifies a password |
| `ProfileService` | Reads and changes what a person chose of their own profile: the name of the account, the language, the time zone, the avatar |
| `PasswordResetService` | Issues a reset link sent by e-mail to a proven address, and spends its token once |
| `EmailVerificationService` | Issues and checks the one-time code that proves an e-mail is read |
| `MfaService`, `LoginOtpService` | Enrolls an authenticator app (TOTP) or the e-mail as second factor, checks a code |
| `RecoveryCodeService` | Issues the recovery codes of a second factor, hashed, and consumes one |
| `AccountAdministrationService` | What an administrator does: create an account without a password and issue its activation link, issue a reset link, block, unblock, delete, reset the failed logins or the second factor; each write names its actor. An administrator never knows a password |
| `IdentityRetentionService` | Removes what identifies a person once it no longer serves: the trace of the logins, the expired tokens and verifications |

The stores are ports, each atomic: `IAuthUserStore`, `IEmailVerificationStore`, `IAccountTokenStore`,
`ILoginEventStore`, `IMfaStore`, `IAvatarStore`, `IRecoveryCodeStore`. `AddStellaegisIdentityInMemory` registers their in-memory
form, for development and tests; `AddStellaegisIdentityPostgreSQL` and `AddStellaegisIdentitySqlServer` those of
the two engines.

### The links an account receives

An activation or a reset is a link carrying a token: 32 random bytes from the system's generator, of which the
store keeps the SHA-256 alone, so that whoever reads the database holds nothing that works. A token is spent once,
atomically, before the password changes; a newer one of the same purpose revokes the previous ones; opening the
link spends nothing, and its page sends no referrer. The links start with `Links:PublicBaseUrl` when set, with
the address of the request otherwise.

A link reaches its person by e-mail, through `IIdentityMailer`, or by hand — given by the administrator by the
means of their choice — when the host declares `Links:HandDelivery`. A link mailed by the system proves the
address; a link handed over proves only that the person received it. While an address is not proven, no reset
link is mailed there: a mistyped address would hand the account to whoever holds it.

### How the person proved who they are

The principal of a session carries one `amr` claim per method, with the values of RFC 8176: `pwd` after a password
alone; `pwd`, `otp` and `mfa` after the code of an authenticator or one sent by e-mail; `pwd` and `mfa` after a
recovery code. `AuthenticationMethods` names them. An issuer carries the claim into its tokens, so that a decision
asks whether a second factor was used for this session, not whether the account has one.

### The profile

What a person chooses of their account, through `ProfileService`:

- **the name** of the account, 1 to 200 characters — the pages ask 2 to 100, as at the registration;
- **the language**, a culture name in its canonical form: `en-GB`, never `en-gb`. The pages follow it, and the
  session carries it as `locale`;
- **the time zone**, an IANA name the system knows, as written: `Europe/Paris`, never a Windows name. The session
  carries it as `zoneinfo`, for an application that shows dates — a server in a container runs in UTC;
- **the avatar**, a PNG of 256 by 256 pixels. `SetAvatarAsync` checks its structure and its checksums, and keeps it
  rebuilt from the chunks that draw the image — `IHDR`, `PLTE`, `tRNS`, `IDAT`, `IEND` —: a text, an EXIF profile, a
  position go, without an image library. It is kept apart from the account, `IAvatarStore`, so that reading an
  account never carries it, and it is removed with the account.

The claims are the session's, taken at the login: a change reaches the tokens of an issuer at the next one. A page
that has just written the profile signs the session in again, `CookieSignIn.RefreshAsync`, and shows it at once.
`picture` carries `IdentityOptions.AvatarUrl`, versioned by the time the avatar was set, when the host declares
that address — the module does not know where the host maps the pages. It answers the person's own session: an
application on the same site shows it, one on another site reads the avatars of others from its registry.

### What is kept, and for how long

The trace of the logins holds an address and a browser; the tokens and the verifications hold an address.
`IdentityRetentionService.PurgeAsync` removes the attempts older than `Retention:LoginEvents` and the tokens and
verifications expired longer than `Retention:Expired`, and says how much it removed. The module schedules nothing:
the host runs the purge every day by its own scheduler, under `IdentityRetentionService.Job`, `job:identity_purge`.
The secrets of the second factor are protected at rest by the application — AES-256-GCM under a key of
`Mfa:SecretKeys`, the account bound to its secret —, the same on every engine, and a code is accepted once.

### Options

One section, `Stellaegis:Identity`, one sub-section per concern, bound by `AddStellaegisIdentity` and validated
when the host starts:

```text
Stellaegis:Identity:PasswordHasher:Pepper          required; a secret of the deployment, never in the repository
Stellaegis:Identity:PasswordHasher:Iterations      310000
Stellaegis:Identity:PasswordPolicy:MinLength       8, and the characters a password must mix
Stellaegis:Identity:LoginPolicy:MaxFailedAttempts  5, then a lockout of LockoutDuration, 15 minutes
Stellaegis:Identity:LoginPolicy:MinResponseTime    300 ms: a login answers no faster, whatever the outcome
Stellaegis:Identity:Mfa:RequireForAllUsers         false; true forces the enrollment at the first login
Stellaegis:Identity:Mfa:SecretKeys                 required; ActiveKeySlot and Keys:<slot>, secrets of the deployment
Stellaegis:Identity:EmailVerification:CodeLength   6 digits, for Lifetime, 15 minutes, MaxAttempts 5
Stellaegis:Identity:PasswordReset:TokenLifetime    1 hour
Stellaegis:Identity:Activation:TokenLifetime       7 days
Stellaegis:Identity:Links:PublicBaseUrl            the address of the request unless set; needed outside a request
Stellaegis:Identity:Links:HandDelivery             false; true lets an administrator receive a link to hand over
Stellaegis:Identity:SelfRegistration               Closed, or Open
Stellaegis:Identity:Retention:LoginEvents          180 days, and never less
Stellaegis:Identity:Retention:Expired              30 days past their expiry, and never less
Stellaegis:Identity:AvatarUrl                      none; the absolute address of /account/avatar, for picture
```

`SelfRegistration` is `Closed` unless set: a host whose people are created by its administration — an
enterprise, a solution installed for one organization — opens nothing. `Open` lets anyone register alone.

### Events

The module publishes four events through the `IEventPublisher` of Primitives — `UserRegistered`, `UserBlocked`
with its reason, `UserUnblocked`, and `UserProfileChanged` when what others see of the person changes, the name or
the avatar —, records implementing `IEvent`. A registry that keeps a copy of the name and the avatar for the
people who share a compartment with the person refreshes it on the last one. It publishes to whatever bus the host
registered, and nowhere when the host registered none; it subscribes to nothing. A host that wants a block to
apply at once connects its bus to the admission (below).

## The cookie

`AddStellaegisIdentityCookie()` registers the cookie scheme as the default authentication of the host: the cookie
`stellaegis_identity`, kept out of scripts, sent on same-site navigations, over HTTPS only, with `/login` for a
challenge. `CookieSignIn` signs a person in — from the principal `LoginService` built, or by id, refusing a blocked
account — and out. The pages of `Stellaegis.Identity.Server` use it; a host writing its own login page does the
same. A host that authenticates its API otherwise, by a bearer token, registers that scheme too and chooses the
default after this call.

## The administration routes

`MapIdentityAdminEndpoints()` maps the administration of the accounts, relative to the group it is called on,
under `identity`. The module has no compartment: its routes read no request context, and the actor of a write
is read from the principal the host authenticated. An account is nobody's resource, so the routes declare they
load none: the operation each is labelled with is the whole decision, and the host declares who may call it.

| Route | Operation |
| --- | --- |
| `GET identity/users?skip=&take=`, `POST identity/users/lookup`, `GET identity/users/{id}` | `users.read` |
| `POST identity/users`, `POST identity/users/{id}/activation`, `/password-reset`, `/block`, `/unblock`, `/reset-failed-logins`, `/reset-mfa` | `users.write` |
| `DELETE identity/users/{id}` | `users.delete` |
| `GET identity/security/blocked-users` | `security.read` |

`POST identity/users` takes `{ "email", "displayName", "delivery" }` and creates the account without a password;
`/activation` issues a new activation link to an account still waiting, `/password-reset` a reset link to an
active one. `delivery` is `email`, the default, or `hand` when the host declares `Links:HandDelivery`: the link is
then in the answer, shown this once. A host with neither a mailer nor the hand delivery could activate nobody, and
`MapIdentityAdminEndpoints()` refuses it.

The module declares these four operations, `IdentityOperations.All`, so that the startup check of Primitives
refuses a route labelled with one the module does not declare, and so that a host harvests its catalogue from the
declarations. `AddStellaegisIdentityAdministration()` registers that startup check: a module without compartments
registers it from its own registration, since no request context does.

## The routes of one's own account

`MapIdentityAccountEndpoints()` maps what a signed-in person calls on their own account from a client of the host,
under `identity/account`, for whoever the cookie signed in: under no operation and no role, on oneself only.

| Route | What it does |
| --- | --- |
| `GET identity/account/profile` | the profile, `AccountProfile` |
| `PUT identity/account/profile` | `{ "displayName", "locale", "timeZone" }`, every field replaced; the session signed in again; 400 with the code of the refusal |

A write is a `PUT` with a JSON body, which a browser does not send cross-site without a preflight the host's CORS
policy answers. The routes belong to the module, and the startup check of Primitives checks them: the host
registers it, `AddStellaegisStartupCheck()` or `AddStellaegisIdentityAdministration()`.

## The admission of actors

A resource server refuses the requests of a blocked account at the door, before any route runs.
`AddStellaegisIdentityAdmission()` keeps the blocked accounts in memory, read from `IBlockedUsersSource` when the
host starts and then every two minutes (`Stellaegis:Identity:Admission:ReconcileInterval`; zero for a single
reading), and registers them as the `IActorAdmission` of the accounts — the contract of
`Stellaegis.Primitives.AspNetCore` since 5.1.0, which every module that knows implements, the token issuer for the
revoked tokens among them. `UseStellaegisActorAdmission()` of Primitives, after `UseAuthentication()`, asks every
admission registered and answers 401 with the code of the first refusal, `Account.Blocked` for a blocked account;
a token issuer asks the same question through `IActorAdmissions`, at the authorization and the refresh.
`UseStellaegisIdentityAdmission()` of the 5.0.0 is kept, deprecated, and enables the same middleware. A source
that cannot be reached is logged as critical, and the host goes on with what it has; no source registered stops
the startup.

The source is local, `AddStellaegisLocalBlockedUsersSource()`, in the host that holds the accounts; or HTTP,
`AddStellaegisIdentityClient(configuration)`, in a resource server apart — `Stellaegis:Identity:Client:BaseUrl` at
the administration routes of the host that holds them, the token for the call coming from an
`IIdentityClientTokenProvider` the host implements.

A block applies without waiting for the next reading when the host connects its bus: on `UserBlocked`, call
`BlockedAccounts.Block(userUniqueId)`; on `UserUnblocked`, `Unblock`. In a single process, the example does it
from its own `IEventPublisher`; with several, from a subscription to `Stellaegis.Backplane`.

## The pages

`Stellaegis.Identity.Server` is a Razor class library: `/login`, `/login/mfa`, `/login/mfa-setup`, `/register`,
`/verify-email`, `/forgot-password`, `/reset-password`, `/activate`, `/language`, and under `/account` the overview — the
avatar and the profile —, the avatar itself, the password, the e-mail, the second factor and its recovery codes, the
sign-in history, the deletion. The host mounts them beside
what it serves:

```csharp
builder.Services.AddStellaegisIdentityCookie();
builder.Services.AddStellaegisIdentityPages(builder.Configuration);        // Stellaegis:Identity:Pages
builder.Services.AddSingleton<IIdentityMailer, MyMailer>();
...
app.MapStaticAssets();                  // the stylesheet, the scripts and the logo, under /_content/Stellaegis.Identity.Server
app.UseAuthentication();
app.UseAuthorization();
app.MapStellaegisIdentityPages();       // the host's MapRazorPages, with the package's pages among them
```

`MapStaticAssets()` serves the static files of the package from the manifest the build writes, in every
environment. A host on `UseStaticFiles()` serves them too, but only in `Development` or once published.

### What the pages send

Five messages, through `IIdentityMailer`, which the host implements on its own messaging with its own wording: a
verification code, a login code, a password reset link, an activation link, and the notice that an e-mail has an
account already. Without an implementation, a host whose self-registration is open or whose password reset is
enabled refuses to start.
`AddStellaegisInMemoryIdentityMailer()` keeps the messages in memory, for development and tests.

### Making the pages the host's own

From the lightest gesture to the heaviest, each one leaving the others untouched:

| Gesture | How |
| --- | --- |
| The name, the logo, a support link, the culture | `IdentityPagesOptions`: `ApplicationName`, `LogoPath`, `SupportUrl`, `Culture`, `DefaultCulture`; also `RedirectRoot`, `DefaultReturnUrl`, `PasswordResetEnabled`, `RateLimitingPolicy`, `AvatarCornerRadius`, `GravatarImport` |
| A text or several | `Texts`, per culture, in the configuration: `Stellaegis:Identity:Pages:Texts:fr:Login.Title = Bienvenue`. The keys are those of `IdentityPagesResources.resx` |
| The colors, the typography, the spacing | a stylesheet of the host that redefines the CSS variables of `identity.css`, named in `StylesheetPath` — or served at the same path, which wins over the package's |
| A layout, a page | a file of the host at the same path — `Pages/Shared/_Layout.cshtml`, `_AuthLayout.cshtml`, `_AccountLayout.cshtml`, `Pages/Login.cshtml` — replaces the package's: ASP.NET Core resolves a page in the host first, then in the libraries |

The texts come in English and in French, and the pages follow the light or dark scheme of the device. The French
texts address nobody — the infinitive or an impersonal turn, never « vous » nor « tu » —: the address of a person
is the host's to choose, and a text of the package never contradicts it.

### The language of the pages

`Culture` imposes one, and the pages offer no choice. Otherwise they are read in the first language they have
texts for — English, French, and every culture the host gives `Texts` for — among: the language of the signed-in
person's account; the `ui_locales` of the authorization request the login page returns to; the choice made on the
pages; the culture the host's request localization decided, or the browser's `Accept-Language` when the host
decides none; `DefaultCulture`. The choice is a row of buttons at the bottom of the pages, which posts to
`/language`: it goes to the culture cookie of ASP.NET Core, `.AspNetCore.Culture` — the host's request
localization reads the same, and shows its own pages in it —, and to the account of whoever is signed in.

### The avatar

The account page carries an editor: an image from a file, or a Gravatar when the host turns on `GravatarImport`,
moved and zoomed under a circular mask, exported by the browser as a PNG of 256 by 256 pixels, which the server
checks again. The Gravatar is asked by the person's browser, on their gesture, from an address they choose —
the account's unless they change it —: Automattic receives that address's hash and the person's IP once, and the
image is kept here. The server makes no call. A host that sets a Content-Security-Policy allows
`https://gravatar.com` in `img-src` before turning it on. `/account/avatar` serves the avatar to its person, private
and sandboxed; `AvatarCornerRadius` rounds it where it is shown, from 0 for a square to 50, the default, for a
circle.

### What waits between two pages

A login whose password held and awaits its second factor, a registration that awaits its code, a change of
e-mail that awaits its code: each waits in a cookie of its own, protected by the data protection of the host, out
of scripts, for ten to fifteen minutes. The registration keeps the password there until the code proves the e-mail,
and the time zone of the browser, written into the account at its creation.

## Tests

```powershell
$env:STELLAEGIS_TEST_POSTGRESQL = "Host=127.0.0.1;Username=postgres;Database=postgres"
$env:STELLAEGIS_TEST_SQLSERVER = "Server=.\DEV;Integrated Security=true;TrustServerCertificate=true"
dotnet test --solution Stellaegis.Identity.slnx
```

The store and host tests run the same scenarios on both engines. On PostgreSQL, they create the database
`stellaegis_identity_tests` if it does not exist, install the schema as an installer does, under that connection,
and run under an ordinary role they create, `stellaegis_identity_app`. On SQL Server, they create that database at
every run and drop it after, and run as a user without login, member of the application's role, by
`EXECUTE AS USER`: an instance with integrated security only runs them. Without a variable, its tests are skipped.
The publishing workflow runs them against a PostgreSQL and a SQL Server service, and fails on a skipped test.

## License

MIT — see [LICENSE](https://github.com/Stellaegis/Stellaegis.Identity/blob/main/LICENSE). The packages depend on
third-party components listed in
[THIRD-PARTY-NOTICES.md](https://github.com/Stellaegis/Stellaegis.Identity/blob/main/THIRD-PARTY-NOTICES.md).
