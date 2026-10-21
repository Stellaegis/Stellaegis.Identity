# Stellaegis.Identity.Server

The pages a person signs in and manages their account with, as a Razor class library any ASP.NET Core host mounts
beside what it serves: `/login`, `/login/mfa`, `/login/mfa-setup`, `/register`, `/verify-email`,
`/forgot-password`, `/reset-password`, and under `/account` the overview, the password, the e-mail, the second
factor and its recovery codes, the sign-in history, the deletion. They call the services of `Stellaegis.Identity`
and sign in through the cookie of `Stellaegis.Identity.AspNetCore`. They know no token: an issuer takes the
signed-in person from there.

```csharp
builder.Services.AddStellaegisIdentityPostgreSQL(builder.Configuration);
builder.Services.AddStellaegisIdentityCookie();
builder.Services.AddStellaegisIdentityPages(builder.Configuration);        // Stellaegis:Identity:Pages
builder.Services.AddSingleton<IIdentityMailer, MyMailer>();                 // what the pages send

var app = builder.Build();
app.UseStaticFiles();                   // the stylesheet and the scripts, under /_content/Stellaegis.Identity.Server
app.UseAuthentication();
app.UseAuthorization();
app.MapStellaegisIdentityPages();       // the host's MapRazorPages, with the package's pages among them
```

## What the pages send

Four messages, through `IIdentityMailer`, which the host implements on its own messaging with its own wording:
a verification code, a login code, a password reset link, and the notice that an e-mail has an account already.
Without an implementation, a host whose registration is open or whose password reset is enabled refuses to start.
`AddStellaegisInMemoryIdentityMailer()` keeps the messages in memory, for development and tests.

## Making the pages the host's own

From the lightest gesture to the heaviest, each one leaving the others untouched:

| Gesture | How |
| --- | --- |
| The name, the logo, a support link, the culture | `IdentityPagesOptions`: `ApplicationName`, `LogoPath`, `SupportUrl`, `Culture` |
| A text or several | `Texts`, per culture, in the configuration: `Stellaegis:Identity:Pages:Texts:fr:Login.Title = Bienvenue`. The keys are those of `IdentityPagesResources.resx` |
| The colors, the typography, the spacing | a stylesheet of the host that redefines the CSS variables of `identity.css`, named in `StylesheetPath` — or served at the same path, which wins over the package's |
| A layout, a page | a file of the host at the same path — `Pages/Shared/_Layout.cshtml`, `_AuthLayout.cshtml`, `_AccountLayout.cshtml`, `Pages/Login.cshtml` — replaces the package's: ASP.NET Core resolves a page in the host first, then in the libraries |

The texts come in English and in French; `Culture` fixes one, otherwise the pages follow the culture of the
request, which the host's request localization decides.

## What waits between two pages

A login whose password held and awaits its second factor, a registration that awaits its code, a change of
e-mail that awaits its code: each waits in a cookie of its own, protected by the data protection of the host, out
of scripts, for ten to fifteen minutes. The registration keeps the password there until the code proves the e-mail;
the host's data protection keys are what protect it.
