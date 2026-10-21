// The example host of Stellaegis.Identity: an enterprise application — one compartment, the company itself —
// that holds the accounts of its own people on PostgreSQL, serves the pages they sign in and manage their account
// with, administers the accounts over HTTP under the operations of the module, and refuses a blocked account at
// the door.
//
//   dotnet run -- install --admin-email admin@acme.test --admin-password 'Correct-Horse-9'
//       creates the database and the application's role if missing, installs the ident schema under the
//       administration connection, and creates the first administrator — the one gesture of the installation.
//   dotnet run
//       verifies the installation under the application's role, then serves.
//
// What a real host adds is its own: its API and its modules, its rights system answering the policies named
// after the operations, its messaging behind IIdentityMailer, its bus behind IEventPublisher.

using Stellaegis.Identity;
using Stellaegis.Identity.AspNetCore;
using Stellaegis.Identity.PostgreSQL;
using Stellaegis.Identity.Sample;
using Stellaegis.Identity.Server;
using Stellaegis.Primitives;
using Stellaegis.Primitives.AspNetCore;
using Stellaegis.Primitives.Data;
using Stellaegis.Primitives.Hosting;

if (args.Length > 0 && args[0] == "install")
    return await Install.RunAsync(args[1..]);

var builder = WebApplication.CreateBuilder(args);

// The frame: one compartment, the company — the case of an enterprise host — with the request context its
// own modules would read. The accounts module has no compartment and reads none.
builder.Services.AddStellaegisFrame(SampleFrame.Value);
builder.Services.AddStellaegisRequestContext();

// The accounts on PostgreSQL (Stellaegis:Identity:PostgreSQL, Stellaegis:Identity), the cookie a person signs in
// with, the pages (Stellaegis:Identity:Pages), the administration routes, and the admission of actors read from
// the local accounts (Stellaegis:Identity:Admission).
builder.Services.AddStellaegisIdentityPostgreSQL(builder.Configuration);
builder.Services.AddStellaegisIdentityCookie();
builder.Services.AddStellaegisIdentityPages(builder.Configuration);
builder.Services.AddStellaegisIdentityAdministration();
builder.Services.AddStellaegisLocalBlockedUsersSource();
builder.Services.AddStellaegisIdentityAdmission(builder.Configuration);

// What the host brings: the mailer the pages send with — here, the log —, the bus the module publishes on — here,
// one that applies a block to the admission at once —, and who may administer the accounts: the people named in
// Sample:Administrators, one policy per operation of the module.
builder.Services.AddSingleton<IIdentityMailer, LoggingMailer>();
builder.Services.AddSingleton<IEventPublisher, AdmissionEventPublisher>();
builder.Services.AddSampleAdministrators(builder.Configuration);

// The pages follow the culture of the request: French and English, French when the browser says nothing.
builder.Services.AddRequestLocalization(options => options
    .SetDefaultCulture("fr")
    .AddSupportedCultures("fr", "en")
    .AddSupportedUICultures("fr", "en"));

var app = builder.Build();

// The installation ran before, under another role: prove it, under this one, before serving anything.
await app.Services.VerifyStellaegisDatabasesAsync();

app.UseRequestLocalization();
app.MapStaticAssets();   // the stylesheet, the scripts and the logo of the pages, under /_content/Stellaegis.Identity.Server
app.UseAuthentication();
app.UseStellaegisActorAdmission();   // of Primitives: every admission registered, the blocked accounts included
app.UseAuthorization();

app.MapStellaegisIdentityPages();
app.MapGroup("/api/admin")
    .MapIdentityAdminEndpoints()
    .RequireAuthorizationPerOperation(operation => operation.ToString());

app.Run();
return 0;
