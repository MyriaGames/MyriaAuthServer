using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using Myria.Server.Auth.Data;
using Myria.Server.Auth.Services;

var builder = WebApplication.CreateBuilder(args);

// Refuse to run in Production with the dev-only placeholder Jwt:Key or Security:Pepper
// from the committed appsettings.json — that file ships inside the public repo and the
// published server zip, so those values are not secret. Real ones must come from
// environment variables (Jwt__Key, Security__Pepper) or a local, gitignored
// appsettings.Production.json.
if (builder.Environment.IsProduction())
{
    var jwtKey = builder.Configuration["Jwt:Key"];
    var pepper = builder.Configuration["Security:Pepper"];
    if (jwtKey == "REPLACE_ME_DEV_PLACEHOLDER_KEY" || string.IsNullOrWhiteSpace(jwtKey))
        throw new InvalidOperationException(
            "Jwt:Key is still the dev placeholder (or unset) while running in Production. " +
            "Set a real secret via the Jwt__Key environment variable before starting this service.");
    // HMAC-SHA256 (see AuthService.BuildToken) wants a key at least as long as its output (32
    // bytes/256 bits) to actually use its full security margin - a short-but-real key would
    // pass the placeholder check above yet still be brute-forceable.
    if (Encoding.UTF8.GetByteCount(jwtKey) < 32)
        throw new InvalidOperationException(
            "Jwt:Key is shorter than 32 bytes while running in Production. Set a longer secret " +
            "via the Jwt__Key environment variable — this key signs every player's session token.");
    if (pepper == "REPLACE_ME_DEV_PLACEHOLDER_PEPPER" || string.IsNullOrWhiteSpace(pepper))
        throw new InvalidOperationException(
            "Security:Pepper is still the dev placeholder (or unset) while running in Production. " +
            "Set a real secret via the Security__Pepper environment variable before starting this service.");

    var adminSecret = builder.Configuration["Admin:InternalSecret"];
    if (adminSecret == "REPLACE_ME_DEV_PLACEHOLDER_ADMIN_SECRET" || string.IsNullOrWhiteSpace(adminSecret))
        throw new InvalidOperationException(
            "Admin:InternalSecret is still the dev placeholder (or unset) while running in Production. " +
            "Set a real secret via the Admin__InternalSecret environment variable before starting this service.");

    // Login/register submit a password — refuse to serve that over plain HTTP. The committed
    // appsettings.json only defines an Http endpoint (fine for local dev on loopback); a real
    // deployment MUST override Kestrel:Endpoints to an Https endpoint with a real certificate
    // via a gitignored appsettings.Production.json (see Setup/README notes on generating one).
    var httpsUrl  = builder.Configuration["Kestrel:Endpoints:Https:Url"];
    var certPath  = builder.Configuration["Kestrel:Endpoints:Https:Certificate:Path"];
    var certPass  = builder.Configuration["Kestrel:Endpoints:Https:Certificate:Password"];
    if (string.IsNullOrWhiteSpace(httpsUrl) || string.IsNullOrWhiteSpace(certPath) || string.IsNullOrWhiteSpace(certPass))
        throw new InvalidOperationException(
            "No Kestrel:Endpoints:Https (with a Certificate:Path/Password) is configured while running " +
            "in Production. This service would otherwise serve login/register — including the password " +
            "— over plain HTTP. Configure a real HTTPS certificate via appsettings.Production.json.");
    if (!File.Exists(Path.IsPathRooted(certPath) ? certPath : Path.Combine(AppContext.BaseDirectory, certPath)))
        throw new InvalidOperationException($"Kestrel:Endpoints:Https:Certificate:Path '{certPath}' does not exist.");
}
// Note: the dev-only Kestrel:Endpoints:Http entry deliberately lives in appsettings.Development.json,
// not here - configuration providers merge by key, so if it lived in this file (loaded in every
// environment) it would stay bound alongside the Https endpoint above even in Production. Verified
// empirically: with it in the shared file, Production served plain HTTP on top of HTTPS despite
// the check above. Keeping it Development-only is what makes "Production requires HTTPS" actually
// mean HTTPS-only.

// Database — local SQLite file, no external server/connection required. The connection
// string's "Data Source" is resolved against AppContext.BaseDirectory so it doesn't
// depend on the process's current working directory at launch.
var sqliteConnStr = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(
    builder.Configuration.GetConnectionString("DefaultConnection"));
if (!Path.IsPathRooted(sqliteConnStr.DataSource))
    sqliteConnStr.DataSource = Path.Combine(AppContext.BaseDirectory, sqliteConnStr.DataSource);
Directory.CreateDirectory(Path.GetDirectoryName(sqliteConnStr.DataSource)!);

builder.Services.AddDbContext<AuthDbContext>(opt => opt.UseSqlite(sqliteConnStr.ConnectionString));

builder.Services.AddScoped<AuthService>();
builder.Services.AddHttpClient();

// Basic brute-force / credential-stuffing friction on register+login: 5 attempts per
// minute per client IP, queueing none (extra requests get an immediate 429). This is a
// coarse first line of defense, not a substitute for proper account lockout — it just
// stops naive automated hammering of the auth endpoints.
//
// ⚠️ Deployment note: this keys off ctx.Connection.RemoteIpAddress, the real TCP peer (this
// service never trusts X-Forwarded-For - there's no app.UseForwardedHeaders() call anywhere
// in this project). That's deliberate: trusting that header from an untrusted client would let
// anyone spoof any IP. But it means if you put a reverse proxy (nginx, Caddy, IIS ARR, ...) on
// THE SAME HOST in front of Kestrel, every request arrives from 127.0.0.1 as far as this code
// is concerned - collapsing this 5/min-per-IP limit into one 5/min budget for your entire
// userbase, AND collapsing AuthController's admin-endpoint loopback-only check (see its
// RemoteIpAddress check) to nothing, since every client - proxied or not - now looks local. If
// you do put a reverse proxy in front of this service, either terminate TLS at Kestrel directly
// (this service can do that itself - see the HTTPS cert check above) instead, or configure
// ForwardedHeadersOptions with an explicit KnownProxies/KnownNetworks allowlist rather than
// trusting X-Forwarded-For from anyone.
builder.Services.AddRateLimiter(opt =>
{
    opt.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    opt.AddPolicy("auth", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 5,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0
        }));
});

// No AddAuthentication/AddJwtBearer here — this service only issues tokens (register/login
// are anonymous endpoints). JWT validation happens on each realm MyriaServer instance, which
// trusts tokens minted here via the shared Jwt:Key/Issuer/Audience config (see appsettings.json
// _JwtSyncNote) — no live call back to this service is needed for validation.

builder.Services.AddControllers().AddJsonOptions(opt =>
    opt.JsonSerializerOptions.PropertyNameCaseInsensitive = true);
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Myria.Server.Auth API", Version = "v1" });
});

var app = builder.Build();

// Startup version banner — reads the .installed_version marker update-production.sh writes
// (into ./auth/ specifically for this service, since it runs from its own AppContext.BaseDirectory)
// after a deploy. Falls back to a clear "dev" label for local runs / manual deployments.
var versionMarkerPath = Path.Combine(AppContext.BaseDirectory, ".installed_version");
var runningVersion = File.Exists(versionMarkerPath)
    ? File.ReadAllText(versionMarkerPath).Trim()
    : "dev (no .installed_version marker — not deployed via update-production.sh)";
app.Logger.LogInformation("Myria.Server.Auth starting — version: {Version}", runningVersion);

// Plain-HTTP realms are allowed (some operators can't put every realm behind HTTPS
// immediately), but every account-delete/rename admin call to one sends Admin:InternalSecret
// in the clear over the network - anyone who can observe that traffic gets the shared secret
// that authenticates realm-to-realm admin calls. Loopback realms are exempt (that traffic
// never leaves the machine). This has to be impossible to miss, so it's both a structured
// LogWarning (for log aggregators/alerting) and a loud console banner (for anyone watching the
// terminal at startup) - deliberately not a hard failure like the Jwt/Admin/HTTPS checks above.
var configuredRealms = builder.Configuration.GetSection("Realms")
    .Get<List<Myria.Server.Auth.Models.RealmDefinition>>() ?? [];
var insecureRealms = configuredRealms
    .Where(r => Uri.TryCreate(r.Url, UriKind.Absolute, out var uri)
        && uri.Scheme == Uri.UriSchemeHttp
        && uri.Host is not ("localhost" or "127.0.0.1" or "::1"))
    .ToList();

if (insecureRealms.Count > 0)
{
    foreach (var r in insecureRealms)
        app.Logger.LogWarning(
            "INSECURE REALM CONFIG: realm '{RealmName}' ({RealmUrl}) is plain HTTP, not HTTPS. " +
            "Admin:InternalSecret is sent in the clear on every admin call to this realm.",
            r.Name, r.Url);

    var prevColor = Console.ForegroundColor;
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine();
    Console.WriteLine("################################################################");
    Console.WriteLine("!!  WARNING: INSECURE REALM CONFIGURATION (plain HTTP)");
    Console.WriteLine("################################################################");
    foreach (var r in insecureRealms)
        Console.WriteLine($"!!  Realm '{r.Name}' ({r.Url}) is NOT behind HTTPS.");
    Console.WriteLine("!!  Every admin call (account delete/rename) to a realm above sends");
    Console.WriteLine("!!  Admin:InternalSecret in the clear over the network. This is only");
    Console.WriteLine("!!  acceptable if that realm is unreachable from outside a trusted");
    Console.WriteLine("!!  network (e.g. same machine or a private LAN) — it is NOT safe for");
    Console.WriteLine("!!  a realm reachable over the public internet.");
    Console.WriteLine("!!  Configure Kestrel:Endpoints:Https on that realm as soon as possible.");
    Console.WriteLine("################################################################");
    Console.WriteLine();
    Console.ForegroundColor = prevColor;
}

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    db.Database.Migrate();
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// No app.UseHttpsRedirection() here: Production is now HTTPS-only at the Kestrel level (see
// the guard above) — there's no plain-HTTP endpoint left to redirect away from. Development
// keeps its plain Http endpoint from appsettings.json for local-loopback convenience.
app.UseRateLimiter();
app.MapControllers();

app.Run();
