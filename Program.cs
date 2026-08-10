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
    if (pepper == "REPLACE_ME_DEV_PLACEHOLDER_PEPPER" || string.IsNullOrWhiteSpace(pepper))
        throw new InvalidOperationException(
            "Security:Pepper is still the dev placeholder (or unset) while running in Production. " +
            "Set a real secret via the Security__Pepper environment variable before starting this service.");
}

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

// Basic brute-force / credential-stuffing friction on register+login: 5 attempts per
// minute per client IP, queueing none (extra requests get an immediate 429). This is a
// coarse first line of defense, not a substitute for proper account lockout — it just
// stops naive automated hammering of the auth endpoints.
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

// No app.UseHttpsRedirection() here: the alpha deployment is HTTP-only (no public cert),
// so redirecting to HTTPS would send every request into a dead endpoint.
app.UseRateLimiter();
app.MapControllers();

app.Run();
